#!/usr/bin/env python3
"""Builds the single-file Wokwi sketches from the real firmware.

Wokwi projects are easiest as one sketch.ino, so link_protocol.h, mesh.h,
secrets.h (and beam.h for the modules) are pasted into it, and the simulator switches are turned on. One
sketch per board: Gateway, SensorModule_A .. SensorModule_D. Run this after
changing the firmware:

  python3 Tools/make_wokwi.py            (writes ../Pinnacle13_v6.1_Wokwi/*/sketch.ino)
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT.parent / f"{ROOT.name}_Wokwi"


def inline(sketch: str, folder: Path) -> str:
    names = ["link_protocol.h", "mesh.h", "secrets.h"]
    if (folder / "beam.h").exists():
        names.append("beam.h")                     # v6.1: the IR beam (modules only)
    for name in names:
        body = (folder / name).read_text()
        body = "\n".join(l for l in body.splitlines()
                         if l.strip() != "#pragma once" and l.strip() != '#include "link_protocol.h"')
        block = (f"// ======== {name} (inlined for Wokwi: no extra files needed) ========\n"
                 f"{body}\n// ======== end of {name} ========")
        sketch, n = re.subn(rf'^#include "{re.escape(name)}"$', lambda _: block, sketch, count=1, flags=re.M)
        if n != 1:
            sys.exit(f"{folder.name}: #include \"{name}\" not found")
    return sketch


def switch(sketch: str, name: str, value: str) -> str:
    sketch, n = re.subn(rf"^(#define {name}\s+)\S+", lambda m: m.group(1) + value, sketch, count=1, flags=re.M)
    if n != 1:
        sys.exit(f"#define {name} not found")
    return sketch


BOARDS = [("Gateway", "Gateway", "Gateway.ino", {"WOKWI_SIM": "1"})]
BOARDS += [(f"SensorModule_{m}", "SensorModule", "SensorModule.ino",
            {"MODULE_ID": f"'{m}'", "WOKWI_SIM": "1", "BENCH_COMMANDS": "1"}) for m in "ABCD"]

for out_name, board, file, switches in BOARDS:
    src = ROOT / board
    sketch = (src / file).read_text()
    for k, v in switches.items():
        sketch = switch(sketch, k, v)
    out = OUT / out_name / "sketch.ino"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(inline(sketch, src))
    print(f"wrote {out.relative_to(ROOT.parent)}")
