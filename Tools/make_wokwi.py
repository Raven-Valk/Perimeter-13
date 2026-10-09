#!/usr/bin/env python3
"""Builds the single-file Wokwi sketches from the real firmware.

Wokwi projects are easiest as one sketch.ino, so link_protocol.h and secrets.h
are pasted into it, and the simulator switches are turned on. Run this after
changing the firmware:

  python3 Tools/make_wokwi.py            (writes ../Pinnacle13_v5.4_Wokwi/*/sketch.ino)
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT.parent / f"{ROOT.name}_Wokwi"


def inline(sketch: str, folder: Path) -> str:
    for name in ("link_protocol.h", "secrets.h"):
        body = (folder / name).read_text()
        body = "\n".join(l for l in body.splitlines() if l.strip() != "#pragma once")
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


for board, file, switches in (("Gateway", "Gateway.ino", {"WOKWI_SIM": "1"}),
                              ("SensorModule", "SensorModule.ino", {"WOKWI_SIM": "1", "BENCH_COMMANDS": "1"})):
    src = ROOT / board
    sketch = (src / file).read_text()
    for k, v in switches.items():
        sketch = switch(sketch, k, v)
    out = OUT / board / "sketch.ino"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(inline(sketch, src))
    print(f"wrote {out.relative_to(ROOT.parent)}")
