#!/usr/bin/env python3
"""Makes new keys for the 10 radio links of the mesh and writes them into
SensorModule/secrets.h and Gateway/secrets.h (between the "radio link keys"
markers; everything else in those files is left alone).

  python3 Tools/make_keys.py

Then upload all five boards again (and re-run Tools/make_wokwi.py for Wokwi).
Each link gets its own random 32-byte key, so a stolen board only holds the
keys of its own four links: it can't fake or read the other six.
The gateway<->server key is separate (Server/scripts/setup.py makes it).
"""

import os
import re
import sys
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NODES = ["A", "B", "C", "D", "GW"]
BEGIN = "// >>> radio link keys (written by Tools/make_keys.py)"
END = "// <<< radio link keys"


def c_array(b: bytes) -> str:
    rows = [", ".join(f"0x{x:02X}" for x in b[i:i + 16]) for i in range(0, len(b), 16)]
    return "{\n  " + ",\n  ".join(rows) + "\n}"


def module_block(keys: dict) -> str:
    out = [BEGIN,
           "// Each module holds only the keys of its own 4 links (MODULE_ID picks them).",
           "// KEY_WITH_x = the key of the link between this module and x."]
    for i, me in enumerate(NODES[:4]):
        out.append(f"#{'if' if i == 0 else 'elif'} MODULE_ID == '{me}'")
        for other in NODES:
            if other == me:
                continue
            pair = tuple(sorted((me, other), key=NODES.index))
            out.append(f"static const uint8_t KEY_WITH_{other}[32] = {c_array(keys[pair])};   // {pair[0]} <-> {pair[1]}")
    out += ["#else", "#error \"MODULE_ID must be 'A', 'B', 'C' or 'D'\"", "#endif", END]
    return "\n".join(out)


def gateway_block(keys: dict) -> str:
    out = [BEGIN, "// The same bytes as KEY_WITH_GW in each module's block of SensorModule/secrets.h."]
    for m in NODES[:4]:
        out.append(f"static const uint8_t KEY_{m}_GW[32] = {c_array(keys[(m, 'GW')])};   // Module {m} <-> Gateway")
    out.append(END)
    return "\n".join(out)


def write(path: Path, block: str) -> None:
    text = path.read_text()
    pattern = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)
    if not pattern.search(text):
        sys.exit(f"{path}: markers not found")
    path.write_text(pattern.sub(lambda _: block, text, count=1))
    print(f"wrote {path.relative_to(ROOT)}")


def main() -> int:
    keys = {pair: os.urandom(32) for pair in combinations(NODES, 2)}
    write(ROOT / "SensorModule" / "secrets.h", module_block(keys))
    write(ROOT / "Gateway" / "secrets.h", gateway_block(keys))
    print("10 new link keys. Upload all five boards again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
