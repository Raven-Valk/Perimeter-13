# Project 13 — Secure Perimeter Intrusion Detection (firmware v4.3)

> **Repository note.** Each `secrets.h` is stored here as `secrets.example.h` with demo values only. Copy it to `secrets.h` in the same folder before compiling, and use your own keys and PINs. `secrets.h` is in `.gitignore` and must never be committed.

| Folder | Board | Status |
|---|---|---|
| `SensorModule/` | Module A and Module B: ESP32 DevKitC **38-pin** (one sketch, `MODULE_ID 'A'` or `'B'`) | done |
| `Gateway/` | Gateway: ESP32 DevKit V1 **30-pin** | done |
| `PC_Dongle/` + `PC_App/` | ESP32 on the PC's USB + dashboard app | next |
| `tests/` | protocol + log-recovery tests that run on a PC | |

The Wokwi versions are in `Wokwi/` (one folder per board, each with its own README).

**`link_protocol.h` must be identical in every board's folder.** The keys in each `secrets.h` must match across boards (the demo files already do).

Setup order: wire and upload all boards → read each MAC from Serial Monitor → put all MACs in every `secrets.h` → upload again (links are encrypted from then on). See `SensorModule/README.md` and `Gateway/README.md`.
