# Project 13: Secure Perimeter Intrusion Detection (v4)

> **Repository note.** Each `secrets.h` is stored here as `secrets.example.h` with demo values only. Copy it to `secrets.h` in the same folder before compiling, and use your own keys and PINs. `secrets.h` is in `.gitignore` and must never be committed.

This version contains the sensor module firmware. Start with [`SensorModule/README.md`](SensorModule/README.md).

| Folder | What |
|---|---|
| `SensorModule/` | Module A and Module B firmware (one sketch, `MODULE_ID 'A'` or `'B'`) |
| `Tools/` | bench tools (RFID card UID reader) |
| `Wokwi/` | the sensor module in the Wokwi simulator |
| `tests/` | protocol tests that run on a PC |

See `CHANGELOG.md` for the version history.
