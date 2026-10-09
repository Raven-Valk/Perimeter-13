# Tests that run on a PC (not on the ESP32)

    ./run_tests.sh          (Linux / macOS / WSL; needs g++, python3, OpenSSL)

- `protocol_tests.cpp` (60 checks): signatures per link, tampering in transit (role, command, target, session), replay, stale commands after a restart, old-HELLO replay, waiting for HELLO after a restart, dashboard login challenge-response against a Python reference, encryption key derivation.
- `interop_tests.py` (20 checks): the server's Python packet code (`Server/p13server/protocol.py`) against this C++ header, using `interop_helper.cpp`. Packets signed in C++ verify in Python and the other way round, a flipped bit is caught, the login answer matches what the gateway computes, and both replay trackers make the same decision on 3,000 random packets.
- `log_recovery_tests.cpp` (11 checks): the gateway's "which module lines do I have" logic, taken straight from `Gateway.ino`: no line stored twice, the right lines asked for again, after a restart too.

`Arduino.h`, `esp_task_wdt.h` and `mbedtls/` here are small stand-ins so the code compiles on a PC.

The server has its own tests: `cd ../Server && python3 -m unittest tests.test_server` (sign-in, roles, cross-site requests, replayed / forged / stale packets, lost log lines fetched again, view-only sign-in while the gateway is offline).
