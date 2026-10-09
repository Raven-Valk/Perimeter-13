# Tests that run on a PC (not on the ESP32)

    ./run_tests.sh          (Linux / macOS / WSL; needs g++, python3, OpenSSL)

- `protocol_tests.cpp` (60 checks): signatures per link, tampering in transit (role, command, target, session), replay, stale commands after a restart, old-HELLO replay, waiting for HELLO after a restart, PC login challenge-response against a Python reference, encryption key derivation.
- `log_recovery_tests.cpp` (11 checks): the gateway's "which module lines do I have" logic, taken straight from `Gateway.ino`: no line stored twice, the right lines asked for again, after a restart too.

`Arduino.h`, `esp_task_wdt.h` and `mbedtls/` here are small stand-ins so the code compiles on a PC.
