# Protocol tests (run on a PC, not the ESP32)

Checks the shared radio protocol: signatures per link, tampering in transit, replay, stale commands after a restart, old-HELLO replay, and the encryption key derivation. The `Arduino.h`, `esp_task_wdt.h` and `mbedtls/` files here are small stand-ins so the header compiles on a PC.

Linux / macOS / WSL (needs OpenSSL):

    cp ../SensorModule/link_protocol.h .
    g++ -std=c++17 -I. -o test protocol_tests.cpp -lcrypto && ./test

Expected last line: `ALL TESTS PASSED (0 failed)`.
