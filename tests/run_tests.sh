#!/bin/sh
# Runs the PC-side tests (Linux / macOS / WSL; needs g++, python3 and OpenSSL).
set -e
cd "$(dirname "$0")"
cp ../SensorModule/link_protocol.h .
g++ -std=c++17 -I. -o protocol_tests protocol_tests.cpp -lcrypto
./protocol_tests
# Log recovery: tests the gateway's real LineWindow code, pulled out of Gateway.ino
python3 - << 'PY'
s=open('../Gateway/Gateway.ino').read()
a=s.index('struct LineWindow {'); b=s.index('\n};',a)+3
c=s.index('// First line number in [.., upTo]'); d=s.index('void onModuleLog')
open('win.h','w').write('#pragma once\n#include <cstdint>\n#include <cstring>\nconst uint16_t LINE_WIN = 1024;\n'+s[a:b]+'\nstruct ModuleView { LineWindow win; uint32_t top=0; };\n'+s[c:d])
PY
g++ -std=c++17 -o log_recovery_tests log_recovery_tests.cpp
./log_recovery_tests
