// ---------------------------------------------------------------------------
// REPOSITORY COPY: demo values only. Copy this file to secrets.h (which git
// ignores) and put your own keys, MAC addresses, PIN hashes and passwords there.
// Never commit secrets.h.
// ---------------------------------------------------------------------------
// =====================================================================
//  secrets.h  —  Node 2 (sensor node)
//  DEMO VALUES. Replace before your demo and DO NOT upload this file
//  to GitHub (it is listed in .gitignore).
// =====================================================================
#pragma once
#include <Arduino.h>

// 32-byte key shared by both nodes. MUST be identical to Node 1's secrets.h.
// Make your own with:
//   python3 -c "import os;print(', '.join('0x%02X'%b for b in os.urandom(32)))"
static const uint8_t SHARED_KEY[32] = {
  0xB7, 0xD8, 0xC0, 0x2C, 0xB9, 0x4B, 0x14, 0x9D, 0xC7, 0x7F, 0x70, 0x35, 0xDC, 0x25, 0x80, 0xCB,
  0x03, 0x10, 0xA5, 0x81, 0xF3, 0xE4, 0x05, 0x03, 0xE1, 0x81, 0x85, 0xF6, 0xB2, 0xBC, 0x86, 0xD6
};

// Node 1's Wi-Fi MAC address. Node 1 prints it on the Serial Monitor at boot:
//   "Node 1 MAC: 24:6F:28:AA:BB:CC"  ->  {0x24, 0x6F, 0x28, 0xAA, 0xBB, 0xCC}
static const uint8_t NODE1_MAC[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
