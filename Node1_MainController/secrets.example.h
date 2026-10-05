// ---------------------------------------------------------------------------
// REPOSITORY COPY: demo values only. Copy this file to secrets.h (which git
// ignores) and put your own keys, MAC addresses, PIN hashes and passwords there.
// Never commit secrets.h.
// ---------------------------------------------------------------------------
// =====================================================================
//  secrets.h  —  Node 1 (main controller)
//  DEMO VALUES. Replace before your demo and DO NOT upload this file
//  to GitHub (it is listed in .gitignore).
// =====================================================================
#pragma once
#include <Arduino.h>

// 32-byte key shared by both nodes. MUST be identical to Node 2's secrets.h.
static const uint8_t SHARED_KEY[32] = {
  0xB7, 0xD8, 0xC0, 0x2C, 0xB9, 0x4B, 0x14, 0x9D, 0xC7, 0x7F, 0x70, 0x35, 0xDC, 0x25, 0x80, 0xCB,
  0x03, 0x10, 0xA5, 0x81, 0xF3, 0xE4, 0x05, 0x03, 0xE1, 0x81, 0x85, 0xF6, 0xB2, 0xBC, 0x86, 0xD6
};

// PINs are never stored in plain text. We store SHA-256(PIN_SALT + PIN).
// Make a hash for a new PIN (example for PIN 1234):
//   python3 -c "import hashlib;print(hashlib.sha256(b'pinnacle13-demo-salt'+b'1234').hexdigest())"
static const char* PIN_SALT = "pinnacle13-demo-salt";

// Card UIDs: set ENROLL_MODE to 1 in Node1_MainController.ino, upload,
// scan each card, copy the UID from the Serial Monitor, then set it back to 0.
//
//  name         card UID bytes                 len  SHA-256(salt+PIN)                                                   role
static const User USERS[] = {
  { "Operator1", { 0xDE, 0xAD, 0xBE, 0xEF },     4,  "484f72dc40d199f0c0eee329591c6a87b904f043b728326f6812abb17ce5c17c", R_OPERATOR    },  // demo PIN 1234
  { "Maint1",    { 0x12, 0x34, 0x56, 0x78 },     4,  "0a283958e3da3847899f2dc9ba7207abcb6efb42a110372a167885f64f7abe0a", R_MAINTENANCE },  // demo PIN 9876
};
static const uint8_t USER_COUNT = sizeof(USERS) / sizeof(USERS[0]);
