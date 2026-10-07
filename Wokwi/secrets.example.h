// ---------------------------------------------------------------------------
// REPOSITORY COPY: demo values only. Copy this file to secrets.h (which git
// ignores) and put your own keys, MAC addresses, PIN hashes and passwords there.
// Never commit secrets.h.
// ---------------------------------------------------------------------------
// =====================================================================
//  secrets.h  —  Board 1 (controller), WOKWI VERSION
//  Card UIDs match Wokwi's preset cards: BLUE card = Operator1 (PIN 1234),
//  GREEN card = Maint1 (PIN 9876).
//  DEMO VALUES. Replace before your demo and DO NOT upload this file
//  to GitHub (it is listed in .gitignore).
// =====================================================================
#pragma once
#include <Arduino.h>

// 32-byte key shared with the gateway. MUST be identical in Gateway/secrets.h.
// Make your own:
//   python3 -c "import os;print(', '.join('0x%02X'%b for b in os.urandom(32)))"
static const uint8_t SHARED_KEY[32] = {
  0xB7, 0xD8, 0xC0, 0x2C, 0xB9, 0x4B, 0x14, 0x9D, 0xC7, 0x7F, 0x70, 0x35, 0xDC, 0x25, 0x80, 0xCB,
  0x03, 0x10, 0xA5, 0x81, 0xF3, 0xE4, 0x05, 0x03, 0xE1, 0x81, 0x85, 0xF6, 0xB2, 0xBC, 0x86, 0xD6
};

// PINs are stored as SHA-256(PIN_SALT + PIN), never as digits.
// Hash for a new PIN (example: 1234):
//   python3 -c "import hashlib;print(hashlib.sha256(b'pinnacle13-demo-salt'+b'1234').hexdigest())"
static const char* PIN_SALT = "pinnacle13-demo-salt";

// Card UIDs: set ENROLL_MODE 1 in Board1_Controller.ino, upload, scan each
// card, copy the UID from Serial Monitor, then set ENROLL_MODE back to 0.
//
//  name         card UID bytes                 len  SHA-256(salt+PIN)                                                   role
static const User USERS[] = {
  { "Operator1", { 0x01, 0x02, 0x03, 0x04 },     4,  "484f72dc40d199f0c0eee329591c6a87b904f043b728326f6812abb17ce5c17c", R_OPERATOR    },  // demo PIN 1234
  { "Maint1",    { 0x11, 0x22, 0x33, 0x44 },     4,  "0a283958e3da3847899f2dc9ba7207abcb6efb42a110372a167885f64f7abe0a", R_MAINTENANCE },  // demo PIN 9876
};
static const uint8_t USER_COUNT = sizeof(USERS) / sizeof(USERS[0]);
