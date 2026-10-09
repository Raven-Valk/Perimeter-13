// ---------------------------------------------------------------------------
// REPOSITORY COPY: demo values only. Copy this file to secrets.h (which git
// ignores) and put your own keys, MAC addresses, PIN hashes and passwords there.
// Never commit secrets.h.
// ---------------------------------------------------------------------------
// =====================================================================
//  secrets.h  —  Gateway
//  DEMO VALUES. Replace before the real demo and DO NOT upload this file
//  to GitHub (it is listed in .gitignore).
// =====================================================================
#pragma once
#include <Arduino.h>

// ---------- Link keys (32 bytes each, one per radio link) ----------
// KEY_A_GW / KEY_B_GW must be the SAME bytes as KEY_MOD_GW in each module's
// secrets.h. KEY_GW_PC must match the PC dongle.
// Make new ones:  python3 -c "import os;print(', '.join('0x%02X'%b for b in os.urandom(32)))"
static const uint8_t KEY_A_GW[32] = {   // Module A <-> Gateway
  0x5B, 0x9F, 0x34, 0x83, 0xC7, 0x94, 0xF8, 0x33, 0xF0, 0xDA, 0x2E, 0xB7, 0x62, 0xAE, 0x36, 0x09,
  0xA4, 0xCE, 0x88, 0x50, 0x45, 0xC4, 0x0F, 0xF0, 0xFC, 0xF2, 0x2E, 0x3C, 0x21, 0x5B, 0xE9, 0x41
};
static const uint8_t KEY_B_GW[32] = {   // Module B <-> Gateway
  0xB2, 0x37, 0x39, 0x02, 0xB5, 0x83, 0x00, 0xCC, 0xFC, 0x53, 0x8E, 0x72, 0x5B, 0x02, 0x05, 0x7C,
  0x18, 0xCB, 0xDD, 0x7F, 0x31, 0x83, 0x85, 0xE1, 0x3D, 0xB0, 0x9B, 0x38, 0x58, 0x40, 0x8E, 0xCE
};
static const uint8_t KEY_GW_PC[32] = {  // Gateway <-> PC dongle
  0xF2, 0x3E, 0xAB, 0xA5, 0x27, 0xC7, 0xE0, 0x35, 0xA8, 0x17, 0x8E, 0xC4, 0x27, 0xF5, 0x04, 0xD0,
  0x91, 0x60, 0x1A, 0xBA, 0xCC, 0x93, 0x9E, 0x6A, 0x71, 0x7D, 0x14, 0xE8, 0x8D, 0xAB, 0xB7, 0x1E
};

// ---------- ESP-NOW encryption (same on every board) ----------
static const uint8_t ESPNOW_PMK[16] = {
  0x0B, 0x56, 0xC0, 0x2C, 0xF6, 0x80, 0xBC, 0x94, 0x6F, 0x89, 0x5B, 0xCD, 0x3E, 0x67, 0xB5, 0x44
};

// ---------- Board MAC addresses (the allow-list) ----------
// Each board prints its MAC on Serial Monitor at boot. All zeros = not set yet:
// that link still works and is signed, but NOT encrypted and the MAC isn't checked.
static const uint8_t MAC_MOD_A[6]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t MAC_MOD_B[6]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t MAC_GATEWAY[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t MAC_DONGLE[6]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// ---------- RFID cards + PINs (gateway keypad) ----------
// PINs are stored as SHA-256(PIN_SALT + PIN). Use the same salt and hashes as
// the modules, so each person has one PIN everywhere.
//   python3 -c "import hashlib;print(hashlib.sha256(b'pinnacle13-demo-salt'+b'1234').hexdigest())"
// Card UIDs: set ENROLL_MODE 1 in Gateway.ino, upload, tap each card, copy the
// UID from Serial Monitor, then set ENROLL_MODE back to 0.
static const char* PIN_SALT = "pinnacle13-demo-salt";

//  name         card UID bytes                 len  SHA-256(salt + PIN)                                                   role
static const CardUser USERS[] = {
#if WOKWI_SIM   // Wokwi's preset cards: Blue = Operator1, Green = Maint1
  { "Operator1", { 0x01, 0x02, 0x03, 0x04 },     4,  "484f72dc40d199f0c0eee329591c6a87b904f043b728326f6812abb17ce5c17c", R_OPERATOR    },  // PIN 1234
  { "Maint1",    { 0x11, 0x22, 0x33, 0x44 },     4,  "0a283958e3da3847899f2dc9ba7207abcb6efb42a110372a167885f64f7abe0a", R_MAINTENANCE },  // PIN 9876
#else           // your real cards
  { "Operator1", { 0xDE, 0xAD, 0xBE, 0xEF },     4,  "484f72dc40d199f0c0eee329591c6a87b904f043b728326f6812abb17ce5c17c", R_OPERATOR    },  // demo PIN 1234
  { "Maint1",    { 0x12, 0x34, 0x56, 0x78 },     4,  "0a283958e3da3847899f2dc9ba7207abcb6efb42a110372a167885f64f7abe0a", R_MAINTENANCE },  // demo PIN 9876
#endif
};
static const uint8_t USER_COUNT = sizeof(USERS) / sizeof(USERS[0]);

// ---------- PC dashboard accounts ----------
// Stored as PBKDF2-HMAC-SHA256(password, salt "p13-pc:" + user, 100000 rounds),
// never the password itself. Use long passwords for the real demo. Hash for a new one:
//   python3 -c "import hashlib;print(hashlib.pbkdf2_hmac('sha256',b'admin123',b'p13-pc:admin',100000).hex())"
//  user        PBKDF2 hash (hex)                                                     role
static const PcUser PC_USERS[] = {
  { "operator", "cb2517ca1d99b7b0997600a15363346a1edbce5213da77ca8da4be00a0135a6b", R_OPERATOR    },  // demo password operator123
  { "admin",    "7493b37e4df180c408885fd146df4792281b6b15d66e213397c9bcc8132f5e2e", R_MAINTENANCE },  // demo password admin123
};
static const uint8_t PC_USER_COUNT = sizeof(PC_USERS) / sizeof(PC_USERS[0]);
