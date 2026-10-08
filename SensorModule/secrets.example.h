// ---------------------------------------------------------------------------
// REPOSITORY COPY: demo values only. Copy this file to secrets.h (which git
// ignores) and put your own keys, MAC addresses, PIN hashes and passwords there.
// Never commit secrets.h.
// ---------------------------------------------------------------------------
// =====================================================================
//  secrets.h  —  Sensor Module (A and B)
//  DEMO VALUES. Replace before the real demo and DO NOT upload this file
//  to GitHub (it is listed in .gitignore).
//
//  The same file goes on both modules: MODULE_ID in SensorModule.ino picks
//  which keys this board gets, so Module A never holds Module B's gateway key.
// =====================================================================
#pragma once
#include <Arduino.h>

// ---------- Link keys (32 bytes each, one per radio link) ----------
// Each link has its own key, so a stolen board can only fake its own links.
// The gateway's secrets.h must hold the SAME bytes for KEY_A_GW / KEY_B_GW.
// Make new ones:  python3 -c "import os;print(', '.join('0x%02X'%b for b in os.urandom(32)))"
static const uint8_t KEY_A_B[32] = {        // Module A <-> Module B
  0x6E, 0xB3, 0x17, 0xE8, 0xCB, 0xD0, 0x6E, 0x27, 0xE0, 0xEA, 0x79, 0xFA, 0x10, 0x63, 0x7A, 0x65,
  0x13, 0x47, 0x85, 0xAC, 0x4C, 0x7B, 0x6C, 0x54, 0xBB, 0x9C, 0x3E, 0xCB, 0x37, 0xF6, 0x5B, 0xB8
};
#if MODULE_ID == 'A'
static const uint8_t KEY_MOD_GW[32] = {     // Module A <-> Gateway  (= KEY_A_GW on the gateway)
  0x5B, 0x9F, 0x34, 0x83, 0xC7, 0x94, 0xF8, 0x33, 0xF0, 0xDA, 0x2E, 0xB7, 0x62, 0xAE, 0x36, 0x09,
  0xA4, 0xCE, 0x88, 0x50, 0x45, 0xC4, 0x0F, 0xF0, 0xFC, 0xF2, 0x2E, 0x3C, 0x21, 0x5B, 0xE9, 0x41
};
#elif MODULE_ID == 'B'
static const uint8_t KEY_MOD_GW[32] = {     // Module B <-> Gateway  (= KEY_B_GW on the gateway)
  0xB2, 0x37, 0x39, 0x02, 0xB5, 0x83, 0x00, 0xCC, 0xFC, 0x53, 0x8E, 0x72, 0x5B, 0x02, 0x05, 0x7C,
  0x18, 0xCB, 0xDD, 0x7F, 0x31, 0x83, 0x85, 0xE1, 0x3D, 0xB0, 0x9B, 0x38, 0x58, 0x40, 0x8E, 0xCE
};
#else
#error "MODULE_ID must be 'A' or 'B'"
#endif

// ---------- ESP-NOW encryption ----------
// Primary key (16 bytes), the same on every board. The per-link keys are derived
// from the link keys above, so nothing else needs setting.
static const uint8_t ESPNOW_PMK[16] = {
  0x0B, 0x56, 0xC0, 0x2C, 0xF6, 0x80, 0xBC, 0x94, 0x6F, 0x89, 0x5B, 0xCD, 0x3E, 0x67, 0xB5, 0x44
};

// ---------- Board MAC addresses (the allow-list) ----------
// Each board prints its MAC on Serial Monitor at boot ("MAC 24:6F:28:..").
// Copy them here (as 0x24, 0x6F, ...) on EVERY board's secrets.h.
// All zeros = not set yet: that link still works and is still signed,
// but it is NOT encrypted and the sender's MAC is not checked.
static const uint8_t MAC_MOD_A[6]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t MAC_MOD_B[6]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t MAC_GATEWAY[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// ---------- PINs for acknowledging an alarm on this module's keypad ----------
// Stored as SHA-256(PIN_SALT + PIN), never as digits. Use the SAME salt and
// hashes as the gateway, so each person has one PIN everywhere.
// Hash for a new PIN (example 1234):
//   python3 -c "import hashlib;print(hashlib.sha256(b'pinnacle13-demo-salt'+b'1234').hexdigest())"
static const char* PIN_SALT = "pinnacle13-demo-salt";

//  name         SHA-256(salt + PIN)                                                  role
static const PinUser USERS[] = {
  { "Operator1", "484f72dc40d199f0c0eee329591c6a87b904f043b728326f6812abb17ce5c17c", R_OPERATOR    },  // demo PIN 1234
  { "Maint1",    "0a283958e3da3847899f2dc9ba7207abcb6efb42a110372a167885f64f7abe0a", R_MAINTENANCE },  // demo PIN 9876
};
static const uint8_t USER_COUNT = sizeof(USERS) / sizeof(USERS[0]);
