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

// ---------- Link keys (32 bytes each, one per link) ----------
// KEY_x_GW must be the SAME bytes as KEY_WITH_GW in module x's block of
// SensorModule/secrets.h:  python3 Tools/make_keys.py  writes both files.
// KEY_GW_SERVER must be the same bytes as gateway_key in the server's config
// (Server/config/p13server.toml): Server/scripts/setup.py prints it for you.
// >>> radio link keys (written by Tools/make_keys.py)
// The same bytes as KEY_WITH_GW in each module's block of SensorModule/secrets.h.
static const uint8_t KEY_A_GW[32] = {
  0x9B, 0xE9, 0x67, 0x7F, 0x5F, 0x4D, 0xDE, 0xD6, 0x8A, 0x6E, 0x87, 0xB3, 0x1C, 0xEB, 0xC6, 0xD1,
  0xB0, 0x54, 0xA3, 0x19, 0x08, 0xE6, 0xE9, 0xB6, 0x79, 0x43, 0x35, 0xCD, 0x3E, 0x3E, 0xEE, 0x43
};   // Module A <-> Gateway
static const uint8_t KEY_B_GW[32] = {
  0x08, 0xBC, 0xE6, 0xCB, 0x4B, 0x89, 0x4F, 0x79, 0x14, 0x5D, 0x77, 0xC5, 0xE0, 0x78, 0xAB, 0xB5,
  0xBB, 0xC2, 0xCF, 0xA8, 0x1E, 0xE8, 0x2D, 0xF1, 0x0E, 0x4F, 0xCC, 0x91, 0x67, 0xFB, 0xB1, 0xC0
};   // Module B <-> Gateway
static const uint8_t KEY_C_GW[32] = {
  0x64, 0xE6, 0xEA, 0x84, 0x93, 0x2F, 0x74, 0xD2, 0x6C, 0x17, 0x17, 0x8F, 0x18, 0xCD, 0xFB, 0x40,
  0x61, 0xD9, 0xCC, 0x9B, 0xE9, 0x8D, 0x4B, 0x6F, 0x72, 0x75, 0x14, 0x5B, 0xE3, 0x47, 0x98, 0xC1
};   // Module C <-> Gateway
static const uint8_t KEY_D_GW[32] = {
  0xBF, 0xEB, 0x14, 0x5F, 0xC6, 0x6C, 0x77, 0x58, 0x1F, 0xD4, 0x39, 0xCC, 0x75, 0xB5, 0x6A, 0x41,
  0x32, 0x18, 0x29, 0x76, 0xCC, 0x5E, 0xC4, 0x27, 0xC4, 0x14, 0x25, 0x9F, 0xDE, 0x83, 0xA8, 0x4C
};   // Module D <-> Gateway
// <<< radio link keys
static const uint8_t KEY_GW_SERVER[32] = {  // Gateway <-> Server (dashboard)
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
static const uint8_t MAC_MOD_C[6]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t MAC_MOD_D[6]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t MAC_GATEWAY[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// ---------- Wi-Fi + server (the laptop that runs the dashboard) ----------
// The gateway joins this Wi-Fi network (laptop hotspot or router; 2.4 GHz only)
// and connects to the server's MQTT broker over TLS. WIFI_SSID "" = no server link.
#define WIFI_SSID      ""
#define WIFI_PASSWORD  ""
#define SERVER_HOST    "192.168.137.1"   // the laptop's address on that network
#define SERVER_PORT    8883
#define SERVER_NAME    "p13-server"      // name in the server's certificate (not a DNS name)
#define MQTT_USER      "gateway"
#define MQTT_PASSWORD  ""                // printed by Server/scripts/setup.py
#define SITE_ID        "site1"           // up to 20 characters. Topics: p13/<SITE_ID>/to/G and /to/P

// The CA certificate that signed the server's certificate (Server/certs/ca.crt,
// printed by setup.py). The gateway only talks to a server holding a
// certificate from this CA. Empty = server link off (it never connects unchecked).
static const char SERVER_CA_PEM[] = "";

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

// ---------- Dashboard accounts ----------
// The dashboard asks for these. The gateway checks them (the server never stores
// them). Stored as PBKDF2-HMAC-SHA256(password, salt "p13-pc:" + user, 100000 rounds),
// never the password itself. Use long passwords for the real demo. Hash for a new one:
//   python3 -c "import hashlib;print(hashlib.pbkdf2_hmac('sha256',b'admin123',b'p13-pc:admin',100000).hex())"
//  user        PBKDF2 hash (hex)                                                     role
static const PcUser PC_USERS[] = {
  { "operator", "cb2517ca1d99b7b0997600a15363346a1edbce5213da77ca8da4be00a0135a6b", R_OPERATOR    },  // demo password operator123
  { "admin",    "7493b37e4df180c408885fd146df4792281b6b15d66e213397c9bcc8132f5e2e", R_MAINTENANCE },  // demo password admin123
};
static const uint8_t PC_USER_COUNT = sizeof(PC_USERS) / sizeof(PC_USERS[0]);
