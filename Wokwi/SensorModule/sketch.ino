// =====================================================================
//  PINNACLE 1 — PROJECT 13 — SECURE PERIMETER INTRUSION DETECTION
//  SENSOR MODULE  (A or B)  —  ESP32 DevKitC 38-pin (WROOM-32)  —  firmware v5
//
//  Two of these sit at the two ends of one wall:
//    WALL PIR  looks along the wall toward the other module
//    SIDE PIR  looks down this module's own side wall
//  plus an enclosure tamper reed, 16x2 LCD, 4x4 keypad, buzzer, 3 LEDs.
//
//  Confirmed intrusion (P2) when, within 20 s:
//    * this module's WALL PIR and the other module's WALL PIR both fire, or
//    * this module's WALL and SIDE PIRs both fire (SIDE_PAIRS_WITH_OWN_WALL), or
//    * one PIR fires 3 times.
//  A single trigger is a warning (P1). On P2 BOTH modules sound.
//
//  Who controls what:
//    * Arm / disarm / maintenance: ONLY by signed commands from the gateway
//      (card + PIN there, or a logged-in PC). This keypad can't do them.
//    * This keypad: during an alarm, any valid PIN + # silences THIS module.
//      During tamper/fault, a MAINTENANCE PIN + # clears it (lid must be shut);
//      the gateway can clear it too. 3 wrong PINs lock the keypad (60, 120, 240 s...).
//
//  Radio: ESP-NOW straight to the other module and to the gateway. Signed,
//  replay-protected, and encrypted once MACs are set in secrets.h.
//  If the gateway or the other module disappears, this module keeps
//  detecting and alarming on its own.
//
//  States:  BOOT -> DISARMED <-> ARMED -> INTRUSION / TAMPER_FAULT / MAINTENANCE
//           -> RECOVERY -> ARMED or DISARMED
//  Priority: P0 normal, P1 warning, P2 intrusion, P3 tamper / fault
//
//  Libraries: Keypad (Mark Stanley / Alexander Brevig),
//             LiquidCrystal I2C (Frank de Brabander),
//             PubSubClient (Nick O'Leary) — only needed for Wokwi (WOKWI_SIM 1).
//  Board: "ESP32 Dev Module".
// =====================================================================

// ---------------- THE SETTINGS YOU CHANGE ----------------
#define MODULE_ID       'A'  // 'A' or 'B'. The ONLY line that differs between the two modules.
#define WOKWI_SIM       1    // 1 = Wokwi simulator: tone() buzzer, 5 s PIR warm-up, MQTT instead of ESP-NOW.
#define BENCH_COMMANDS  1    // 1 = type commands (arm, disarm, ...) in Serial Monitor to test
                             //     without the gateway. MUST be 0 for the demo: USB would bypass card + PIN.
#define SIDE_PAIRS_WITH_OWN_WALL 1   // 1 = this module's SIDE + WALL firing within 20 s also confirms
#define ALLOW_UNENCRYPTED 0  // 0 = a radio link is only used once it is encrypted (MACs set in secrets.h).
                             // 1 = also use links without MACs (signed but readable). Setup/testing only.

#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <Preferences.h>
#include <LittleFS.h>
#include <Wire.h>
#include <Keypad.h>
#include <LiquidCrystal_I2C.h>

// The Arduino IDE / Wokwi auto-insert function prototypes above the first
// function in the sketch. Declare our own types before that point.
enum State : uint8_t;
class ZoneSensor;
struct PeerLink;
struct RxItem;
struct PinUser;

// ======== link_protocol.h (inlined for Wokwi: no extra files needed) ========
// =====================================================================
//  link_protocol.h  —  v3, shared by ALL boards of Project 13:
//    Sensor Module A, Sensor Module B, Gateway, PC dongle.
//  Keep this file IDENTICAL in every sketch folder.
//
//  Links:  Module A <-> Module B,  Module A/B <-> Gateway,  Gateway <-> PC dongle.
//
//  Every packet is:
//    * signed with HMAC-SHA256 using the key of that one link
//      (A<->B, A<->Gateway, B<->Gateway, Gateway<->PC each have their own key),
//    * numbered (bootId + seq) so copies and old packets are rejected,
//    * addressed (src + dst), so a packet for A can't be fed to B,
//    * for commands and alarms: tied to the receiver's CURRENT boot (dstBoot),
//      so a command recorded earlier can't be replayed after a restart.
//  On real hardware ESP-NOW also encrypts each link (AES) once the board
//  MAC addresses are filled in secrets.h.
// =====================================================================
#include <Arduino.h>
#include <esp_task_wdt.h>
#include "mbedtls/md.h"

// Declared early so the Arduino IDE / Wokwi auto-prototypes compile when this
// file is pasted into a single-file sketch.
struct LinkPacket;

#define LINK_VERSION    3
#define ESPNOW_CHANNEL  1      // every board must use the same Wi-Fi channel
#define SIG_LEN         8      // bytes of HMAC-SHA256 kept in each packet
#define LINK_TEXT_MAX   160    // one log line / status line

// Wokwi simulator only (WOKWI_SIM 1): Wokwi can't do ESP-NOW between two
// simulations, so the same signed packets travel over MQTT instead.
// Each board listens on  <base>/to/<letter>  (A, B, G = gateway, P = PC dongle).
#define MQTT_BROKER      "broker.hivemq.com"
#define MQTT_PORT        1883
#define MQTT_TOPIC_BASE  "pinnacle13/p13-2d386efc/v5"

enum LinkNode : uint8_t { NODE_NONE = 0, NODE_MOD_A = 1, NODE_MOD_B = 2, NODE_GATEWAY = 9, NODE_DONGLE = 10 };

enum LinkType : uint8_t {
  L_HELLO      = 1,  // status beat that also says "this is my boot ID". At boot and every 10th beat.
  L_STATUS     = 2,  // status beat, every second: state, priority, health in text
  L_LOG        = 3,  // one event-log line (logNo = line number; code 1 = re-sent on request)
  L_ACK        = 4,  // gateway -> module: reply to each status beat ("link alive")
  L_PEER_EVENT = 5,  // module -> module: one of my zones fired (code = zone, arg = age in ms)
  L_PEER_ALARM = 6,  // module -> module: I confirmed an intrusion, sound too (arg = alarm no., text = why)
  L_CMD        = 7,  // gateway -> module: command (code = Cmd, role, arg, text = "user@source")
  L_CMD_RESULT = 8,  // result of a command (code = Cmd, result, arg = the command packet's seq, text = details)
                     //   module -> gateway, and gateway -> PC
  // ---- PC dongle <-> gateway ----
  L_LOGIN_REQ    = 9,   // PC -> gateway: text = user name. Gateway answers with a challenge.
  L_LOGIN_CHAL   = 10,  // gateway -> PC: text = 32 hex chars (16-byte random challenge)
  L_LOGIN_RESP   = 11,  // PC -> gateway: text = "user:" + hex(HMAC-SHA256(pwHash, challenge || user))
  L_LOGIN_RESULT = 12,  // gateway -> PC: result OK/DENIED, role, session = new session ID (0 = none), text = message
  L_PC_CMD       = 13,  // PC -> gateway: code = Cmd, target, arg, session = session ID
  L_TYPE_MAX     = 13
};
//  PC password: the gateway stores
//      pwHash = PBKDF2-HMAC-SHA256(password, salt = "p13-pc:" + user, 100000 rounds, 32 bytes)
//  (hex). Only the PC ever computes it (slow on purpose, so guessing is slow).
//  The password never travels; the PC proves it knows it by answering the random
//  challenge. Status to the PC: L_STATUS with code = the node it describes.
//
//  L_CMD (gateway -> module): logNo = command ID (the same on every retry; the
//  module answers a repeat with its first result instead of running it twice;
//  0 = no ID). For CMD_RESEND_LOG: arg = first line, session = last line (0 = no limit).

enum Cmd : uint8_t {
  CMD_ARM = 1, CMD_DISARM = 2,
  CMD_MAINT_START = 3,   // arg = seconds (30..900)
  CMD_MAINT_END = 4,
  CMD_ACK_ALARM = 5,     // acknowledge an intrusion
  CMD_CLEAR_FAULT = 6,   // clear tamper / fault (MAINTENANCE only)
  CMD_SET_TIME = 7,      // arg = Unix time (seconds)
  CMD_RESEND_LOG = 8,    // arg = first log line number wanted
  CMD_LOGOUT = 9,        // PC -> gateway: end the session
  CMD_MAX = 9
};
// Command target (L_PC_CMD): 0 = both modules, or NODE_MOD_A / NODE_MOD_B / NODE_GATEWAY
const uint8_t TARGET_BOTH = 0;
enum CmdResult : uint8_t { RES_OK = 0, RES_REFUSED = 1, RES_DENIED = 2, RES_BAD = 3 };
enum Role : uint8_t { R_NONE = 0, R_OPERATOR = 1, R_MAINTENANCE = 2 };
enum ZoneCode : uint8_t { ZONE_WALL = 1, ZONE_SIDE = 2 };
enum Health : uint8_t { H_OK = 0, H_WARMUP = 1, H_STUCK = 2, H_OFFLINE = 3 };

// Sensor module states, as sent in LinkPacket.state (the module's own enum must match).
enum ModState : uint8_t { MS_BOOT, MS_DISARMED, MS_ARMED, MS_INTRUSION, MS_TAMPER_FAULT, MS_MAINTENANCE, MS_RECOVERY, MS_COUNT };
inline const char* modStateShort(uint8_t s) {      // 3 letters, for the gateway LCD
  static const char* N[] = { "BT ", "DIS", "ARM", "ALM", "TMP", "MNT", "REC" };
  return s < MS_COUNT ? N[s] : "?? ";
}

#pragma pack(push, 1)
struct LinkPacket {
  uint8_t  version;        // LINK_VERSION
  uint8_t  src;            // LinkNode of the sender
  uint8_t  dst;            // LinkNode it is meant for
  uint8_t  type;           // LinkType
  uint32_t bootId;         // random number chosen at the sender's boot
  uint32_t seq;            // +1 on every packet the sender sends (replay protection)
  uint32_t dstBoot;        // the receiver's bootId as the sender last saw it (0 = unknown)
  uint32_t logNo;          // L_LOG: log line number
  uint8_t  state;          // sender's state number
  uint8_t  priority;       // 0..3
  uint8_t  resetReason;    // sender's last reset reason
  uint8_t  code;           // command / zone / flag, depending on type
  uint8_t  role;           // L_CMD: role of the user who gave the command
  uint8_t  result;         // L_CMD_RESULT: CmdResult
  uint32_t arg;            // number argument, depending on type
  uint32_t session;        // L_PC_CMD / L_LOGIN_RESULT: session ID
  uint8_t  target;         // L_PC_CMD: which board the command is for (TARGET_BOTH, NODE_...)
  uint8_t  textLen;        // bytes used in text[]
  char     text[LINK_TEXT_MAX];
  uint8_t  sig[SIG_LEN];   // HMAC over every byte above
};
#pragma pack(pop)

static const size_t LINK_SIGNED_LEN = offsetof(LinkPacket, sig);

inline void linkSign(const uint8_t* key, size_t keyLen, const LinkPacket& p, uint8_t out[SIG_LEN]) {
  uint8_t full[32];
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                  key, keyLen, (const uint8_t*)&p, LINK_SIGNED_LEN, full);
  memcpy(out, full, SIG_LEN);
}

// ESP-NOW encryption key (LMK, 16 bytes) for one link, derived from that
// link's signing key, so both ends get the same LMK without a second secret.
inline void linkLmk(const uint8_t* key, size_t keyLen, uint8_t out[16]) {
  uint8_t full[32];
  const char* label = "p13-espnow-lmk";
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                  key, keyLen, (const uint8_t*)label, strlen(label), full);
  memcpy(out, full, 16);
}

inline void sha256(const uint8_t* msg, size_t len, uint8_t out[32]) {
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), msg, len, out);
}
inline void hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t len, uint8_t out[32]) {
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, keyLen, msg, len, out);
}
inline String toHex(const uint8_t* b, size_t n) {
  static const char* H = "0123456789abcdef";
  String s; s.reserve(n * 2);
  for (size_t i = 0; i < n; i++) { s += H[b[i] >> 4]; s += H[b[i] & 15]; }
  return s;
}
inline bool fromHex(const String& s, uint8_t* out, size_t n) {   // exactly n bytes, or false
  if (s.length() != n * 2) return false;
  for (size_t i = 0; i < n; i++) {
    uint8_t v = 0;
    for (int k = 0; k < 2; k++) {
      char c = s[2 * i + k];
      v <<= 4;
      if (c >= '0' && c <= '9') v |= c - '0';
      else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
      else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
      else return false;
    }
    out[i] = v;
  }
  return true;
}

// Constant-time compare (does not leak how many bytes matched).
inline bool sameBytes(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t diff = 0;
  for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
  return diff == 0;
}

// Structure check before anything else is trusted.
inline bool linkWellFormed(const LinkPacket& p, int len) {
  return len == (int)sizeof(LinkPacket) && p.version == LINK_VERSION &&
         p.type >= L_HELLO && p.type <= L_TYPE_MAX && p.textLen <= LINK_TEXT_MAX;
}

// Packet types that change what a board does. They must carry the
// receiver's current boot ID, so recordings from before a restart are useless.
inline bool linkNeedsFreshness(uint8_t type) {
  return type == L_CMD || type == L_PEER_EVENT || type == L_PEER_ALARM ||
         type == L_PC_CMD || type == L_LOGIN_RESP;
}

// Boot ID = (boot counter << 16) | 16 random bits. The boot counter is kept in
// flash and only goes up, so a recorded HELLO from an OLDER boot can never be
// replayed to reset the replay protection. (If a board's flash is fully erased,
// its counter restarts at 1: then restart the other boards too.)
//
// After WE restart, only a HELLO is accepted from each sender. Whoever sees a
// packet that carries an out-of-date dstBoot answers with a HELLO at once, so
// links come back within about a second.
inline uint32_t makeBootId(uint32_t bootNo, uint32_t rnd) { return ((bootNo & 0xFFFF) << 16) | (rnd & 0xFFFF); }
inline bool bootIsNewer(uint32_t a, uint32_t b) {      // is boot a later than boot b?
#if defined(WOKWI_SIM) && WOKWI_SIM
  return a != b;           // simulator: no flash between runs, every run's counter is 1
#else
  return (int16_t)(uint16_t)((a >> 16) - (b >> 16)) > 0;
#endif
}

// Tracks one sender's boot ID + sequence number to reject replayed packets.
enum TrackResult : uint8_t { TR_OK, TR_SYNCED, TR_NEW_BOOT, TR_REPLAY, TR_UNSYNCED, TR_OLD_BOOT };
struct PeerTracker {
  bool     synced = false;
  bool     online = false;
  bool     sendHello = false;     // the sender has an out-of-date idea of OUR boot: send it a HELLO
  uint32_t bootId = 0, lastSeq = 0, lastHeard = 0;

  TrackResult accept(const LinkPacket& p) {
    TrackResult r;
    if (p.type == L_HELLO && synced && p.bootId != bootId) {                 // sender restarted?
      if (!bootIsNewer(p.bootId, bootId)) return TR_OLD_BOOT;                // HELLO from an older boot
      r = TR_NEW_BOOT;
    }
    else if (!synced) {                                                      // first packet since WE booted:
      if (p.type != L_HELLO) return TR_UNSYNCED;                             // wait for its HELLO
      r = TR_SYNCED;
    }
    else if (p.bootId != bootId || p.seq <= lastSeq)        return TR_REPLAY; // old or copied packet
    else                                                    r = TR_OK;
    bootId = p.bootId; lastSeq = p.seq; synced = true; lastHeard = millis();
    return r;
  }
};

inline char nodeLetter(uint8_t n) {
  switch (n) { case NODE_MOD_A: return 'A'; case NODE_MOD_B: return 'B';
               case NODE_GATEWAY: return 'G'; case NODE_DONGLE: return 'P'; default: return '?'; }
}

inline const char* roleName(uint8_t r) {
  switch (r) { case R_OPERATOR: return "OPERATOR"; case R_MAINTENANCE: return "MAINTENANCE"; default: return "NONE"; }
}

inline const char* cmdName(uint8_t c) {
  switch (c) {
    case CMD_ARM: return "ARM";             case CMD_DISARM: return "DISARM";
    case CMD_MAINT_START: return "MAINT";   case CMD_MAINT_END: return "MAINT_END";
    case CMD_ACK_ALARM: return "ACK_ALARM"; case CMD_CLEAR_FAULT: return "CLEAR_FAULT";
    case CMD_SET_TIME: return "SET_TIME";   case CMD_RESEND_LOG: return "RESEND_LOG";
    case CMD_LOGOUT: return "LOGOUT";
    default: return "UNKNOWN";
  }
}

inline const char* resultName(uint8_t r) {
  switch (r) { case RES_OK: return "OK"; case RES_REFUSED: return "REFUSED";
               case RES_DENIED: return "DENIED"; default: return "BAD"; }
}

inline const char* healthName(uint8_t h) {
  switch (h) {
    case H_OK:      return "OK";
    case H_WARMUP:  return "WARMUP";
    case H_STUCK:   return "STUCK";
    case H_OFFLINE: return "OFFLINE";
    default:        return "UNKNOWN";
  }
}

inline const char* resetReasonName(int r) {
  switch (r) {
    case ESP_RST_POWERON:  return "POWER_ON";
    case ESP_RST_SW:       return "SOFTWARE";
    case ESP_RST_PANIC:    return "CRASH";
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:      return "WATCHDOG";
    case ESP_RST_BROWNOUT: return "BROWNOUT";
    case ESP_RST_EXT:      return "RESET_PIN";
    default:               return "OTHER";
  }
}

// Task watchdog: if loop() stops calling esp_task_wdt_reset() for timeoutMs,
// the chip restarts. Core 3.x already starts the watchdog, so reconfigure it.
inline void startWatchdog(uint32_t timeoutMs) {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  esp_task_wdt_config_t cfg = {};
  cfg.timeout_ms     = timeoutMs;
  cfg.idle_core_mask = 0;
  cfg.trigger_panic  = true;
  if (esp_task_wdt_reconfigure(&cfg) != ESP_OK) esp_task_wdt_init(&cfg);
#else
  esp_task_wdt_init(timeoutMs / 1000, true);
#endif
  esp_task_wdt_add(NULL);
}

// true while millis() has not yet reached t (safe across millis() overflow)
inline bool notYet(uint32_t t) { return (int32_t)(t - millis()) > 0; }
// ======== end of link_protocol.h ========
struct PinUser { const char* name; const char* pinHashHex; Role role; };
// ======== secrets.h (inlined for Wokwi: no extra files needed) ========
// =====================================================================
//  secrets.h  —  Sensor Module (A and B)
//  DEMO VALUES. Replace before the real demo and DO NOT upload this file
//  to GitHub (it is listed in .gitignore).
//
//  The same file goes on both modules: MODULE_ID in SensorModule.ino picks
//  which keys this board gets, so Module A never holds Module B's gateway key.
// =====================================================================
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
// ======== end of secrets.h ========

// =====================================================================
//  PINS — ESP32 DevKitC 38-pin (WROOM-32). Check against your board's labels.
//  GPIO 34/35/36/39 are input-only with NO internal pull-ups -> external pull-up.
//  Strapping pins (0, 2, 5, 12, 15) are left unused.
// =====================================================================
const uint8_t PIN_SDA = 21, PIN_SCL = 22;                        // LCD I2C
byte KP_ROWS[4] = { 13, 14, 27, 26 };                            // keypad pins 1-4
byte KP_COLS[4] = { 25, 33, 32, 4 };                             // keypad pins 5-8 (driven: normal I/O only)
const uint8_t PIN_BUZZER     = 16;
const uint8_t PIN_LED_GREEN  = 18;
const uint8_t PIN_LED_YELLOW = 19;
const uint8_t PIN_LED_RED    = 23;
const uint8_t PIN_PIR_WALL   = 35;    // + pull-up (3 x 2.2k in series) to 3.3 V
const uint8_t PIN_PIR_SIDE   = 34;    // + pull-up (3 x 2.2k in series) to 3.3 V
const uint8_t PIN_TAMPER     = 39;    // VN. + 2.2k pull-up; reed switch to GND
const uint8_t PIN_IR         = 36;    // VP. Spare for an IR sensor later

const uint8_t TAMPER_CLOSED_LEVEL = LOW;   // lid shut = LOW; lid open OR wire cut = HIGH
const bool    BUZZER_ACTIVE_LOW   = false; // true if your buzzer module beeps when the pin is LOW
const uint8_t LCD_ADDR            = 0x27;  // try 0x3F if the LCD stays blank

// ---------------- identity (from MODULE_ID) ----------------
#if MODULE_ID == 'A'
const uint8_t MY_NODE = NODE_MOD_A, PEER_NODE = NODE_MOD_B;
#define ZN_WALL   "A-WALL"
#define ZN_SIDE   "A-SIDE"
#define ZN_IR     "A-IR"
#define PEER_WALL "B-WALL"
#define PEER_NAME "Module B"
const uint8_t* const MAC_SELF = MAC_MOD_A;
const uint8_t* const MAC_PEER = MAC_MOD_B;
#else
const uint8_t MY_NODE = NODE_MOD_B, PEER_NODE = NODE_MOD_A;
#define ZN_WALL   "B-WALL"
#define ZN_SIDE   "B-SIDE"
#define ZN_IR     "B-IR"
#define PEER_WALL "A-WALL"
#define PEER_NAME "Module A"
const uint8_t* const MAC_SELF = MAC_MOD_B;
const uint8_t* const MAC_PEER = MAC_MOD_A;
#endif
const char MY_LETTER = MODULE_ID;

// =====================================================================
//  TIMING / LIMITS
// =====================================================================
const uint32_t LOOP_MS              = 50;
const uint32_t PIR_WARMUP_MS        = WOKWI_SIM ? 5000 : 60000;
const uint32_t SENSOR_MAX_ACTIVE_MS = 30000;   // active longer = stuck / disconnected
const uint32_t TAMPER_DEBOUNCE_MS   = 60;
const uint32_t CORROBORATION_MS     = 20000;   // window for confirming a trigger
const uint8_t  REPEAT_TRIGGERS      = 3;       // same PIR this often in the window = P2
const uint32_t STATUS_EVERY_MS      = 1000;
const uint32_t LINK_TIMEOUT_MS      = WOKWI_SIM ? 8000 : 3000;   // MQTT via internet is slower
const uint8_t  MAX_ATTEMPTS         = 3;
const uint32_t BASE_LOCKOUT_S       = 60;      // 60, 120, 240, 480, 960
const uint8_t  MAX_LOCKOUT_LEVEL    = 4;
const uint32_t PIN_TIMEOUT_MS       = 30000;
const uint32_t MAINT_DEFAULT_S      = 300, MAINT_MIN_S = 30, MAINT_MAX_S = 900;
const uint32_t PERIPH_CHECK_MS      = 5000;
const uint32_t FAULT_REMINDER_MS    = 60000;
const uint32_t MSG_SHOW_MS          = 1500;
const size_t   LOG_MAX_BYTES        = 64 * 1024;
const uint16_t RESEND_MAX_LINES     = 600;
const uint8_t  ALARM_COPIES         = 3;       // peer alarm: 3 quick copies (radio can drop one)
const uint32_t ALARM_COPY_GAP_MS    = 300;
const uint32_t ALARM_REPEAT_MS      = 2000;    // then repeated while the alarm lasts

// =====================================================================
//  STATE MACHINE DEFINITIONS
// =====================================================================
enum State : uint8_t { S_BOOT, S_DISARMED, S_ARMED, S_INTRUSION,
                       S_TAMPER_FAULT, S_MAINTENANCE, S_RECOVERY };
const uint8_t STATE_COUNT = 7;
const char* STATE_NAMES[] = { "BOOT", "DISARMED", "ARMED", "INTRUSION",
                              "TAMPER_FAULT", "MAINTENANCE", "RECOVERY" };
#define ST(s) (1 << (s))
const uint8_t ALLOWED[] = {      // allowed transitions; anything else is refused + logged
  /* BOOT         */ ST(S_DISARMED) | ST(S_ARMED) | ST(S_INTRUSION) | ST(S_TAMPER_FAULT),
  /* DISARMED     */ ST(S_ARMED) | ST(S_TAMPER_FAULT) | ST(S_MAINTENANCE),
  /* ARMED        */ ST(S_INTRUSION) | ST(S_TAMPER_FAULT) | ST(S_MAINTENANCE) | ST(S_DISARMED),
  /* INTRUSION    */ ST(S_RECOVERY) | ST(S_TAMPER_FAULT) | ST(S_DISARMED),
  /* TAMPER_FAULT */ ST(S_RECOVERY) | ST(S_MAINTENANCE),
  /* MAINTENANCE  */ ST(S_RECOVERY),
  /* RECOVERY     */ ST(S_ARMED) | ST(S_DISARMED) | ST(S_TAMPER_FAULT) | ST(S_INTRUSION),
};
const char* stateName(uint8_t s) { return s < STATE_COUNT ? STATE_NAMES[s] : "INVALID"; }
// The gateway reads our state number: keep it in step with link_protocol.h
static_assert((int)S_BOOT == MS_BOOT && (int)S_DISARMED == MS_DISARMED && (int)S_ARMED == MS_ARMED &&
              (int)S_INTRUSION == MS_INTRUSION && (int)S_TAMPER_FAULT == MS_TAMPER_FAULT &&
              (int)S_MAINTENANCE == MS_MAINTENANCE && (int)S_RECOVERY == MS_RECOVERY, "state numbers must match ModState");

State    state          = S_BOOT;
uint32_t stateEnteredAt = 0;
bool     armedMode      = false;   // the mode the gateway set: armed or disarmed (survives restarts)
String   faultReason    = "";
String   selfTestReason = "";

// forward declarations (default arguments live here only)
bool goTo(State next, const String& reason);
void logEvent(const char* type, const String& event, const char* zone = "-",
              const char* result = "-", int prio = -1, const String& user = "-");
void chirp(uint32_t ms = 120);
void showMsg(const String& l1, const String& l2);
uint8_t currentPriority();
String statusText();
uint8_t applyCommand(uint8_t cmd, uint8_t role, const String& who, uint32_t arg, String& why);
String faultBlocker();

// =====================================================================
//  ZONE SENSOR  (one object per PIR / IR sensor)
//  Health: WARMUP for the first 60 s (PIR only); STUCK if "active" for
//  longer than SENSOR_MAX_ACTIVE_MS. With a pull-up, an unplugged PIR reads
//  HIGH forever -> STUCK.
// =====================================================================
class ZoneSensor {
public:
  ZoneSensor(uint8_t code_, const char* name_, uint8_t pin_, bool activeHigh_, bool warmup_, bool enabled_)
    : code(code_), name(name_), pin(pin_), enabled(enabled_), activeHigh(activeHigh_), needsWarmup(warmup_) {}

  void begin() {
    if (!enabled) return;
    pinMode(pin, INPUT);                       // pull-up is external (34-39)
    health = needsWarmup ? H_WARMUP : H_OK;
  }

  void update(uint32_t now) {
    if (!enabled) return;
    bool raw = digitalRead(pin) == HIGH;
    bool act = activeHigh ? raw : !raw;

    if (needsWarmup && !warmedUp) {            // PIR still settling: ignore (only once, after boot)
      if (now < PIR_WARMUP_MS) { health = H_WARMUP; lastActive = act; activeSince = now; return; }
      warmedUp = true;
    }
    bool rising = act && !lastActive;
    if (rising) activeSince = now;
    lastActive = act;

    if (act && now - activeSince > SENSOR_MAX_ACTIVE_MS) health = H_STUCK;
    else if (!act || health == H_WARMUP)                  health = H_OK;
    if (rising && health == H_OK) eventPending = true;
  }

  bool faulty() const { return enabled && (health == H_STUCK || health == H_OFFLINE); }
  bool warming() const { return enabled && health == H_WARMUP; }

  // Sliding window: the last REPEAT_TRIGGERS trigger times.
  void addTrigger(uint32_t now) {
    if (trigN < REPEAT_TRIGGERS) { trig[trigN++] = now; return; }
    for (uint8_t i = 0; i + 1 < REPEAT_TRIGGERS; i++) trig[i] = trig[i + 1];
    trig[REPEAT_TRIGGERS - 1] = now;
  }
  uint8_t recentCount(uint32_t now) const {          // triggers in the last 20 s
    uint8_t c = 0;
    for (uint8_t i = 0; i < trigN; i++) if (now - trig[i] < CORROBORATION_MS) c++;
    return c;
  }
  bool recent(uint32_t now) const { return trigN > 0 && now - trig[trigN - 1] < CORROBORATION_MS; }
  uint32_t lastTrig() const { return trigN ? trig[trigN - 1] : 0; }
  void clearWindow() { trigN = 0; eventPending = false; }

  const uint8_t code;
  const char*   name;
  const uint8_t pin;
  const bool    enabled;
  uint8_t  health = H_WARMUP;
  bool     eventPending = false;
  uint8_t  loggedHealth = 0xFF;   // last health written to the log
private:
  const bool activeHigh, needsWarmup;
  bool     warmedUp = false;
  bool     lastActive = false;
  uint32_t activeSince = 0;
  uint32_t trig[REPEAT_TRIGGERS] = {};
  uint8_t  trigN = 0;
};

ZoneSensor zones[] = {
  //          code       name     pin           activeHigh warmup enabled
  ZoneSensor( ZONE_WALL, ZN_WALL, PIN_PIR_WALL, true,      true,  true  ),
  ZoneSensor( ZONE_SIDE, ZN_SIDE, PIN_PIR_SIDE, true,      true,  true  ),
  ZoneSensor( 3,         ZN_IR,   PIN_IR,       false,     false, false ),   // IR: enabled=true when fitted
};
const uint8_t ZONE_COUNT = sizeof(zones) / sizeof(zones[0]);
ZoneSensor& wallZone = zones[0];
ZoneSensor& sideZone = zones[1];

// The other module's WALL trigger, as reported over the radio
uint32_t peerWallAt = 0;
bool     peerWallValid = false, peerWallNew = false;
bool peerWallRecent(uint32_t now) { return peerWallValid && now - peerWallAt < CORROBORATION_MS; }

// =====================================================================
//  TAMPER SENSOR  (time-debounced; open lid and cut wire both read "open")
// =====================================================================
class TamperSensor {
public:
  void begin() {
    pinMode(PIN_TAMPER, INPUT);              // external pull-up (GPIO 39)
    stable = candidate = digitalRead(PIN_TAMPER);
    changedAt = millis();
  }
  bool update(uint32_t now) {                // true when the debounced state changes
    uint8_t raw = digitalRead(PIN_TAMPER);
    if (raw != candidate) { candidate = raw; changedAt = now; }
    if (candidate != stable && now - changedAt >= TAMPER_DEBOUNCE_MS) { stable = candidate; return true; }
    return false;
  }
  bool isOpen() const { return stable != TAMPER_CLOSED_LEVEL; }
private:
  uint8_t  stable = HIGH, candidate = HIGH;
  uint32_t changedAt = 0;
};
TamperSensor tamper;

// =====================================================================
//  LCD  (detects a missing/re-plugged display; only rewrites changed text)
// =====================================================================
class Display {
public:
  Display() : lcd(LCD_ADDR, 16, 2) {}
  void begin() {
    online = probe();
    if (online) { lcd.init(); lcd.backlight(); }
  }
  bool check() {                             // true when online/offline changes
    bool now = probe();
    if (now && !online) { lcd.init(); lcd.backlight(); cache[0] = cache[1] = "#"; }
    bool changed = now != online;
    online = now;
    return changed;
  }
  void show(String l1, String l2) {
    if (!online) return;
    l1 = pad(l1); l2 = pad(l2);
    if (l1 != cache[0]) { lcd.setCursor(0, 0); lcd.print(l1); cache[0] = l1; }
    if (l2 != cache[1]) { lcd.setCursor(0, 1); lcd.print(l2); cache[1] = l2; }
  }
  bool online = false;
private:
  LiquidCrystal_I2C lcd;
  String cache[2];
  static bool probe() { Wire.beginTransmission(LCD_ADDR); return Wire.endTransmission() == 0; }
  static String pad(String s) { if (s.length() > 16) s = s.substring(0, 16); while (s.length() < 16) s += ' '; return s; }
};
Display display;

// =====================================================================
//  OUTPUTS: LEDs + buzzer  (unknown state fails closed: red + buzzer)
// =====================================================================
uint32_t chirpUntil = 0, outputTestUntil = 0;
void chirp(uint32_t ms) { chirpUntil = millis() + ms; }

void setBuzzer(bool on) {
#if WOKWI_SIM
  static bool was = false;                   // Wokwi's buzzer needs a tone
  if (on != was) { was = on; if (on) tone(PIN_BUZZER, 2000); else noTone(PIN_BUZZER); }
#else
  digitalWrite(PIN_BUZZER, BUZZER_ACTIVE_LOW ? !on : on);   // active buzzer: steady on/off
#endif
}

void updateOutputs() {
  uint32_t now = millis();
  bool fast = (now / 250) % 2, slow = (now / 500) % 2, beat = (now / 1000) % 2;
  bool g = false, r = false, y = false, buz = false;
  switch (state) {
    case S_BOOT:         y = slow; break;
    case S_DISARMED:     g = beat; break;                                   // disarmed: slow green
    case S_ARMED:        if (currentPriority() == 1) y = true; else g = true; break;
    case S_INTRUSION:    { r = true; uint32_t ph = now % 1000;               // P2: double beep
                           buz = ph < 200 || (ph >= 400 && ph < 600); } break;
    case S_TAMPER_FAULT: r = fast; buz = (now % 1000) < 700; break;         // P3: long pulses
    case S_MAINTENANCE:  y = slow; break;
    case S_RECOVERY:     y = true; break;
    default:             r = true; buz = true; break;                       // fail closed
  }
  if (notYet(outputTestUntil)) { g = r = y = true; buz = (now / 300) % 2; }
  if (notYet(chirpUntil)) buz = true;
  digitalWrite(PIN_LED_GREEN, g);
  digitalWrite(PIN_LED_RED, r);
  digitalWrite(PIN_LED_YELLOW, y);
  setBuzzer(buz);
}

// =====================================================================
//  PERSISTENT STORAGE (NVS). Written only on changes, not every loop.
// =====================================================================
Preferences prefs;
uint32_t bootNo = 0, logNo = 0;
uint8_t  failedAttempts = 0, lockoutLevel = 0;
uint32_t lockoutRemainingS = 0, lastLockTick = 0;
uint8_t  savedState = S_DISARMED;
String   savedReason = "";

void saveAuthCounters() {
  prefs.putUChar("failed", failedAttempts);
  prefs.putUChar("lockLvl", lockoutLevel);
  prefs.putUInt("lockRem", lockoutRemainingS);
}
void saveArmed() { prefs.putBool("armed", armedMode); }

// Real time, once the gateway has sent it (0 = not known yet)
bool     timeSynced = false;
uint32_t timeBase = 0, timeBaseMs = 0;
uint32_t unixNow() { return timeSynced ? timeBase + (millis() - timeBaseMs) / 1000 : 0; }

// =====================================================================
//  RADIO LINKS: to the gateway and to the other module
//  Real board: ESP-NOW (encrypted per link when MACs are set).
//  Wokwi: the same signed packets over MQTT.
// =====================================================================
struct RxItem { uint8_t src[6]; int len; uint8_t data[sizeof(LinkPacket)]; };
QueueHandle_t rxQueue;
const uint8_t BROADCAST[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

struct PeerLink {
  uint8_t        node;
  const char*    name;
  const uint8_t* mac;
  const uint8_t* key;
  PeerTracker    trk;
  bool           macSet = false;
  bool           encrypted = false;
  uint32_t       beats = 0;
  PeerLink(uint8_t n, const char* nm, const uint8_t* m, const uint8_t* k) : node(n), name(nm), mac(m), key(k) {}
};
PeerLink gwLink  (NODE_GATEWAY, "Gateway", MAC_GATEWAY, KEY_MOD_GW);
PeerLink peerLink(PEER_NODE,    PEER_NAME, MAC_PEER,    KEY_A_B);

uint32_t myBoot = 0, mySeq = 0;
uint8_t  myReset = 0;
bool     radioReady = false;

bool macIsSet(const uint8_t* m) { for (int i = 0; i < 6; i++) if (m[i]) return true; return false; }

// A link is only used when it is encrypted, unless ALLOW_UNENCRYPTED (Wokwi has no encryption).
bool linkUsable(const PeerLink& L) { return WOKWI_SIM || ALLOW_UNENCRYPTED || L.encrypted; }

#if WOKWI_SIM
#include <PubSubClient.h>
WiFiClient   mqttNet;
PubSubClient mqtt(mqttNet);
uint32_t     lastMqttTry = 0;
bool         mixedBoot = false;
String topicFor(uint8_t node) { return String(MQTT_TOPIC_BASE) + "/to/" + nodeLetter(node); }
void onMqtt(char* topic, byte* payload, unsigned int len) {
  RxItem it;
  memset(it.src, 0, 6);
  it.len = len;
  memcpy(it.data, payload, min((int)len, (int)sizeof(it.data)));
  xQueueSend(rxQueue, &it, 0);
}
#endif

#if ESP_ARDUINO_VERSION_MAJOR >= 3
void onRecv(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
  const uint8_t* src = info->src_addr;
#else
void onRecv(const uint8_t* src, const uint8_t* data, int len) {
#endif
  RxItem it;                                   // runs in the Wi-Fi task: copy + queue only
  memcpy(it.src, src, 6);
  it.len = len;
  memcpy(it.data, data, min(len, (int)sizeof(it.data)));
  xQueueSend(rxQueue, &it, 0);
}

bool addEncryptedPeer(PeerLink& L) {
  if (!L.macSet) return true;                  // no MAC yet: uses signed broadcast instead
  esp_now_peer_info_t pi = {};
  memcpy(pi.peer_addr, L.mac, 6);
  pi.channel = ESPNOW_CHANNEL;
  pi.ifidx   = WIFI_IF_STA;
  pi.encrypt = true;
  linkLmk(L.key, 32, pi.lmk);
  L.encrypted = esp_now_add_peer(&pi) == ESP_OK;
  return L.encrypted;
}

void radioBegin() {
  myBoot  = makeBootId(bootNo, esp_random());   // boot counter + random: only ever goes up
  myReset = (uint8_t)esp_reset_reason();
  rxQueue = xQueueCreate(16, sizeof(RxItem));
  gwLink.macSet   = macIsSet(gwLink.mac);
  peerLink.macSet = macIsSet(peerLink.mac);
#if WOKWI_SIM
  WiFi.mode(WIFI_STA);
  WiFi.begin("Wokwi-GUEST", "", 6);            // Wokwi's simulated Wi-Fi
  mqtt.setServer(MQTT_BROKER, MQTT_PORT);
  mqtt.setCallback(onMqtt);
  mqtt.setBufferSize(512);
  mqtt.setSocketTimeout(2);
  radioReady = true;
#else
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_channel(ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE);
  if (esp_now_init() != ESP_OK) { radioReady = false; return; }
  esp_now_register_recv_cb(onRecv);
  esp_now_set_pmk(ESPNOW_PMK);
  addEncryptedPeer(gwLink);                    // on failure that link falls back to signed broadcast
  addEncryptedPeer(peerLink);
  esp_now_peer_info_t bc = {};                 // fallback for links whose MAC isn't set yet
  memcpy(bc.peer_addr, BROADCAST, 6);
  bc.channel = ESPNOW_CHANNEL;
  bc.ifidx   = WIFI_IF_STA;
  bc.encrypt = false;
  esp_now_add_peer(&bc);
  radioReady = true;
#endif
}

void linkSend(PeerLink& L, uint8_t type, uint8_t code, uint8_t role, uint8_t result,
              uint32_t arg, uint32_t no, const char* text) {
  if (!radioReady || !linkUsable(L)) return;
  LinkPacket p = {};
  p.version = LINK_VERSION; p.src = MY_NODE; p.dst = L.node; p.type = type;
  p.bootId = myBoot; p.seq = ++mySeq;
  p.dstBoot = L.trk.synced ? L.trk.bootId : 0;
  p.logNo = no; p.state = state; p.priority = currentPriority(); p.resetReason = myReset;
  p.code = code; p.role = role; p.result = result; p.arg = arg;
  size_t n = text ? strnlen(text, LINK_TEXT_MAX) : 0;
  if (n) memcpy(p.text, text, n);
  p.textLen = n;
  linkSign(L.key, 32, p, p.sig);
#if WOKWI_SIM
  if (mqtt.connected()) mqtt.publish(topicFor(L.node).c_str(), (const uint8_t*)&p, sizeof(p));
#else
  esp_now_send(L.encrypted ? L.mac : BROADCAST, (const uint8_t*)&p, sizeof(p));
#endif
}

String textOf(const LinkPacket& p) {           // text[] is not NUL-terminated: copy by length
  char buf[LINK_TEXT_MAX + 1];
  memcpy(buf, p.text, p.textLen);
  buf[p.textLen] = 0;
  return String(buf);
}

// ---------------- event-log queue to the gateway ----------------
const uint8_t QSIZE = 24;
char     logQ[QSIZE][LINK_TEXT_MAX];
uint32_t logQNo[QSIZE];
uint8_t  qHead = 0, qCount = 0;

void queueLog(const String& line, uint32_t no) {
  if (qCount == QSIZE) { qHead = (qHead + 1) % QSIZE; qCount--; }   // drop oldest: gateway sees a gap and asks again
  uint8_t slot = (qHead + qCount) % QSIZE;
  strncpy(logQ[slot], line.c_str(), LINK_TEXT_MAX - 1);
  logQ[slot][LINK_TEXT_MAX - 1] = 0;
  logQNo[slot] = no;
  qCount++;
}

// ---------------- re-sending old log lines on request ----------------
bool     resendActive = false;
uint32_t resendFrom = 0, resendTo = 0;            // resendTo 0 = no upper limit
uint32_t logRotations = 0, resendRot = 0;
uint8_t  resendFile = 0;
size_t   resendPos = 0;
uint16_t resendSent = 0;
bool     fsOk = false;

void startResend(uint32_t from) {
  resendActive = fsOk; resendFrom = from; resendFile = 0; resendPos = 0; resendSent = 0; resendRot = logRotations;
}

void resendNextLine() {                        // sends at most one line per call
  if (resendRot != logRotations) {             // the log rotated: start the scan again
    resendRot = logRotations; resendFile = 0; resendPos = 0;   // (the gateway drops lines it already has)
  }
  const char* files[] = { "/log_old.csv", "/log.csv" };
  while (resendFile < 2) {
    File f = LittleFS.open(files[resendFile], FILE_READ);
    if (!f) { resendFile++; resendPos = 0; continue; }
    f.seek(resendPos);
    for (uint8_t scanned = 0; scanned < 64 && f.available(); scanned++) {
      String line = f.readStringUntil('\n');
      resendPos = f.position();
      line.trim();
      uint32_t no = (uint32_t)line.toInt();    // first column = log line number (header -> 0)
      if (no == 0 || no < resendFrom) continue;
      f.close();
      if (resendTo && no > resendTo) { resendActive = false; return; }
      linkSend(gwLink, L_LOG, 1, 0, 0, 0, no, line.c_str());
      if (++resendSent >= RESEND_MAX_LINES) resendActive = false;
      return;
    }
    bool more = f.available();
    f.close();
    if (more) return;                          // 64 lines scanned: carry on next time
    resendFile++; resendPos = 0;
  }
  resendActive = false;
}

// ---------------- alarm to the other module ----------------
// The module that confirms an intrusion sends 3 quick copies, then repeats
// every 2 s for as long as it stays in INTRUSION. The other module acts on
// each alarm number once, so acknowledging it there sticks.
uint32_t alarmNo = 0, nextAlarmCopyAt = 0;
uint8_t  alarmBurstLeft = 0;
bool     alarmMine = false;
String   alarmWhy = "";
uint32_t actedAlarmBoot = 0, actedAlarmNo = 0, ignoredAlarmBoot = 0, ignoredAlarmNo = 0;

void startPeerAlarm(const String& why) {
  alarmNo++; alarmWhy = why; alarmMine = true; alarmBurstLeft = ALARM_COPIES; nextAlarmCopyAt = millis();
}

// Rejected packets: each kind is logged at most every 2 s, with a count of the rest.
enum RejectKind : uint8_t { RJ_MALFORMED, RJ_UNKNOWN, RJ_MAC, RJ_SIG, RJ_REPLAY, RJ_STALE, RJ_OTHER, RJ_KINDS };
uint32_t rejLastLog[RJ_KINDS] = {};
uint16_t rejSuppressed[RJ_KINDS] = {};
void reject(uint8_t kind, const String& why) {
  uint32_t now = millis();
  if (rejLastLog[kind] && now - rejLastLog[kind] < 2000) { if (rejSuppressed[kind] < 65535) rejSuppressed[kind]++; return; }
  String msg = why;
  if (rejSuppressed[kind]) { msg += " (+"; msg += String(rejSuppressed[kind]); msg += " more)"; }
  rejSuppressed[kind] = 0;
  rejLastLog[kind] = now ? now : 1;
  logEvent("COMM", msg, "-", "REJECTED");
}

// ---------------- handlers for verified packets ----------------
// The gateway retries a command if our answer is lost. A retry carries the
// same command ID: answer it with the first result instead of running it twice.
uint32_t lastCmdBoot = 0, lastCmdId = 0;
uint8_t  lastCmdCode = 0, lastCmdRes = 0;
String   lastCmdWhy = "";

void onCommand(const LinkPacket& p) {
  uint32_t id = p.logNo, gwBootNow = p.bootId;     // copies: packed fields
  uint8_t  code = p.code;
  if (id && gwBootNow == lastCmdBoot && id == lastCmdId && code == lastCmdCode) {
    linkSend(gwLink, L_CMD_RESULT, code, p.role, lastCmdRes, p.seq, 0, lastCmdWhy.c_str());
    return;
  }
  String who = textOf(p);
  if (!who.length()) who = "gateway";
  if (code == CMD_RESEND_LOG) resendTo = p.session;
  String why;
  uint8_t res = applyCommand(code, p.role, who, p.arg, why);
  if (id) { lastCmdBoot = gwBootNow; lastCmdId = id; lastCmdCode = code; lastCmdRes = res; lastCmdWhy = why; }
  linkSend(gwLink, L_CMD_RESULT, code, p.role, res, p.seq, 0, why.c_str());
}

void onPeerEvent(const LinkPacket& p) {
  if (p.code != ZONE_WALL || state != S_ARMED) return;
  uint32_t age = p.arg;                            // copy: packed field
  if (age > CORROBORATION_MS) age = CORROBORATION_MS;
  peerWallAt = millis() - age;
  peerWallValid = true;
  peerWallNew = true;
}

void onPeerAlarm(const LinkPacket& p) {
  uint32_t b = p.bootId, n = p.arg;               // copies: packed fields
  if (b == actedAlarmBoot && n == actedAlarmNo) return;     // already acted on this alarm
  String why = textOf(p);
  bool armedHere = state == S_ARMED || (armedMode && (state == S_BOOT || state == S_RECOVERY));
  if (armedHere) {
    actedAlarmBoot = b; actedAlarmNo = n;
    logEvent("ALERT", String(PEER_NAME) + " confirmed: " + why, "-", "-", 2);
    goTo(S_INTRUSION, String(PEER_NAME) + " alarm");
  } else if (state == S_INTRUSION || state == S_TAMPER_FAULT) {
    actedAlarmBoot = b; actedAlarmNo = n;          // already sounding here
    logEvent("ALERT", String(PEER_NAME) + " also confirmed: " + why, "-", "-", 2);
  } else if (b != ignoredAlarmBoot || n != ignoredAlarmNo) {   // disarmed / maintenance: log once
    ignoredAlarmBoot = b; ignoredAlarmNo = n;
    logEvent("ALERT", String(PEER_NAME) + " alarm ignored here (" + stateName(state) + ")", "-", "IGNORED");
  }
}

void handlePacket(const RxItem& it) {
  LinkPacket p;
  memcpy(&p, it.data, sizeof(p));
  if (!linkWellFormed(p, it.len)) { reject(RJ_MALFORMED, "Malformed packet"); return; }     // T08
  if (p.dst != MY_NODE) return;                    // meant for another board (signed broadcast)
  PeerLink* L = p.src == NODE_GATEWAY ? &gwLink : p.src == PEER_NODE ? &peerLink : nullptr;
  if (!L) { reject(RJ_UNKNOWN, "Unknown sender"); return; }
  if (!linkUsable(*L)) { reject(RJ_OTHER, String(L->name) + ": link not encrypted - set MACs"); return; }
#if !WOKWI_SIM
  if (L->macSet && memcmp(it.src, L->mac, 6) != 0) { reject(RJ_MAC, String(L->name) + ": MAC not allowed"); return; }
#endif
  uint8_t exp[SIG_LEN];
  linkSign(L->key, 32, p, exp);
  if (!sameBytes(exp, p.sig, SIG_LEN)) { reject(RJ_SIG, String(L->name) + ": bad signature (spoofed?)"); return; }
  if (p.dstBoot != myBoot) L->trk.sendHello = true;          // it doesn't know our current boot yet
  if (linkNeedsFreshness(p.type) && p.dstBoot != myBoot) {
    reject(RJ_STALE, String(L->name) + ": stale (made before our restart)"); return;
  }
  TrackResult tr = L->trk.accept(p);
  if (tr == TR_UNSYNCED) return;                             // waiting for its HELLO (about 1 s)
  if (tr == TR_OLD_BOOT) { reject(RJ_REPLAY, String(L->name) + ": older boot number refused (flash erased? restart this board)"); return; }
  if (tr == TR_REPLAY) { reject(RJ_REPLAY, String(L->name) + ": replayed/old packet"); return; }
  if (tr == TR_NEW_BOOT) logEvent("COMM", String(L->name) + " restarted (" + resetReasonName(p.resetReason) + ")");
  if (!L->trk.online) {
    L->trk.online = true;
    logEvent("COMM", String(L->name) + " link UP");
  }
  switch (p.type) {
    case L_CMD:        if (L == &gwLink) onCommand(p); else reject(RJ_OTHER, "Command from a module refused"); break;
    case L_PEER_EVENT: if (L == &peerLink) onPeerEvent(p); break;
    case L_PEER_ALARM: if (L == &peerLink) onPeerAlarm(p); break;
    default: break;                                // HELLO / STATUS / ACK keep the link alive
  }
}

void checkLinkTimeout(PeerLink& L) {
  if (L.trk.online && (int32_t)(millis() - L.trk.lastHeard) > (int32_t)LINK_TIMEOUT_MS) {
    L.trk.online = false;
    logEvent("COMM", String(L.name) + " link DOWN (alarm still works here)");          // T09
  }
}

uint32_t lastStatus = 0;

void linkLoop(uint32_t now) {
  if (!radioReady) return;
#if WOKWI_SIM
  if (WiFi.status() == WL_CONNECTED && !mqtt.connected() && now - lastMqttTry > 5000) {
    lastMqttTry = now;
    esp_task_wdt_reset();
    String id = String("p13-") + MY_LETTER + "-" + String(myBoot, HEX);
    if (mqtt.connect(id.c_str())) {
      if (!mixedBoot) { myBoot ^= (uint32_t)micros() & 0xFFFF; mixedBoot = true; }   // simulator RNG may repeat
      mqtt.subscribe(topicFor(MY_NODE).c_str());
      Serial.println("[sim] MQTT connected");
    }
  }
  mqtt.loop();
#endif
  RxItem it;
  while (xQueueReceive(rxQueue, &it, 0) == pdTRUE) handlePacket(it);
  checkLinkTimeout(gwLink);
  checkLinkTimeout(peerLink);

  if (alarmMine && state == S_INTRUSION && !notYet(nextAlarmCopyAt)) {
    linkSend(peerLink, L_PEER_ALARM, 0, 0, 0, alarmNo, 0, alarmWhy.c_str());
    if (alarmBurstLeft) alarmBurstLeft--;
    nextAlarmCopyAt = millis() + (alarmBurstLeft ? ALARM_COPY_GAP_MS : ALARM_REPEAT_MS);
  }
  if (now - lastStatus >= STATUS_EVERY_MS) {       // 1 s beat to both; every 10th is a HELLO
    lastStatus = now;
    String st = statusText();
    PeerLink* both[2] = { &gwLink, &peerLink };
    for (PeerLink* L : both) {
      bool hello = ++L->beats % 10 == 1 || L->trk.sendHello;
      L->trk.sendHello = false;
      linkSend(*L, hello ? L_HELLO : L_STATUS, 0, 0, 0, unixNow(), 0, st.c_str());
    }
  } else if (gwLink.trk.online) {                  // logs only while the gateway is listening
    if (qCount > 0) {
      linkSend(gwLink, L_LOG, 0, 0, 0, 0, logQNo[qHead], logQ[qHead]);
      qHead = (qHead + 1) % QSIZE; qCount--;
    } else if (resendActive) {
      resendNextLine();
    }
  }
}

// =====================================================================
//  EVENT LOG  -> LittleFS /log.csv + Serial + gateway
// =====================================================================
bool dumpActive = false;                            // a log export to USB is running
const char* LOG_HEADER = "log_no,boot,uptime_ms,unix_time,module,priority,state,type,event,zone,user,result";

void logEvent(const char* type, const String& event, const char* zone,
              const char* result, int prio, const String& user) {
  String ev = event; ev.replace(",", ";"); ev.replace("\n", " ");
  String us = user;  us.replace(",", ";");
  uint32_t no = ++logNo;
  if (no % 16 == 0) prefs.putUInt("logNo", no);
  String line = String(no) + "," + String(bootNo) + "," + String(millis()) + "," + String(unixNow()) + "," +
                MY_LETTER + ",P" + String(prio < 0 ? currentPriority() : prio) + "," + stateName(state) + "," +
                type + "," + ev + "," + zone + "," + us + "," + result;
  if (!dumpActive) Serial.println(line);              // don't break up a log export (line is in the file anyway)
  queueLog(line, no);
  if (!fsOk) return;
  File f = LittleFS.open("/log.csv", FILE_APPEND);
  if (!f) return;
  if (f.size() > LOG_MAX_BYTES) {                  // rotate: keep one old file
    f.close();
    LittleFS.remove("/log_old.csv");
    LittleFS.rename("/log.csv", "/log_old.csv");
    logRotations++;
    f = LittleFS.open("/log.csv", FILE_APPEND);
    if (!f) return;
  }
  if (f.size() == 0) f.println(LOG_HEADER);
  f.println(line);
  f.close();
}

// The log is printed to USB in small pieces, one per loop pass, so the
// radio links and the alarm keep running while it prints.
uint8_t dumpFile = 0;
size_t  dumpPos = 0;

void startLogDump() {
  if (!fsOk) { Serial.println("No log storage"); return; }
  dumpActive = true; dumpFile = 0; dumpPos = 0;
  Serial.println("----- EVENT LOG START -----");
}

// The number of the last line in the log file, so numbering carries on
// exactly after a restart (0 = no log yet).
uint32_t lastNumberInLog() {
  const char* files[] = { "/log.csv", "/log_old.csv" };
  for (const char* name : files) {
    File f = LittleFS.open(name, FILE_READ);
    if (!f) continue;
    size_t sz = f.size();
    f.seek(sz > 400 ? sz - 400 : 0);
    String tail = f.readString();
    f.close();
    tail.trim();
    int nl = tail.lastIndexOf('\n');
    uint32_t no = (uint32_t)(nl >= 0 ? tail.substring(nl + 1) : tail).toInt();
    if (no) return no;
  }
  return 0;
}

void dumpStep() {
  const char* files[] = { "/log_old.csv", "/log.csv" };
  while (dumpFile < 2) {
    File f = LittleFS.open(files[dumpFile], FILE_READ);
    if (!f || dumpPos >= f.size()) { if (f) f.close(); dumpFile++; dumpPos = 0; continue; }
    f.seek(dumpPos);
    uint8_t buf[256];
    size_t n = f.read(buf, sizeof(buf));
    f.close();
    dumpPos += n;
    Serial.write(buf, n);
    return;
  }
  dumpActive = false;
  Serial.println("----- EVENT LOG END -----");
}

// =====================================================================
//  LCD TEXT
// =====================================================================
String screen1 = "", screen2 = "", msg1 = "", msg2 = "";
uint32_t msgUntil = 0;
void setScreen(const String& l1, const String& l2) { screen1 = l1; screen2 = l2; }
void showMsg(const String& l1, const String& l2) { msg1 = l1; msg2 = l2; msgUntil = millis() + MSG_SHOW_MS; }

void rejectInput(const String& why) {               // T08
  logEvent("INPUT", why, "-", "REJECTED");
  showMsg("Invalid input", why);
  chirp();
}

String linkLine() {                                  // second LCD line when all is calm
  bool gw = gwLink.trk.online, pr = peerLink.trk.online;
  if (!gw && !pr) return "GW+PEER DOWN";
  if (!gw)        return "GW link DOWN";
  if (!pr)        return String(PEER_NAME) + " DOWN";
  return "All OK";
}

// =====================================================================
//  PRIORITY + STATUS TEXT (sent to the gateway every second)
// =====================================================================
uint8_t currentPriority() {
  if (state == S_TAMPER_FAULT) return 3;
  if (state == S_INTRUSION)    return 2;
  if (state == S_ARMED) {
    if (peerWallRecent(millis())) return 1;
    uint32_t now = millis();
    for (uint8_t i = 0; i < ZONE_COUNT; i++) if (zones[i].recent(now)) return 1;
  }
  return 0;
}

String statusText() {
  String s = String(MY_LETTER) + "," + stateName(state) + ",P" + String(currentPriority());
  s += String(",WALL:") + healthName(wallZone.health) + ",SIDE:" + healthName(sideZone.health);
  s += String(",LID:") + (tamper.isOpen() ? "OPEN" : "SHUT");
  s += String(",LCD:") + (display.online ? "OK" : "OFFLINE");
  s += String(",PEER:") + (peerLink.trk.online ? "UP" : "DOWN");
  s += String(",LOCK:") + String(lockoutRemainingS);
  s += String(",LOGNO:") + String(logNo);
  return s;
}

// =====================================================================
//  STATE TRANSITIONS  (every change is validated, logged and saved)
// =====================================================================
String   pinBuf = "";
uint32_t pinStartedAt = 0;
void resetPin() { pinBuf = ""; pinStartedAt = 0; }

uint32_t maintUntil = 0, maintSeconds = MAINT_DEFAULT_S, lastFaultReminder = 0;
bool     maintShowStatus = false;

void onEnter(State s, const String& reason) {
  resetPin();
  switch (s) {
    case S_TAMPER_FAULT: faultReason = reason; lastFaultReminder = millis(); prefs.putString("reason", reason); break;
    case S_MAINTENANCE:  maintUntil = millis() + maintSeconds * 1000; maintShowStatus = false; break;
    case S_ARMED:        // fresh start: no stale detections, no open window
      for (uint8_t i = 0; i < ZONE_COUNT; i++) zones[i].clearWindow();
      peerWallValid = peerWallNew = false;
      break;
    default: break;
  }
  if (s != S_INTRUSION) alarmMine = false;         // stop repeating our alarm to the other module
}

bool goTo(State next, const String& reason) {
  if (next >= STATE_COUNT || !(ALLOWED[state] & ST(next))) {
    logEvent("STATE", String("Invalid ") + stateName(state) + "->" + stateName(next), "-", "REJECTED");
    return false;
  }
  logEvent("STATE", String(stateName(state)) + "->" + stateName(next) + " (" + reason + ")");
  state = next;
  stateEnteredAt = millis();
  onEnter(next, reason);
  prefs.putUChar("state", (uint8_t)next);          // survives power loss (T10)
  return true;
}

// =====================================================================
//  KEYPAD PIN (only used to acknowledge an alarm on this module)
// =====================================================================
void tickLockout() {
  if (lockoutRemainingS == 0) return;
  if (millis() - lastLockTick >= 1000) {
    lastLockTick += 1000;
    lockoutRemainingS--;
    if (lockoutRemainingS % 5 == 0) prefs.putUInt("lockRem", lockoutRemainingS);
    if (lockoutRemainingS == 0) logEvent("AUTH", "Keypad lockout ended");
  }
}

String sha256Hex(const String& s) {
  uint8_t out[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const uint8_t*)s.c_str(), s.length(), out);
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", out[i]);
  hex[64] = 0;
  return String(hex);
}

const PinUser* checkPin() {
  String pin = pinBuf;
  resetPin();
  const PinUser* who = nullptr;
  if (pin.length() >= 4) {                          // a short PIN is simply a wrong PIN
    String h = sha256Hex(String(PIN_SALT) + pin);
    for (uint8_t i = 0; i < USER_COUNT; i++)
      if (h.equalsIgnoreCase(USERS[i].pinHashHex)) { who = &USERS[i]; break; }
  }
  if (who) {
    failedAttempts = 0; lockoutLevel = 0; saveAuthCounters();
    logEvent("AUTH", "PIN accepted", "-", "SUCCESS", -1, String(who->name) + "@" + MY_LETTER + "-KEYPAD");
    return who;
  }
  failedAttempts++;
  logEvent("AUTH", "Wrong PIN", "-", "FAIL", -1, String(MY_LETTER) + "-KEYPAD");          // T02
  chirp(300);
  if (failedAttempts >= MAX_ATTEMPTS) {                                                    // T03
    lockoutRemainingS = BASE_LOCKOUT_S << lockoutLevel;
    if (lockoutLevel < MAX_LOCKOUT_LEVEL) lockoutLevel++;
    failedAttempts = 0;
    lastLockTick = millis();
    logEvent("AUTH", "Keypad locked " + String(lockoutRemainingS) + " s", "-", "LOCKED", 1);
    showMsg("LOCKED", String(lockoutRemainingS) + " s");
  } else {
    showMsg("Wrong PIN", String(MAX_ATTEMPTS - failedAttempts) + " tries left");
  }
  saveAuthCounters();
  return nullptr;
}

// Returns the user once a correct PIN + # is entered.
const PinUser* pollPin(char key) {
  if (lockoutRemainingS > 0) {
    if (key && strchr("0123456789*#", key)) showMsg("LOCKED", String(lockoutRemainingS) + " s left");
    else if (key) rejectInput("Key not valid");
    return nullptr;
  }
  if (pinStartedAt && millis() - pinStartedAt > PIN_TIMEOUT_MS) {
    resetPin(); logEvent("AUTH", "PIN entry timeout"); showMsg("Timed out", "Enter PIN again");
  }
  if (!key) return nullptr;
  if (key >= '0' && key <= '9') {
    if (pinBuf.length() >= 6) { resetPin(); rejectInput("PIN too long"); return nullptr; }
    if (!pinStartedAt) pinStartedAt = millis();
    pinBuf += key;
  } else if (key == '*') {
    resetPin();
  } else if (key == '#') {
    if (pinBuf.length()) return checkPin();
  } else {
    rejectInput("Key not valid");               // A-D
  }
  return nullptr;
}

// Keys pressed in states where this keypad has no job: explain, reject A-D.
void keypadHint(char key, const String& l1, const String& l2) {
  if (!key) return;
  if (key >= 'A' && key <= 'D') rejectInput("Key not valid");                       // T08
  else showMsg(l1, l2);
}

// =====================================================================
//  SELF-TEST (boot + recovery) and arming checks
// =====================================================================
bool selfTest() {
  selfTestReason = "";
  if (tamper.isOpen()) selfTestReason += "Lid open ";
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].faulty()) selfTestReason += String(zones[i].name) + " " + healthName(zones[i].health) + " ";
  if (!display.online)      logEvent("TEST", "LCD missing - LEDs and buzzer only");
  if (!gwLink.trk.online)   logEvent("TEST", "Gateway not connected - local log only");
  if (!peerLink.trk.online) logEvent("TEST", String(PEER_NAME) + " not connected - 3-hit rule only");
  outputTestUntil = millis() + 800;                 // short lamp + buzzer test
  selfTestReason.trim();
  return selfTestReason.length() == 0;
}

String armBlocker() {                               // "" = OK to arm
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].warming()) return String(zones[i].name) + " warming";
  return faultBlocker();
}

String faultBlocker() {                             // "" = no lid / sensor problem
  if (tamper.isOpen()) return "Lid open";
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].faulty()) return String(zones[i].name) + " " + healthName(zones[i].health);
  return "";
}

// =====================================================================
//  COMMANDS FROM THE GATEWAY (card + PIN there, or the logged-in PC)
//  The gateway has already checked who the user is. This module checks
//  AGAIN that the role is allowed and that the state allows it.
// =====================================================================
uint8_t applyCommand(uint8_t cmd, uint8_t role, const String& who, uint32_t arg, String& why) {
  why = "";
  uint8_t need;
  switch (cmd) {
    case CMD_ARM: case CMD_DISARM: case CMD_ACK_ALARM: case CMD_MAINT_END: need = R_OPERATOR;    break;
    case CMD_MAINT_START: case CMD_CLEAR_FAULT:                            need = R_MAINTENANCE; break;
    case CMD_SET_TIME: case CMD_RESEND_LOG:                                need = R_NONE;        break;
    default:
      why = "Unknown command";
      logEvent("CMD", "Unknown command " + String(cmd) + " from " + who, "-", "BAD", -1, who);
      return RES_BAD;
  }
  if (role > R_MAINTENANCE || role < need) {
    why = String("Needs ") + roleName(need);
    logEvent("CMD", String(cmdName(cmd)) + " denied: " + why, "-", "DENIED", -1, who);
    return RES_DENIED;
  }

  uint8_t res = RES_OK;
  bool quiet = false;
  switch (cmd) {
    case CMD_ARM:
      if (state == S_ARMED) { why = "Already armed"; break; }
      if (state != S_DISARMED) { why = String("Not possible in ") + stateName(state); res = RES_REFUSED; break; }
      why = armBlocker();
      if (why.length()) { res = RES_REFUSED; break; }                  // never arm with a problem present
      armedMode = true; saveArmed();
      goTo(S_ARMED, "armed by " + who);
      break;

    case CMD_DISARM:                                                   // the PC/gateway has priority
      if (state == S_DISARMED) { why = "Already disarmed"; break; }
      if (state == S_BOOT) { armedMode = false; saveArmed(); why = "Stays disarmed after warm-up"; break; }
      if (state == S_TAMPER_FAULT) { why = "Clear the fault first"; res = RES_REFUSED; break; }
      if (state == S_MAINTENANCE)  { why = "End maintenance first"; res = RES_REFUSED; break; }
      armedMode = false; saveArmed();
      if (state == S_INTRUSION) logEvent("ALERT", "Intrusion acknowledged by disarm", "-", "ACK", 2, who);
      goTo(S_DISARMED, "disarmed by " + who);
      break;

    case CMD_MAINT_START:
      maintSeconds = constrain(arg ? arg : MAINT_DEFAULT_S, MAINT_MIN_S, MAINT_MAX_S);
      if (state == S_MAINTENANCE) { maintUntil = millis() + maintSeconds * 1000; why = "Extended"; break; }
      if (state != S_ARMED && state != S_DISARMED && state != S_TAMPER_FAULT) {
        why = String("Not possible in ") + stateName(state); res = RES_REFUSED; break;
      }
      goTo(S_MAINTENANCE, "maintenance " + String(maintSeconds) + " s by " + who);       // T11
      break;

    case CMD_MAINT_END:
      if (state != S_MAINTENANCE) { why = "Not in maintenance"; res = RES_REFUSED; break; }
      goTo(S_RECOVERY, "maintenance ended by " + who);
      break;

    case CMD_ACK_ALARM:
      if (state != S_INTRUSION) { why = "No alarm to acknowledge"; res = RES_REFUSED; break; }
      logEvent("ALERT", "Intrusion acknowledged", "-", "ACK", 2, who);
      goTo(S_RECOVERY, "acknowledged by " + who);
      break;

    case CMD_CLEAR_FAULT:
      if (state != S_TAMPER_FAULT) { why = "No fault to clear"; res = RES_REFUSED; break; }
      why = faultBlocker();                                            // can't clear while the lid is open
      if (why.length()) { res = RES_REFUSED; break; }
      goTo(S_RECOVERY, "fault cleared by " + who);
      break;

    case CMD_SET_TIME: {
      if (arg < 1600000000UL) { why = "Bad time"; res = RES_BAD; break; }
      int32_t drift = timeSynced ? (int32_t)(arg - unixNow()) : 0;
      quiet = timeSynced && drift > -5 && drift < 5;                   // only log first sync or big jumps
      timeSynced = true; timeBase = arg; timeBaseMs = millis();
      why = "Time set";
      break;
    }

    case CMD_RESEND_LOG:
      startResend(arg);
      why = fsOk ? "Resending from " + String(arg) : "No log storage";
      if (!fsOk) res = RES_REFUSED;
      break;
  }
  if (!quiet) {
    String msg = cmdName(cmd);
    if (why.length()) { msg += ": "; msg += why; }
    logEvent("CMD", msg, "-", resultName(res), -1, who);
  }
  return res;
}

// =====================================================================
//  STATE HANDLERS
// =====================================================================
void confirmIntrusion(const String& why, const char* zone) {
  logEvent("ALERT", "Intrusion: " + why, zone, "-", 2);
  if (goTo(S_INTRUSION, why)) startPeerAlarm(why);  // the other module sounds too
}

void logMotionOutsideArmed(uint8_t prio, const char* what) {
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].eventPending) { zones[i].eventPending = false; logEvent("SENSOR", what, zones[i].name, "-", prio); }
}

void handleBoot() {
  uint32_t el = millis();
  if (el < PIR_WARMUP_MS) {
    setScreen(String(MY_LETTER) + " Warming up " + String((PIR_WARMUP_MS - el) / 1000) + "s", linkLine());
    return;
  }
  if (!selfTest()) {
    logEvent("TEST", "Self-test FAILED: " + selfTestReason, "-", "FAIL", 3);
    goTo(S_TAMPER_FAULT, selfTestReason);
    return;
  }
  logEvent("TEST", "Self-test OK", "-", "PASS");
  if (armedMode) goTo(S_ARMED, "re-armed after restart");    // pulling the plug never disarms (T10)
  else           goTo(S_DISARMED, "boot complete");
}

void handleDisarmed(char key) {
  logMotionOutsideArmed(0, "Motion (disarmed)");
  String b = faultBlocker();
  setScreen(String(MY_LETTER) + " DISARMED", b.length() ? b : (gwLink.trk.online && peerLink.trk.online ? String("Arm at gateway") : linkLine()));
  keypadHint(key, "Arm and disarm", "at the gateway");
}

void handleArmed(char key) {
  uint32_t now = millis();
  // 1) Health first: a broken sensor is a FAULT, never an intrusion.          T06
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].faulty()) { goTo(S_TAMPER_FAULT, String(zones[i].name) + " " + healthName(zones[i].health)); return; }

  // 2) Own triggers
  for (uint8_t i = 0; i < ZONE_COUNT; i++) {
    ZoneSensor& z = zones[i];
    if (!z.eventPending) continue;
    z.eventPending = false;
    if (z.health != H_OK) continue;
    z.addTrigger(now);
    uint8_t hits = z.recentCount(now);             // sliding 20 s window

    if (z.code == ZONE_WALL) {
      linkSend(peerLink, L_PEER_EVENT, ZONE_WALL, 0, 0, 0, 0, nullptr);       // tell the other module
      if (peerWallRecent(now)) { confirmIntrusion(String(PEER_WALL) + " + " + z.name, z.name); return; }   // T05a
    }
#if SIDE_PAIRS_WITH_OWN_WALL
    if (z.code == ZONE_WALL || z.code == ZONE_SIDE) {
      ZoneSensor& other = z.code == ZONE_WALL ? sideZone : wallZone;
      if (other.recent(now)) { confirmIntrusion(String(wallZone.name) + " + " + sideZone.name, z.name); return; }
    }
#endif
    if (hits >= REPEAT_TRIGGERS) { confirmIntrusion(String(z.name) + " x" + String(hits), z.name); return; }  // T05b
    chirp();                                                                   // T04
    logEvent("ALERT", "Motion warning " + String(hits) + "/" + String(REPEAT_TRIGGERS), z.name, "-", 1);
  }

  // 3) The other module's WALL PIR fired
  if (peerWallNew) {
    peerWallNew = false;
    if (wallZone.recent(now)) { confirmIntrusion(String(wallZone.name) + " + " + PEER_WALL, PEER_WALL); return; }
    logEvent("ALERT", "Motion seen by " + String(PEER_NAME), PEER_WALL, "-", 1);
  }

  // 4) Screen
  ZoneSensor* wz = nullptr;
  for (uint8_t i = 0; i < ZONE_COUNT; i++) if (zones[i].recent(now)) { wz = &zones[i]; break; }
  if (wz) {
    setScreen(String(MY_LETTER) + " WARN P1 " + String((CORROBORATION_MS - (now - wz->lastTrig())) / 1000 + 1) + "s",
              String(wz->name) + " " + String(wz->recentCount(now)) + "/" + String(REPEAT_TRIGGERS));
  } else if (peerWallRecent(now)) {
    setScreen(String(MY_LETTER) + " WARN P1", String(PEER_WALL) + " motion");
  } else {
    setScreen(String(MY_LETTER) + " ARMED       P0", linkLine());
  }
  keypadHint(key, "Disarm at", "the gateway");
}

void handleIntrusion(char key) {
  setScreen("!! INTRUSION !!", "PIN + # = ack");
  logMotionOutsideArmed(2, "Motion during intrusion");
  const PinUser* u = pollPin(key);
  if (u) {
    String who = String(u->name) + "@" + MY_LETTER + "-KEYPAD";
    logEvent("ALERT", "Intrusion acknowledged on keypad", "-", "ACK", 2, who);
    showMsg("Acknowledged", u->name);
    goTo(S_RECOVERY, "acknowledged by " + who);
  }
}

void handleTamperFault(char key) {
  bool isTamper = faultReason.indexOf("tamper") >= 0 || faultReason.indexOf("Lid") >= 0;
  setScreen(isTamper ? "!! TAMPER  P3 !!" : "!! FAULT   P3 !!", faultReason + " | MAINT PIN + #");
  if (millis() - lastFaultReminder > FAULT_REMINDER_MS) {
    lastFaultReminder = millis();
    logEvent("FAULT", "Condition persists: " + faultReason);
  }
  for (uint8_t i = 0; i < ZONE_COUNT; i++)          // keep watching zones that work
    if (zones[i].eventPending) {
      zones[i].eventPending = false;
      if (zones[i].health == H_OK) logEvent("SENSOR", "Motion during fault", zones[i].name, "-", 3);
    }

  // Clear here with a MAINTENANCE PIN (or from the gateway). Lid must be shut.
  const PinUser* u = pollPin(key);
  if (!u) return;
  String who = String(u->name) + "@" + MY_LETTER + "-KEYPAD";
  if (u->role != R_MAINTENANCE) {
    logEvent("FAULT", "Clear attempt by operator", "-", "DENIED", 3, who);
    showMsg("Access denied", "Needs MAINT PIN");
    return;
  }
  String b = faultBlocker();
  if (b.length()) {
    logEvent("FAULT", "Clear refused: " + b, "-", "REFUSED", 3, who);
    showMsg("Cannot clear", b);
    return;
  }
  logEvent("FAULT", "Fault cleared on keypad", "-", "OK", -1, who);
  showMsg("Fault cleared", u->name);
  goTo(S_RECOVERY, "fault cleared by " + who);                // self-test, then back to armed/disarmed
}

void handleMaintenance(char key) {
  uint32_t left = notYet(maintUntil) ? (maintUntil - millis()) / 1000 : 0;
  String st = String("W:") + (wallZone.health == H_OK ? "OK" : wallZone.health == H_STUCK ? "STK" : "WUP") +
              " S:" + (sideZone.health == H_OK ? "OK" : sideZone.health == H_STUCK ? "STK" : "WUP") +
              (gwLink.trk.online ? " G" : " -") + (peerLink.trk.online ? "P" : "-");
  setScreen(String(MY_LETTER) + " MAINT " + String(left) + "s", maintShowStatus ? st : "1Tst 2Sts 3Log C");
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].eventPending) { zones[i].eventPending = false; logEvent("MAINT", "Test trigger", zones[i].name); }

  if (!notYet(maintUntil)) { logEvent("MAINT", "Session timed out"); goTo(S_RECOVERY, "maintenance timeout"); return; }
  if (!key) return;
  switch (key) {
    case '1': outputTestUntil = millis() + 1500; logEvent("MAINT", "Output test", "-", "OK"); break;
    case '2': maintShowStatus = !maintShowStatus; break;
    case '3': startLogDump(); showMsg("Log sending to", "USB serial"); logEvent("MAINT", "Log export to USB", "-", "OK"); break;
    case 'C': logEvent("MAINT", "Maintenance ended on keypad", "-", "OK"); goTo(S_RECOVERY, "maintenance exit"); break;
    default:  rejectInput("Unknown command"); break;                               // T08
  }
}

void handleRecovery() {
  bool warming = false;
  for (uint8_t i = 0; i < ZONE_COUNT; i++) if (zones[i].warming()) warming = true;
  setScreen(String(MY_LETTER) + " RECOVERY", warming ? "PIRs warming up" : "Revalidating...");
  if (millis() - stateEnteredAt < 1500 || warming) return;   // visible pause; PIRs must be ready
  if (selfTest()) {
    logEvent("TEST", "Recovery self-test OK", "-", "PASS");
    goTo(armedMode ? S_ARMED : S_DISARMED, "revalidated");                          // T12
  } else {
    logEvent("TEST", "Recovery self-test FAILED: " + selfTestReason, "-", "FAIL", 3);
    goTo(S_TAMPER_FAULT, selfTestReason);
  }
}

// =====================================================================
//  LCD RENDER
// =====================================================================
String marquee(const String& s) {                  // scroll text longer than 16 characters
  if (s.length() <= 16) return s;
  uint32_t steps = s.length() - 16;
  uint32_t t = (millis() / 600) % (steps + 6);      // pause 3 steps at each end
  uint32_t off = t < 3 ? 0 : (t - 3 > steps ? steps : t - 3);
  return s.substring(off, off + 16);
}

void renderLcd() {
  String l1 = screen1, l2 = screen2;
  if (pinBuf.length()) {
    l1 = "Enter PIN, #";
    l2 = "PIN: ";
    for (unsigned i = 0; i < pinBuf.length(); i++) l2 += '*';   // never show digits
  }
  if (lockoutRemainingS > 0 && (state == S_INTRUSION || state == S_TAMPER_FAULT)) l2 = "Locked " + String(lockoutRemainingS) + "s";
  if (notYet(msgUntil)) { l1 = msg1; l2 = msg2; }
  display.show(l1, marquee(l2));
}

// =====================================================================
//  BENCH COMMANDS (BENCH_COMMANDS 1 only): test without the gateway
// =====================================================================
#if BENCH_COMMANDS
String benchBuf = "";
void benchPoll() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\r') continue;
    if (c != '\n') { if (benchBuf.length() < 40) benchBuf += c; continue; }
    String line = benchBuf; benchBuf = "";
    line.trim(); line.toLowerCase();
    if (!line.length()) continue;
    int sp = line.indexOf(' ');
    String word = sp < 0 ? line : line.substring(0, sp);
    uint32_t arg = sp < 0 ? 0 : (uint32_t)line.substring(sp + 1).toInt();
    if (word == "status") { Serial.println(statusText()); continue; }
    if (word == "log")    { startLogDump(); continue; }
    uint8_t cmd = word == "arm" ? CMD_ARM : word == "disarm" ? CMD_DISARM : word == "maint" ? CMD_MAINT_START :
                  word == "end" ? CMD_MAINT_END : word == "ack" ? CMD_ACK_ALARM : word == "clear" ? CMD_CLEAR_FAULT :
                  word == "time" ? CMD_SET_TIME : 0;
    if (!cmd) {
      Serial.println("Bench commands: arm | disarm | maint [seconds] | end | ack | clear | time <unix> | status | log");
      continue;
    }
    String why;
    uint8_t r = applyCommand(cmd, R_MAINTENANCE, "bench@USB", arg, why);
    Serial.printf("> %s: %s %s\n", cmdName(cmd), resultName(r), why.c_str());
  }
}
#endif

// =====================================================================
//  SETUP + LOOP
// =====================================================================
char KEYS[4][4] = { { '1', '2', '3', 'A' },
                    { '4', '5', '6', 'B' },
                    { '7', '8', '9', 'C' },
                    { '*', '0', '#', 'D' } };
Keypad keypad = Keypad(makeKeymap(KEYS), KP_ROWS, KP_COLS, 4, 4);
uint32_t lastPeriphCheck = 0;

void setup() {
  Serial.begin(115200);
  delay(200);
  pinMode(PIN_LED_GREEN, OUTPUT); pinMode(PIN_LED_YELLOW, OUTPUT); pinMode(PIN_LED_RED, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);    digitalWrite(PIN_BUZZER, BUZZER_ACTIVE_LOW ? HIGH : LOW);
  for (uint8_t i = 0; i < ZONE_COUNT; i++) zones[i].begin();
  tamper.begin();

  // Persistent values (validated: corrupted data is ignored)
  prefs.begin("p13mod", false);
  bootNo            = prefs.getUInt("boot", 0) + 1;  prefs.putUInt("boot", bootNo);
  failedAttempts    = prefs.getUChar("failed", 0);
  lockoutLevel      = min((int)prefs.getUChar("lockLvl", 0), (int)MAX_LOCKOUT_LEVEL);
  lockoutRemainingS = prefs.getUInt("lockRem", 0);
  armedMode         = prefs.getBool("armed", false);
  savedState        = prefs.getUChar("state", S_DISARMED);
  if (savedState >= STATE_COUNT) savedState = S_TAMPER_FAULT;      // unknown value: fail closed
  savedReason       = prefs.getString("reason", "");
  lastLockTick      = millis();

  fsOk = LittleFS.begin(true);
  uint32_t savedNo = prefs.getUInt("logNo", 0);
  uint32_t fileNo  = fsOk ? lastNumberInLog() : 0;   // carry on exactly after the last line
  logNo = fileNo ? max(fileNo, savedNo) : savedNo + 16;   // no file: skip ahead, never reuse a number
  prefs.putUInt("logNo", logNo);
  Wire.begin(PIN_SDA, PIN_SCL);
  display.begin();
  radioBegin();
  startWatchdog(WOKWI_SIM ? 20000 : 5000);   // sim: MQTT connect can take a few seconds

  String mac = WiFi.macAddress();
  Serial.printf("\nSensor Module %c, MAC %s\n", MY_LETTER, mac.c_str());
  logEvent("SYSTEM", String("Boot #") + bootNo + " reason=" + resetReasonName(esp_reset_reason()) +
                     " saved=" + stateName(savedState) + (armedMode ? " armed" : " disarmed"));     // T10
  if (!fsOk)           logEvent("SYSTEM", "Log storage unavailable", "-", "ERROR");
  if (!radioReady)     logEvent("COMM", "Radio start FAILED", "-", "ERROR");
  if (!display.online) logEvent("COMM", "LCD not found at boot");
#if !WOKWI_SIM
  uint8_t own[6];
  WiFi.macAddress(own);
  if (macIsSet(MAC_SELF) && memcmp(own, MAC_SELF, 6) != 0)
    logEvent("SYSTEM", "MAC differs from secrets.h - wrong MODULE_ID?", "-", "WARN");
  PeerLink* both[2] = { &gwLink, &peerLink };
  for (PeerLink* L : both) {
    if (linkUsable(*L) && L->encrypted) continue;
    String why = L->macSet ? " encryption setup FAILED" : " MAC not set in secrets.h";
    if (ALLOW_UNENCRYPTED) logEvent("COMM", String(L->name) + why + ": signed, NOT encrypted", "-", "WARN");
    else                   logEvent("COMM", String(L->name) + why + ": link OFF", "-", "ERROR");
  }
#endif
#if BENCH_COMMANDS
  logEvent("SYSTEM", "BENCH COMMANDS ON - USB can arm/disarm. Set 0 for the demo", "-", "WARN");
  Serial.println("Type 'help' + Enter for bench commands.");
#endif
  if (lockoutRemainingS > 0) logEvent("AUTH", "Lockout restored after reboot: " + String(lockoutRemainingS) + " s");
  stateEnteredAt = millis();

  // Alarms survive a power cut: restore them at once, before warm-up.          T10
  if (savedState == S_INTRUSION) {
    if (goTo(S_INTRUSION, "Restored")) startPeerAlarm("Restored after restart");   // the other module sounds too
  }
  else if (savedState == S_TAMPER_FAULT) goTo(S_TAMPER_FAULT, savedReason.length() ? savedReason : String("Restored"));
}

void loop() {
  esp_task_wdt_reset();                       // "still alive" — else the watchdog restarts the board
  uint32_t now = millis();
  char key = keypad.getKey();

  // ---- run in EVERY state ----
  for (uint8_t i = 0; i < ZONE_COUNT; i++) {
    zones[i].update(now);
    if (zones[i].enabled && zones[i].health != zones[i].loggedHealth) {
      if (zones[i].loggedHealth != 0xFF)
        logEvent("HEALTH", String(healthName(zones[i].loggedHealth)) + "->" + healthName(zones[i].health), zones[i].name);
      zones[i].loggedHealth = zones[i].health;
    }
  }
  if (tamper.update(now))
    logEvent("TAMPER", tamper.isOpen() ? "Enclosure opened" : "Enclosure closed", "-", "-",
             tamper.isOpen() && state != S_MAINTENANCE ? 3 : -1);
  if (now - lastPeriphCheck > PERIPH_CHECK_MS) {
    lastPeriphCheck = now;
    if (display.check()) logEvent("COMM", display.online ? "LCD online" : "LCD OFFLINE - LEDs and buzzer only");
  }
  tickLockout();
  linkLoop(now);
  if (dumpActive) dumpStep();
#if BENCH_COMMANDS
  benchPoll();
#endif

  // Tamper overrides every state except MAINTENANCE (lid may be opened;
  // re-checked on exit) and TAMPER_FAULT itself.                               T07
  if (tamper.isOpen() && state != S_MAINTENANCE && state != S_TAMPER_FAULT)
    goTo(S_TAMPER_FAULT, "Enclosure tamper");

  switch (state) {
    case S_BOOT:         handleBoot();            break;
    case S_DISARMED:     handleDisarmed(key);     break;
    case S_ARMED:        handleArmed(key);        break;
    case S_INTRUSION:    handleIntrusion(key);    break;
    case S_TAMPER_FAULT: handleTamperFault(key);  break;
    case S_MAINTENANCE:  handleMaintenance(key);  break;
    case S_RECOVERY:     handleRecovery();        break;
    default:             state = S_TAMPER_FAULT; faultReason = "Invalid state"; break;   // fail closed
  }

  updateOutputs();
  renderLcd();
  delay(LOOP_MS);
}
