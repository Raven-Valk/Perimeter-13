// =====================================================================
//  PINNACLE 1 — PROJECT 13 — SECURE PERIMETER INTRUSION DETECTION
//  SENSOR MODULE  (A, B, C or D)  —  ESP32 DevKitC 38-pin (WROOM-32)  —  firmware v6.0
//
//  Four of these sit at the corners of the site, the gateway in the middle:
//
//        A ---- zone 2 ---- B        Each protected wall (zone) has a PIR at both
//        |                  |        ends, on the OUTSIDE face of the wall, looking
//     zone 1      G      zone 3      along it. Set each HC-SR501 to low sensitivity
//        |                  |        and range (see README) so it only sees the
//        D -----(none)----- C        strip just outside the wall.
//
//    A: PIRs A-Z1 (wall A-D) + A-Z2 (wall A-B), tamper reed, LCD, keypad, buzzer, 3 LEDs
//    B: PIRs B-Z2 (wall A-B) + B-Z3 (wall B-C), tamper reed, LCD, keypad, buzzer, 3 LEDs
//    C: PIR  C-Z3 (wall B-C), LCD, keypad           } low-cost corners: tamper switch
//    D: PIR  D-Z1 (wall A-D), LCD, keypad           } and LEDs optional, no buzzer
//
//  Confirmed intrusion (P2) when, within 20 s:
//    * both PIRs of one wall fire (this module's and the module's at the other end), or
//    * both PIRs of this module fire (A or B: someone at the corner), or
//    * one PIR fires 3 times.
//  A single trigger is a warning (P1).
//  While an intrusion is active (not yet acknowledged), the 20 s / 3-hit rules are
//  off: ANY PIR firing anywhere is at once an intrusion in its zone.
//  On P2 every armed module goes to INTRUSION; the buzzer sounds on each module
//  standing on a wall in alarm (zone 1 -> A, zone 2 -> A + B, zone 3 -> B).
//
//  Who controls what:
//    * Arm / disarm / maintenance: ONLY by signed commands from the gateway
//      (card + PIN there, or a logged-in dashboard). This keypad can't do them.
//    * This keypad: during an alarm, any valid PIN + # silences THIS module.
//      During tamper/fault, a MAINTENANCE PIN + # clears it (lid must be shut);
//      the gateway can clear it too. 3 wrong PINs lock the keypad (60, 120, 240 s...).
//
//  Radio: a full mesh (mesh.h). ESP-NOW straight to the other three modules and
//  the gateway; when one link fails its packets go through a board that hears
//  both ends. Signed end to end, replay-protected, encrypted per link once MACs
//  are set in secrets.h. Without the gateway this module keeps detecting and alarming.
//
//  Radio channel: the gateway's Wi-Fi network decides it. When nobody hears the
//  gateway any more, one module looks for it on the other channels (about 2 s)
//  and remembers where it found it.
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
#define MODULE_ID       'B'  // 'A', 'B', 'C' or 'D'. The line that differs between the four modules.
#define WOKWI_SIM       1    // 1 = Wokwi simulator: tone() buzzer, 5 s PIR warm-up, MQTT instead of ESP-NOW.
#define BENCH_COMMANDS  1    // 1 = type commands (arm, disarm, ...) in Serial Monitor to test
                             //     without the gateway. MUST be 0 for the demo: USB would bypass card + PIN.
#define CORNER_PAIRS    1    // 1 = this module's two PIRs firing within 20 s also confirms (A and B)
#define ALLOW_UNENCRYPTED 0  // 0 = a radio link is only used once it is encrypted (MACs set in secrets.h).
                             // 1 = also use links without MACs (signed but readable). Setup/testing only.

// Modules C and D: what is fitted (A and B always have everything).
// Anything left out simply isn't used; the firmware is the same.
#define CD_TAMPER_FITTED 0   // 1 = enclosure reed switch on pin 23 (as on A and B)
#define CD_LED_GREEN     0   // 1 = green LED on pin 18
#define CD_LED_YELLOW    1   // 1 = LED on pin 2. Many ESP32 boards already have a small LED on
                             //     pin 2, so this works with nothing added.
#define CD_LED_RED       0   // 1 = red LED on pin 15
// With fewer than three LEDs the ones fitted take over: an alarm or fault
// blinks fast, a warning blinks slowly, armed and all well = steady.

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
struct RxItem;
struct PinUser;

// ======== link_protocol.h (inlined for Wokwi: no extra files needed) ========
// =====================================================================
//  link_protocol.h  —  v4 (firmware 6.0), shared by every part of Project 13:
//    Sensor Modules A, B, C, D, the Gateway, and the server (Server/p13server/protocol.py
//    is the same format in Python). Keep this file IDENTICAL in every sketch folder.
//
//  Links:  a full mesh of 5 radios (ESP-NOW): A, B, C, D and the gateway each
//          talk straight to the other 4 (10 links). If one link fails, its
//          packets go through a third board that still hears both (mesh.h).
//          Gateway <-> Server: Wi-Fi, MQTT over TLS.
//
//  Every packet is:
//    * signed with HMAC-SHA256 using the key of that one link (each of the 10
//      radio links and Gateway<->Server has its own key). A relayed packet keeps
//      the signature of the two END boards, so the board in the middle can pass
//      it on but can't read the key, change it, or make one up,
//    * numbered (bootId + seq) so copies and old packets are rejected,
//    * addressed (src + dst), so a packet for A can't be fed to B,
//    * for commands and alarms: tied to the receiver's CURRENT boot (dstBoot),
//      so a command recorded earlier can't be replayed after a restart.
//  On real hardware ESP-NOW also encrypts each radio link (AES) once the board
//  MAC addresses are filled in secrets.h, and the server link runs inside TLS.
// =====================================================================
#include <Arduino.h>
#include <esp_task_wdt.h>
#include "mbedtls/md.h"

// Declared early so the Arduino IDE / Wokwi auto-prototypes compile when this
// file is pasted into a single-file sketch.
struct LinkPacket;
struct MeshPeer;      // mesh.h
class Mesh;

#define LINK_VERSION    4
#define FIRMWARE_VERSION "6.0"
#define ESPNOW_DEFAULT_CHANNEL 1  // until the gateway's Wi-Fi decides: the gateway uses its
                                  // network's channel and the modules find it by themselves
#define SIG_LEN         8      // bytes of HMAC-SHA256 kept in each packet
#define LINK_TEXT_MAX   160    // one log line / status line

// Wokwi simulator only (WOKWI_SIM 1): Wokwi can't do ESP-NOW between two
// simulations, so the same signed packets travel over a public MQTT broker.
// Each part listens on  <base>/to/<letter>  (A, B, C, D, G = gateway, P = server).
// The real gateway uses the same topic layout on the server's own broker:
//   p13/<SITE_ID>/to/G  and  p13/<SITE_ID>/to/P   (see Gateway/secrets.h).
#define MQTT_BROKER      "broker.hivemq.com"
#define MQTT_PORT        1883
#define MQTT_TOPIC_BASE  "pinnacle13/p13-2d386efc/v6"

enum LinkNode : uint8_t { NODE_NONE = 0, NODE_MOD_A = 1, NODE_MOD_B = 2, NODE_MOD_C = 3, NODE_MOD_D = 4,
                         NODE_GATEWAY = 9, NODE_SERVER = 10 };
inline bool isModule(uint8_t n) { return n >= NODE_MOD_A && n <= NODE_MOD_D; }

// ---------------- the site: a rectangle, modules at the corners ----------------
//        A ---- zone 2 ---- B          Each protected wall (zone) has a PIR at
//        |                  |          both ends, mounted on the OUTSIDE face
//     zone 1      G      zone 3        and looking along it (a "curtain").
//        |                  |          Wall C-D has no sensors.
//        D -----(none)----- C          G = gateway, in the middle.
//  Zone 1 = wall A-D (PIRs "A-Z1", "D-Z1"), zone 2 = wall A-B ("A-Z2", "B-Z2"),
//  zone 3 = wall B-C ("B-Z3", "C-Z3"). A and B have buzzers: an intrusion in a
//  zone sounds the buzzer of each module on that wall that has one.
const uint8_t SITE_ZONES = 3;
const uint8_t ZONE_END1[SITE_ZONES + 1] = { 0, NODE_MOD_A, NODE_MOD_A, NODE_MOD_B };
const uint8_t ZONE_END2[SITE_ZONES + 1] = { 0, NODE_MOD_D, NODE_MOD_B, NODE_MOD_C };
inline uint8_t zoneBit(uint8_t z) { return z >= 1 && z <= SITE_ZONES ? 1 << (z - 1) : 0; }
inline uint8_t zonePartner(uint8_t z, uint8_t me) {      // the module at the other end of zone z's wall
  if (!zoneBit(z)) return NODE_NONE;
  return ZONE_END1[z] == me ? ZONE_END2[z] : ZONE_END2[z] == me ? ZONE_END1[z] : (uint8_t)NODE_NONE;
}
inline uint8_t zonesOf(uint8_t node) {                  // the walls a module stands on (bit mask)
  uint8_t m = 0;
  for (uint8_t z = 1; z <= SITE_ZONES; z++) if (ZONE_END1[z] == node || ZONE_END2[z] == node) m |= zoneBit(z);
  return m;
}

enum LinkType : uint8_t {
  L_HELLO      = 1,  // status beat that also says "this is my boot ID". At boot and every 10th beat.
  L_STATUS     = 2,  // status beat, every second: state, priority, health in text
  L_LOG        = 3,  // one event-log line (logNo = line number; code 1 = re-sent on request)
  L_ACK        = 4,  // gateway -> module: reply to each status beat ("link alive").
                     //   HELLO / ACK from the gateway: code = its radio channel (0 = not said)
  L_PEER_EVENT = 5,  // module -> module at the other end of the wall: my PIR on zone `code` fired (arg = age in ms)
  L_PEER_ALARM = 6,  // module -> the other modules: intrusion confirmed, alarm everyone
                     //   (code = zones in alarm (bits), arg = alarm no., text = why)
  L_CMD        = 7,  // gateway -> module: command (code = Cmd, role, arg, text = "user@source")
  L_CMD_RESULT = 8,  // result of a command (code = Cmd, result, arg = the command packet's seq, text = details)
                     //   module -> gateway, and gateway -> server
  // ---- server <-> gateway ----
  L_LOGIN_REQ    = 9,   // server -> gateway: text = user name. Gateway answers with a challenge.
  L_LOGIN_CHAL   = 10,  // gateway -> server: text = 32 hex chars (16-byte random challenge)
  L_LOGIN_RESP   = 11,  // server -> gateway: text = "user:" + hex(HMAC-SHA256(pwHash, challenge || user))
  L_LOGIN_RESULT = 12,  // gateway -> server: result OK/DENIED, role, session = new session ID (0 = none), text = message
  L_PC_CMD       = 13,  // server -> gateway: code = Cmd, target, arg, session = session ID
  L_TYPE_MAX     = 13
};
//  Dashboard password: the gateway stores
//      pwHash = PBKDF2-HMAC-SHA256(password, salt = "p13-pc:" + user, 100000 rounds, 32 bytes)
//  (hex). Only the server computes it, from the password typed into the dashboard
//  (slow on purpose, so guessing is slow). The password never reaches the gateway;
//  the server proves it knows it by answering the random challenge.
//  Status to the server: L_STATUS with code = the node it describes.
//
//  L_CMD (gateway -> module): logNo = command ID (the same on every retry; the
//  module answers a repeat with its first result instead of running it twice;
//  0 = no ID). For CMD_RESEND_LOG: arg = first line, session = last line (0 = no limit).
//  The same holds for CMD_RESEND_LOG in L_PC_CMD (server -> gateway).

enum Cmd : uint8_t {
  CMD_ARM = 1, CMD_DISARM = 2,
  CMD_MAINT_START = 3,   // arg = seconds (30..900)
  CMD_MAINT_END = 4,
  CMD_ACK_ALARM = 5,     // acknowledge an intrusion
  CMD_CLEAR_FAULT = 6,   // clear tamper / fault (MAINTENANCE only)
  CMD_SET_TIME = 7,      // arg = Unix time (seconds)
  CMD_RESEND_LOG = 8,    // arg = first log line number wanted
  CMD_LOGOUT = 9,        // server -> gateway: end the session
  CMD_TEST_CUT = 10,     // test the relays: treat the direct link to node (arg >> 16) as broken
                         //   for (arg & 0xFFFF) seconds (max 300; 0 = end the test). MAINTENANCE only.
  CMD_MAX = 10
};
// Command target (L_PC_CMD): 0 = all four modules, or NODE_MOD_A..D / NODE_GATEWAY
const uint8_t TARGET_ALL = 0;
const uint32_t TEST_CUT_MAX_S = 300;
enum CmdResult : uint8_t { RES_OK = 0, RES_REFUSED = 1, RES_DENIED = 2, RES_BAD = 3 };
enum Role : uint8_t { R_NONE = 0, R_OPERATOR = 1, R_MAINTENANCE = 2 };
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
  uint8_t  via;            // 0 = sent straight to dst; else the board asked to pass it on (one hop)
  uint8_t  mesh;           // the boards the sender hears directly right now (meshBit() of each)
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
  uint8_t  target;         // L_PC_CMD: which board the command is for (TARGET_ALL, NODE_...)
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

// Tracks one sender's boot ID + sequence numbers to reject replayed packets.
// With relays a packet can arrive twice (straight and through another board) or
// a little out of order, so the last 32 sequence numbers are remembered:
// each one is accepted once (TR_LATE if it is older than the newest seen),
// a second copy is a duplicate (TR_DUP, dropped quietly), anything older is refused.
enum TrackResult : uint8_t { TR_OK, TR_LATE, TR_SYNCED, TR_NEW_BOOT, TR_DUP, TR_REPLAY, TR_UNSYNCED, TR_OLD_BOOT };
const uint8_t SEQ_WINDOW = 32;
struct PeerTracker {
  bool     synced = false;
  bool     online = false;
  bool     sendHello = false;     // the sender has an out-of-date idea of OUR boot: send it a HELLO
  uint32_t bootId = 0, lastSeq = 0, lastHeard = 0;
  uint32_t seen = 0;              // bit i set = packet (lastSeq - i) has arrived

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
    else if (p.bootId != bootId) return TR_REPLAY;                           // from another boot
    else if (p.seq > lastSeq) {                                              // the newest so far
      uint32_t shift = p.seq - lastSeq;
      seen = shift >= SEQ_WINDOW ? 1 : (seen << shift) | 1;
      lastSeq = p.seq; lastHeard = millis();
      return TR_OK;
    }
    else {                                                                   // older: once, if still in the window
      uint32_t back = lastSeq - p.seq;
      if (back >= SEQ_WINDOW) return TR_REPLAY;
      if (seen & (1UL << back)) return TR_DUP;
      seen |= 1UL << back; lastHeard = millis();
      return TR_LATE;
    }
    bootId = p.bootId; lastSeq = p.seq; seen = 1; synced = true; lastHeard = millis();
    return r;
  }
};

inline char nodeLetter(uint8_t n) {
  switch (n) { case NODE_MOD_A: return 'A'; case NODE_MOD_B: return 'B'; case NODE_MOD_C: return 'C';
               case NODE_MOD_D: return 'D'; case NODE_GATEWAY: return 'G'; case NODE_SERVER: return 'P';
               default: return '?'; }
}
inline uint8_t nodeFromLetter(char c) {
  switch (c) { case 'A': case 'a': return NODE_MOD_A; case 'B': case 'b': return NODE_MOD_B;
               case 'C': case 'c': return NODE_MOD_C; case 'D': case 'd': return NODE_MOD_D;
               case 'G': case 'g': return NODE_GATEWAY; default: return NODE_NONE; }
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
    case CMD_LOGOUT: return "LOGOUT";       case CMD_TEST_CUT: return "TEST_CUT";
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
// ======== mesh.h (inlined for Wokwi: no extra files needed) ========
// =====================================================================
//  mesh.h  —  the radio mesh (firmware 6.0). IDENTICAL in Gateway/ and SensorModule/.
//
//  Five radios: modules A, B, C, D and the gateway. Each one talks straight to
//  the other four (a full mesh: 10 links, each with its own key).
//
//  Every packet carries the sender's "mesh" byte: which boards it hears
//  directly right now. From that each board knows, for every link, whether it
//  works BOTH ways. When the direct link to a board fails, packets for it also
//  go through a third board (a relay) that hears both ends:
//
//      A --x-- C        A sends to C straight (in case it comes back) AND
//       \     /         through G with via = G. G passes it on unchanged.
//        \   /          C accepts whichever copy arrives first and drops the
//          G            other (each sequence number is accepted once).
//
//  The relay can't read or fake what it carries: the packet is signed with the
//  A<->C key, which G doesn't have, and the radio hops are encrypted per link
//  (A->G with the A<->G key, G->C with the G<->C key). One hop only: a board
//  only passes on packets that name it as `via` and come straight from the sender.
// =====================================================================

// The "mesh" byte: bit 0..3 = modules A..D, bit 4 = gateway.
inline uint8_t meshBit(uint8_t node) {
  return isModule(node) ? 1 << (node - 1) : node == NODE_GATEWAY ? 1 << 4 : 0;
}
const uint8_t MESH_SIZE = 5;
const uint8_t MESH_ORDER[MESH_SIZE] = { NODE_MOD_A, NODE_MOD_B, NODE_MOD_C, NODE_MOD_D, NODE_GATEWAY };

// One link: what this board knows about one other board.
struct MeshPeer {
  uint8_t        node;
  const char*    name;
  const uint8_t* mac;
  const uint8_t* key;              // the signing key of this link
  PeerTracker    trk;              // replay protection; trk.online = heard (any way) recently
  bool           macSet = false;
  bool           encrypted = false;
  uint32_t       beats = 0;
  uint32_t       lastKick = 0;     // last HELLO sent to nudge it after a restart
  int8_t         rssi = 0;         // signal of its last packet that came straight from it
  uint32_t       directAt = 0;     // when a good packet last came straight from it
  uint8_t        theirMesh = 0;    // who IT hears directly (from its newest packet)
  uint8_t        state = 0xFF;     // its state and priority (from its newest packet)
  uint8_t        prio = 0;
  uint8_t        route = 0;        // how our packets reach it: 0 = straight, else the relay's node
  uint8_t        loggedRoute = 0;  // the route last written to the log
  uint32_t       routeSince = 0;   // when the route last changed (logged once it has held 2 s)
  uint32_t       cutUntil = 0;     // relay test: direct link treated as broken until then (0 = no test)
  MeshPeer(uint8_t n, const char* nm, const uint8_t* m, const uint8_t* k) : node(n), name(nm), mac(m), key(k) {}
};

class Mesh {
public:
  Mesh(uint8_t me_, MeshPeer* const* peers_, uint8_t count_) : me(me_), peers(peers_), count(count_) {}

  uint32_t directTimeout = 2500;   // no packet straight from a board for this long: direct link down
  uint32_t forwarded = 0;          // packets passed on for other boards
  uint32_t forwardDropped = 0;     // ... and refused by the rate limit

  MeshPeer* find(uint8_t node) const {
    for (uint8_t i = 0; i < count; i++) if (peers[i]->node == node) return peers[i];
    return nullptr;
  }
  bool isCut(const MeshPeer& P) const { return P.cutUntil && notYet(P.cutUntil); }

  // We hear P directly (and the link isn't cut for a test).
  bool hears(const MeshPeer& P) const {
    return !isCut(P) && P.directAt && millis() - P.directAt <= directTimeout;
  }
  // The direct link works both ways: we hear P, and P's newest packet says it hears us.
  bool directOk(const MeshPeer& P) const { return hears(P) && (P.theirMesh & meshBit(me)); }

  uint8_t mask() const {                                   // our "mesh" byte
    uint8_t m = 0;
    for (uint8_t i = 0; i < count; i++) if (hears(*peers[i])) m |= meshBit(peers[i]->node);
    return m;
  }

  // Picks how packets for T travel. 0 = straight; else a board that we and T
  // both reach directly. Keeps the current relay while it works, then prefers
  // the gateway (in the middle of the site), then the strongest signal.
  uint8_t chooseRoute(MeshPeer& T) {
    if (directOk(T)) { T.route = 0; return 0; }
    uint8_t best = 0;
    int bestScore = -10000;
    for (uint8_t i = 0; i < count; i++) {
      MeshPeer& R = *peers[i];
      if (&R == &T || !directOk(R) || !(R.theirMesh & meshBit(T.node))) continue;
      int score = R.rssi ? R.rssi : -90;
      if (R.node == T.route)      score += 15;
      if (R.node == NODE_GATEWAY) score += 5;
      if (score > bestScore) { bestScore = score; best = R.node; }
    }
    T.route = best;
    return best;
  }

  // After a packet from P passed every check: remember what it tells us.
  void heard(MeshPeer& P, const LinkPacket& p, TrackResult tr, int8_t rssi) {
    if (p.via == 0) {                                      // came straight from P
      P.directAt = millis() ? millis() : 1;
      if (rssi) P.rssi = rssi;
    }
    if (tr != TR_LATE) { P.theirMesh = p.mesh; P.state = p.state; P.prio = p.priority; }
  }

  // A packet not addressed to us: should we pass it on, and to whom?
  // Only when it names us as `via`, came straight from its sender (fromMac,
  // real boards), and both ends are boards of this mesh. Rate-limited.
  MeshPeer* forwardTo(const LinkPacket& p, const uint8_t* fromMac) {
    if (p.via != me || p.dst == me || p.src == me || p.src == p.dst) return nullptr;
    MeshPeer* S = find(p.src);
    MeshPeer* D = find(p.dst);
    if (!S || !D || isCut(*S) || isCut(*D)) return nullptr;
    if (fromMac && S->macSet && memcmp(fromMac, S->mac, 6) != 0) return nullptr;
    uint32_t now = millis(), el = now - tokenAt;           // token bucket: 40 packets, one more every 25 ms
    if (el >= 1000)    { tokens = 40; tokenAt = now; }
    else if (el >= 25) { tokens += el / 25; if (tokens > 40) tokens = 40; tokenAt += el / 25 * 25; }
    if (tokens < 1) { forwardDropped++; return nullptr; }
    tokens--;
    forwarded++;
    return D;
  }

  // One character per board, in the order A B C D G, for the status line:
  //   '*' this board   'D' direct both ways   'a'..'d','g' relayed through that board
  //   '?' heard, but no working route back yet   '-' not heard at all
  char netChar(uint8_t node) const {
    if (node == me) return '*';
    const MeshPeer* P = find(node);
    if (!P || !P->trk.online) return '-';
    if (directOk(*P)) return 'D';
    if (P->route) return (char)(nodeLetter(P->route) - 'A' + 'a');
    return '?';
  }
  void netText(char out[MESH_SIZE + 1]) const {
    for (uint8_t i = 0; i < MESH_SIZE; i++) out[i] = netChar(MESH_ORDER[i]);
    out[MESH_SIZE] = 0;
  }

  const uint8_t me;
private:
  MeshPeer* const* peers;
  const uint8_t count;
  uint32_t tokens = 40, tokenAt = 0;    // relay rate limit
};
// ======== end of mesh.h ========
struct PinUser { const char* name; const char* pinHashHex; Role role; };
// ======== secrets.h (inlined for Wokwi: no extra files needed) ========
// =====================================================================
//  secrets.h  —  Sensor Modules (A, B, C and D)
//  DEMO VALUES. Replace before the real demo and DO NOT upload this file
//  to GitHub (it is listed in .gitignore).
//
//  The same file goes on all four modules: MODULE_ID in SensorModule.ino picks
//  which keys a board gets, so Module A never holds the keys of links it isn't on.
// =====================================================================
#include <Arduino.h>

// ---------- Link keys (32 bytes each, one per radio link) ----------
// 10 radio links (A-B, A-C, A-D, B-C, B-D, C-D and each module to the gateway),
// each with its own key. New ones for all five boards:  python3 Tools/make_keys.py
// >>> radio link keys (written by Tools/make_keys.py)
// Each module holds only the keys of its own 4 links (MODULE_ID picks them).
// KEY_WITH_x = the key of the link between this module and x.
#if MODULE_ID == 'A'
static const uint8_t KEY_WITH_B[32] = {
  0xA2, 0xB7, 0xF3, 0x31, 0x02, 0x5C, 0x0B, 0x1E, 0xD0, 0x95, 0xE7, 0xAB, 0x19, 0x18, 0xA5, 0xB4,
  0xC0, 0xC6, 0x33, 0xE7, 0x01, 0x1F, 0x3F, 0xF2, 0xD9, 0xA8, 0x87, 0x9D, 0xA7, 0xFD, 0xD2, 0x5C
};   // A <-> B
static const uint8_t KEY_WITH_C[32] = {
  0x19, 0x13, 0x3B, 0xCF, 0x9A, 0x8F, 0x3C, 0xD2, 0x1E, 0xDF, 0x61, 0x27, 0x17, 0x77, 0xF4, 0x71,
  0x0F, 0x38, 0xA4, 0x9B, 0x05, 0x9F, 0x71, 0x8C, 0x25, 0x82, 0x45, 0x0A, 0xAE, 0x26, 0xFA, 0xF6
};   // A <-> C
static const uint8_t KEY_WITH_D[32] = {
  0xF0, 0x75, 0x16, 0x41, 0xF3, 0xEC, 0x98, 0xE8, 0xFE, 0x19, 0x49, 0xAF, 0x4C, 0xA2, 0x3A, 0x2A,
  0x53, 0x2A, 0x46, 0x2B, 0xFC, 0x6E, 0x66, 0xCC, 0xCC, 0x4D, 0x77, 0xFA, 0x41, 0x87, 0xA9, 0xEC
};   // A <-> D
static const uint8_t KEY_WITH_GW[32] = {
  0x9B, 0xE9, 0x67, 0x7F, 0x5F, 0x4D, 0xDE, 0xD6, 0x8A, 0x6E, 0x87, 0xB3, 0x1C, 0xEB, 0xC6, 0xD1,
  0xB0, 0x54, 0xA3, 0x19, 0x08, 0xE6, 0xE9, 0xB6, 0x79, 0x43, 0x35, 0xCD, 0x3E, 0x3E, 0xEE, 0x43
};   // A <-> GW
#elif MODULE_ID == 'B'
static const uint8_t KEY_WITH_A[32] = {
  0xA2, 0xB7, 0xF3, 0x31, 0x02, 0x5C, 0x0B, 0x1E, 0xD0, 0x95, 0xE7, 0xAB, 0x19, 0x18, 0xA5, 0xB4,
  0xC0, 0xC6, 0x33, 0xE7, 0x01, 0x1F, 0x3F, 0xF2, 0xD9, 0xA8, 0x87, 0x9D, 0xA7, 0xFD, 0xD2, 0x5C
};   // A <-> B
static const uint8_t KEY_WITH_C[32] = {
  0x94, 0x60, 0xF0, 0xE7, 0xE4, 0xF0, 0x18, 0x0E, 0x9C, 0xF0, 0xA4, 0xD4, 0x87, 0x33, 0xD1, 0x86,
  0xF3, 0xCE, 0xB9, 0xB7, 0x8C, 0xEB, 0x85, 0x66, 0xB6, 0xD7, 0xAB, 0xC8, 0x76, 0x4E, 0xBA, 0x6F
};   // B <-> C
static const uint8_t KEY_WITH_D[32] = {
  0xFC, 0xC3, 0xF1, 0xE2, 0xE4, 0x6C, 0x34, 0xA9, 0xB8, 0x1C, 0x1A, 0x05, 0xBF, 0x47, 0x5A, 0x6E,
  0xD2, 0x65, 0xE0, 0xA0, 0x35, 0xB2, 0xB7, 0xD6, 0x48, 0x10, 0x37, 0x22, 0x59, 0xBD, 0x3B, 0xDB
};   // B <-> D
static const uint8_t KEY_WITH_GW[32] = {
  0x08, 0xBC, 0xE6, 0xCB, 0x4B, 0x89, 0x4F, 0x79, 0x14, 0x5D, 0x77, 0xC5, 0xE0, 0x78, 0xAB, 0xB5,
  0xBB, 0xC2, 0xCF, 0xA8, 0x1E, 0xE8, 0x2D, 0xF1, 0x0E, 0x4F, 0xCC, 0x91, 0x67, 0xFB, 0xB1, 0xC0
};   // B <-> GW
#elif MODULE_ID == 'C'
static const uint8_t KEY_WITH_A[32] = {
  0x19, 0x13, 0x3B, 0xCF, 0x9A, 0x8F, 0x3C, 0xD2, 0x1E, 0xDF, 0x61, 0x27, 0x17, 0x77, 0xF4, 0x71,
  0x0F, 0x38, 0xA4, 0x9B, 0x05, 0x9F, 0x71, 0x8C, 0x25, 0x82, 0x45, 0x0A, 0xAE, 0x26, 0xFA, 0xF6
};   // A <-> C
static const uint8_t KEY_WITH_B[32] = {
  0x94, 0x60, 0xF0, 0xE7, 0xE4, 0xF0, 0x18, 0x0E, 0x9C, 0xF0, 0xA4, 0xD4, 0x87, 0x33, 0xD1, 0x86,
  0xF3, 0xCE, 0xB9, 0xB7, 0x8C, 0xEB, 0x85, 0x66, 0xB6, 0xD7, 0xAB, 0xC8, 0x76, 0x4E, 0xBA, 0x6F
};   // B <-> C
static const uint8_t KEY_WITH_D[32] = {
  0x22, 0xC5, 0x09, 0x49, 0x21, 0xB0, 0x19, 0x0F, 0xB9, 0x4B, 0xB9, 0x41, 0x9E, 0x5E, 0x53, 0x07,
  0x1D, 0xA0, 0x55, 0x93, 0x70, 0x53, 0xDA, 0x73, 0xCD, 0x33, 0xCA, 0x45, 0xD3, 0xA8, 0x0C, 0x68
};   // C <-> D
static const uint8_t KEY_WITH_GW[32] = {
  0x64, 0xE6, 0xEA, 0x84, 0x93, 0x2F, 0x74, 0xD2, 0x6C, 0x17, 0x17, 0x8F, 0x18, 0xCD, 0xFB, 0x40,
  0x61, 0xD9, 0xCC, 0x9B, 0xE9, 0x8D, 0x4B, 0x6F, 0x72, 0x75, 0x14, 0x5B, 0xE3, 0x47, 0x98, 0xC1
};   // C <-> GW
#elif MODULE_ID == 'D'
static const uint8_t KEY_WITH_A[32] = {
  0xF0, 0x75, 0x16, 0x41, 0xF3, 0xEC, 0x98, 0xE8, 0xFE, 0x19, 0x49, 0xAF, 0x4C, 0xA2, 0x3A, 0x2A,
  0x53, 0x2A, 0x46, 0x2B, 0xFC, 0x6E, 0x66, 0xCC, 0xCC, 0x4D, 0x77, 0xFA, 0x41, 0x87, 0xA9, 0xEC
};   // A <-> D
static const uint8_t KEY_WITH_B[32] = {
  0xFC, 0xC3, 0xF1, 0xE2, 0xE4, 0x6C, 0x34, 0xA9, 0xB8, 0x1C, 0x1A, 0x05, 0xBF, 0x47, 0x5A, 0x6E,
  0xD2, 0x65, 0xE0, 0xA0, 0x35, 0xB2, 0xB7, 0xD6, 0x48, 0x10, 0x37, 0x22, 0x59, 0xBD, 0x3B, 0xDB
};   // B <-> D
static const uint8_t KEY_WITH_C[32] = {
  0x22, 0xC5, 0x09, 0x49, 0x21, 0xB0, 0x19, 0x0F, 0xB9, 0x4B, 0xB9, 0x41, 0x9E, 0x5E, 0x53, 0x07,
  0x1D, 0xA0, 0x55, 0x93, 0x70, 0x53, 0xDA, 0x73, 0xCD, 0x33, 0xCA, 0x45, 0xD3, 0xA8, 0x0C, 0x68
};   // C <-> D
static const uint8_t KEY_WITH_GW[32] = {
  0xBF, 0xEB, 0x14, 0x5F, 0xC6, 0x6C, 0x77, 0x58, 0x1F, 0xD4, 0x39, 0xCC, 0x75, 0xB5, 0x6A, 0x41,
  0x32, 0x18, 0x29, 0x76, 0xCC, 0x5E, 0xC4, 0x27, 0xC4, 0x14, 0x25, 0x9F, 0xDE, 0x83, 0xA8, 0x4C
};   // D <-> GW
#else
#error "MODULE_ID must be 'A', 'B', 'C' or 'D'"
#endif
// <<< radio link keys

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
static const uint8_t MAC_MOD_C[6]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t MAC_MOD_D[6]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
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
//  The same wiring on all four modules; C and D just leave parts out.
//  The PIRs and the tamper switch are on normal pins and use the ESP32's
//  built-in pull-up (INPUT_PULLUP): no resistors needed for them.
//  Two LEDs sit on boot pins 2 and 15: an LED + resistor to GND is safe there.
//  Pins 0, 5, 12 and the input-only pins 34-39 are left unused (36 is spare).
// =====================================================================
const uint8_t PIN_SDA = 21, PIN_SCL = 22;                        // LCD I2C
byte KP_ROWS[4] = { 13, 14, 27, 26 };                            // keypad pins 1-4
byte KP_COLS[4] = { 25, 33, 32, 4 };                             // keypad pins 5-8 (driven: normal I/O only)
const uint8_t PIN_BUZZER     = 16;    // A and B
const uint8_t PIN_LED_GREEN  = 18;
const uint8_t PIN_LED_YELLOW = 2;     // boot pin: the LED to GND keeps it LOW at boot, which is what it needs
const uint8_t PIN_LED_RED    = 15;    // boot pin: the LED to GND only hides the boot messages; may blink at power-on
const uint8_t PIN_PIR_1      = 17;    // A, B: the PIR on wall A-B (zone 2).   C, D: their only PIR
const uint8_t PIN_PIR_2      = 19;    // A: the PIR on wall A-D (zone 1).      B: on wall B-C (zone 3)
const uint8_t PIN_TAMPER     = 23;    // reed switch to GND; built-in pull-up

const uint8_t TAMPER_CLOSED_LEVEL = LOW;   // lid shut = LOW; lid open OR wire cut = HIGH
const bool    BUZZER_ACTIVE_LOW   = false; // true if your buzzer module beeps when the pin is LOW
const uint8_t LCD_ADDR            = 0x27;  // try 0x3F if the LCD stays blank

// ---------------- identity (from MODULE_ID) ----------------
#if MODULE_ID == 'A'
const uint8_t MY_NODE = NODE_MOD_A;
const uint8_t* const MAC_SELF = MAC_MOD_A;
#elif MODULE_ID == 'B'
const uint8_t MY_NODE = NODE_MOD_B;
const uint8_t* const MAC_SELF = MAC_MOD_B;
#elif MODULE_ID == 'C'
const uint8_t MY_NODE = NODE_MOD_C;
const uint8_t* const MAC_SELF = MAC_MOD_C;
#else
const uint8_t MY_NODE = NODE_MOD_D;
const uint8_t* const MAC_SELF = MAC_MOD_D;
#endif
const char    MY_LETTER = MODULE_ID;
const bool    FULL_CORNER = MODULE_ID == 'A' || MODULE_ID == 'B';   // 2 PIRs, buzzer, tamper, 3 LEDs
const bool    HAS_BUZZER  = FULL_CORNER;
const bool    HAS_TAMPER  = FULL_CORNER || CD_TAMPER_FITTED;
const bool    HAS_GREEN   = FULL_CORNER || CD_LED_GREEN;
const bool    HAS_YELLOW  = FULL_CORNER || CD_LED_YELLOW;
const bool    HAS_RED     = FULL_CORNER || CD_LED_RED;
const uint8_t MY_WALLS    = zonesOf(MY_NODE);   // the zones (walls) this module stands on

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
const uint32_t GW_SEARCH_AFTER_MS   = 8000;    // gateway silent this long: look for it on the other channels
const uint32_t CH_DWELL_MS          = 160;     // per channel: send a HELLO, wait for the gateway's answer
const uint32_t CH_SEARCH_MIN_MS     = 10000;   // not found: stay on our channel, try again after 10, 20, 40, 60 s
const uint32_t CH_SEARCH_MAX_MS     = 60000;
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
//  ZONE SENSOR  (one object per PIR)
//  Health: WARMUP for the first 60 s (PIR only); STUCK if "active" for
//  longer than SENSOR_MAX_ACTIVE_MS. With a pull-up, an unplugged PIR reads
//  HIGH forever -> STUCK.
// =====================================================================
class ZoneSensor {
public:
  ZoneSensor(uint8_t code_, const char* name_, uint8_t pin_, bool activeHigh_, bool warmup_, bool enabled_)   // code = zone
    : code(code_), name(name_), pin(pin_), enabled(enabled_), activeHigh(activeHigh_), needsWarmup(warmup_) {}

  void begin() {
    if (!enabled) return;
    pinMode(pin, pin >= 34 ? INPUT : INPUT_PULLUP);   // built-in pull-up (pins 34-39 have none)
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

// This module's PIRs: zone number, name, pin
#if MODULE_ID == 'A'
ZoneSensor zones[] = {
  //          zone name    pin        activeHigh warmup enabled
  ZoneSensor( 2,   "A-Z2", PIN_PIR_1, true,      true,  true ),
  ZoneSensor( 1,   "A-Z1", PIN_PIR_2, true,      true,  true ),
};
#elif MODULE_ID == 'B'
ZoneSensor zones[] = {
  ZoneSensor( 2,   "B-Z2", PIN_PIR_1, true,      true,  true ),
  ZoneSensor( 3,   "B-Z3", PIN_PIR_2, true,      true,  true ),
};
#elif MODULE_ID == 'C'
ZoneSensor zones[] = {
  ZoneSensor( 3,   "C-Z3", PIN_PIR_1, true,      true,  true ),
};
#else
ZoneSensor zones[] = {
  ZoneSensor( 1,   "D-Z1", PIN_PIR_1, true,      true,  true ),
};
#endif
const uint8_t ZONE_COUNT = sizeof(zones) / sizeof(zones[0]);
ZoneSensor* zoneSensor(uint8_t zone) {             // this module's PIR on that zone (nullptr = none)
  for (uint8_t i = 0; i < ZONE_COUNT; i++) if (zones[i].code == zone) return &zones[i];
  return nullptr;
}

// The PIR at the other end of each wall, as reported over the radio (index = zone)
uint32_t partnerAt[SITE_ZONES + 1] = {};
bool     partnerValid[SITE_ZONES + 1] = {}, partnerNew[SITE_ZONES + 1] = {};
bool partnerRecent(uint8_t z, uint32_t now) { return partnerValid[z] && now - partnerAt[z] < CORROBORATION_MS; }
bool anyPartnerRecent(uint32_t now) {
  for (uint8_t z = 1; z <= SITE_ZONES; z++) if (partnerRecent(z, now)) return true;
  return false;
}
void clearPartners() { for (uint8_t z = 0; z <= SITE_ZONES; z++) partnerValid[z] = partnerNew[z] = false; }

// Zones in alarm (bits): set by our own confirmation or another module's alarm.
uint8_t alarmZones = 0;
String zoneList(uint8_t bits) {                    // "1+3", or "-" for none
  String s = "";
  for (uint8_t z = 1; z <= SITE_ZONES; z++) if (bits & zoneBit(z)) { if (s.length()) s += "+"; s += String(z); }
  return s.length() ? s : String("-");
}

// =====================================================================
//  TAMPER SENSOR  (time-debounced; open lid and cut wire both read "open")
// =====================================================================
class TamperSensor {
public:
  void begin() {
    if (!HAS_TAMPER) { stable = candidate = TAMPER_CLOSED_LEVEL; return; }   // not fitted: always "shut"
    pinMode(PIN_TAMPER, INPUT_PULLUP);       // built-in pull-up: lid open or wire cut reads HIGH
    stable = candidate = digitalRead(PIN_TAMPER);
    changedAt = millis();
  }
  bool update(uint32_t now) {                // true when the debounced state changes
    if (!HAS_TAMPER) return false;
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

// All three LEDs (A, B): green / yellow / red as usual. Fewer (C, D): every LED
// fitted shows one pattern: fast blink = alarm or fault, slow blink = warning
// or busy, steady = armed and all well, 1 s blink = disarmed.
void writeLeds(bool g, bool y, bool r, bool fast, bool slow) {
  if (!(HAS_GREEN && HAS_YELLOW && HAS_RED)) { bool lamp = r ? fast : y ? slow : g; g = y = r = lamp; }
  if (HAS_GREEN)  digitalWrite(PIN_LED_GREEN, g);
  if (HAS_YELLOW) digitalWrite(PIN_LED_YELLOW, y);
  if (HAS_RED)    digitalWrite(PIN_LED_RED, r);
}

void updateOutputs() {
  uint32_t now = millis();
  bool fast = (now / 250) % 2, slow = (now / 500) % 2, beat = (now / 1000) % 2;
  bool g = false, r = false, y = false, buz = false;
  switch (state) {
    case S_BOOT:         y = slow; break;
    case S_DISARMED:     g = beat; break;                                   // disarmed: slow green
    case S_ARMED:        if (currentPriority() == 1) y = true; else g = true; break;
    case S_INTRUSION:    { r = true; uint32_t ph = now % 1000;               // P2: double beep, but only
                           buz = (alarmZones & MY_WALLS) &&                  // for an alarm on our own walls
                                 (ph < 200 || (ph >= 400 && ph < 600)); } break;
    case S_TAMPER_FAULT: r = fast; buz = (now % 1000) < 700; break;         // P3: long pulses
    case S_MAINTENANCE:  y = slow; break;
    case S_RECOVERY:     y = true; break;
    default:             r = true; buz = true; break;                       // fail closed
  }
  if (notYet(outputTestUntil)) { g = r = y = true; buz = (now / 300) % 2; }
  if (notYet(chirpUntil)) buz = true;
  writeLeds(g, y, r, fast, slow);
  if (HAS_BUZZER) setBuzzer(buz);
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
void saveAlarmZones() { prefs.putUChar("azones", alarmZones); }

// Real time, once the gateway has sent it (0 = not known yet)
bool     timeSynced = false;
uint32_t timeBase = 0, timeBaseMs = 0;
uint32_t unixNow() { return timeSynced ? timeBase + (millis() - timeBaseMs) / 1000 : 0; }

// =====================================================================
//  RADIO: the mesh (mesh.h). Straight to the gateway and the other three
//  modules; through a relay when a direct link fails.
//  Real board: ESP-NOW (encrypted per link when MACs are set).
//  Wokwi: the same signed packets over MQTT.
// =====================================================================
struct RxItem { uint8_t src[6]; int8_t rssi; int len; uint8_t data[sizeof(LinkPacket)]; };
QueueHandle_t rxQueue;
const uint8_t BROADCAST[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

MeshPeer gwLink(NODE_GATEWAY, "Gateway", MAC_GATEWAY, KEY_WITH_GW);
#if MODULE_ID != 'A'
MeshPeer linkA(NODE_MOD_A, "Module A", MAC_MOD_A, KEY_WITH_A);
#endif
#if MODULE_ID != 'B'
MeshPeer linkB(NODE_MOD_B, "Module B", MAC_MOD_B, KEY_WITH_B);
#endif
#if MODULE_ID != 'C'
MeshPeer linkC(NODE_MOD_C, "Module C", MAC_MOD_C, KEY_WITH_C);
#endif
#if MODULE_ID != 'D'
MeshPeer linkD(NODE_MOD_D, "Module D", MAC_MOD_D, KEY_WITH_D);
#endif
MeshPeer* const PEERS[] = {
  &gwLink,
#if MODULE_ID != 'A'
  &linkA,
#endif
#if MODULE_ID != 'B'
  &linkB,
#endif
#if MODULE_ID != 'C'
  &linkC,
#endif
#if MODULE_ID != 'D'
  &linkD,
#endif
};
const uint8_t PEER_COUNT = sizeof(PEERS) / sizeof(PEERS[0]);
Mesh mesh(MY_NODE, PEERS, PEER_COUNT);

uint32_t myBoot = 0, mySeq = 0;
uint8_t  myReset = 0;
bool     radioReady = false;
uint8_t  radioCh = ESPNOW_DEFAULT_CHANNEL;     // channel ESP-NOW is on (the gateway's Wi-Fi decides it)
uint8_t  gwSaysCh = 0;                         // the channel the gateway says it is on (in its HELLO / ACK)

bool macIsSet(const uint8_t* m) { for (int i = 0; i < 6; i++) if (m[i]) return true; return false; }

// A link is only used when it is encrypted, unless ALLOW_UNENCRYPTED (Wokwi has no encryption).
bool linkUsable(const MeshPeer& L) { return WOKWI_SIM || ALLOW_UNENCRYPTED || L.encrypted; }

// A module at the end of one of our walls that is in INTRUSION right now (nullptr = none).
// While one is, any of our PIRs firing is an intrusion at once (no 20 s / 3-hit rule).
const MeshPeer* moduleInAlarm() {
  for (MeshPeer* P : PEERS) if (isModule(P->node) && P->trk.online && P->state == MS_INTRUSION) return P;
  return nullptr;
}

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
  it.rssi = 0;
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
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  it.rssi = info->rx_ctrl ? (int8_t)info->rx_ctrl->rssi : 0;
#else
  it.rssi = 0;
#endif
  it.len = len;
  memcpy(it.data, data, min(len, (int)sizeof(it.data)));
  xQueueSend(rxQueue, &it, 0);
}

bool addEncryptedPeer(MeshPeer& L) {
  if (!L.macSet) return true;                  // no MAC yet: uses signed broadcast instead
  esp_now_peer_info_t pi = {};
  memcpy(pi.peer_addr, L.mac, 6);
  pi.channel = 0;                              // 0 = whatever channel the radio is on
  pi.ifidx   = WIFI_IF_STA;
  pi.encrypt = true;
  linkLmk(L.key, 32, pi.lmk);
  L.encrypted = esp_now_add_peer(&pi) == ESP_OK;
  return L.encrypted;
}

void radioBegin() {
  myBoot  = makeBootId(bootNo, esp_random());   // boot counter + random: only ever goes up
  myReset = (uint8_t)esp_reset_reason();
  rxQueue = xQueueCreate(24, sizeof(RxItem));
  for (MeshPeer* P : PEERS) P->macSet = macIsSet(P->mac);
  mesh.directTimeout = WOKWI_SIM ? 6000 : 2500;
#if WOKWI_SIM
  WiFi.mode(WIFI_STA);
  WiFi.begin("Wokwi-GUEST", "", 6);            // Wokwi's simulated Wi-Fi
  mqtt.setServer(MQTT_BROKER, MQTT_PORT);
  mqtt.setCallback(onMqtt);
  mqtt.setBufferSize(512);
  mqtt.setSocketTimeout(2);
  radioReady = true;
#else
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  radioCh = prefs.getUChar("ch", ESPNOW_DEFAULT_CHANNEL);   // where the gateway was last time
  if (radioCh < 1 || radioCh > 13) radioCh = ESPNOW_DEFAULT_CHANNEL;
  esp_wifi_set_channel(radioCh, WIFI_SECOND_CHAN_NONE);
  if (esp_now_init() != ESP_OK) { radioReady = false; return; }
  esp_now_register_recv_cb(onRecv);
  esp_now_set_pmk(ESPNOW_PMK);
  for (MeshPeer* P : PEERS) addEncryptedPeer(*P);   // on failure that link falls back to signed broadcast
  esp_now_peer_info_t bc = {};                 // fallback for links whose MAC isn't set yet
  memcpy(bc.peer_addr, BROADCAST, 6);
  bc.channel = 0;
  bc.ifidx   = WIFI_IF_STA;
  bc.encrypt = false;
  esp_now_add_peer(&bc);
  radioReady = true;
#endif
}

void rawSend(const MeshPeer& to, const LinkPacket& p) {      // one radio hop
#if WOKWI_SIM
  if (mqtt.connected()) mqtt.publish(topicFor(to.node).c_str(), (const uint8_t*)&p, sizeof(p));
#else
  esp_now_send(to.encrypted ? to.mac : BROADCAST, (const uint8_t*)&p, sizeof(p));
#endif
}

// Sends straight to L, and also through a relay while the direct link doesn't
// work both ways. Both copies carry the same sequence number: L keeps the first.
void linkSend(MeshPeer& L, uint8_t type, uint8_t code, uint8_t role, uint8_t result,
              uint32_t arg, uint32_t no, const char* text) {
  if (!radioReady || !linkUsable(L)) return;
  LinkPacket p = {};
  p.version = LINK_VERSION; p.src = MY_NODE; p.dst = L.node; p.type = type;
  p.via = 0; p.mesh = mesh.mask();
  p.bootId = myBoot; p.seq = ++mySeq;
  p.dstBoot = L.trk.synced ? L.trk.bootId : 0;
  p.logNo = no; p.state = state; p.priority = currentPriority(); p.resetReason = myReset;
  p.code = code; p.role = role; p.result = result; p.arg = arg;
  size_t n = text ? strnlen(text, LINK_TEXT_MAX) : 0;
  if (n) memcpy(p.text, text, n);
  p.textLen = n;
  linkSign(L.key, 32, p, p.sig);
  uint8_t via = mesh.chooseRoute(L);
  if (!mesh.isCut(L)) rawSend(L, p);           // straight (also how a broken link is noticed coming back)
  MeshPeer* R = via ? mesh.find(via) : nullptr;
  if (R && linkUsable(*R)) {
    p.via = via;
    linkSign(L.key, 32, p, p.sig);             // still the L link's key: R can't make or change it
    rawSend(*R, p);
  }
}

String textOf(const LinkPacket& p) {           // text[] is not NUL-terminated: copy by length
  char buf[LINK_TEXT_MAX + 1];
  memcpy(buf, p.text, p.textLen);
  buf[p.textLen] = 0;
  return String(buf);
}

String nodeName(uint8_t node) {
  if (node == NODE_GATEWAY) return "Gateway";
  return String("Module ") + nodeLetter(node);
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

// ---------------- alarm to the other modules ----------------
// The module that confirms an intrusion sends 3 quick copies to each other
// module, then repeats every 2 s for as long as it stays in INTRUSION. A
// receiver acts on each alarm number once, so acknowledging it there sticks.
// The alarm carries its zones: the buzzers on those walls sound.
uint32_t alarmNo = 0, nextAlarmCopyAt = 0;
uint8_t  alarmBurstLeft = 0;
bool     alarmMine = false;
String   alarmWhy = "";
uint32_t actedAlarmBoot[5] = {}, actedAlarmNo[5] = {}, ignoredAlarmBoot[5] = {}, ignoredAlarmNo[5] = {};   // per module (1..4)

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

String partnerPir(uint8_t z) { return String(nodeLetter(zonePartner(z, MY_NODE))) + "-Z" + String(z); }

// The module at the other end of one of our walls: its PIR on that wall fired.
void onPeerEvent(const MeshPeer& L, const LinkPacket& p) {
  uint8_t z = p.code;
  if (!zoneBit(z) || zonePartner(z, MY_NODE) != L.node || state != S_ARMED) return;
  uint32_t age = p.arg;                            // copy: packed field
  if (age > CORROBORATION_MS) age = CORROBORATION_MS;
  partnerAt[z] = millis() - age;
  partnerValid[z] = true;
  partnerNew[z] = true;
}

void onPeerAlarm(const MeshPeer& L, const LinkPacket& p) {
  uint8_t  i = L.node;
  uint32_t b = p.bootId, n = p.arg;               // copies: packed fields
  uint8_t  zones = p.code & 0x07;
  if (b == actedAlarmBoot[i] && n == actedAlarmNo[i]) return;     // already acted on this alarm
  String why = textOf(p);
  String zl  = " (zone " + zoneList(zones) + ")";
  bool armedHere = state == S_ARMED || (armedMode && (state == S_BOOT || state == S_RECOVERY));
  if (armedHere) {
    actedAlarmBoot[i] = b; actedAlarmNo[i] = n;
    alarmZones = zones;
    logEvent("ALERT", String(L.name) + " confirmed" + zl + ": " + why, "-", "-", 2);
    goTo(S_INTRUSION, String(L.name) + " alarm");
  } else if (state == S_INTRUSION || state == S_TAMPER_FAULT) {
    actedAlarmBoot[i] = b; actedAlarmNo[i] = n;    // already in alarm here: add its zones
    if (state == S_INTRUSION && (zones & ~alarmZones)) { alarmZones |= zones; saveAlarmZones(); }
    logEvent("ALERT", String(L.name) + " also confirmed" + zl + ": " + why, "-", "-", 2);
  } else if (b != ignoredAlarmBoot[i] || n != ignoredAlarmNo[i]) {   // disarmed / maintenance: log once
    ignoredAlarmBoot[i] = b; ignoredAlarmNo[i] = n;
    logEvent("ALERT", String(L.name) + " alarm" + zl + " ignored here (" + stateName(state) + ")", "-", "IGNORED");
  }
}

void handlePacket(const RxItem& it) {
  LinkPacket p;
  memcpy(&p, it.data, sizeof(p));
  if (!linkWellFormed(p, it.len)) { reject(RJ_MALFORMED, "Malformed packet"); return; }     // T08
  if (p.dst != MY_NODE) {                          // for another board: pass it on if it asks us to relay
    MeshPeer* to = mesh.forwardTo(p, WOKWI_SIM ? nullptr : it.src);
    if (to && linkUsable(*to)) rawSend(*to, p);    // unchanged: still signed by its sender for its receiver
    return;
  }
  MeshPeer* L = mesh.find(p.src);
  if (!L) { reject(RJ_UNKNOWN, "Unknown sender"); return; }
  MeshPeer* hop = L;                               // the board the radio frame came from
  if (p.via) {
    hop = mesh.find(p.via);
    if (!hop || hop == L) { reject(RJ_OTHER, String(L->name) + ": bad relay"); return; }
  }
  if (mesh.isCut(*hop)) return;                    // relay test: this direct link counts as broken
  if (!linkUsable(*L) || !linkUsable(*hop)) { reject(RJ_OTHER, String(hop->name) + ": link not encrypted - set MACs"); return; }
#if !WOKWI_SIM
  if (hop->macSet && memcmp(it.src, hop->mac, 6) != 0) { reject(RJ_MAC, String(hop->name) + ": MAC not allowed"); return; }
#endif
  uint8_t exp[SIG_LEN];
  linkSign(L->key, 32, p, exp);
  if (!sameBytes(exp, p.sig, SIG_LEN)) { reject(RJ_SIG, String(L->name) + ": bad signature (spoofed?)"); return; }
  if (p.dstBoot != myBoot) L->trk.sendHello = true;          // it doesn't know our current boot yet
  if (linkNeedsFreshness(p.type) && p.dstBoot != myBoot) {
    reject(RJ_STALE, String(L->name) + ": stale (made before our restart)"); return;
  }
  TrackResult tr = L->trk.accept(p);
  if (tr == TR_UNSYNCED || tr == TR_DUP) return;              // waiting for its HELLO / second copy of a packet
  if (tr == TR_OLD_BOOT) { reject(RJ_REPLAY, String(L->name) + ": older boot number refused (flash erased? restart this board)"); return; }
  if (tr == TR_REPLAY) { reject(RJ_REPLAY, String(L->name) + ": replayed/old packet"); return; }
  mesh.heard(*L, p, tr, it.rssi);
  if (L == &gwLink && (p.type == L_HELLO || p.type == L_ACK) && p.code >= 1 && p.code <= 13 && tr != TR_LATE)
    gwSaysCh = p.code;
  if (tr == TR_NEW_BOOT) logEvent("COMM", String(L->name) + " restarted (" + resetReasonName(p.resetReason) + ")");
  if (!L->trk.online) {
    L->trk.online = true;
    logEvent("COMM", String(L->name) + " link UP" + (p.via ? " (through " + nodeName(p.via) + ")" : String("")));
  }
  switch (p.type) {
    case L_CMD:        if (L == &gwLink) onCommand(p); else reject(RJ_OTHER, "Command from a module refused"); break;
    case L_PEER_EVENT: if (L != &gwLink) onPeerEvent(*L, p); break;
    case L_PEER_ALARM: if (L != &gwLink) onPeerAlarm(*L, p); break;
    default: break;                                // HELLO / STATUS / ACK keep the link alive
  }
}

void checkLinkTimeout(MeshPeer& L) {
  if (L.trk.online && (int32_t)(millis() - L.trk.lastHeard) > (int32_t)LINK_TIMEOUT_MS) {
    L.trk.online = false;
    L.loggedRoute = 0; L.routeSince = 0;
    logEvent("COMM", String(L.name) + " link DOWN (alarm still works here)");          // T09
  }
}

// A link switched between direct and relayed: logged once the new way has held 2 s.
void routeCheck(MeshPeer& L, uint32_t now) {
  if (!L.trk.online || L.route == L.loggedRoute) { L.routeSince = 0; return; }
  if (!L.routeSince) { L.routeSince = now; return; }
  if (now - L.routeSince < 2000) return;
  if (L.route) logEvent("COMM", String(L.name) + ": direct link lost, relayed through " + nodeName(L.route));
  else         logEvent("COMM", String(L.name) + ": direct link back");
  L.loggedRoute = L.route;
  L.routeSince = 0;
}

void cutCheck(MeshPeer& L) {                       // the end of a relay test
  if (!L.cutUntil || notYet(L.cutUntil)) return;
  L.cutUntil = 0;
  logEvent("COMM", "Relay test over: direct link to " + String(L.name) + " back in use");
}

uint32_t lastStatus = 0;

// ---------------- finding the gateway's channel (real board) ----------------
// The gateway's radio sits on its Wi-Fi network's channel, which can change
// (a laptop hotspot follows the laptop's own Wi-Fi). Every HELLO / ACK from the
// gateway says which channel it is on: if that isn't ours (2.4 GHz channels
// overlap, so a neighbour channel can still hear it), move there at once.
// When nobody can reach the gateway (not straight, not through another module),
// step through the other channels: on each one send it a HELLO and listen
// briefly — it answers at once. Not found: go back to our channel and try again
// later. Alarms run locally the whole time.
//   * No search during an intrusion, or while a single trigger is waiting to be
//     confirmed: another module's alarm or wall event must not be missed.
//   * Of the modules that hear each other, only the first (A, then B...) searches.
//     The others follow when they lose it (then they search every 10 s).
#if !WOKWI_SIM
struct {
  bool     active = false;
  uint8_t  homeCh = 0, step = 0;
  uint32_t startedAt = 0, nextStepAt = 0, nextSearchAt = 0, waitMs = CH_SEARCH_MIN_MS;
  bool     reported = false;                    // "not found" logged once per outage
} chSearch;

void setRadioChannel(uint8_t ch) { esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE); radioCh = ch; }

bool gatewayHeardSince(uint32_t t) { return gwLink.trk.lastHeard && (int32_t)(gwLink.trk.lastHeard - t) >= 0; }

bool triggerPending(uint32_t now) {
  for (uint8_t i = 0; i < ZONE_COUNT; i++) if (zones[i].recent(now)) return true;
  return anyPartnerRecent(now);
}

void endSearch(bool found) {
  chSearch.active = false;
  if (found) { chSearch.waitMs = CH_SEARCH_MIN_MS; chSearch.reported = false; }
}

void channelLoop(uint32_t now) {
  if (gwSaysCh && gwSaysCh != radioCh) {                       // the gateway told us where it is
    uint8_t was = radioCh;
    setRadioChannel(gwSaysCh);
    prefs.putUChar("ch", radioCh);
    if (chSearch.active) endSearch(true);
    logEvent("COMM", "Gateway is on channel " + String(radioCh) + " (was " + String(was) + ")");
    return;
  }
  bool hold = state == S_INTRUSION || triggerPending(now);
  if (chSearch.active) {
    if (gatewayHeardSince(chSearch.startedAt)) {               // it answered on this channel
      if (radioCh != chSearch.homeCh) {
        prefs.putUChar("ch", radioCh);
        logEvent("COMM", "Gateway found on channel " + String(radioCh) + " (was " + String(chSearch.homeCh) + ")");
      }
      endSearch(true);
      return;
    }
    if (hold) { setRadioChannel(chSearch.homeCh); endSearch(false); return; }   // stay with the other modules
    if (notYet(chSearch.nextStepAt)) return;
    if (++chSearch.step > 13) {                                // every channel tried
      setRadioChannel(chSearch.homeCh);
      endSearch(false);
      chSearch.nextSearchAt = now + chSearch.waitMs;
      chSearch.waitMs = min(chSearch.waitMs * 2, CH_SEARCH_MAX_MS);
      if (!chSearch.reported) {
        chSearch.reported = true;
        logEvent("COMM", "Gateway not found on any channel: staying on " + String(radioCh) + ", retrying");
      }
      return;
    }
    if (chSearch.step == chSearch.homeCh) return;              // already listened there
    setRadioChannel(chSearch.step);
    linkSend(gwLink, L_HELLO, 0, 0, 0, unixNow(), 0, statusText().c_str());
    chSearch.nextStepAt = now + CH_DWELL_MS;
    return;
  }
  bool quiet = gwLink.trk.lastHeard ? now - gwLink.trk.lastHeard > GW_SEARCH_AFTER_MS : now > GW_SEARCH_AFTER_MS;
  if (!quiet) { endSearch(true); return; }
  bool alone = true;
  for (MeshPeer* P : PEERS) {
    if (!isModule(P->node) || !P->trk.online) continue;
    alone = false;
    if (P->node < MY_NODE) return;                             // a module before us searches for us all
  }
  if (hold) return;
  if (alone) {                                                 // alone anyway: no reason to wait long
    chSearch.waitMs = CH_SEARCH_MIN_MS;
    if (notYet(chSearch.nextSearchAt) && chSearch.nextSearchAt - now > CH_SEARCH_MIN_MS)
      chSearch.nextSearchAt = now + CH_SEARCH_MIN_MS;
  }
  if (notYet(chSearch.nextSearchAt)) return;
  chSearch.active = true;
  chSearch.homeCh = radioCh;
  chSearch.step = 0;
  chSearch.startedAt = now;
  chSearch.nextStepAt = now;
}
#endif

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
  for (MeshPeer* P : PEERS) { checkLinkTimeout(*P); cutCheck(*P); }
#if !WOKWI_SIM
  channelLoop(now);
#endif

  if (alarmMine && state == S_INTRUSION && !notYet(nextAlarmCopyAt)) {
    for (MeshPeer* P : PEERS)
      if (isModule(P->node)) linkSend(*P, L_PEER_ALARM, alarmZones, 0, 0, alarmNo, 0, alarmWhy.c_str());
    if (alarmBurstLeft) alarmBurstLeft--;
    nextAlarmCopyAt = millis() + (alarmBurstLeft ? ALARM_COPY_GAP_MS : ALARM_REPEAT_MS);
  }
  if (now - lastStatus >= STATUS_EVERY_MS) {       // 1 s beat to all four; every 10th is a HELLO
    lastStatus = now;
    String st = statusText();
    for (MeshPeer* P : PEERS) {
      bool hello = ++P->beats % 10 == 1 || P->trk.sendHello;
      P->trk.sendHello = false;
      linkSend(*P, hello ? L_HELLO : L_STATUS, 0, 0, 0, unixNow(), 0, st.c_str());
      routeCheck(*P, now);
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
  uint8_t up = 0, relayed = 0;
  for (MeshPeer* P : PEERS) if (P->trk.online) { up++; if (!mesh.directOk(*P)) relayed++; }
  String s = gwLink.trk.online ? "Mesh " : "GW DOWN ";
  s += String(up) + "/" + String(PEER_COUNT);
  if (relayed) s += " " + String(relayed) + " rly";
  else if (up == PEER_COUNT) s += " OK";
  return s;
}

// =====================================================================
//  PRIORITY + STATUS TEXT (sent to the gateway every second)
// =====================================================================
uint8_t currentPriority() {
  if (state == S_TAMPER_FAULT) return 3;
  if (state == S_INTRUSION)    return 2;
  if (state == S_ARMED) {
    uint32_t now = millis();
    if (anyPartnerRecent(now)) return 1;
    for (uint8_t i = 0; i < ZONE_COUNT; i++) if (zones[i].recent(now)) return 1;
  }
  return 0;
}

//  A,ARMED,P1,Z2:OK,Z1:OK,HIT:2,ALM:-,LID:SHUT,LCD:OK,LOCK:0,LOGNO:57,CH:6,NET:*DgDD,FWD:0,FW:6.0
//  Z<n>: health of our PIR on zone n.  HIT: zones whose PIR (ours) fired in the last 20 s.
//  ALM: zones in alarm.  NET: how we reach A B C D G (mesh.h netChar).  FWD: packets relayed.
String statusText() {
  uint32_t now = millis();
  String s = String(MY_LETTER) + "," + stateName(state) + ",P" + String(currentPriority());
  uint8_t hit = 0;
  for (uint8_t i = 0; i < ZONE_COUNT; i++) {
    s += ",Z" + String(zones[i].code) + ":" + healthName(zones[i].health);
    if (zones[i].recent(now) && (state == S_ARMED || state == S_INTRUSION)) hit |= zoneBit(zones[i].code);
  }
  s += ",HIT:" + zoneList(hit);
  s += ",ALM:" + (state == S_INTRUSION ? zoneList(alarmZones) : String("-"));
  s += String(",LID:") + (!HAS_TAMPER ? "NONE" : tamper.isOpen() ? "OPEN" : "SHUT");
  s += String(",LCD:") + (display.online ? "OK" : "OFFLINE");
  s += String(",LOCK:") + String(lockoutRemainingS);
  s += String(",LOGNO:") + String(logNo);
  s += String(",CH:") + String(radioCh);
  char net[MESH_SIZE + 1];
  mesh.netText(net);
  s += String(",NET:") + net;
  s += String(",FWD:") + String(mesh.forwarded);
  String cut = "";
  for (MeshPeer* P : PEERS) if (mesh.isCut(*P)) cut += nodeLetter(P->node);
  if (cut.length()) s += ",CUT:" + cut;
  s += String(",FW:") + FIRMWARE_VERSION;
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
      clearPartners();
      break;
    default: break;
  }
  if (s != S_INTRUSION) { alarmMine = false; alarmZones = 0; }   // the alarm is over here
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
  saveAlarmZones();
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
  if (!display.online)      logEvent("TEST", String("LCD missing - ") + (HAS_BUZZER ? "LEDs and buzzer only" : "LEDs only"));
  if (!gwLink.trk.online)   logEvent("TEST", "Gateway not connected - local log only");
  for (uint8_t i = 0; i < ZONE_COUNT; i++) {        // the module at the other end of each of our walls
    MeshPeer* P = mesh.find(zonePartner(zones[i].code, MY_NODE));
    if (P && !P->trk.online) logEvent("TEST", String(P->name) + " not connected - zone " + String(zones[i].code) + " on 3-hit rule");
  }
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
    case CMD_MAINT_START: case CMD_CLEAR_FAULT: case CMD_TEST_CUT:         need = R_MAINTENANCE; break;
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

    case CMD_TEST_CUT: {                                               // relay test: radio only, detection carries on
      MeshPeer* P = mesh.find((uint8_t)(arg >> 16));
      uint32_t secs = min(arg & 0xFFFF, TEST_CUT_MAX_S);
      if (!P) { why = "Not a link of this module"; res = RES_BAD; break; }
      if (secs) {
        P->cutUntil = millis() + secs * 1000;
        if (!P->cutUntil) P->cutUntil = 1;
        why = "Direct link to " + String(P->name) + " cut for " + String(secs) + " s (relay test)";
      } else {
        P->cutUntil = 0;
        why = "Relay test ended: direct link to " + String(P->name) + " back";
      }
      break;
    }
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
void confirmIntrusion(const String& why, const char* zone, uint8_t zoneBits) {
  alarmZones |= zoneBits;
  logEvent("ALERT", "Intrusion zone " + zoneList(zoneBits) + ": " + why, zone, "-", 2);
  if (goTo(S_INTRUSION, why)) startPeerAlarm(why);  // the other modules go to alarm too
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
  setScreen(String(MY_LETTER) + " DISARMED", b.length() ? b : (gwLink.trk.online ? String("Arm at gateway") : linkLine()));
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
    uint8_t zb = zoneBit(z.code);
    MeshPeer* partner = mesh.find(zonePartner(z.code, MY_NODE));
    if (partner) linkSend(*partner, L_PEER_EVENT, z.code, 0, 0, 0, 0, nullptr);   // tell the other end of the wall

    const MeshPeer* inAlarm = moduleInAlarm();     // an intrusion is still active elsewhere:
    if (inAlarm) { confirmIntrusion(String(z.name) + " while " + inAlarm->name + " is in alarm", z.name, zb); return; }
    if (partnerRecent(z.code, now)) { confirmIntrusion(partnerPir(z.code) + " + " + z.name, z.name, zb); return; }   // T05a
#if CORNER_PAIRS
    for (uint8_t k = 0; k < ZONE_COUNT; k++) {     // our other PIR, round the corner
      if (k == i || !zones[k].recent(now)) continue;
      confirmIntrusion(String(zones[k].name) + " + " + z.name + " (corner)", z.name, zb | zoneBit(zones[k].code));
      return;
    }
#endif
    if (hits >= REPEAT_TRIGGERS) { confirmIntrusion(String(z.name) + " x" + String(hits), z.name, zb); return; }  // T05b
    chirp();                                                                   // T04
    logEvent("ALERT", "Motion warning " + String(hits) + "/" + String(REPEAT_TRIGGERS), z.name, "-", 1);
  }

  // 3) The PIR at the other end of one of our walls fired
  for (uint8_t zn = 1; zn <= SITE_ZONES; zn++) {
    if (!partnerNew[zn]) continue;
    partnerNew[zn] = false;
    ZoneSensor* mine = zoneSensor(zn);
    String other = partnerPir(zn);
    if (mine && mine->recent(now)) { confirmIntrusion(String(mine->name) + " + " + other, other.c_str(), zoneBit(zn)); return; }
    logEvent("ALERT", "Motion seen by " + nodeName(zonePartner(zn, MY_NODE)), other.c_str(), "-", 1);
  }

  // 4) Screen
  ZoneSensor* wz = nullptr;
  for (uint8_t i = 0; i < ZONE_COUNT; i++) if (zones[i].recent(now)) { wz = &zones[i]; break; }
  if (wz) {
    setScreen(String(MY_LETTER) + " WARN P1 " + String((CORROBORATION_MS - (now - wz->lastTrig())) / 1000 + 1) + "s",
              String(wz->name) + " " + String(wz->recentCount(now)) + "/" + String(REPEAT_TRIGGERS));
  } else if (anyPartnerRecent(now)) {
    uint8_t zn = 1;
    while (zn < SITE_ZONES && !partnerRecent(zn, now)) zn++;
    setScreen(String(MY_LETTER) + " WARN P1", partnerPir(zn) + " motion");
  } else {
    setScreen(String(MY_LETTER) + " ARMED       P0", linkLine());
  }
  keypadHint(key, "Disarm at", "the gateway");
}

// While the intrusion is active, any of our PIRs firing is an intrusion in its
// zone at once: no 20 s window, no 3 hits (the alarm escalates to that wall).
void handleIntrusion(char key) {
  setScreen("!! INTRUSION !!", "Zone " + zoneList(alarmZones) + " | PIN + # = ack");
  for (uint8_t i = 0; i < ZONE_COUNT; i++) {
    ZoneSensor& z = zones[i];
    if (!z.eventPending) continue;
    z.eventPending = false;
    if (z.health != H_OK) continue;
    z.addTrigger(millis());
    uint8_t zb = zoneBit(z.code);
    if (alarmZones & zb) { logEvent("ALERT", "Motion during intrusion", z.name, "-", 2); continue; }
    alarmZones |= zb;
    saveAlarmZones();
    String why = String(z.name) + " during the alarm";
    logEvent("ALERT", "Intrusion zone " + String(z.code) + " (escalated): " + why, z.name, "-", 2);
    startPeerAlarm(why);                           // the other modules: zone added, buzzers on that wall
  }
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
  String st = "";
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    st += "Z" + String(zones[i].code) + ":" + (zones[i].health == H_OK ? "OK " : zones[i].health == H_STUCK ? "STK " : "WUP ");
  uint8_t up = 0;
  for (MeshPeer* P : PEERS) if (P->trk.online) up++;
  st += String(up) + "/" + String(PEER_COUNT);
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
    if (word == "cut") {                           // cut <a|b|c|d|g> [seconds]: relay test on one link
      String rest = sp < 0 ? String("") : line.substring(sp + 1);
      rest.trim();
      uint8_t node = rest.length() ? nodeFromLetter(rest[0]) : (uint8_t)NODE_NONE;
      int sp2 = rest.indexOf(' ');
      uint32_t secs = sp2 < 0 ? 60 : (uint32_t)rest.substring(sp2 + 1).toInt();
      String why;
      uint8_t r = applyCommand(CMD_TEST_CUT, R_MAINTENANCE, "bench@USB", ((uint32_t)node << 16) | secs, why);
      Serial.printf("> TEST_CUT: %s %s\n", resultName(r), why.c_str());
      continue;
    }
    uint8_t cmd = word == "arm" ? CMD_ARM : word == "disarm" ? CMD_DISARM : word == "maint" ? CMD_MAINT_START :
                  word == "end" ? CMD_MAINT_END : word == "ack" ? CMD_ACK_ALARM : word == "clear" ? CMD_CLEAR_FAULT :
                  word == "time" ? CMD_SET_TIME : 0;
    if (!cmd) {
      Serial.println("Bench commands: arm | disarm | maint [seconds] | end | ack | clear | time <unix> | status | log\n"
                     "                cut <a|b|c|d|g> [seconds]  (relay test: that direct link counts as broken; 0 s = end)");
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
  if (HAS_GREEN)  pinMode(PIN_LED_GREEN, OUTPUT);
  if (HAS_YELLOW) pinMode(PIN_LED_YELLOW, OUTPUT);
  if (HAS_RED)    pinMode(PIN_LED_RED, OUTPUT);
  if (HAS_BUZZER) { pinMode(PIN_BUZZER, OUTPUT); digitalWrite(PIN_BUZZER, BUZZER_ACTIVE_LOW ? HIGH : LOW); }
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
  uint8_t savedZones = prefs.getUChar("azones", 0) & 0x07;
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
  Serial.printf("\nSensor Module %c (walls: zone %s), MAC %s\n", MY_LETTER, zoneList(MY_WALLS).c_str(), mac.c_str());
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
  for (MeshPeer* L : PEERS) {
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
    alarmZones = savedZones ? savedZones : MY_WALLS;
    if (goTo(S_INTRUSION, "Restored")) startPeerAlarm("Restored after restart");   // the other modules go to alarm too
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
    if (display.check()) logEvent("COMM", display.online ? "LCD online" : HAS_BUZZER ? "LCD OFFLINE - LEDs and buzzer only" : "LCD OFFLINE - LEDs only");
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
