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
#pragma once
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
