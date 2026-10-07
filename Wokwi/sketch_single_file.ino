// SINGLE-FILE WOKWI VERSION: link_protocol.h and secrets.h are pasted inside.
// In Wokwi you need only this sketch.ino + diagram.json + libraries.txt.
// =====================================================================
//  PINNACLE 1 — PROJECT 13 — SECURE PERIMETER INTRUSION DETECTION
//  BOARD 1 : CONTROLLER  (ESP32 38-pin DevKitC, WROOM-32)  —  firmware v4
//
//  This board does all sensing and all decisions:
//    PIR-L (Zone 1) + PIR-R (Zone 2) [+ IR Zone 3 later], enclosure tamper
//    reed, RC522 RFID + 4x4 keypad (card + PIN), LCD1602, R/G/Y LEDs, buzzer.
//  It sends every event-log line and a 1 s status beat to Board 2
//  (gateway -> PC). If the gateway disappears the system keeps working
//  locally and only logs/display "PC link DOWN" (spec: safe local behaviour).
//
//  States: BOOT -> WAIT_AUTH -> MONITORING -> INTRUSION / TAMPER_FAULT /
//          MAINTENANCE -> RECOVERY -> MONITORING
//  Priority: P0 normal, P1 warning, P2 intrusion, P3 tamper/fault
//
//  Libraries: MFRC522 (GithubCommunity), Keypad (Mark Stanley / Alexander
//  Brevig), LiquidCrystal I2C (Frank de Brabander).  Board: "ESP32 Dev Module".
// =====================================================================
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <Preferences.h>
#include <LittleFS.h>
#include <Wire.h>
#include <SPI.h>
#include <MFRC522.h>
#include <Keypad.h>
#include <LiquidCrystal_I2C.h>
// (link_protocol.h is pasted further down, just above the first function)

// ---------------- roles + user table type (used by secrets.h) ----------------
enum Role : uint8_t { R_NONE = 0, R_OPERATOR = 1, R_MAINTENANCE = 2 };
const char* ROLE_NAMES[] = { "NONE", "OPERATOR", "MAINTENANCE" };
struct User {
  const char* name;
  uint8_t     uid[10];
  uint8_t     uidLen;
  const char* pinHashHex;     // SHA-256(PIN_SALT + PIN), lowercase hex
  Role        role;
};
// ===== secrets.h (built in for Wokwi) =====
// =====================================================================
//  secrets.h  —  Board 1 (controller), WOKWI VERSION
//  Card UIDs match Wokwi's preset cards: BLUE card = Operator1 (PIN 1234),
//  GREEN card = Maint1 (PIN 9876).
//  DEMO VALUES. Replace before your demo and DO NOT upload this file
//  to GitHub (it is listed in .gitignore).
// =====================================================================
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

// ===== end secrets.h =====

// The Arduino IDE / Wokwi auto-insert function prototypes above the first
// function in this file. Declare our own types before that point so those
// prototypes compile (e.g. "ZoneSensor* findZone(uint8_t id);").
class ZoneSensor;

#define ENROLL_MODE 0   // 1 = print full card UIDs on Serial (setup only). Keep 0 for the demo.
#define WOKWI_SIM   1   // 1 = running in the Wokwi simulator: buzzer uses tone(), PIR warm-up 5 s,
                        //     and the gateway link uses MQTT instead of ESP-NOW.
                        // Keep 0 on the real board.

// =====================================================================
//  PINS — ESP32 DevKitC 38-pin (WROOM-32). Check against your board's labels.
//  GPIO 34/35/36/39 are input-only with NO internal pull-ups -> external 10k.
//  Input-only pins are used ONLY for sensors, never for the keypad.
// =====================================================================
const uint8_t PIN_SDA = 21, PIN_SCL = 22;                       // LCD I2C
const uint8_t PIN_RFID_SCK = 18, PIN_RFID_MISO = 19;            // RC522 SPI
const uint8_t PIN_RFID_MOSI = 23, PIN_RFID_SS = 5;              // RC522 RST wired to 3.3 V
byte KP_ROWS[4] = { 13, 14, 27, 26 };                           // keypad pins 1-4
byte KP_COLS[4] = { 25, 33, 32, 4 };                            // keypad pins 5-8 (driven: normal I/O only)
const uint8_t PIN_BUZZER     = 16;    // WROVER boards use GPIO 16/17 internally: WROOM-32 needed
const uint8_t PIN_LED_GREEN  = 2;
const uint8_t PIN_LED_RED    = 15;
const uint8_t PIN_LED_YELLOW = 12;    // strapping pin: LED+resistor to GND keeps it LOW at boot
const uint8_t PIN_PIR_L      = 35;    // + 10k pull-up to 3.3 V
const uint8_t PIN_PIR_R      = 34;    // + 10k pull-up to 3.3 V
const uint8_t PIN_TAMPER     = 39;    // + 10k pull-up; reed switch to GND
const uint8_t PIN_IR         = 36;    // FC-51 (later). Its module has its own pull-up.

const uint8_t TAMPER_CLOSED_LEVEL = LOW;   // lid shut = LOW; lid open OR wire cut = HIGH
const bool    BUZZER_ACTIVE_LOW   = false; // true if your module beeps when the pin is LOW
const uint8_t LCD_ADDR            = 0x27;  // try 0x3F if the LCD stays blank

// =====================================================================
//  TIMING / LIMITS  (finalise at Design Review 1)
// =====================================================================
const uint32_t LOOP_MS             = 50;
const uint32_t PIR_WARMUP_MS       = WOKWI_SIM ? 5000 : 60000;
const uint32_t SENSOR_MAX_ACTIVE_MS= 30000;   // active longer = stuck / disconnected / blocked
const uint32_t TAMPER_DEBOUNCE_MS  = 60;
const uint32_t CORROBORATION_MS    = 20000;   // P1 window from the first trigger
const uint8_t  REPEAT_TRIGGERS     = 3;       // same side this often in the window = P2
const uint32_t STATUS_EVERY_MS     = 1000;
const uint32_t GATEWAY_TIMEOUT_MS  = WOKWI_SIM ? 8000 : 3000;   // MQTT via internet is slower
const uint8_t  MAX_ATTEMPTS        = 3;
const uint32_t BASE_LOCKOUT_S      = 60;      // 60, 120, 240, 480, 960
const uint8_t  MAX_LOCKOUT_LEVEL   = 4;
const uint32_t PIN_TIMEOUT_MS      = 30000;   // card scanned -> PIN must follow within this
const uint32_t DISARM_REQUEST_MS   = 20000;
const uint32_t MAINT_TIMEOUT_MS    = 300000;  // 5 minutes
const uint32_t PERIPH_CHECK_MS     = 5000;
const uint32_t FAULT_REMINDER_MS   = 60000;
const uint32_t MSG_SHOW_MS         = 1500;
const size_t   LOG_MAX_BYTES       = 32 * 1024;

// =====================================================================
//  STATE MACHINE DEFINITIONS
// =====================================================================
enum State : uint8_t { S_BOOT, S_WAIT_AUTH, S_MONITORING, S_INTRUSION,
                       S_TAMPER_FAULT, S_MAINTENANCE, S_RECOVERY };
const uint8_t STATE_COUNT = 7;
const char* STATE_NAMES[] = { "BOOT", "WAIT_AUTH", "MONITORING", "INTRUSION",
                              "TAMPER_FAULT", "MAINTENANCE", "RECOVERY" };
#define B(s) (1 << (s))
const uint8_t ALLOWED[] = {      // allowed transitions; anything else is refused + logged
  /* BOOT         */ B(S_WAIT_AUTH) | B(S_MONITORING) | B(S_INTRUSION) | B(S_TAMPER_FAULT),
  /* WAIT_AUTH    */ B(S_MONITORING) | B(S_TAMPER_FAULT),
  /* MONITORING   */ B(S_INTRUSION) | B(S_TAMPER_FAULT) | B(S_MAINTENANCE) | B(S_WAIT_AUTH),
  /* INTRUSION    */ B(S_RECOVERY) | B(S_TAMPER_FAULT),
  /* TAMPER_FAULT */ B(S_RECOVERY),
  /* MAINTENANCE  */ B(S_RECOVERY) | B(S_TAMPER_FAULT),
  /* RECOVERY     */ B(S_MONITORING) | B(S_WAIT_AUTH) | B(S_TAMPER_FAULT),
};
// ===== link_protocol.h (built in for Wokwi) =====
// =====================================================================
//  link_protocol.h  —  shared by Board 1 (controller) and Board 2 (gateway).
//  Keep this file IDENTICAL in both sketch folders.
// =====================================================================
#include <Arduino.h>
#include <esp_task_wdt.h>
#include "mbedtls/md.h"

#define LINK_VERSION    2
#define ESPNOW_CHANNEL  1      // both boards must use the same Wi-Fi channel
#define SIG_LEN         8      // bytes of HMAC-SHA256 kept in each packet
#define LINK_TEXT_MAX   160    // one log line / status line

// Wokwi simulator only (WOKWI_SIM 1): Wokwi cannot do ESP-NOW between two
// simulations, so the same signed packets travel over MQTT instead.
// Both boards must use the SAME topic. Real hardware ignores these.
#define MQTT_BROKER      "broker.hivemq.com"
#define MQTT_PORT        1883
#define MQTT_TOPIC_BASE  "pinnacle13/p13-2d386efc"
#define MQTT_TOPIC_CTRL  MQTT_TOPIC_BASE "/ctrl"     // controller -> gateway
#define MQTT_TOPIC_GW    MQTT_TOPIC_BASE "/gw"       // gateway -> controller

enum LinkNode : uint8_t { NODE_CONTROLLER = 1, NODE_GATEWAY = 9 };
enum LinkType : uint8_t {
  L_HELLO  = 1,   // "I (re)started" + carries status/ack. Sent at boot and every 10th beat.
  L_STATUS = 2,   // controller -> gateway, every second: state, priority, zone health
  L_LOG    = 3,   // controller -> gateway, one event-log line
  L_ACK    = 4    // gateway -> controller, reply to each status: "PC link alive"
};
enum Health : uint8_t { H_OK = 0, H_WARMUP = 1, H_STUCK = 2, H_OFFLINE = 3 };

#pragma pack(push, 1)
struct LinkPacket {
  uint8_t  version;        // LINK_VERSION
  uint8_t  nodeId;         // LinkNode of the sender
  uint8_t  type;           // LinkType
  uint32_t bootId;         // random number chosen at sender boot
  uint32_t seq;            // +1 on every packet (replay protection)
  uint32_t logNo;          // L_LOG: running log-line number (gateway spots gaps)
  uint8_t  state;          // controller state number
  uint8_t  priority;       // 0..3
  uint8_t  resetReason;    // sender's last reset reason
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

// Constant-time compare (does not leak how many bytes matched).
inline bool sameBytes(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t diff = 0;
  for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
  return diff == 0;
}

// Structure check before anything else is trusted.
inline bool linkWellFormed(const LinkPacket& p, int len) {
  return len == (int)sizeof(LinkPacket) && p.version == LINK_VERSION &&
         p.type >= L_HELLO && p.type <= L_ACK && p.textLen <= LINK_TEXT_MAX;
}

// Tracks one peer's boot ID + sequence number to reject replayed packets.
enum TrackResult : uint8_t { TR_OK, TR_SYNCED, TR_NEW_BOOT, TR_REPLAY };
struct PeerTracker {
  bool     synced = false;
  bool     online = false;
  uint32_t bootId = 0, lastSeq = 0, lastHeard = 0;

  TrackResult accept(const LinkPacket& p) {
    TrackResult r;
    if (p.type == L_HELLO && synced && p.bootId != bootId) r = TR_NEW_BOOT;  // peer restarted
    else if (!synced)                                       r = TR_SYNCED;    // first packet since WE booted
    else if (p.bootId != bootId || p.seq <= lastSeq)        return TR_REPLAY; // old or copied packet
    else                                                    r = TR_OK;
    bootId = p.bootId; lastSeq = p.seq; synced = true; lastHeard = millis();
    return r;
  }
};

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

// ===== end link_protocol.h =====

const char* stateName(uint8_t s) { return s < STATE_COUNT ? STATE_NAMES[s] : "INVALID"; }

State    state          = S_BOOT;
uint32_t stateEnteredAt = 0;
Role     sessionRole    = R_NONE;
String   faultReason    = "";
String   selfTestReason = "";

// forward declarations
bool goTo(State next, const String& reason);
void logEvent(const char* type, const String& event, const char* zone = "-",
              const char* result = "-", int prio = -1, int role = -1, const String& uid = "-");
void chirp(uint32_t ms = 120);
void showMsg(const String& l1, const String& l2);
uint8_t currentPriority();
String statusText();

// =====================================================================
//  ZONE SENSOR  (one object per PIR / IR sensor)
//  Health: WARMUP for the first 60 s (PIR only); STUCK if "active" for
//  longer than SENSOR_MAX_ACTIVE_MS. With a pull-up, an unplugged PIR reads
//  HIGH forever -> STUCK. A covered/blocked IR reads active forever -> STUCK.
// =====================================================================
class ZoneSensor {
public:
  ZoneSensor(uint8_t id_, const char* name_, uint8_t pin_, bool activeHigh_, bool warmup_, bool enabled_)
    : id(id_), name(name_), pin(pin_), enabled(enabled_), activeHigh(activeHigh_), needsWarmup(warmup_) {}

  void begin() {
    if (!enabled) return;
    pinMode(pin, INPUT);                       // pull-up is external (34-39)
    health = needsWarmup ? H_WARMUP : H_OK;
  }

  void update(uint32_t now) {
    if (!enabled) return;
    bool raw = digitalRead(pin) == HIGH;
    bool act = activeHigh ? raw : !raw;

    if (needsWarmup && now < PIR_WARMUP_MS) {  // PIR still settling: ignore
      health = H_WARMUP; active = false; lastActive = act; activeSince = now;
      return;
    }
    bool rising = act && !lastActive;
    if (rising) activeSince = now;
    lastActive = act;

    if (act && now - activeSince > SENSOR_MAX_ACTIVE_MS) health = H_STUCK;
    else if (!act || health == H_WARMUP)                  health = H_OK;
    active = act && health == H_OK;
    if (rising && health == H_OK) eventPending = true;
  }

  bool faulty() const { return enabled && (health == H_STUCK || health == H_OFFLINE); }

  const uint8_t id;
  const char*   name;
  const uint8_t pin;
  const bool    enabled;
  uint8_t health = H_WARMUP;
  bool    active = false;
  bool    eventPending = false;
  uint8_t hits = 0;               // triggers inside the current P1 window
  uint8_t loggedHealth = 0xFF;    // last health written to the log
private:
  const bool activeHigh, needsWarmup;
  bool     lastActive = false;
  uint32_t activeSince = 0;
};

ZoneSensor zones[] = {
  //          id  name        pin        activeHigh warmup enabled
  ZoneSensor( 1, "Z1-LEFT",  PIN_PIR_L, true,      true,  true  ),
  ZoneSensor( 2, "Z2-RIGHT", PIN_PIR_R, true,      true,  true  ),
  ZoneSensor( 3, "Z3-IR",    PIN_IR,    false,     false, false ),   // FC-51: enabled=true when fitted
};
const uint8_t ZONE_COUNT = sizeof(zones) / sizeof(zones[0]);
ZoneSensor* findZone(uint8_t id) {
  for (uint8_t i = 0; i < ZONE_COUNT; i++) if (zones[i].id == id) return &zones[i];
  return nullptr;
}

uint32_t windowUntil = 0;
uint8_t  windowZone  = 0;

// =====================================================================
//  TAMPER SENSOR  (time-debounced; open lid and cut wire both read "open")
// =====================================================================
class TamperSensor {
public:
  void begin() {
    pinMode(PIN_TAMPER, INPUT);              // external 10k pull-up (GPIO 39)
    stable = candidate = digitalRead(PIN_TAMPER);
    changedAt = millis();
  }
  // returns true when the debounced state changes
  bool update(uint32_t now) {
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
  // returns true when online/offline changes
  bool check() {
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
//  RFID READER  (RST tied to 3.3 V; library does a soft reset)
// =====================================================================
class RfidReader {
public:
  RfidReader() : reader(PIN_RFID_SS, MFRC522::UNUSED_PIN) {}
  void begin() {
    SPI.begin(PIN_RFID_SCK, PIN_RFID_MISO, PIN_RFID_MOSI, PIN_RFID_SS);
    reader.PCD_Init();
    online = healthy();
  }
  bool healthy() {                           // 0x91/0x92 on a real RC522
    byte v = reader.PCD_ReadRegister(MFRC522::VersionReg);
    return v != 0x00 && v != 0xFF;
  }
  bool check() {                             // returns true when online/offline changes
    bool now = healthy();
    if (now && !online) reader.PCD_Init();
    bool changed = now != online;
    online = now;
    return changed;
  }
  bool readCard(uint8_t* uid, uint8_t& len) {
    if (!online) return false;
    if (!reader.PICC_IsNewCardPresent() || !reader.PICC_ReadCardSerial()) return false;
    len = min((int)reader.uid.size, 10);
    memcpy(uid, reader.uid.uidByte, len);
    reader.PICC_HaltA();
    reader.PCD_StopCrypto1();
    return true;
  }
  bool online = false;
private:
  MFRC522 reader;
};
RfidReader rfid;

// =====================================================================
//  OUTPUTS: LEDs + buzzer  (unknown state fails closed: red + buzzer)
// =====================================================================
uint32_t chirpUntil = 0, outputTestUntil = 0;
void chirp(uint32_t ms) { chirpUntil = millis() + ms; }

// Real board: active buzzer = steady ON/OFF. Wokwi's buzzer needs a tone.
void setBuzzer(bool on) {
#if WOKWI_SIM
  static bool was = false;
  if (on != was) { was = on; if (on) tone(PIN_BUZZER, 2000); else noTone(PIN_BUZZER); }
#else
  digitalWrite(PIN_BUZZER, BUZZER_ACTIVE_LOW ? !on : on);
#endif
}

void updateOutputs() {
  uint32_t now = millis();
  bool fast = (now / 250) % 2, slow = (now / 500) % 2, beat = (now / 1000) % 2;
  bool g = false, r = false, y = false, buz = false;
  switch (state) {
    case S_BOOT:         y = slow; break;
    case S_WAIT_AUTH:    g = beat; break;                                   // disarmed: slow green
    case S_MONITORING:   if (currentPriority() == 1) y = true; else g = true; break;
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
uint32_t bootNo = 0;
uint8_t  failedAttempts = 0, lockoutLevel = 0;
uint32_t lockoutRemainingS = 0, lastLockTick = 0;
uint8_t  savedState = S_WAIT_AUTH;
String   savedReason = "";

void saveAuthCounters() {
  prefs.putUChar("failed", failedAttempts);
  prefs.putUChar("lockLvl", lockoutLevel);
  prefs.putUInt("lockRem", lockoutRemainingS);
}

// =====================================================================
//  GATEWAY LINK (ESP-NOW). Board 1 broadcasts signed packets, so no MAC
//  addresses need configuring. The gateway answers each status with an ACK.
// =====================================================================
struct RxItem { int len; uint8_t data[sizeof(LinkPacket)]; };
QueueHandle_t rxQueue;
const uint8_t BROADCAST[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

#if WOKWI_SIM
// ---- Simulator transport: MQTT over Wokwi's internet (replaces ESP-NOW) ----
#include <PubSubClient.h>
WiFiClient   mqttNet;
PubSubClient mqtt(mqttNet);
void onMqtt(char* topic, byte* payload, unsigned int len) {
  RxItem it;
  it.len = len;
  memcpy(it.data, payload, min((int)len, (int)sizeof(it.data)));
  xQueueSend(rxQueue, &it, 0);
}
#endif

#if ESP_ARDUINO_VERSION_MAJOR >= 3
void onRecv(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
#else
void onRecv(const uint8_t* mac, const uint8_t* data, int len) {
#endif
  RxItem it;                                  // runs in the Wi-Fi task: copy + queue only
  it.len = len;
  memcpy(it.data, data, min(len, (int)sizeof(it.data)));
  xQueueSend(rxQueue, &it, 0);
}

class GatewayLink {
public:
  void begin() {
    bootId = esp_random();
    resetReason = (uint8_t)esp_reset_reason();
    rxQueue = xQueueCreate(8, sizeof(RxItem));
#if WOKWI_SIM
    WiFi.mode(WIFI_STA);
    WiFi.begin("Wokwi-GUEST", "", 6);            // Wokwi's simulated Wi-Fi
    mqtt.setServer(MQTT_BROKER, MQTT_PORT);
    mqtt.setCallback(onMqtt);
    mqtt.setBufferSize(512);
    mqtt.setSocketTimeout(2);
    ready = true;
    return;
#endif
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_channel(ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE);
    if (esp_now_init() != ESP_OK) { ready = false; return; }
    esp_now_register_recv_cb(onRecv);
    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, BROADCAST, 6);
    peer.channel = ESPNOW_CHANNEL;
    peer.encrypt = false;                       // packets are signed (HMAC), not encrypted
    ready = esp_now_add_peer(&peer) == ESP_OK;
  }

  // Called by logEvent(): queue the line; loop() sends one per pass.
  void queueLog(const String& line) {
    if (count == QSIZE) { head = (head + 1) % QSIZE; count--; }      // drop oldest -> gateway sees a gap
    uint8_t slot = (head + count) % QSIZE;
    strncpy(q[slot], line.c_str(), LINK_TEXT_MAX - 1);
    q[slot][LINK_TEXT_MAX - 1] = 0;
    qNo[slot] = ++logNo;
    count++;
  }

  void loop(uint32_t now) {
    if (!ready) return;
#if WOKWI_SIM
    if (WiFi.status() == WL_CONNECTED && !mqtt.connected() && now - lastMqttTry > 5000) {
      lastMqttTry = now;
      esp_task_wdt_reset();
      String id = "p13-ctrl-" + String(bootId, HEX);
      if (mqtt.connect(id.c_str())) {
        if (!mixedBootId) { bootId ^= (uint32_t)micros(); mixedBootId = true; }   // simulator RNG may repeat
        mqtt.subscribe(MQTT_TOPIC_GW);
        Serial.println("[sim] MQTT connected");
      }
    }
    mqtt.loop();
#endif
    receive();
    if (online && now - peer.lastHeard > GATEWAY_TIMEOUT_MS) {
      online = false;
      logEvent("COMM", "Gateway lost - PC link DOWN (local alarm unaffected)");   // T09
    }
    if (now - lastStatus >= STATUS_EVERY_MS) {
      lastStatus = now;
      String st = statusText();
      send(++beats % 10 == 1 ? L_HELLO : L_STATUS, st.c_str(), 0);
    } else if (count > 0 && linkUp()) {         // keep lines queued while the link is down
      send(L_LOG, q[head], qNo[head]);
      head = (head + 1) % QSIZE; count--;
    }
  }

  bool online = false;
private:
  static const uint8_t QSIZE = 24;
  char     q[QSIZE][LINK_TEXT_MAX];
  uint32_t qNo[QSIZE];
  uint8_t  head = 0, count = 0;
  uint32_t logNo = 0, bootId = 0, seq = 0, beats = 0, lastStatus = 0, lastRejectLog = 0;
  uint8_t  resetReason = 0;
  bool     ready = false;
  uint32_t lastMqttTry = 0;
  bool     mixedBootId = false;
  PeerTracker peer;

#if WOKWI_SIM
  bool linkUp() { return mqtt.connected(); }
#else
  bool linkUp() { return true; }
#endif

  void send(uint8_t type, const char* text, uint32_t no) {
    LinkPacket p = {};
    p.version = LINK_VERSION; p.nodeId = NODE_CONTROLLER; p.type = type;
    p.bootId = bootId; p.seq = ++seq; p.logNo = no;
    p.state = state; p.priority = currentPriority(); p.resetReason = resetReason;
    size_t n = strnlen(text, LINK_TEXT_MAX);
    memcpy(p.text, text, n); p.textLen = n;
    linkSign(SHARED_KEY, sizeof(SHARED_KEY), p, p.sig);
#if WOKWI_SIM
    if (mqtt.connected()) mqtt.publish(MQTT_TOPIC_CTRL, (const uint8_t*)&p, sizeof(p));
#else
    esp_now_send(BROADCAST, (const uint8_t*)&p, sizeof(p));
#endif
  }

  void reject(const String& why) {
    if (millis() - lastRejectLog < 2000) return;       // don't flood the log
    lastRejectLog = millis();
    logEvent("COMM", why, "-", "REJECTED");
  }

  void receive() {
    RxItem it;
    while (xQueueReceive(rxQueue, &it, 0) == pdTRUE) {
      LinkPacket p;
      memcpy(&p, it.data, sizeof(p));
      if (!linkWellFormed(p, it.len))  { reject("Malformed packet");   continue; }    // T08
      if (p.nodeId != NODE_GATEWAY)    { reject("Unknown sender");     continue; }
      uint8_t exp[SIG_LEN];
      linkSign(SHARED_KEY, sizeof(SHARED_KEY), p, exp);
      if (!sameBytes(exp, p.sig, SIG_LEN)) { reject("Bad signature (spoofed?)"); continue; }
      TrackResult tr = peer.accept(p);
      if (tr == TR_REPLAY) { reject("Replayed/old packet"); continue; }
      if (tr == TR_NEW_BOOT) logEvent("COMM", String("Gateway restarted reason=") + resetReasonName(p.resetReason));
      if (!online) { online = true; logEvent("COMM", "Gateway online - PC link UP"); }
    }
  }
};
GatewayLink gateway;

// =====================================================================
//  EVENT LOG  -> LittleFS /log.csv + Serial + gateway
//  boot,uptime_ms,priority,state,type,event,zone,role,uid,result
// =====================================================================
bool fsOk = false;

void logEvent(const char* type, const String& event, const char* zone,
              const char* result, int prio, int role, const String& uid) {
  String ev = event; ev.replace(",", ";");
  String line = String(bootNo) + "," + String(millis()) + ",P" +
                String(prio < 0 ? currentPriority() : prio) + "," + stateName(state) + "," +
                type + "," + ev + "," + zone + "," + ROLE_NAMES[role < 0 ? sessionRole : role] + "," +
                uid + "," + result;
  Serial.println(line);
  gateway.queueLog(line);
  if (!fsOk) return;
  File f = LittleFS.open("/log.csv", FILE_APPEND);
  if (!f) return;
  if (f.size() > LOG_MAX_BYTES) {                     // rotate: keep one old file
    f.close();
    LittleFS.remove("/log_old.csv");
    LittleFS.rename("/log.csv", "/log_old.csv");
    f = LittleFS.open("/log.csv", FILE_APPEND);
    if (!f) return;
  }
  if (f.size() == 0) f.println("boot,uptime_ms,priority,state,type,event,zone,role,uid,result");
  f.println(line);
  f.close();
}

void dumpLogToSerial() {
  Serial.println("----- EVENT LOG START -----");
  const char* files[] = { "/log_old.csv", "/log.csv" };
  for (const char* name : files) {
    File f = LittleFS.open(name, FILE_READ);
    if (!f) continue;
    while (f.available()) { Serial.write(f.read()); if ((f.position() & 1023) == 0) esp_task_wdt_reset(); }
    f.close();
  }
  Serial.println("----- EVENT LOG END -----");
}

// =====================================================================
//  LCD TEXT
// =====================================================================
String screen1 = "", screen2 = "", msg1 = "", msg2 = "";
uint32_t msgUntil = 0;
void setScreen(const String& l1, const String& l2) { screen1 = l1; screen2 = l2; }
void showMsg(const String& l1, const String& l2) { msg1 = l1; msg2 = l2; msgUntil = millis() + MSG_SHOW_MS; }

void rejectInput(const String& why) {                 // T08
  logEvent("INPUT", why, "-", "REJECTED");
  showMsg("Invalid input", why);
  chirp();
}

// =====================================================================
//  PRIORITY + STATUS TEXT (sent to the gateway every second)
// =====================================================================
uint8_t currentPriority() {
  if (state == S_TAMPER_FAULT) return 3;
  if (state == S_INTRUSION)    return 2;
  if (state == S_MONITORING && notYet(windowUntil)) return 1;
  return 0;
}

String statusText() {
  String s = String(stateName(state)) + ",P" + currentPriority();
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].enabled) s += String(",") + zones[i].name + ":" + healthName(zones[i].health);
  s += String(",LID:") + (tamper.isOpen() ? "OPEN" : "SHUT");
  s += String(",RFID:") + (rfid.online ? "OK" : "OFFLINE");
  s += String(",LCD:") + (display.online ? "OK" : "OFFLINE");
  return s;
}

// =====================================================================
//  STATE TRANSITIONS  (every change is validated, logged and saved)
// =====================================================================
struct AuthEntry {
  bool     haveCard = false;
  uint8_t  uid[10];
  uint8_t  uidLen = 0;
  String   pin = "";
  uint32_t startedAt = 0;
} auth;
void resetAuth() { auth.haveCard = false; auth.uidLen = 0; auth.pin = ""; auth.startedAt = 0; }

uint32_t maintUntil = 0, lastFaultReminder = 0, disarmRequestAt = 0;
bool     maintShowStatus = false, disarmRequested = false;

void onEnter(State s, const String& reason) {
  resetAuth();
  disarmRequested = false;
  switch (s) {
    case S_TAMPER_FAULT: faultReason = reason; lastFaultReminder = millis(); break;
    case S_MAINTENANCE:  maintUntil = millis() + MAINT_TIMEOUT_MS; maintShowStatus = false; break;
    case S_MONITORING:   // fresh start: no stale detections, no open window
      windowUntil = millis();
      for (uint8_t i = 0; i < ZONE_COUNT; i++) { zones[i].eventPending = false; zones[i].hits = 0; }
      break;
    case S_WAIT_AUTH:    sessionRole = R_NONE; break;
    default: break;
  }
}

bool goTo(State next, const String& reason) {
  if (next >= STATE_COUNT || !(ALLOWED[state] & B(next))) {
    logEvent("STATE", String("Invalid ") + stateName(state) + "->" + stateName(next), "-", "REJECTED");
    return false;
  }
  logEvent("STATE", String(stateName(state)) + "->" + stateName(next) + " (" + reason + ")");
  state = next;
  stateEnteredAt = millis();
  onEnter(next, reason);
  prefs.putUChar("state", (uint8_t)next);                       // survives power loss
  if (next == S_TAMPER_FAULT) prefs.putString("reason", reason);
  return true;
}

// =====================================================================
//  AUTHENTICATION: card + PIN  (T02, T03, T08)
// =====================================================================
void tickLockout() {
  if (lockoutRemainingS == 0) return;
  if (millis() - lastLockTick >= 1000) {
    lastLockTick += 1000;
    lockoutRemainingS--;
    if (lockoutRemainingS % 5 == 0) prefs.putUInt("lockRem", lockoutRemainingS);
    if (lockoutRemainingS == 0) logEvent("AUTH", "Lockout ended");
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

String maskUid(const uint8_t* uid, uint8_t len) {      // only the last 2 bytes are ever logged
  if (len == 0) return "-";
  String s = "**";
  for (uint8_t i = (len > 2 ? len - 2 : 0); i < len; i++) { char b[4]; sprintf(b, ":%02X", uid[i]); s += b; }
  return s;
}

const User* findUserByUid(const uint8_t* uid, uint8_t len) {
  for (uint8_t i = 0; i < USER_COUNT; i++)
    if (USERS[i].uidLen == len && memcmp(USERS[i].uid, uid, len) == 0) return &USERS[i];
  return nullptr;
}

Role checkCredentials() {
  String uidMasked = maskUid(auth.uid, auth.uidLen);
  if (auth.pin.length() < 4) { rejectInput("PIN too short"); resetAuth(); return R_NONE; }

  String h = sha256Hex(String(PIN_SALT) + auth.pin);
  const User* who = nullptr;
  Role role = R_NONE;
  if (auth.haveCard) {                                       // normal path: card + PIN
    const User* u = findUserByUid(auth.uid, auth.uidLen);
    if (u && h.equalsIgnoreCase(u->pinHashHex)) { who = u; role = u->role; }
  } else {                                                   // RFID reader dead: PIN only,
    for (uint8_t i = 0; i < USER_COUNT; i++)                 // OPERATOR rights at most
      if (USERS[i].role == R_OPERATOR && h.equalsIgnoreCase(USERS[i].pinHashHex)) {
        who = &USERS[i]; role = R_OPERATOR; break;
      }
    logEvent("AUTH", "PIN-only attempt (RFID offline)");
  }
  resetAuth();

  if (role != R_NONE) {
    failedAttempts = 0; lockoutLevel = 0; saveAuthCounters();
    logEvent("AUTH", String("Login ") + who->name, "-", "SUCCESS", -1, role, uidMasked);
    showMsg("Welcome", who->name);
    return role;
  }
  failedAttempts++;
  logEvent("AUTH", "Login failed", "-", "FAIL", -1, R_NONE, uidMasked);              // T02
  chirp(300);
  if (failedAttempts >= MAX_ATTEMPTS) {                                              // T03
    lockoutRemainingS = BASE_LOCKOUT_S << lockoutLevel;
    if (lockoutLevel < MAX_LOCKOUT_LEVEL) lockoutLevel++;
    failedAttempts = 0;
    lastLockTick = millis();
    logEvent("AUTH", "Lockout " + String(lockoutRemainingS) + " s", "-", "LOCKED", 1);
    showMsg("LOCKED", String(lockoutRemainingS) + " s");
  } else {
    showMsg("Access denied", String(MAX_ATTEMPTS - failedAttempts) + " tries left");
  }
  saveAuthCounters();
  return R_NONE;
}

// Called every loop by states that accept a login. Returns the role once on success.
Role pollAuth(char key) {
  uint8_t uid[10], len = 0;
  bool cardHere = rfid.readCard(uid, len);

  if (lockoutRemainingS > 0) {                               // input blocked; sensors keep running
    if (cardHere || (key && strchr("0123456789*#", key))) showMsg("LOCKED", String(lockoutRemainingS) + " s left");
    return R_NONE;
  }
  if (cardHere) {
    auth.haveCard = true; auth.uidLen = len; memcpy(auth.uid, uid, len);
    auth.pin = ""; auth.startedAt = millis();
#if ENROLL_MODE
    Serial.print("ENROLL card UID: ");
    for (uint8_t i = 0; i < len; i++) Serial.printf("0x%02X%s", uid[i], i + 1 < len ? ", " : "");
    Serial.printf("   (len %u)\n", len);
#endif
    chirp(40);
  }
  if (auth.startedAt && millis() - auth.startedAt > PIN_TIMEOUT_MS) {
    resetAuth(); logEvent("AUTH", "PIN entry timeout"); showMsg("Timed out", "Scan card again");
  }
  if (!key) return R_NONE;
  if (key >= '0' && key <= '9') {
    if (rfid.online && !auth.haveCard) { showMsg("Scan card first", ""); return R_NONE; }
    if (auth.pin.length() >= 6) { rejectInput("PIN too long"); resetAuth(); return R_NONE; }
    if (!auth.startedAt) auth.startedAt = millis();
    auth.pin += key;
  } else if (key == '*') {
    auth.pin = "";
  } else if (key == '#') {
    if (auth.haveCard || auth.pin.length()) return checkCredentials();
  }
  return R_NONE;                                             // A-D handled by the states
}
bool authInProgress() { return auth.haveCard || auth.pin.length() > 0; }

// =====================================================================
//  SELF-TEST (boot + recovery) and arming checks
// =====================================================================
bool selfTest() {
  selfTestReason = "";
  if (tamper.isOpen()) selfTestReason += "Lid open ";
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].faulty()) selfTestReason += String(zones[i].name) + " " + healthName(zones[i].health) + " ";
  if (!rfid.online)    logEvent("TEST", "RFID offline - degraded (PIN-only operator)");
  if (!gateway.online) logEvent("TEST", "Gateway not connected - local logging only");
  outputTestUntil = millis() + 800;                           // short lamp + buzzer test
  selfTestReason.trim();
  return selfTestReason.length() == 0;
}

String armBlocker() {                                         // "" = OK to arm
  if (tamper.isOpen()) return "Lid open";
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].faulty()) return String(zones[i].name) + " " + healthName(zones[i].health);
  return "";
}

// =====================================================================
//  STATE HANDLERS
// =====================================================================
bool bootRestoreChecked = false;

void handleBoot() {
  // Alarms survive a power cut: restore them at once, before warm-up.
  if (!bootRestoreChecked) {
    bootRestoreChecked = true;
    if (savedState == S_INTRUSION)    { goTo(S_INTRUSION, "restored after restart"); return; }
    if (savedState == S_TAMPER_FAULT) { goTo(S_TAMPER_FAULT, savedReason.length() ? savedReason : "restored after restart"); return; }
  }
  uint32_t el = millis();
  if (el < PIR_WARMUP_MS) {
    setScreen("Warming up " + String((PIR_WARMUP_MS - el) / 1000) + "s",
              String("PC link: ") + (gateway.online ? "UP" : "--"));
    return;
  }
  if (!selfTest()) {
    logEvent("TEST", "Self-test FAILED: " + selfTestReason, "-", "FAIL", 3);
    goTo(S_TAMPER_FAULT, selfTestReason);
    return;
  }
  logEvent("TEST", "Self-test OK", "-", "PASS");
  bool wasArmed = savedState == S_MONITORING || savedState == S_MAINTENANCE || savedState == S_RECOVERY;
  if (wasArmed) goTo(S_MONITORING, "re-armed after restart");    // pulling the plug never disarms
  else          goTo(S_WAIT_AUTH, "boot complete");
}

void handleWaitAuth(char key) {
  String blocker = armBlocker();
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].eventPending) { zones[i].eventPending = false; logEvent("SENSOR", "Motion (disarmed)", zones[i].name, "-", 0); }
  setScreen("DISARMED", blocker.length() ? blocker : "Card + PIN, #");

  if (key >= 'A' && key <= 'D') rejectInput("Key not valid now");
  Role r = pollAuth(key);
  if (r == R_NONE) return;
  if (blocker.length()) {                                     // never arm with a problem present
    logEvent("STATE", "Arm refused: " + blocker, "-", "REJECTED", -1, r);
    showMsg("Cannot arm", blocker);
    return;
  }
  sessionRole = r;
  goTo(S_MONITORING, String(ROLE_NAMES[r]) + " armed");
}

void handleMonitoring(char key) {
  // 1) Health first: a broken sensor is a FAULT, never an intrusion.         T06
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].faulty()) { goTo(S_TAMPER_FAULT, String(zones[i].name) + " " + healthName(zones[i].health)); return; }

  // 2) Left/right corroboration. P2 when, inside one window:
  //    a) both sides detect, or b) the same side fires REPEAT_TRIGGERS times.
  if (!notYet(windowUntil))
    for (uint8_t i = 0; i < ZONE_COUNT; i++) zones[i].hits = 0;

  for (uint8_t i = 0; i < ZONE_COUNT; i++) {
    ZoneSensor& z = zones[i];
    if (!z.eventPending) continue;
    z.eventPending = false;
    if (z.health != H_OK) continue;

    if (!notYet(windowUntil)) { windowUntil = millis() + CORROBORATION_MS; windowZone = z.id; }
    if (z.hits < 255) z.hits++;

    const char* otherSide = nullptr;
    for (uint8_t j = 0; j < ZONE_COUNT; j++)
      if (j != i && zones[j].hits > 0) otherSide = zones[j].name;

    if (otherSide) {                                                            // T05a
      logEvent("ALERT", String("Corroborated ") + otherSide + "+" + z.name, z.name, "-", 2);
      goTo(S_INTRUSION, "two zones"); return;
    }
    if (z.hits >= REPEAT_TRIGGERS) {                                            // T05b
      logEvent("ALERT", String("Sustained motion ") + z.name + " x" + z.hits, z.name, "-", 2);
      goTo(S_INTRUSION, "sustained motion"); return;
    }
    chirp();                                                                    // T04
    logEvent("ALERT", "Motion warning " + String(z.hits) + "/" + String(REPEAT_TRIGGERS), z.name, "-", 1);
  }

  // 3) Screen
  if (disarmRequested && millis() - disarmRequestAt > DISARM_REQUEST_MS) disarmRequested = false;
  if (notYet(windowUntil)) {
    ZoneSensor* wz = findZone(windowZone);
    setScreen("WARNING P1 " + String((windowUntil - millis()) / 1000 + 1) + "s",
              String(wz ? wz->name : "?") + " " + String(wz ? wz->hits : 0) + "/" + String(REPEAT_TRIGGERS));
  } else {
    setScreen("ARMED    P0", disarmRequested ? "Disarm: card+PIN" : (gateway.online ? "All zones OK" : "PC link DOWN"));
  }

  // 4) Commands: D = disarm request; A/B/C invalid here
  if (key == 'D') { disarmRequested = true; disarmRequestAt = millis(); showMsg("Disarm request", "Card + PIN, #"); }
  else if (key == 'A' || key == 'B' || key == 'C') rejectInput("Key not valid armed");      // T08

  Role r = pollAuth(key);
  if (r == R_NONE) return;
  if (disarmRequested) {
    sessionRole = r;
    goTo(S_WAIT_AUTH, String(ROLE_NAMES[r]) + " disarmed");
  } else if (r == R_MAINTENANCE) {                                              // T11
    sessionRole = r;
    goTo(S_MAINTENANCE, "maintenance login");
  } else {
    showMsg("Already armed", "D first=disarm");
  }
}

void handleIntrusion(char key) {
  setScreen("!! INTRUSION !!", "Card+PIN to ack");
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].eventPending) { zones[i].eventPending = false; logEvent("SENSOR", "Motion during intrusion", zones[i].name, "-", 2); }
  if (key >= 'A' && key <= 'D') rejectInput("Key not valid now");
  Role r = pollAuth(key);                                     // same lockout rules as any login
  if (r != R_NONE) {
    sessionRole = r;
    logEvent("ALERT", "Intrusion acknowledged", "-", "ACK", 2);
    goTo(S_RECOVERY, "intrusion acknowledged");
  }
}

void handleTamperFault(char key) {
  bool isTamper = faultReason.indexOf("tamper") >= 0 || faultReason.indexOf("Lid") >= 0;
  setScreen(isTamper ? "!! TAMPER  P3 !!" : "!! FAULT   P3 !!", faultReason);
  if (millis() - lastFaultReminder > FAULT_REMINDER_MS) {
    lastFaultReminder = millis();
    logEvent("FAULT", "Condition persists: " + faultReason);
  }
  for (uint8_t i = 0; i < ZONE_COUNT; i++)                    // keep watching zones that work
    if (zones[i].eventPending) {
      zones[i].eventPending = false;
      if (zones[i].health == H_OK) logEvent("SENSOR", "Motion during fault", zones[i].name, "-", 3);
    }
  if (key >= 'A' && key <= 'D') rejectInput("Key not valid now");
  Role r = pollAuth(key);
  if (r == R_MAINTENANCE) {                                   // only MAINTENANCE may clear
    sessionRole = r;
    logEvent("FAULT", "Clear requested", "-", "OK");
    goTo(S_RECOVERY, "maintenance clear");
  } else if (r == R_OPERATOR) {
    logEvent("FAULT", "Clear attempt by operator", "-", "DENIED", 3, R_OPERATOR);
    showMsg("Access denied", "Needs MAINTENANCE");
  }
}

void handleMaintenance(char key) {
  uint32_t left = notYet(maintUntil) ? (maintUntil - millis()) / 1000 : 0;
  String st = "";
  for (uint8_t i = 0; i < ZONE_COUNT; i++) {
    if (!zones[i].enabled) continue;
    const char* h = zones[i].health == H_OK ? "OK" : zones[i].health == H_STUCK ? "STK" : "WUP";
    st += "Z" + String(zones[i].id) + ":" + h + " ";
  }
  st += gateway.online ? "PC" : "--";
  setScreen("MAINT " + String(left) + "s", maintShowStatus ? st : "1Tst 2Sts 3Log C");
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].eventPending) { zones[i].eventPending = false; logEvent("MAINT", "Test trigger", zones[i].name); }

  if (!notYet(maintUntil)) { logEvent("MAINT", "Session timed out"); goTo(S_RECOVERY, "maintenance timeout"); return; }
  if (!key) return;
  switch (key) {
    case '1': outputTestUntil = millis() + 1500; logEvent("MAINT", "Output test", "-", "OK"); break;
    case '2': maintShowStatus = !maintShowStatus; logEvent("MAINT", "Status view", "-", "OK"); break;
    case '3': dumpLogToSerial(); showMsg("Log sent to", "USB serial"); logEvent("MAINT", "Log exported", "-", "OK"); break;
    case 'C': logEvent("MAINT", "Maintenance ended", "-", "OK"); goTo(S_RECOVERY, "maintenance exit"); break;
    default:  rejectInput("Unknown command"); break;                            // T08
  }
}

void handleRecovery() {
  setScreen("RECOVERY", "Revalidating...");
  if (millis() - stateEnteredAt < 1500) return;               // visible pause; PIRs settle
  if (selfTest()) {
    logEvent("TEST", "Recovery self-test OK", "-", "PASS");
    goTo(S_MONITORING, "revalidated");                        // T12
  } else {
    logEvent("TEST", "Recovery self-test FAILED: " + selfTestReason, "-", "FAIL", 3);
    goTo(S_TAMPER_FAULT, selfTestReason);
  }
}

// =====================================================================
//  LCD RENDER
// =====================================================================
void renderLcd() {
  String l1 = screen1, l2 = screen2;
  if (authInProgress()) {
    l1 = auth.haveCard ? "Card read" : "PIN only";
    l2 = "PIN: ";
    for (unsigned i = 0; i < auth.pin.length(); i++) l2 += '*';     // never show digits
  }
  if (lockoutRemainingS > 0 && state != S_BOOT) l2 = "Locked " + String(lockoutRemainingS) + "s";
  if (notYet(msgUntil)) { l1 = msg1; l2 = msg2; }
  display.show(l1, l2);
}

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
  pinMode(PIN_LED_GREEN, OUTPUT); pinMode(PIN_LED_RED, OUTPUT); pinMode(PIN_LED_YELLOW, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);    digitalWrite(PIN_BUZZER, BUZZER_ACTIVE_LOW ? HIGH : LOW);
  for (uint8_t i = 0; i < ZONE_COUNT; i++) zones[i].begin();
  tamper.begin();

  // Persistent values (validated: corrupted data is ignored)
  prefs.begin("pids", false);
  bootNo            = prefs.getUInt("boot", 0) + 1;  prefs.putUInt("boot", bootNo);
  failedAttempts    = prefs.getUChar("failed", 0);
  lockoutLevel      = min((int)prefs.getUChar("lockLvl", 0), (int)MAX_LOCKOUT_LEVEL);
  lockoutRemainingS = prefs.getUInt("lockRem", 0);
  savedState        = prefs.getUChar("state", S_WAIT_AUTH);
  if (savedState >= STATE_COUNT) savedState = S_TAMPER_FAULT;     // unknown value: fail closed
  savedReason       = prefs.getString("reason", "");
  lastLockTick      = millis();

  fsOk = LittleFS.begin(true);
  Wire.begin(PIN_SDA, PIN_SCL);
  display.begin();
  rfid.begin();
  gateway.begin();
  startWatchdog(WOKWI_SIM ? 20000 : 5000);   // sim: MQTT connect can take a few seconds

  Serial.printf("\nBoard 1 controller, MAC %s\n", WiFi.macAddress().c_str());
  logEvent("SYSTEM", String("Boot #") + bootNo + " reason=" + resetReasonName(esp_reset_reason()) +
                     " saved=" + stateName(savedState));                                       // T10
  if (!fsOk)           logEvent("SYSTEM", "Log storage unavailable", "-", "ERROR");
  if (!display.online) logEvent("COMM", "LCD not found at boot");
  if (!rfid.online)    logEvent("COMM", "RFID reader not found at boot");
  if (lockoutRemainingS > 0) logEvent("AUTH", "Lockout restored after reboot: " + String(lockoutRemainingS) + " s");
  stateEnteredAt = millis();
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
    if (rfid.check())    logEvent("COMM", rfid.online ? "RFID reader online" : "RFID reader OFFLINE - PIN-only operator login");
    if (display.check()) logEvent("COMM", display.online ? "LCD online" : "LCD OFFLINE - LEDs and buzzer only");
  }
  tickLockout();
  gateway.loop(now);

  // Tamper overrides every state except BOOT (self-test / restore handles it),
  // MAINTENANCE (lid may be opened; re-checked on exit) and TAMPER_FAULT.      T07
  if (tamper.isOpen() && state != S_BOOT && state != S_MAINTENANCE && state != S_TAMPER_FAULT)
    goTo(S_TAMPER_FAULT, "Enclosure tamper");

  switch (state) {
    case S_BOOT:         handleBoot();            break;
    case S_WAIT_AUTH:    handleWaitAuth(key);     break;
    case S_MONITORING:   handleMonitoring(key);   break;
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
