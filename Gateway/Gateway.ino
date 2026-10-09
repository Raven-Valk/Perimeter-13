// =====================================================================
//  PINNACLE 1 — PROJECT 13 — SECURE PERIMETER INTRUSION DETECTION
//  GATEWAY  —  ESP32 DevKit V1 30-pin  —  firmware v5
//
//  The control box. Runs on a power adapter; talks by radio (ESP-NOW) to
//  Sensor Module A, Sensor Module B and the PC dongle.
//
//  What it does:
//    * Card + PIN on its own RFID reader and keypad, then a menu:
//        1 Arm   2 Disarm   3 Acknowledge alarm      (OPERATOR or MAINTENANCE)
//        4 Maintenance  5 Clear tamper  6 End maint  (4 and 5: MAINTENANCE only)
//      3 wrong card/PIN tries lock the keypad (60, 120, 240 s...).
//    * PC dashboard: user name + password login (challenge-response, the
//      password never travels), 5-min idle session, own lockout. A PC command
//      has priority over a keypad entry in progress.
//    * Sends each command to the modules, collects their answers and shows
//      them ("A:OK B:Lid open"). The modules check role and state again.
//    * Keeps one event log for the whole system (its own events + every line
//      from both modules), fetches lines the modules sent while the radio
//      dropped, and gives the PC any lines it missed.
//    * Relays status (its own + both modules) to the PC every second and
//      gives the modules the real time once the PC has sent it.
//    * Its own tamper switch: lid opened -> P3, and the gateway refuses all
//      commands until a MAINTENANCE card + PIN (or PC admin) clears it.
//
//  Libraries: MFRC522 (GithubCommunity), Keypad (Mark Stanley / Alexander
//  Brevig), LiquidCrystal I2C (Frank de Brabander), PubSubClient (Wokwi only).
//  Board: "ESP32 Dev Module".
// =====================================================================

// ---------------- THE SETTINGS YOU CHANGE ----------------
#define WOKWI_SIM    0   // 1 = Wokwi simulator: MQTT instead of ESP-NOW, Wokwi's preset RFID cards.
#define ENROLL_MODE  0   // 1 = print full card UIDs on Serial (to fill secrets.h). Keep 0 for the demo.
#define ALLOW_UNENCRYPTED 0  // 0 = a radio link is only used once it is encrypted (MACs set in secrets.h).
                             // 1 = also use links without MACs (signed but readable). Setup/testing only.

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

// The Arduino IDE / Wokwi auto-insert function prototypes above the first
// function in the sketch. Declare our own types before that point.
enum GwState : uint8_t;
struct PeerLink;
struct RxItem;
struct CardUser;
struct PcUser;
struct ModuleView;

#include "link_protocol.h"
struct CardUser { const char* name; uint8_t uid[10]; uint8_t uidLen; const char* pinHashHex; Role role; };
struct PcUser   { const char* name; const char* pwHashHex; Role role; };
#include "secrets.h"

// =====================================================================
//  PINS — ESP32 DevKit V1 30-pin. RFID, keypad and LCD as on Board 1 before.
//  LEDs on 2 (also the on-board LED), 16 and 17.
// =====================================================================
const uint8_t PIN_SDA = 21, PIN_SCL = 22;                        // LCD I2C
const uint8_t PIN_RFID_SCK = 18, PIN_RFID_MISO = 19;             // RC522 SPI
const uint8_t PIN_RFID_MOSI = 23, PIN_RFID_SS = 5;               // RC522 RST wired to 3.3 V
byte KP_ROWS[4] = { 13, 14, 27, 26 };                            // keypad pins 1-4
byte KP_COLS[4] = { 25, 33, 32, 4 };                             // keypad pins 5-8
const uint8_t PIN_LED_GREEN  = 2;
const uint8_t PIN_LED_YELLOW = 16;    // RX2
const uint8_t PIN_LED_RED    = 17;    // TX2
const uint8_t PIN_TAMPER     = 39;    // VN. + 2.2k pull-up; reed switch to GND

const uint8_t TAMPER_CLOSED_LEVEL = LOW;   // lid shut = LOW; lid open OR wire cut = HIGH
const uint8_t LCD_ADDR            = 0x27;  // try 0x3F if the LCD stays blank

// =====================================================================
//  TIMING / LIMITS
// =====================================================================
const uint32_t LOOP_MS             = 20;
const uint32_t STATUS_EVERY_MS     = 1000;
const uint32_t LINK_TIMEOUT_MS     = WOKWI_SIM ? 8000 : 3000;
const uint32_t TAMPER_DEBOUNCE_MS  = 60;
const uint8_t  MAX_ATTEMPTS        = 3;
const uint32_t BASE_LOCKOUT_S      = 60;      // 60, 120, 240, 480, 960
const uint8_t  MAX_LOCKOUT_LEVEL   = 4;
const uint32_t PIN_TIMEOUT_MS      = 30000;   // card tapped -> PIN must follow within this
const uint32_t MENU_TIMEOUT_MS     = 20000;   // menu closes after this without a key
const uint32_t CMD_RETRY_MS        = WOKWI_SIM ? 2500 : 700;
const uint32_t CMD_DEADLINE_MS     = WOKWI_SIM ? 9000 : 3000;
const uint8_t  CMD_TRIES           = 3;
const uint32_t SESSION_IDLE_MS     = 5UL * 60 * 1000;
const uint32_t SESSION_MAX_MS      = 30UL * 60 * 1000;
const uint32_t LOGIN_CHALLENGE_MS  = 30000;
const uint32_t TIME_RESYNC_MS      = 10UL * 60 * 1000;
const uint32_t PERIPH_CHECK_MS     = 5000;
const uint32_t MSG_SHOW_MS         = 2000;
const uint32_t RESULT_SHOW_MS      = 3500;
const size_t   LOG_MAX_BYTES       = 400 * 1024;   // x2 files: the last ~5,000 lines
const uint16_t RESEND_MAX_LINES    = 3000;
const uint32_t RESEND_IDLE_MS      = WOKWI_SIM ? 10000 : 3000;   // a module's re-send is over after this quiet time
const uint8_t  MOD_RESEND_TRIES    = 3;
const uint16_t LINE_WIN            = 1024;         // per module: which of its last 1024 lines are stored

// =====================================================================
//  GATEWAY STATE
// =====================================================================
enum GwState : uint8_t { GS_BOOT, GS_READY, GS_TAMPER };
const char* GW_STATE_NAMES[] = { "BOOT", "READY", "GW_TAMPER" };
const char* gwStateName(uint8_t s) { return s < 3 ? GW_STATE_NAMES[s] : "INVALID"; }
GwState  gwState = GS_BOOT;
String   tamperReason = "";

// forward declarations (default arguments live here only)
void logEvent(const char* type, const String& event, const char* zone = "-",
              const char* result = "-", int prio = -1, const String& user = "-");
void showMsg(const String& l1, const String& l2, uint32_t ms = MSG_SHOW_MS);
uint8_t systemPriority();

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
//  RFID READER  (RST tied to 3.3 V; the library does a soft reset)
// =====================================================================
class RfidReader {
public:
  RfidReader() : reader(PIN_RFID_SS, MFRC522::UNUSED_PIN) {}
  void begin() {
    SPI.begin(PIN_RFID_SCK, PIN_RFID_MISO, PIN_RFID_MOSI, PIN_RFID_SS);
    reader.PCD_Init();
    online = healthy();
  }
  bool healthy() {                           // 0x00 / 0xFF = nothing answering
    byte v = reader.PCD_ReadRegister(MFRC522::VersionReg);
    return v != 0x00 && v != 0xFF;
  }
  bool check() {                             // true when online/offline changes
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
//  PERSISTENT STORAGE (NVS) + LOCKOUT COUNTERS
// =====================================================================
Preferences prefs;
uint32_t bootNo = 0, gwNo = 0;

// One lockout counter (keypad and PC have one each). Survives restarts.
class Lockout {
public:
  Lockout(const char* prefix_, const char* name_) : prefix(prefix_), name(name_) {}
  void load() {
    failed    = prefs.getUChar(key("F").c_str(), 0);
    level     = min((int)prefs.getUChar(key("L").c_str(), 0), (int)MAX_LOCKOUT_LEVEL);
    remaining = prefs.getUInt(key("R").c_str(), 0);
    lastTick  = millis();
    if (remaining) logEvent("AUTH", String(name) + " lockout restored: " + String(remaining) + " s");
  }
  bool locked() const { return remaining > 0; }
  uint8_t triesLeft() const { return MAX_ATTEMPTS - failed; }
  void tick() {
    if (!remaining || millis() - lastTick < 1000) return;
    lastTick += 1000;
    remaining--;
    if (remaining % 5 == 0) save();
    if (!remaining) logEvent("AUTH", String(name) + " lockout ended");
  }
  void success() { failed = 0; level = 0; save(); }
  uint32_t fail() {                          // returns the lockout length started, or 0
    failed++;
    uint32_t started = 0;
    if (failed >= MAX_ATTEMPTS) {
      remaining = BASE_LOCKOUT_S << level;
      if (level < MAX_LOCKOUT_LEVEL) level++;
      failed = 0;
      lastTick = millis();
      started = remaining;
      logEvent("AUTH", String(name) + " locked " + String(remaining) + " s", "-", "LOCKED", 1);
    }
    save();
    return started;
  }
  uint32_t remaining = 0;
private:
  const char* prefix;
  const char* name;
  uint8_t  failed = 0, level = 0;
  uint32_t lastTick = 0;
  String key(const char* s) const { return String(prefix) + s; }
  void save() {
    prefs.putUChar(key("F").c_str(), failed);
    prefs.putUChar(key("L").c_str(), level);
    prefs.putUInt(key("R").c_str(), remaining);
  }
};
Lockout kpLock("kp", "Keypad");
Lockout pcLock("pc", "PC login");

// Real time, once the PC has sent it (0 = not known yet)
bool     timeSynced = false;
uint32_t timeBase = 0, timeBaseMs = 0;
uint32_t unixNow() { return timeSynced ? timeBase + (millis() - timeBaseMs) / 1000 : 0; }

// =====================================================================
//  RADIO LINKS: Module A, Module B, PC dongle
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
  uint32_t       lastKick = 0;     // last HELLO sent to nudge a restarted module
  PeerLink(uint8_t n, const char* nm, const uint8_t* m, const uint8_t* k) : node(n), name(nm), mac(m), key(k) {}
};
PeerLink linkA (NODE_MOD_A,  "Module A", MAC_MOD_A,  KEY_A_GW);
PeerLink linkB (NODE_MOD_B,  "Module B", MAC_MOD_B,  KEY_B_GW);
PeerLink linkPc(NODE_DONGLE, "PC",       MAC_DONGLE, KEY_GW_PC);
PeerLink* const LINKS[3] = { &linkA, &linkB, &linkPc };
PeerLink* linkFor(uint8_t node) {
  for (PeerLink* L : LINKS) if (L->node == node) return L;
  return nullptr;
}

// Which of a module's recent log lines the gateway has stored (a ring of bits),
// so a line is never stored twice and missing ones can be asked for again.
struct LineWindow {
  uint32_t base = 1;                       // first line number in the window
  uint8_t  bits[LINE_WIN / 8] = {};
  bool has(uint32_t n) const {             // older than the window counts as "have"
    if (n < base) return true;
    if (n >= base + LINE_WIN) return false;
    uint16_t i = n % LINE_WIN;
    return bits[i >> 3] & (1 << (i & 7));
  }
  void mark(uint32_t n) {
    if (n < base) return;
    if (n >= base + LINE_WIN) {            // slide forward; freed slots are cleared
      uint32_t newBase = n - LINE_WIN + 1;
      if (newBase - base >= LINE_WIN) memset(bits, 0, sizeof(bits));
      else for (uint32_t k = base; k < newBase; k++) { uint16_t i = k % LINE_WIN; bits[i >> 3] &= ~(1 << (i & 7)); }
      base = newBase;
    }
    uint16_t i = n % LINE_WIN;
    bits[i >> 3] |= 1 << (i & 7);
  }
  void reset(uint32_t newBase) { base = newBase ? newBase : 1; memset(bits, 0, sizeof(bits)); }
};

// What the gateway knows about each sensor module
struct ModuleView {
  PeerLink* L;
  char      letter;
  uint8_t   mask;            // 1 = A, 2 = B (for command targets)
  uint8_t   state = 0xFF;          // ModState from its last status
  uint8_t   prio = 0;
  String    status = "";
  bool      seenStatus = false;    // first status since the link came up
  bool      wasArmed = false;
  LineWindow win;                  // which of its recent log lines are stored
  uint32_t  top = 0;               // highest line number it has written (from its lines and status)
  uint32_t  checkedTop = 0;        // top at the previous check: lines get 1 s to arrive by themselves
  bool      reqActive = false;     // a re-send we asked for is running
  uint32_t  reqAt = 0, reqTo = 0, lastReqFrom = 0;
  uint8_t   reqTries = 0;
  uint32_t  savedTop = 0, savedTopAt = 0, savedMiss = 0;
  bool      timeSent = false;
  uint32_t  lastTimeSync = 0;
  ModuleView(PeerLink* l, char c, uint8_t b) : L(l), letter(c), mask(b) {}
};
ModuleView modA(&linkA, 'A', 1);
ModuleView modB(&linkB, 'B', 2);
ModuleView* const MODS[2] = { &modA, &modB };
ModuleView* modFor(uint8_t node) { return node == NODE_MOD_A ? &modA : node == NODE_MOD_B ? &modB : nullptr; }

bool modOnline(const ModuleView& m) { return m.L->trk.online; }
bool anyModIn(uint8_t s) { for (ModuleView* m : MODS) if (modOnline(*m) && m->state == s) return true; return false; }
bool bothIn(uint8_t s)   { for (ModuleView* m : MODS) if (!modOnline(*m) || m->state != s) return false; return true; }

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
  rxQueue = xQueueCreate(24, sizeof(RxItem));
  for (PeerLink* L : LINKS) L->macSet = macIsSet(L->mac);
#if WOKWI_SIM
  WiFi.mode(WIFI_STA);
  WiFi.begin("Wokwi-GUEST", "", 6);
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
  for (PeerLink* L : LINKS) addEncryptedPeer(*L);   // on failure that link uses signed broadcast
  esp_now_peer_info_t bc = {};
  memcpy(bc.peer_addr, BROADCAST, 6);
  bc.channel = ESPNOW_CHANNEL;
  bc.ifidx   = WIFI_IF_STA;
  bc.encrypt = false;
  esp_now_add_peer(&bc);
  radioReady = true;
#endif
}

void linkSend(PeerLink& L, uint8_t type, uint8_t code, uint8_t role, uint8_t result,
              uint32_t arg, uint32_t no, const char* text, uint32_t session, uint8_t target) {
  if (!radioReady || !linkUsable(L)) return;
  LinkPacket p = {};
  p.version = LINK_VERSION; p.src = NODE_GATEWAY; p.dst = L.node; p.type = type;
  p.bootId = myBoot; p.seq = ++mySeq;
  p.dstBoot = L.trk.synced ? L.trk.bootId : 0;
  p.logNo = no; p.state = gwState; p.priority = systemPriority(); p.resetReason = myReset;
  p.code = code; p.role = role; p.result = result; p.arg = arg; p.session = session; p.target = target;
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

// =====================================================================
//  SYSTEM EVENT LOG  -> LittleFS + USB serial + PC
//  Every line (gateway's own and the modules') gets a gateway number gw_no.
//  Stored as  gw_no,<line>  where <line> is in the module log format.
// =====================================================================
bool fsOk = false;
uint32_t logRotations = 0;
const char* LOG_HEADER = "gw_no,log_no,boot,uptime_ms,unix_time,module,priority,state,type,event,zone,user,result";

const uint8_t QSIZE = 32;                      // lines waiting to go to the PC
char     pcQ[QSIZE][LINK_TEXT_MAX];
uint32_t pcQNo[QSIZE];
uint8_t  qHead = 0, qCount = 0;

void queuePc(uint32_t no, const String& line) {
  if (qCount == QSIZE) { qHead = (qHead + 1) % QSIZE; qCount--; }   // oldest dropped: the PC asks again
  uint8_t slot = (qHead + qCount) % QSIZE;
  strncpy(pcQ[slot], line.c_str(), LINK_TEXT_MAX - 1);
  pcQ[slot][LINK_TEXT_MAX - 1] = 0;
  pcQNo[slot] = no;
  qCount++;
}

uint32_t nextGwNo() {
  uint32_t no = ++gwNo;
  if (no % 16 == 0) prefs.putUInt("logNo", no);
  return no;
}

void storeLine(uint32_t no, const String& line) {
  Serial.print("LOG,"); Serial.print(no); Serial.print(','); Serial.println(line);
  queuePc(no, line);
  if (!fsOk) return;
  File f = LittleFS.open("/log.csv", FILE_APPEND);
  if (!f) return;
  if (f.size() > LOG_MAX_BYTES) {              // rotate: keep one old file
    f.close();
    LittleFS.remove("/log_old.csv");
    LittleFS.rename("/log.csv", "/log_old.csv");
    logRotations++;
    f = LittleFS.open("/log.csv", FILE_APPEND);
    if (!f) return;
  }
  if (f.size() == 0) f.println(LOG_HEADER);
  f.print(no); f.print(','); f.println(line);
  f.close();
}

void logEvent(const char* type, const String& event, const char* zone,
              const char* result, int prio, const String& user) {
  String ev = event; ev.replace(",", ";"); ev.replace("\n", " ");
  String us = user;  us.replace(",", ";");
  uint32_t no = nextGwNo();
  String line = String(no) + "," + String(bootNo) + "," + String(millis()) + "," + String(unixNow()) +
                ",G,P" + String(prio < 0 ? systemPriority() : prio) + "," + gwStateName(gwState) + "," +
                type + "," + ev + "," + zone + "," + us + "," + result;
  storeLine(no, line);
}

// ---------------- giving the PC lines it missed ----------------
bool     pcResendActive = false;
uint32_t pcResendFrom = 0;
uint8_t  pcResendFile = 0;
size_t   pcResendPos = 0;
uint16_t pcResendSent = 0;
uint32_t pcResendRot = 0;

void startPcResend(uint32_t from) {
  pcResendActive = fsOk; pcResendFrom = from; pcResendFile = 0; pcResendPos = 0; pcResendSent = 0;
  pcResendRot = logRotations;
}

void pcResendStep() {                          // sends at most one line per call
  if (pcResendRot != logRotations) {           // the log rotated: start the scan again
    pcResendRot = logRotations; pcResendFile = 0; pcResendPos = 0;   // (the PC drops lines it already has)
  }
  const char* files[] = { "/log_old.csv", "/log.csv" };
  while (pcResendFile < 2) {
    File f = LittleFS.open(files[pcResendFile], FILE_READ);
    if (!f) { pcResendFile++; pcResendPos = 0; continue; }
    f.seek(pcResendPos);
    for (uint8_t scanned = 0; scanned < 64 && f.available(); scanned++) {
      String line = f.readStringUntil('\n');
      pcResendPos = f.position();
      line.trim();
      uint32_t no = (uint32_t)line.toInt();    // first column = gw_no (header -> 0)
      int comma = line.indexOf(',');
      if (no == 0 || no < pcResendFrom || comma < 0) continue;
      f.close();
      String rest = line.substring(comma + 1);
      linkSend(linkPc, L_LOG, 1, 0, 0, 0, no, rest.c_str(), 0, 0);
      if (++pcResendSent >= RESEND_MAX_LINES) pcResendActive = false;
      return;
    }
    bool more = f.available();
    f.close();
    if (more) return;                          // 64 lines scanned: carry on next time
    pcResendFile++; pcResendPos = 0;
  }
  pcResendActive = false;
}

// At boot: the last gw_no and the last line number of each module in the log
// file, so numbering and "what we already have" carry on exactly.
void scanLogTail(uint32_t& lastGw, uint32_t& lastA, uint32_t& lastB) {
  lastGw = lastA = lastB = 0;
  const char* files[] = { "/log_old.csv", "/log.csv" };
  for (const char* name : files) {
    File f = LittleFS.open(name, FILE_READ);
    if (!f) continue;
    size_t sz = f.size();
    if (sz > 32768) { f.seek(sz - 32768); f.readStringUntil('\n'); }   // skip the cut line
    while (f.available()) {
      String line = f.readStringUntil('\n');
      uint32_t g = (uint32_t)line.toInt();
      if (!g) continue;
      if (g > lastGw) lastGw = g;
      int c = -1;                                                   // fields: gw_no,log_no,boot,uptime,unix,module
      for (int k = 0; k < 5 && (c = line.indexOf(',', c + 1)) >= 0; k++) {}
      int c1 = line.indexOf(',');
      if (c < 0 || c1 < 0 || c + 1 >= (int)line.length()) continue;
      uint32_t ln = (uint32_t)line.substring(c1 + 1).toInt();
      char mod = line[c + 1];
      if (mod == 'A' && ln > lastA) lastA = ln;
      if (mod == 'B' && ln > lastB) lastB = ln;
    }
    f.close();
  }
}

// =====================================================================
//  LINES FROM THE MODULES (with recovery of lines lost on the radio)
// =====================================================================
void saveTop(ModuleView& m) { prefs.putUInt(m.letter == 'A' ? "topA" : "topB", m.top); m.savedTop = m.top; }
void saveMissing(ModuleView& m, uint32_t from) {          // where recovery stands, in case we restart
  if (from == m.savedMiss) return;
  m.savedMiss = from;
  prefs.putUInt(m.letter == 'A' ? "missA" : "missB", from);
}

// First line number in [.., upTo] that we don't have (0 = none missing)
uint32_t lowestMissing(const ModuleView& m, uint32_t upTo) {
  if (!upTo) return 0;
  uint32_t lo = upTo >= LINE_WIN ? upTo - LINE_WIN + 1 : 1;
  if (lo < m.win.base) lo = m.win.base;
  for (uint32_t n = lo; n <= upTo; n++) if (!m.win.has(n)) return n;
  return 0;
}
uint32_t missingRunEnd(const ModuleView& m, uint32_t from, uint32_t upTo) {
  uint32_t n = from;
  while (n < upTo && !m.win.has(n + 1)) n++;
  return n;
}

void onModuleLog(ModuleView& m, const LinkPacket& p) {
  uint32_t n = p.logNo;
  if (p.code == 1 && m.reqActive) {                        // a re-sent line: the re-send is moving
    m.reqAt = millis();
    if (m.reqTo && n >= m.reqTo) m.reqActive = false;
  }
  if (!n || m.win.has(n)) return;                          // already stored: never twice
  m.win.mark(n);
  if (n > m.top) { m.top = n; if (n % 16 == 0) saveTop(m); }
  storeLine(nextGwNo(), textOf(p));
}

void onModuleStatus(ModuleView& m, const LinkPacket& p) {
  m.state = p.state;
  m.prio  = p.priority;
  m.status = textOf(p);
  m.wasArmed = m.state == MS_ARMED || m.state == MS_INTRUSION;
  int i = m.status.indexOf("LOGNO:");
  uint32_t x = i >= 0 ? (uint32_t)m.status.substring(i + 6).toInt() : 0;
  if (!x) return;
  if (!m.seenStatus) {                                      // first status since link up / its restart
    m.seenStatus = true;
    if (x < m.top) {                                        // its numbering went back: flash erased
      logEvent("COMM", String(m.L->name) + " log numbers restarted (flash erased?)");
      m.win.reset(1); m.top = 0; m.checkedTop = 0; m.reqActive = false; m.lastReqFrom = 0; m.reqTries = 0;
    }
  }
  if (m.top && x > m.top + LINE_WIN)
    logEvent("COMM", String(m.L->name) + " log lines " + String(m.top + 1) + "-" + String(x - LINE_WIN) + " too old to fetch", "-", "LOST");
  if (x > m.top) m.top = x;                                 // lines up to x exist: fetch any we miss
}

// =====================================================================
//  COMMANDS: from the keypad (card + PIN) or the PC (logged-in session)
//  Sent to each target module, which answers OK / REFUSED / DENIED.
// =====================================================================
struct PendingCmd {
  bool     active = false;
  uint32_t id = 0;                 // the same on every retry, so a module never runs it twice
  uint8_t  cmd = 0, role = 0, targets = 0, done = 0;
  uint32_t arg = 0, pcSeq = 0, deadline = 0;
  bool     fromPc = false;
  String   who = "";
  uint8_t  res[2] = {};
  String   why[2];
  uint32_t firstSeq[2] = {}, lastSeq[2] = {}, nextTry[2] = {};
  uint8_t  tries[2] = {};
} pend;

uint32_t cmdCounter = 0;
uint32_t pcSessionId();

uint32_t sendModuleCmd(ModuleView& m, uint8_t cmd, uint8_t role, uint32_t arg, const String& who, uint32_t id, uint32_t to) {
  linkSend(*m.L, L_CMD, cmd, role, 0, arg, id, who.c_str(), to, 0);
  return mySeq;
}

// A PC command that arrives while a keypad command is still running waits
// for it (at most a few seconds), then runs: the PC goes next, ahead of the keypad.
struct {
  bool     active = false;
  uint8_t  cmd = 0, target = 0, role = 0;
  uint32_t arg = 0, seq = 0, sessionId = 0;
  String   who = "";
} pcWait;
bool pcSessionStill(uint32_t id);
void runCommand(uint8_t cmd, uint8_t target, uint8_t role, const String& who, uint32_t arg, bool fromPc, uint32_t pcSeq);

bool pendTargets(const ModuleView& m) { return pend.active && (pend.targets & m.mask); }

const char* cmdShort(uint8_t c) {               // short names for the 16-character LCD
  switch (c) {
    case CMD_ARM: return "ARM";          case CMD_DISARM: return "DISARM";
    case CMD_ACK_ALARM: return "ACK";    case CMD_MAINT_START: return "MAINT";
    case CMD_MAINT_END: return "END";    case CMD_CLEAR_FAULT: return "CLEAR";
    case CMD_SET_TIME: return "TIME";    case CMD_RESEND_LOG: return "RESEND";
    default: return "CMD";
  }
}

// Final answer: to the log, the LCD, and the PC if it asked.
void report(bool fromPc, uint32_t pcSeq, uint8_t cmd, uint8_t res, const String& text, const String& who) {
  String msg = cmdName(cmd);
  if (text.length()) { msg += ": "; msg += text; }
  logEvent("CMD", msg, "-", resultName(res), -1, who);
  if (fromPc) linkSend(linkPc, L_CMD_RESULT, cmd, 0, res, pcSeq, 0, text.c_str(), 0, 0);
  String l1 = fromPc ? String("PC ") : String("");
  l1 += cmdShort(cmd);
  l1 += res == RES_OK ? " OK" : " FAILED";
  showMsg(l1, text, RESULT_SHOW_MS);
}

void finishPending(const String& extra) {
  String text = "";
  uint8_t overall = RES_OK;
  for (uint8_t i = 0; i < 2; i++) {
    ModuleView& m = *MODS[i];
    if (!(pend.targets & m.mask)) continue;
    String r;
    if (pend.done & m.mask) {
      if (pend.res[i] == RES_OK) r = "OK";
      else { r = pend.why[i].length() ? pend.why[i] : String(resultName(pend.res[i])); if (overall == RES_OK) overall = pend.res[i]; }
    } else {
      r = "no reply";
      if (overall == RES_OK) overall = RES_REFUSED;
    }
    text += String(m.letter) + ":" + r + " ";
  }
  text += extra;
  text.trim();
  pend.active = false;
  report(pend.fromPc, pend.pcSeq, pend.cmd, overall, text, pend.who);
  if (pcWait.active) {                                      // the PC command that was waiting
    pcWait.active = false;
    if (pcSessionStill(pcWait.sessionId))
      runCommand(pcWait.cmd, pcWait.target, pcWait.role, pcWait.who, pcWait.arg, true, pcWait.seq);
    else
      report(true, pcWait.seq, pcWait.cmd, RES_DENIED, "Session ended before it ran", pcWait.who);
  }
}

void pendingStep() {
  if (!pend.active) return;
  uint32_t now = millis();
  for (uint8_t i = 0; i < 2; i++) {
    ModuleView& m = *MODS[i];
    if (!(pend.targets & m.mask) || (pend.done & m.mask)) continue;
    if (!modOnline(m)) { pend.res[i] = RES_REFUSED; pend.why[i] = "offline"; pend.done |= m.mask; continue; }
    if (pend.tries[i] < CMD_TRIES && !notYet(pend.nextTry[i])) {     // radio can drop one: try again
      uint32_t s = sendModuleCmd(m, pend.cmd, pend.role, pend.arg, pend.who, pend.id, 0);
      if (!pend.tries[i]) pend.firstSeq[i] = s;
      pend.lastSeq[i] = s;
      pend.tries[i]++;
      pend.nextTry[i] = now + CMD_RETRY_MS;
    }
  }
  if ((pend.done & pend.targets) == pend.targets || !notYet(pend.deadline)) finishPending("");
}

void onModuleCmdResult(ModuleView& m, const LinkPacket& p) {
  uint8_t i = m.letter == 'A' ? 0 : 1;
  uint32_t s = p.arg;
  if (!pendTargets(m) || (pend.done & m.mask) || p.code != pend.cmd) return;
  if (s < pend.firstSeq[i] || s > pend.lastSeq[i]) return;   // answer to something else
  pend.res[i] = p.result;
  pend.why[i] = textOf(p);
  pend.done |= m.mask;
}

uint8_t roleNeeded(uint8_t cmd) {               // 0xFF = unknown command
  switch (cmd) {
    case CMD_ARM: case CMD_DISARM: case CMD_ACK_ALARM: case CMD_MAINT_END: return R_OPERATOR;
    case CMD_MAINT_START: case CMD_CLEAR_FAULT:                            return R_MAINTENANCE;
    case CMD_SET_TIME: case CMD_RESEND_LOG: case CMD_LOGOUT:               return R_NONE;
    default:                                                               return 0xFF;
  }
}

void enterTamper(const String& why) {
  if (gwState == GS_TAMPER) return;
  gwState = GS_TAMPER;
  tamperReason = why;
  prefs.putBool("tamper", true);
  prefs.putString("reason", why);
  logEvent("TAMPER", "Gateway " + why + " - commands blocked", "-", "-", 3);   // T07
  if (pend.active) finishPending("(gateway tamper: result unknown)");
}

void clearGatewayTamper(const String& who, bool fromPc, uint32_t pcSeq) {
  if (gwState != GS_TAMPER) { report(fromPc, pcSeq, CMD_CLEAR_FAULT, RES_REFUSED, "No gateway tamper", who); return; }
  if (tamper.isOpen())      { report(fromPc, pcSeq, CMD_CLEAR_FAULT, RES_REFUSED, "Gateway lid open", who); return; }
  gwState = GS_READY;
  prefs.putBool("tamper", false);
  report(fromPc, pcSeq, CMD_CLEAR_FAULT, RES_OK, "Gateway tamper cleared", who);
}

void runCommand(uint8_t cmd, uint8_t target, uint8_t role, const String& who, uint32_t arg, bool fromPc, uint32_t pcSeq) {
  uint8_t need = roleNeeded(cmd);
  if (need == 0xFF || cmd == CMD_LOGOUT) { report(fromPc, pcSeq, cmd, RES_BAD, "Unknown command", who); return; }
  if (role > R_MAINTENANCE || role < need) { report(fromPc, pcSeq, cmd, RES_DENIED, String("Needs ") + roleName(need), who); return; }

  // ---- handled by the gateway itself ----
  if (cmd == CMD_SET_TIME) {
    if (arg < 1600000000UL) { report(fromPc, pcSeq, cmd, RES_BAD, "Bad time", who); return; }
    bool first = !timeSynced;
    timeSynced = true; timeBase = arg; timeBaseMs = millis();
    for (ModuleView* m : MODS) m->timeSent = false;          // pass it on to the modules
    if (first) logEvent("SYSTEM", "Real time received from " + who);
    if (fromPc) linkSend(linkPc, L_CMD_RESULT, cmd, 0, RES_OK, pcSeq, 0, "Time set", 0, 0);
    return;
  }
  if (cmd == CMD_RESEND_LOG) {
    startPcResend(arg);
    if (fromPc) linkSend(linkPc, L_CMD_RESULT, cmd, 0, fsOk ? RES_OK : RES_REFUSED, pcSeq, 0,
                         fsOk ? "Resending" : "No log storage", 0, 0);
    return;
  }
  if (target == NODE_GATEWAY) {
    if (cmd == CMD_CLEAR_FAULT) clearGatewayTamper(who, fromPc, pcSeq);
    else report(fromPc, pcSeq, cmd, RES_BAD, "Not a gateway command", who);
    return;
  }

  // ---- sent to the modules ----
  if (gwState == GS_TAMPER) { report(fromPc, pcSeq, cmd, RES_REFUSED, "Gateway tamper: clear it first", who); return; }
  if (gwState == GS_BOOT)   { report(fromPc, pcSeq, cmd, RES_REFUSED, "Gateway starting", who); return; }
  uint8_t targets = target == TARGET_BOTH ? 3 : target == NODE_MOD_A ? 1 : target == NODE_MOD_B ? 2 : 0;
  if (!targets) { report(fromPc, pcSeq, cmd, RES_BAD, "Unknown target", who); return; }
  if (pend.active) {
    if (fromPc && !pend.fromPc && !pcWait.active) {          // PC goes next, right after the keypad command
      pcWait.active = true; pcWait.cmd = cmd; pcWait.target = target; pcWait.role = role;
      pcWait.arg = arg; pcWait.seq = pcSeq; pcWait.who = who;
      pcWait.sessionId = pcSessionId();
      return;
    }
    report(fromPc, pcSeq, cmd, RES_REFUSED, "Busy, try again", who);
    return;
  }
  pend.active = true; pend.id = ++cmdCounter; pend.cmd = cmd; pend.role = role; pend.arg = arg; pend.who = who;
  pend.fromPc = fromPc; pend.pcSeq = pcSeq; pend.targets = targets; pend.done = 0;
  pend.deadline = millis() + CMD_DEADLINE_MS;
  for (uint8_t i = 0; i < 2; i++) { pend.res[i] = 0; pend.why[i] = ""; pend.tries[i] = 0; pend.nextTry[i] = 0; pend.firstSeq[i] = pend.lastSeq[i] = 0; }
  logEvent("CMD", String(cmdName(cmd)) + " sent to " + (targets == 3 ? "A+B" : targets == 1 ? "A" : "B"), "-", "SENT", -1, who);
  pendingStep();
}

// =====================================================================
//  PC LOGIN + SESSION
// =====================================================================
struct {
  bool     pending = false;
  String   user = "";
  uint8_t  nonce[16] = {};
  uint32_t until = 0, lastReq = 0;
} chal;

struct {
  bool     active = false;
  uint32_t id = 0;
  String   user = "";
  Role     role = R_NONE;
  uint32_t lastUse = 0, started = 0;
} sess;

bool pcSessionStill(uint32_t id) { return id && sess.active && sess.id == id; }
uint32_t pcSessionId() { return sess.active ? sess.id : 0; }

void sendLoginResult(uint8_t res, uint8_t role, uint32_t sid, const String& msg) {
  linkSend(linkPc, L_LOGIN_RESULT, 0, role, res, 0, 0, msg.c_str(), sid, 0);
}

const PcUser* findPcUser(const String& u) {
  for (uint8_t i = 0; i < PC_USER_COUNT; i++) if (u == PC_USERS[i].name) return &PC_USERS[i];
  return nullptr;
}

void endSession(const String& why, bool notifyPc) {
  if (!sess.active) return;
  logEvent("AUTH", "PC session ended (" + why + ")", "-", "-", -1, sess.user + "@PC");
  sess.active = false;
  sess.id = 0;                                     // a PC command still waiting won't run now
  if (notifyPc && linkPc.trk.online) sendLoginResult(RES_DENIED, R_NONE, 0, "Session ended: " + why);
}

void onLoginReq(const LinkPacket& p) {
  if (millis() - chal.lastReq < 1000) return;              // one challenge per second at most
  chal.lastReq = millis();
  if (pcLock.locked()) { sendLoginResult(RES_DENIED, R_NONE, 0, "Locked " + String(pcLock.remaining) + " s"); return; }
  String u = textOf(p);
  u.trim();
  if (u.length() > 31) u = u.substring(0, 31);
  esp_fill_random(chal.nonce, sizeof(chal.nonce));         // unknown users get a challenge too:
  chal.user = u;                                           // the reply doesn't reveal valid names
  chal.pending = true;
  chal.until = millis() + LOGIN_CHALLENGE_MS;
  String hx = toHex(chal.nonce, sizeof(chal.nonce));
  linkSend(linkPc, L_LOGIN_CHAL, 0, 0, 0, 0, 0, hx.c_str(), 0, 0);
}

void onLoginResp(const LinkPacket& p) {
  String t = textOf(p);
  int c = t.lastIndexOf(':');
  String u  = c > 0 ? t.substring(0, c) : String("");
  String hx = c > 0 ? t.substring(c + 1) : String("");
  if (pcLock.locked()) { sendLoginResult(RES_DENIED, R_NONE, 0, "Locked " + String(pcLock.remaining) + " s"); return; }

  const PcUser* pu = nullptr;
  bool ok = false;
  if (chal.pending && notYet(chal.until) && u == chal.user) {
    pu = findPcUser(u);
    uint8_t got[32], key[32];
    if (pu && fromHex(hx, got, 32) && fromHex(String(pu->pwHashHex), key, 32)) {
      uint8_t msg[16 + 32];
      size_t ul = min((size_t)u.length(), (size_t)32);
      memcpy(msg, chal.nonce, 16);
      memcpy(msg + 16, u.c_str(), ul);
      uint8_t exp[32];
      hmacSha256(key, 32, msg, 16 + ul, exp);
      ok = sameBytes(exp, got, 32);
    }
  }
  chal.pending = false;                                    // every challenge is single-use
  String who = (u.length() ? u : String("?")) + "@PC";

  if (ok) {
    pcLock.success();
    if (sess.active) endSession("new login", false);     // the new login's answer follows
    sess.active = true; sess.id = esp_random() | 1; sess.user = u; sess.role = pu->role;
    sess.lastUse = sess.started = millis();
    logEvent("AUTH", String("PC login (") + roleName(pu->role) + ")", "-", "SUCCESS", -1, who);
    sendLoginResult(RES_OK, pu->role, sess.id, "Welcome " + u);
    showMsg("PC login", u);
    return;
  }
  uint32_t lockS = pcLock.fail();
  logEvent("AUTH", "PC login failed", "-", "FAIL", -1, who);
  if (lockS) sendLoginResult(RES_DENIED, R_NONE, 0, "Locked " + String(lockS) + " s");
  else       sendLoginResult(RES_DENIED, R_NONE, 0, "Wrong user or password, " + String(pcLock.triesLeft()) + " tries left");
}

void kpLogout();
bool kpBusy();

void onPcCommand(const LinkPacket& p) {
  uint8_t  cmd = p.code, target = p.target;
  uint32_t arg = p.arg, sid = p.session, seq = p.seq;
  if (cmd == CMD_LOGOUT) {
    bool mine = sess.active && sid == sess.id;
    if (mine) endSession("logout", false);
    linkSend(linkPc, L_CMD_RESULT, cmd, 0, mine ? RES_OK : RES_REFUSED, seq, 0, mine ? "Logged out" : "No session", 0, 0);
    return;
  }
  bool needsLogin = !(cmd == CMD_SET_TIME || cmd == CMD_RESEND_LOG);   // read-only / housekeeping
  if (!needsLogin) { runCommand(cmd, target, R_NONE, "PC", arg, true, seq); return; }
  if (!sess.active || sid != sess.id) {
    logEvent("CMD", String(cmdName(cmd)) + " from PC refused: not logged in", "-", "DENIED", -1, "?@PC");
    linkSend(linkPc, L_CMD_RESULT, cmd, 0, RES_DENIED, seq, 0, "Not logged in", 0, 0);
    return;
  }
  sess.lastUse = millis();
  if (kpBusy()) { logEvent("AUTH", "Keypad entry cancelled: PC command has priority"); kpLogout(); }
  runCommand(cmd, target, sess.role, sess.user + "@PC", arg, true, seq);
}

void checkSession() {
  if (!sess.active) return;
  if (!linkPc.trk.online)                          endSession("PC link lost", false);
  else if (millis() - sess.lastUse > SESSION_IDLE_MS) endSession("idle 5 min", true);
  else if (millis() - sess.started > SESSION_MAX_MS)  endSession("30 min limit", true);
}

// =====================================================================
//  PACKETS IN
// =====================================================================
void onLinkUp(PeerLink& L) {
  ModuleView* m = modFor(L.node);
  if (m) { m->seenStatus = false; m->timeSent = false; }
}

void onLinkDown(PeerLink& L) {
  ModuleView* m = modFor(L.node);
  if (m && m->top != m->savedTop) saveTop(*m);
  if (m && m->wasArmed) logEvent("COMM", String(L.name) + " LOST while armed (jammed or destroyed?)", "-", "-", 3);
  else                  logEvent("COMM", String(L.name) + " link DOWN");
  if (m) m->seenStatus = false;
}

void handlePacket(const RxItem& it) {
  LinkPacket p;
  memcpy(&p, it.data, sizeof(p));
  if (!linkWellFormed(p, it.len)) { reject(RJ_MALFORMED, "Malformed packet"); return; }     // T08
  if (p.dst != NODE_GATEWAY) return;               // meant for another board (signed broadcast)
  PeerLink* L = linkFor(p.src);
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
  ModuleView* m = modFor(p.src);
  TrackResult tr = L->trk.accept(p);
  if (tr == TR_UNSYNCED) {                                   // waiting for its HELLO: tell it who we are
    if (m) { L->trk.sendHello = false; linkSend(*L, L_HELLO, 0, 0, 0, unixNow(), 0, nullptr, 0, 0); }
    return;
  }
  if (tr == TR_OLD_BOOT) { reject(RJ_REPLAY, String(L->name) + ": older boot number refused (flash erased? restart the gateway)"); return; }
  if (tr == TR_REPLAY) {
    uint32_t b = p.bootId;
    if (m && b != L->trk.bootId && millis() - L->lastKick > 1000) {   // a module restarted and its HELLO
      L->lastKick = millis();                                         // was lost: nudge it to send another
      linkSend(*L, L_HELLO, 0, 0, 0, unixNow(), 0, nullptr, 0, 0);
    }
    reject(RJ_REPLAY, String(L->name) + ": replayed/old packet");
    return;
  }
  if (tr == TR_NEW_BOOT) {
    logEvent("COMM", String(L->name) + " restarted (" + resetReasonName(p.resetReason) + ")");
    if (m) m->seenStatus = false;                           // re-check its log numbering
    else   endSession("PC dongle restarted", true);
  }
  if (!L->trk.online) {
    L->trk.online = true;
    logEvent("COMM", String(L->name) + " link UP");
    onLinkUp(*L);
  }

  if (m) {
    switch (p.type) {
      case L_HELLO: case L_STATUS:
        onModuleStatus(*m, p);
        {
          bool hello = ++L->beats % 10 == 1 || L->trk.sendHello;
          L->trk.sendHello = false;
          linkSend(*L, hello ? L_HELLO : L_ACK, 0, 0, 0, unixNow(), 0, nullptr, 0, 0);   // "link alive"
        }
        break;
      case L_LOG:        onModuleLog(*m, p); break;
      case L_CMD_RESULT: onModuleCmdResult(*m, p); break;
      default:           reject(RJ_OTHER, String(L->name) + ": unexpected packet type " + String(p.type)); break;
    }
  } else {                                         // the PC dongle
    switch (p.type) {
      case L_HELLO: case L_STATUS: break;          // heartbeat
      case L_LOGIN_REQ:  onLoginReq(p); break;
      case L_LOGIN_RESP: onLoginResp(p); break;
      case L_PC_CMD:     onPcCommand(p); break;
      default:           reject(RJ_OTHER, String("PC: unexpected packet type ") + String(p.type)); break;
    }
  }
}

void checkLinkTimeout(PeerLink& L) {
  if (L.trk.online && (int32_t)(millis() - L.trk.lastHeard) > (int32_t)LINK_TIMEOUT_MS) {
    L.trk.online = false;
    onLinkDown(L);                                                                         // T09
  }
}

// =====================================================================
//  STATUS TO THE PC + HOUSEKEEPING WITH THE MODULES
// =====================================================================
uint32_t lastStatus = 0;

String gwStatusText() {
  String s = String("G,") + gwStateName(gwState) + ",P" + String(systemPriority());
  s += String(",RFID:") + (rfid.online ? "OK" : "OFFLINE");
  s += String(",LCD:") + (display.online ? "OK" : "OFFLINE");
  s += String(",LID:") + (tamper.isOpen() ? "OPEN" : "SHUT");
  s += String(",USER:") + (sess.active ? sess.user : String("-"));
  s += String(",TIME:") + (timeSynced ? "Y" : "N");
  s += String(",KPLOCK:") + String(kpLock.remaining) + ",PCLOCK:" + String(pcLock.remaining);
  s += String(",LOGNO:") + String(gwNo);
  return s;
}

void sendPcStatus(uint8_t about, const String& text) {
  bool hello = ++linkPc.beats % 10 == 1 || linkPc.trk.sendHello;
  linkPc.trk.sendHello = false;
  linkSend(linkPc, hello ? L_HELLO : L_STATUS, about, 0, 0, unixNow(), 0, text.c_str(), 0, 0);
}

void moduleHousekeeping(ModuleView& m) {
  uint32_t upTo = m.checkedTop;                     // only lines missing for over a second count
  m.checkedTop = m.top;
  if (m.top != m.savedTop && millis() - m.savedTopAt > 5000) { saveTop(m); m.savedTopAt = millis(); }
  saveMissing(m, lowestMissing(m, upTo));
  if (!modOnline(m) || pendTargets(m)) return;      // don't mix with a command waiting for its answer
  uint32_t now = millis();
  if (m.reqActive && now - m.reqAt > RESEND_IDLE_MS) m.reqActive = false;      // re-send over or stalled
  if (!m.reqActive) {
    uint32_t from = lowestMissing(m, upTo);
    if (from) {                                     // ask the module for lines we missed
      uint32_t to = missingRunEnd(m, from, upTo);
      if (from == m.lastReqFrom) m.reqTries++; else { m.lastReqFrom = from; m.reqTries = 1; }
      if (m.reqTries > MOD_RESEND_TRIES) {          // asked 3 times: it doesn't have them
        logEvent("COMM", String(m.L->name) + " log lines " + String(from) + "-" + String(to) + " not received", "-", "LOST");
        for (uint32_t n = from; n <= to; n++) m.win.mark(n);
        m.lastReqFrom = 0; m.reqTries = 0;
        saveTop(m);
      } else {
        sendModuleCmd(m, CMD_RESEND_LOG, R_NONE, from, "gateway", 0, to);
        m.reqActive = true; m.reqAt = now; m.reqTo = to;
      }
      return;
    }
  }
  if (timeSynced && (!m.timeSent || now - m.lastTimeSync > TIME_RESYNC_MS)) {   // pass on the real time
    sendModuleCmd(m, CMD_SET_TIME, R_NONE, unixNow(), "gateway", 0, 0);
    m.timeSent = true;
    m.lastTimeSync = now;
  }
}

void linkLoop() {
  if (!radioReady) return;
  uint32_t now = millis();
#if WOKWI_SIM
  if (WiFi.status() == WL_CONNECTED && !mqtt.connected() && now - lastMqttTry > 5000) {
    lastMqttTry = now;
    esp_task_wdt_reset();
    String id = "p13-G-" + String(myBoot, HEX);
    if (mqtt.connect(id.c_str())) {
      if (!mixedBoot) { myBoot ^= (uint32_t)micros() & 0xFFFF; mixedBoot = true; }   // simulator RNG may repeat
      mqtt.subscribe(topicFor(NODE_GATEWAY).c_str());
      Serial.println("[sim] MQTT connected");
    }
  }
  mqtt.loop();
#endif
  RxItem it;
  while (xQueueReceive(rxQueue, &it, 0) == pdTRUE) handlePacket(it);
  for (PeerLink* L : LINKS) checkLinkTimeout(*L);
  pendingStep();

  if (now - lastStatus >= STATUS_EVERY_MS) {        // 1 s: three status lines to the PC
    lastStatus = now;
    sendPcStatus(NODE_GATEWAY, gwStatusText());
    for (ModuleView* m : MODS) {
      String st = m->status;
      if (!modOnline(*m)) { st = String(m->letter); st += ",OFFLINE"; }
      sendPcStatus(m->L->node, st);
    }
    for (ModuleView* m : MODS) moduleHousekeeping(*m);
  } else if (linkPc.trk.online) {                   // log lines only while the PC is listening
    if (qCount > 0) {
      linkSend(linkPc, L_LOG, 0, 0, 0, 0, pcQNo[qHead], pcQ[qHead], 0, 0);
      qHead = (qHead + 1) % QSIZE; qCount--;
    } else if (pcResendActive) {
      pcResendStep();
    }
  }
}

// =====================================================================
//  PRIORITY + LEDs
// =====================================================================
uint8_t systemPriority() {
  uint8_t pr = gwState == GS_TAMPER ? 3 : 0;
  for (ModuleView* m : MODS) {
    if (modOnline(*m)) { if (m->prio > pr && m->prio <= 3) pr = m->prio; }
    else if (m->wasArmed) pr = 3;                   // an armed module went silent
  }
  return pr;
}

uint32_t outputTestUntil = 0;
void updateOutputs() {
  uint32_t now = millis();
  bool fast = (now / 250) % 2, slow = (now / 500) % 2, beat = (now / 1000) % 2;
  bool g = false, r = false, y = false;
  if (gwState == GS_BOOT) {
    y = slow;
  } else {
    uint8_t pr = systemPriority();
    if (pr == 3) r = fast; else if (pr == 2) r = true;
    bool attention = pr == 1 || anyModIn(MS_MAINTENANCE) || anyModIn(MS_RECOVERY) || anyModIn(MS_BOOT);
    bool linkProblem = !modOnline(modA) || !modOnline(modB);
    if (attention) y = true; else if (linkProblem) y = slow;
    if (pr < 2) g = bothIn(MS_ARMED) ? true : beat;  // steady = system armed, blinking = not
  }
  if (notYet(outputTestUntil)) g = r = y = true;
  digitalWrite(PIN_LED_GREEN, g);
  digitalWrite(PIN_LED_YELLOW, y);
  digitalWrite(PIN_LED_RED, r);
}

// =====================================================================
//  KEYPAD + CARD (card + PIN, then the menu)
// =====================================================================
enum KpStage : uint8_t { KP_IDLE, KP_MENU, KP_TARGET };
KpStage         kpStage = KP_IDLE;
const CardUser* kpUser = nullptr;
uint8_t         kpCmd = 0;
uint32_t        kpUntil = 0;

struct {
  bool     haveCard = false;
  uint8_t  uid[10] = {};
  uint8_t  uidLen = 0;
  String   pin = "";
  uint32_t startedAt = 0;
} auth;
void resetAuth() { auth.haveCard = false; auth.uidLen = 0; auth.pin = ""; auth.startedAt = 0; }
bool kpBusy() { return kpStage != KP_IDLE || auth.haveCard || auth.pin.length() > 0; }
void kpLogout() { kpStage = KP_IDLE; kpUser = nullptr; kpCmd = 0; resetAuth(); }

String sha256Hex(const String& s) {
  uint8_t out[32];
  sha256((const uint8_t*)s.c_str(), s.length(), out);
  return toHex(out, 32);
}

String maskUid(const uint8_t* uid, uint8_t len) {      // only the last 2 bytes are ever logged
  if (len == 0) return "-";
  String s = "**";
  for (uint8_t i = (len > 2 ? len - 2 : 0); i < len; i++) { char b[4]; sprintf(b, ":%02X", uid[i]); s += b; }
  return s;
}

const CardUser* findUserByUid(const uint8_t* uid, uint8_t len) {
  for (uint8_t i = 0; i < USER_COUNT; i++)
    if (USERS[i].uidLen == len && memcmp(USERS[i].uid, uid, len) == 0) return &USERS[i];
  return nullptr;
}

void rejectInput(const String& why) {                  // T08
  logEvent("INPUT", why, "-", "REJECTED");
  showMsg("Invalid input", why);
}

const CardUser* checkCredentials() {
  String masked = maskUid(auth.uid, auth.uidLen);
  const CardUser* who = nullptr;
  if (auth.pin.length() >= 4) {                        // a short PIN is simply a wrong PIN
    String h = sha256Hex(String(PIN_SALT) + auth.pin);
    const CardUser* u = findUserByUid(auth.uid, auth.uidLen);
    if (u && h.equalsIgnoreCase(u->pinHashHex)) who = u;
  }
  resetAuth();
  if (who) {
    kpLock.success();
    logEvent("AUTH", "Card + PIN accepted", "-", "SUCCESS", -1, String(who->name) + "@GW " + masked);
    return who;
  }
  uint32_t lockS = kpLock.fail();
  logEvent("AUTH", "Card + PIN refused", "-", "FAIL", -1, "card " + masked + "@GW");                  // T02
  if (lockS) showMsg("LOCKED", String(lockS) + " s");                                                // T03
  else       showMsg("Access denied", String(kpLock.triesLeft()) + " tries left");
  return nullptr;
}

const CardUser* pollAuth(char key) {
  uint8_t uid[10], len = 0;
  bool card = rfid.readCard(uid, len);
  if (kpLock.locked()) {                               // input blocked; everything else keeps running
    if (card || (key && strchr("0123456789*#", key))) showMsg("LOCKED", String(kpLock.remaining) + " s left");
    else if (key) rejectInput("Key not valid");
    return nullptr;
  }
  if (card) {
    auth.haveCard = true; auth.uidLen = len; memcpy(auth.uid, uid, len);
    auth.pin = ""; auth.startedAt = millis();
#if ENROLL_MODE
    Serial.print("ENROLL card UID: ");
    for (uint8_t i = 0; i < len; i++) Serial.printf("0x%02X%s", uid[i], i + 1 < len ? ", " : "");
    Serial.printf("   (len %u)\n", len);
#endif
  }
  if (auth.startedAt && millis() - auth.startedAt > PIN_TIMEOUT_MS) {
    resetAuth(); logEvent("AUTH", "PIN entry timeout"); showMsg("Timed out", "Tap card again");
  }
  if (!key) return nullptr;
  if (key >= '0' && key <= '9') {
    if (!auth.haveCard) { showMsg("Tap card first", "then PIN + #"); return nullptr; }
    if (auth.pin.length() >= 6) { resetAuth(); rejectInput("PIN too long"); return nullptr; }
    auth.pin += key;
  } else if (key == '*') {
    if (auth.pin.length()) auth.pin = ""; else resetAuth();   // * clears the PIN, twice cancels the card
  } else if (key == '#') {
    if (auth.haveCard) return checkCredentials();
  } else {
    rejectInput("Key not valid");
  }
  return nullptr;
}

void handleUi(char key) {
  if (gwState == GS_BOOT) return;
  if (kpStage != KP_IDLE && !notYet(kpUntil)) {
    logEvent("AUTH", "Keypad menu timed out", "-", "-", -1, String(kpUser ? kpUser->name : "?") + "@GW");
    kpLogout();
    showMsg("Logged out", "(timeout)");
  }
  switch (kpStage) {
    case KP_IDLE: {
      const CardUser* u = pollAuth(key);
      if (!u) return;
      String who = String(u->name) + "@GW";
      if (gwState == GS_TAMPER) {                      // only a MAINTENANCE card clears a gateway tamper
        if (u->role != R_MAINTENANCE) {
          logEvent("TAMPER", "Clear attempt by operator", "-", "DENIED", 3, who);
          showMsg("Access denied", "Needs MAINT card");
        } else {
          clearGatewayTamper(who, false, 0);
        }
        return;
      }
      kpUser = u; kpStage = KP_MENU; kpUntil = millis() + MENU_TIMEOUT_MS;
      showMsg("Welcome", u->name, 1000);
      return;
    }

    case KP_MENU: {
      if (!key) return;
      kpUntil = millis() + MENU_TIMEOUT_MS;
      Role   role = kpUser->role;
      String who  = String(kpUser->name) + "@GW";
      switch (key) {
        case '1': kpLogout(); runCommand(CMD_ARM,       TARGET_BOTH, role, who, 0, false, 0); break;   // T01
        case '2': kpLogout(); runCommand(CMD_DISARM,    TARGET_BOTH, role, who, 0, false, 0); break;
        case '3': kpLogout(); runCommand(CMD_ACK_ALARM, TARGET_BOTH, role, who, 0, false, 0); break;
        case '4': case '5':
          if (role != R_MAINTENANCE) {
            logEvent("CMD", String(key == '4' ? "MAINT" : "CLEAR") + " denied: needs MAINTENANCE", "-", "DENIED", -1, who);
            showMsg("Access denied", "Needs MAINT card");
            kpLogout();
            break;
          }
          kpCmd = key == '4' ? CMD_MAINT_START : CMD_CLEAR_FAULT;
          kpStage = KP_TARGET;
          break;
        case '6': kpCmd = CMD_MAINT_END; kpStage = KP_TARGET; break;
        case '*': logEvent("AUTH", "Logged out", "-", "-", -1, who); kpLogout(); showMsg("Logged out", ""); break;
        default:  rejectInput("Not a menu key"); break;                                               // T08
      }
      return;
    }

    case KP_TARGET: {
      if (!key) return;
      kpUntil = millis() + MENU_TIMEOUT_MS;
      uint8_t t = 0xFF;
      if (key == '1') t = NODE_MOD_A;
      else if (key == '2') t = NODE_MOD_B;
      else if (key == '3') t = TARGET_BOTH;
      else if (key == '0' && kpCmd == CMD_CLEAR_FAULT) t = NODE_GATEWAY;
      else if (key == '*') { kpLogout(); showMsg("Cancelled", ""); return; }
      if (t == 0xFF) { rejectInput("Not a target"); return; }
      Role role = kpUser->role;
      String who = String(kpUser->name) + "@GW";
      uint8_t cmd = kpCmd;
      kpLogout();
      runCommand(cmd, t, role, who, 0, false, 0);     // maintenance: the module's default time (300 s)
      return;
    }
  }
}

// =====================================================================
//  LCD
// =====================================================================
String screen1 = "", screen2 = "", msg1 = "", msg2 = "";
uint32_t msgUntil = 0;
void showMsg(const String& l1, const String& l2, uint32_t ms) { msg1 = l1; msg2 = l2; msgUntil = millis() + ms; }

String marquee(const String& s) {                    // scroll text longer than 16 characters
  if (s.length() <= 16) return s;
  uint32_t steps = s.length() - 16;
  uint32_t t = (millis() / 600) % (steps + 6);       // pause 3 steps at each end
  uint32_t off = t < 3 ? 0 : (t - 3 > steps ? steps : t - 3);
  return s.substring(off, off + 16);
}

String modCell(const ModuleView& m) {                // "A:ARM", "B:-- "
  return String(m.letter) + ":" + (modOnline(m) ? String(modStateShort(m.state)) : String("-- "));
}

void renderLcd() {
  String l1, l2;
  if (gwState == GS_BOOT) {
    l1 = "Gateway starting"; l2 = "";
  } else if (gwState == GS_TAMPER) {
    l1 = "!! GW TAMPER !!";
    l2 = tamperReason + " | MAINT card + PIN";
  } else {
    if (anyModIn(MS_INTRUSION))         l1 = "!! INTRUSION !!";
    else if (anyModIn(MS_TAMPER_FAULT)) l1 = "!! MOD TAMPER !!";
    else {
      String mode = bothIn(MS_ARMED) ? "ARMED" : bothIn(MS_DISARMED) ? "DISARMED" : "MIXED";
      l1 = "SYS " + mode + " P" + String(systemPriority());
    }
    l2 = modCell(modA) + " " + modCell(modB) + " PC:" + (sess.active ? "L" : linkPc.trk.online ? "Y" : "N");
  }
  if (pend.active) { l1 = String("Sending ") + cmdShort(pend.cmd); l2 = "please wait"; }
  else if (kpStage == KP_MENU) {
    l1 = "1Arm 2Dis 3Ack";
    l2 = kpUser && kpUser->role == R_MAINTENANCE ? "4Mnt 5Clr 6End" : "6EndMnt *=out";
  } else if (kpStage == KP_TARGET) {
    l1 = String(cmdShort(kpCmd)) + " on which?";
    l2 = kpCmd == CMD_CLEAR_FAULT ? "1A 2B 3Both 0GW" : "1A 2B 3Both *";
  } else if (auth.haveCard) {
    l1 = "Card read";
    l2 = "PIN: ";
    for (unsigned i = 0; i < auth.pin.length(); i++) l2 += '*';   // never show digits
    if (!auth.pin.length()) l2 = "Enter PIN + #";
  } else if (kpLock.locked() && gwState != GS_BOOT) {
    l2 = "Keypad lock " + String(kpLock.remaining) + "s";
  }
  if (notYet(msgUntil)) { l1 = msg1; l2 = msg2; }
  display.show(l1, marquee(l2));
}

// =====================================================================
//  SETUP + LOOP
// =====================================================================
char KEYS[4][4] = { { '1', '2', '3', 'A' },
                    { '4', '5', '6', 'B' },
                    { '7', '8', '9', 'C' },
                    { '*', '0', '#', 'D' } };
Keypad keypad = Keypad(makeKeymap(KEYS), KP_ROWS, KP_COLS, 4, 4);
uint32_t lastPeriphCheck = 0, bootAt = 0;

void setup() {
  Serial.begin(115200);
  delay(200);
  pinMode(PIN_LED_GREEN, OUTPUT); pinMode(PIN_LED_YELLOW, OUTPUT); pinMode(PIN_LED_RED, OUTPUT);
  tamper.begin();

  prefs.begin("p13gw", false);
  bootNo = prefs.getUInt("boot", 0) + 1;    prefs.putUInt("boot", bootNo);
  bool savedTamper = prefs.getBool("tamper", false);
  tamperReason = prefs.getString("reason", "");

  fsOk = LittleFS.begin(true);
  uint32_t fileGw = 0, fileA = 0, fileB = 0;
  if (fsOk) scanLogTail(fileGw, fileA, fileB);      // carry on exactly where the log file ends
  uint32_t savedGw = prefs.getUInt("logNo", 0);
  gwNo = fileGw ? max(fileGw, savedGw) : savedGw + 16;   // no file: skip ahead, never reuse a number
  prefs.putUInt("logNo", gwNo);
  modA.top = max(fileA, (uint32_t)prefs.getUInt("topA", 0));
  modB.top = max(fileB, (uint32_t)prefs.getUInt("topB", 0));
  uint32_t missA = prefs.getUInt("missA", 0), missB = prefs.getUInt("missB", 0);
  for (ModuleView* m : MODS) { m->win.reset(m->top + 1); m->checkedTop = m->top; m->savedTop = m->top; }
  Wire.begin(PIN_SDA, PIN_SCL);
  display.begin();
  rfid.begin();
  radioBegin();
  startWatchdog(WOKWI_SIM ? 20000 : 5000);

  Serial.printf("\nGateway, MAC %s\n", WiFi.macAddress().c_str());
  logEvent("SYSTEM", String("Boot #") + bootNo + " reason=" + resetReasonName(esp_reset_reason()));
  kpLock.load();
  pcLock.load();
  if (!fsOk)           logEvent("SYSTEM", "Log storage unavailable", "-", "ERROR");
  if (!radioReady)     logEvent("COMM", "Radio start FAILED", "-", "ERROR");
  if (!display.online) logEvent("COMM", "LCD not found at boot");
  if (!rfid.online)    logEvent("COMM", "RFID reader not found - use the PC", "-", "ERROR");
#if !WOKWI_SIM
  uint8_t own[6];
  WiFi.macAddress(own);
  if (macIsSet(MAC_GATEWAY) && memcmp(own, MAC_GATEWAY, 6) != 0)
    logEvent("SYSTEM", "MAC differs from MAC_GATEWAY in secrets.h", "-", "WARN");
  for (PeerLink* L : LINKS) {
    if (linkUsable(*L) && L->encrypted) continue;
    String why = L->macSet ? " encryption setup FAILED" : " MAC not set in secrets.h";
    if (ALLOW_UNENCRYPTED) logEvent("COMM", String(L->name) + why + ": signed, NOT encrypted", "-", "WARN");
    else                   logEvent("COMM", String(L->name) + why + ": link OFF", "-", "ERROR");
  }
#endif
#if ENROLL_MODE
  logEvent("SYSTEM", "ENROLL MODE ON - card UIDs printed. Set 0 for the demo", "-", "WARN");
#endif
  uint32_t misses[2] = { missA, missB };
  for (uint8_t i = 0; i < 2; i++) {
    ModuleView& m = *MODS[i];
    m.savedMiss = misses[i];
    if (misses[i] && misses[i] <= m.top)                   // we restarted in the middle of fetching lines
      logEvent("COMM", String(m.L->name) + " log lines from " + String(misses[i]) + " to " + String(m.top) + " may be incomplete (gateway restarted)", "-", "LOST");
  }
  if (savedTamper) {
    gwState = GS_TAMPER;
    logEvent("TAMPER", "Gateway tamper restored after restart", "-", "-", 3);              // T10
  }
  bootAt = millis();
}

void loop() {
  esp_task_wdt_reset();                       // "still alive" — else the watchdog restarts the board
  uint32_t now = millis();
  char key = keypad.getKey();

  if (tamper.update(now))
    logEvent("TAMPER", tamper.isOpen() ? "Gateway lid opened" : "Gateway lid closed", "-", "-", tamper.isOpen() ? 3 : -1);
  if (gwState == GS_BOOT && now - bootAt > 1500) {          // short self-test
    outputTestUntil = now + 800;
    if (tamper.isOpen()) enterTamper("lid open at boot");
    else { gwState = GS_READY; logEvent("TEST", "Gateway self-test OK", "-", "PASS"); }
  }
  if (tamper.isOpen() && gwState == GS_READY) { kpLogout(); enterTamper("lid opened"); }      // T07

  if (now - lastPeriphCheck > PERIPH_CHECK_MS) {
    lastPeriphCheck = now;
    if (rfid.check())    logEvent("COMM", rfid.online ? "RFID reader online" : "RFID reader OFFLINE - use the PC", "-", "-", rfid.online ? -1 : 3);
    if (display.check()) logEvent("COMM", display.online ? "LCD online" : "LCD OFFLINE");
  }
  kpLock.tick();
  pcLock.tick();
  linkLoop();
  checkSession();
  handleUi(key);
  updateOutputs();
  renderLcd();
  delay(LOOP_MS);
}
