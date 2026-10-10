// =====================================================================
//  PINNACLE 1 — PROJECT 13 — SECURE PERIMETER INTRUSION DETECTION
//  GATEWAY  —  ESP32 DevKit V1 30-pin  —  firmware v6.0
//
//  The control box, in the middle of the site. Runs on a power adapter; one of
//  the five radios of the mesh (mesh.h) with Sensor Modules A, B, C and D at the
//  corners, and over Wi-Fi to the server laptop that runs the dashboard (MQTT
//  inside TLS, the server's own broker).
//
//  What it does:
//    * Card + PIN on its own RFID reader and keypad, then a menu:
//        1 Arm   2 Disarm   3 Acknowledge alarm      (OPERATOR or MAINTENANCE)
//        4 Maintenance  5 Clear tamper  6 End maint  (4 and 5: MAINTENANCE only)
//      3 wrong card/PIN tries lock the keypad (60, 120, 240 s...).
//    * Dashboard: user name + password login (challenge-response: the
//      password never reaches the gateway), 5-min idle session, own lockout.
//      A dashboard command has priority over a keypad entry in progress.
//    * Sends each command to the modules, collects their answers and shows
//      them ("A:OK B:OK C:Lid open D:OK"). The modules check role and state again.
//    * Keeps one event log for the whole system (its own events + every line
//      from the four modules), fetches lines the modules sent while the radio
//      dropped, and gives the server any lines it missed.
//    * Sends status (its own + the four modules', with how each radio link is
//      doing) to the server every second and gives the modules the real time.
//    * Mesh: talks straight to each module; when a link fails, through another
//      module. Passes on packets between modules whose own link failed.
//    * Its own tamper switch: lid opened -> P3, and the gateway refuses all
//      commands until a MAINTENANCE card + PIN (or dashboard admin) clears it.
//    * Wi-Fi: joins the network in secrets.h. ESP-NOW then runs on that
//      network's channel; the modules follow it by themselves. If the network
//      is gone, the gateway stays on the last channel (modules keep working)
//      and tries again every 30 s .. 5 min.
//
//  Libraries: MFRC522 (GithubCommunity), Keypad (Mark Stanley / Alexander
//  Brevig), LiquidCrystal I2C (Frank de Brabander), PubSubClient (Wokwi only).
//  The server link uses ESP-MQTT, which is built into the ESP32 core.
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
#if !WOKWI_SIM
#include <mqtt_client.h>
#include <esp_tls_errors.h>
#endif

// The Arduino IDE / Wokwi auto-insert function prototypes above the first
// function in the sketch. Declare our own types before that point.
enum GwState : uint8_t;
struct RxItem;
struct CardUser;
struct PcUser;
struct ModuleView;

#include "link_protocol.h"
#include "mesh.h"
struct CardUser { const char* name; uint8_t uid[10]; uint8_t uidLen; const char* pinHashHex; Role role; };
struct PcUser   { const char* name; const char* pwHashHex; Role role; };
#include "secrets.h"

// =====================================================================
//  PINS — ESP32 DevKit V1 30-pin. RFID, keypad and LCD as on Board 1 before.
//  Tamper switch on RX2 (16) with the ESP32's built-in pull-up: no resistor.
//  LEDs on D2 (also the on-board LED), D15 and TX2 (17). D2 and D15 are boot
//  pins: an LED + resistor to GND is safe there.
// =====================================================================
const uint8_t PIN_SDA = 21, PIN_SCL = 22;                        // LCD I2C
const uint8_t PIN_RFID_SCK = 18, PIN_RFID_MISO = 19;             // RC522 SPI
const uint8_t PIN_RFID_MOSI = 23, PIN_RFID_SS = 5;               // RC522 RST wired to 3.3 V
byte KP_ROWS[4] = { 13, 14, 27, 26 };                            // keypad pins 1-4
byte KP_COLS[4] = { 25, 33, 32, 4 };                             // keypad pins 5-8
const uint8_t PIN_LED_GREEN  = 2;
const uint8_t PIN_LED_YELLOW = 15;    // D15 (boot pin: the LED only hides the boot messages; may blink at power-on)
const uint8_t PIN_LED_RED    = 17;    // TX2
const uint8_t PIN_TAMPER     = 16;    // RX2. Reed switch to GND; built-in pull-up

const uint8_t TAMPER_CLOSED_LEVEL = LOW;   // lid shut = LOW; lid open OR wire cut = HIGH
const uint8_t LCD_ADDR            = 0x27;  // try 0x3F if the LCD stays blank

// =====================================================================
//  TIMING / LIMITS
// =====================================================================
const uint32_t LOOP_MS             = 20;
const uint32_t STATUS_EVERY_MS     = 1000;
const uint32_t LINK_TIMEOUT_MS     = WOKWI_SIM ? 8000 : 3000;
const uint32_t SERVER_TIMEOUT_MS   = 8000;    // server link: Wi-Fi + broker in between
const uint32_t RADIO_SETTLE_MS     = 25000;   // module link timeout while Wi-Fi scans / modules re-find the channel
const uint32_t WIFI_JOIN_MS        = 15000;   // give up one attempt to join after this
const uint32_t WIFI_RETRY_MIN_S    = 30;      // then wait 30, 60, 120, 240, 300 s
const uint32_t WIFI_RETRY_MAX_S    = 300;
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
    pinMode(PIN_TAMPER, INPUT_PULLUP);       // built-in pull-up: lid open or wire cut reads HIGH
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

// One lockout counter (keypad and dashboard have one each). Survives restarts.
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
Lockout pcLock("pc", "Dashboard login");

// Real time, once the server has sent it (0 = not known yet)
bool     timeSynced = false;
uint32_t timeBase = 0, timeBaseMs = 0;
uint32_t unixNow() { return timeSynced ? timeBase + (millis() - timeBaseMs) / 1000 : 0; }

// =====================================================================
//  LINKS: Module A, Module B (ESP-NOW radio), Server (Wi-Fi + MQTT/TLS)
// =====================================================================
enum Via : uint8_t { VIA_RADIO = 0, VIA_MQTT = 1 };
struct RxItem { uint8_t src[6]; int8_t rssi; uint8_t via; int len; uint8_t data[sizeof(LinkPacket)]; };
QueueHandle_t rxQueue;
const uint8_t BROADCAST[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

const uint8_t NO_MAC[6] = { 0, 0, 0, 0, 0, 0 };
MeshPeer linkA (NODE_MOD_A,  "Module A", MAC_MOD_A, KEY_A_GW);
MeshPeer linkB (NODE_MOD_B,  "Module B", MAC_MOD_B, KEY_B_GW);
MeshPeer linkC (NODE_MOD_C,  "Module C", MAC_MOD_C, KEY_C_GW);
MeshPeer linkD (NODE_MOD_D,  "Module D", MAC_MOD_D, KEY_D_GW);
MeshPeer linkPc(NODE_SERVER, "Server",   NO_MAC,    KEY_GW_SERVER);   // over MQTT/TLS, not the radio
MeshPeer* const RADIO_PEERS[4] = { &linkA, &linkB, &linkC, &linkD };
MeshPeer* const LINKS[5] = { &linkA, &linkB, &linkC, &linkD, &linkPc };
Mesh mesh(NODE_GATEWAY, RADIO_PEERS, 4);
MeshPeer* linkFor(uint8_t node) {
  for (MeshPeer* L : LINKS) if (L->node == node) return L;
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
  MeshPeer* L;
  char      letter;
  uint8_t   idx;             // 0..3 = A..D
  uint8_t   mask;            // 1 = A, 2 = B, 4 = C, 8 = D (for command targets)
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
  ModuleView(MeshPeer* l, char c, uint8_t i) : L(l), letter(c), idx(i), mask(1 << i) {}
  String key(const char* what) const { return String(what) + letter; }   // NVS key, e.g. "topC"
};
ModuleView modA(&linkA, 'A', 0);
ModuleView modB(&linkB, 'B', 1);
ModuleView modC(&linkC, 'C', 2);
ModuleView modD(&linkD, 'D', 3);
const uint8_t MOD_COUNT = 4;
const uint8_t ALL_MODS = 0x0F;
ModuleView* const MODS[MOD_COUNT] = { &modA, &modB, &modC, &modD };
ModuleView* modFor(uint8_t node) { return isModule(node) ? MODS[node - NODE_MOD_A] : nullptr; }

bool modOnline(const ModuleView& m) { return m.L->trk.online; }
bool anyModIn(uint8_t s) { for (ModuleView* m : MODS) if (modOnline(*m) && m->state == s) return true; return false; }
bool allIn(uint8_t s)    { for (ModuleView* m : MODS) if (!modOnline(*m) || m->state != s) return false; return true; }
String maskText(uint8_t mask) {                      // 0x0F -> "all", 0x05 -> "A+C"
  if (mask == ALL_MODS) return "all";
  String t = "";
  for (ModuleView* m : MODS) if (mask & m->mask) { if (t.length()) t += "+"; t += m->letter; }
  return t;
}

uint32_t myBoot = 0, mySeq = 0;
uint8_t  myReset = 0;
bool     radioReady = false;

bool macIsSet(const uint8_t* m) { for (int i = 0; i < 6; i++) if (m[i]) return true; return false; }

// A radio link is only used when it is encrypted, unless ALLOW_UNENCRYPTED (Wokwi has no
// encryption). The server link is always inside TLS.
bool linkUsable(const MeshPeer& L) { return WOKWI_SIM || ALLOW_UNENCRYPTED || L.encrypted || &L == &linkPc; }

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
  it.rssi = 0; it.via = VIA_MQTT;
  it.len = len;
  memcpy(it.data, payload, min((int)len, (int)sizeof(it.data)));
  xQueueSend(rxQueue, &it, 0);
}
#endif

// ---------------- Wi-Fi + server link (real board) ----------------
#if !WOKWI_SIM
enum NetStage : uint8_t { NET_OFF, NET_JOINING, NET_UP, NET_WAIT };
NetStage netStage = NET_OFF;
uint8_t  netCh = ESPNOW_DEFAULT_CHANNEL;   // the channel ESP-NOW runs on (the network's, once joined)
uint32_t netSince = 0, netRetryS = WIFI_RETRY_MIN_S;
uint32_t radioSettleUntil = 0;             // until then, module links get RADIO_SETTLE_MS before "DOWN"

esp_mqtt_client_handle_t mq = nullptr;
QueueHandle_t txQueue = nullptr;              // packets waiting for the sender task
char topicIn[48], topicOut[48], topicState[48];
// Set by the MQTT task, read (and logged) by loop()
volatile bool mqUp = false, mqSawConnect = false, mqSawDrop = false, mqSawError = false;
volatile int  mqErrType = 0, mqTlsErr = 0, mqConnRc = 0;
uint32_t mqLastErrLog = 0;

void onMqttEvent(void*, esp_event_base_t, int32_t id, void* data) {   // runs in the MQTT task
  esp_mqtt_event_handle_t ev = (esp_mqtt_event_handle_t)data;
  switch ((esp_mqtt_event_id_t)id) {
    case MQTT_EVENT_CONNECTED:
      esp_mqtt_client_subscribe(ev->client, topicIn, 0);
      esp_mqtt_client_publish(ev->client, topicState, "online", 0, 1, 1);
      mqUp = true; mqSawConnect = true;
      break;
    case MQTT_EVENT_DISCONNECTED:
      if (mqUp) mqSawDrop = true;
      mqUp = false;
      break;
    case MQTT_EVENT_ERROR:
      if (ev->error_handle) {
        mqErrType = ev->error_handle->error_type;
        mqTlsErr  = ev->error_handle->esp_tls_last_esp_err;
        mqConnRc  = ev->error_handle->connect_return_code;
      }
      mqSawError = true;
      break;
    case MQTT_EVENT_DATA: {
      bool ours = ev->topic_len == (int)strlen(topicIn) && memcmp(ev->topic, topicIn, ev->topic_len) == 0;
      if (!ours || ev->current_data_offset != 0 || ev->data_len != ev->total_data_len) break;
      RxItem it;
      memset(it.src, 0, 6);
      it.rssi = 0; it.via = VIA_MQTT;
      it.len  = ev->data_len;
      memcpy(it.data, ev->data, min(ev->data_len, (int)sizeof(it.data)));
      xQueueSend(rxQueue, &it, 0);
      break;
    }
    default: break;
  }
}

// Sends what loop() queued. Publishing can wait on the network (a slow Wi-Fi
// hop, a reconnect): it waits here, never in loop(), so the keypad, LEDs and
// module links carry on.
// A Wi-Fi scan takes the radio off the modules' channel for a few seconds, and
// after a channel change the modules need a few seconds to find us. Neither is
// a module going missing, so it must not raise "LOST while armed" (P3).
uint32_t moduleLinkTimeout() {
  return netStage == NET_JOINING || notYet(radioSettleUntil) ? RADIO_SETTLE_MS : LINK_TIMEOUT_MS;
}

void serverTxTask(void*) {
  LinkPacket p;
  for (;;) {
    if (xQueueReceive(txQueue, &p, portMAX_DELAY) == pdTRUE && mq && mqUp)
      esp_mqtt_client_publish(mq, topicOut, (const char*)&p, sizeof(p), 0, 0);
  }
}

void serverStart() {                           // once; ESP-MQTT reconnects by itself after that
  if (mq || !SERVER_CA_PEM[0]) return;
  snprintf(topicIn,    sizeof(topicIn),    "p13/%s/to/G",    SITE_ID);
  snprintf(topicOut,   sizeof(topicOut),   "p13/%s/to/P",    SITE_ID);
  snprintf(topicState, sizeof(topicState), "p13/%s/state/G", SITE_ID);
  static char uri[72], cid[40];
  snprintf(uri, sizeof(uri), "mqtts://%s:%d", SERVER_HOST, SERVER_PORT);
  snprintf(cid, sizeof(cid), "p13-gw-%s", SITE_ID);
  esp_mqtt_client_config_t c = {};
  c.broker.address.uri                 = uri;
  c.broker.verification.certificate    = SERVER_CA_PEM;   // only our CA's certificates are accepted
  c.broker.verification.common_name    = SERVER_NAME;     // and only the one issued to the server
  c.credentials.client_id              = cid;
  c.credentials.username               = MQTT_USER;
  c.credentials.authentication.password = MQTT_PASSWORD;
  c.session.keepalive                  = 10;
  c.session.last_will.topic            = topicState;      // the broker announces "offline" if we vanish
  c.session.last_will.msg              = "offline";
  c.session.last_will.qos              = 1;
  c.session.last_will.retain           = 1;
  c.network.reconnect_timeout_ms       = 5000;
  c.network.timeout_ms                 = 5000;
  c.buffer.size                        = 512;
  c.buffer.out_size                    = 512;
  txQueue = xQueueCreate(24, sizeof(LinkPacket));
  mq = esp_mqtt_client_init(&c);
  if (!mq || !txQueue) { logEvent("COMM", "Server link start FAILED", "-", "ERROR"); mq = nullptr; return; }
  xTaskCreate(serverTxTask, "serverTx", 6144, nullptr, 2, nullptr);   // TLS encryption runs on this stack
  esp_mqtt_client_register_event(mq, MQTT_EVENT_ANY, onMqttEvent, nullptr);
  esp_mqtt_client_start(mq);
}

void serverSend(const LinkPacket& p) {        // never waits: if the queue is full the packet is dropped
  if (mq && mqUp) xQueueSend(txQueue, &p, 0);  // (status repeats every second; the server re-asks for log lines)
}

String mqErrorText() {
  if (mqErrType == MQTT_ERROR_TYPE_CONNECTION_REFUSED)
    return mqConnRc == MQTT_CONNECTION_REFUSE_BAD_USERNAME || mqConnRc == MQTT_CONNECTION_REFUSE_NOT_AUTHORIZED
           ? "broker refused the gateway's user name / password" : "broker refused the connection";
  if (mqTlsErr == ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED) return "TLS check failed (certificate / CA / name?)";
  if (mqTlsErr == ESP_ERR_ESP_TLS_FAILED_CONNECT_TO_HOST || mqTlsErr == ESP_ERR_ESP_TLS_CONNECTION_TIMEOUT)
    return "server not reachable (address / broker running?)";
  return "connection failed (code " + String(mqErrType) + "/" + String(mqTlsErr) + ")";
}

void netJoin() {
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD, netCh);   // scans from the last known channel first
  netStage = NET_JOINING;
  netSince = millis();
}

void netBegin() {
  if (!WIFI_SSID[0]) { logEvent("COMM", "Wi-Fi not set in secrets.h: no server link", "-", "WARN"); return; }
  if (!SERVER_CA_PEM[0]) logEvent("COMM", "Server CA not set in secrets.h: server link off", "-", "WARN");
  netJoin();
}

void netLoop() {
  uint32_t now = millis();
  if (mqSawConnect) { mqSawConnect = false; logEvent("COMM", "Server link connected (TLS)"); mqSawError = false; }
  if (mqSawDrop)    { mqSawDrop = false;    logEvent("COMM", "Server link dropped"); }
  if (mqSawError && (!mqLastErrLog || now - mqLastErrLog > 60000)) {   // retries every 5 s: log once a minute
    mqSawError = false; mqLastErrLog = now;
    logEvent("COMM", "Server link: " + mqErrorText(), "-", "ERROR");
  }
  switch (netStage) {
    case NET_JOINING:
      if (WiFi.status() == WL_CONNECTED) {
        netStage = NET_UP;
        netRetryS = WIFI_RETRY_MIN_S;
        uint8_t ch = WiFi.channel();
        radioSettleUntil = millis() + 3000;
        if (ch != netCh) {
          logEvent("COMM", "Radio channel " + String(netCh) + " -> " + String(ch) + " (Wi-Fi network): modules follow");
          netCh = ch;
          prefs.putUChar("wifiCh", ch);
          radioSettleUntil = millis() + RADIO_SETTLE_MS;
        }
        logEvent("COMM", String("Wi-Fi joined ") + WIFI_SSID + " ch " + String(ch) + " " +
                         WiFi.localIP().toString() + " " + String(WiFi.RSSI()) + " dBm");
        showMsg("Wi-Fi ch " + String(ch), WiFi.localIP().toString(), 4000);
        serverStart();
      } else if (now - netSince > WIFI_JOIN_MS) {
        wl_status_t st = WiFi.status();
        WiFi.disconnect();
        esp_wifi_set_channel(netCh, WIFI_SECOND_CHAN_NONE);   // back to the modules' channel
        radioSettleUntil = millis() + 5000;
        String why = st == WL_NO_SSID_AVAIL ? " not found" : st == WL_CONNECT_FAILED ? " refused (password?)" : " did not answer";
        logEvent("COMM", String("Wi-Fi ") + WIFI_SSID + why + ": retry in " + String(netRetryS) + " s", "-", "FAIL");
        netStage = NET_WAIT;
        netSince = now;
      }
      break;
    case NET_UP:
      if (WiFi.status() != WL_CONNECTED) { logEvent("COMM", "Wi-Fi lost: rejoining"); netJoin(); }
      break;
    case NET_WAIT:
      if (now - netSince >= netRetryS * 1000UL) { netRetryS = min(netRetryS * 2, WIFI_RETRY_MAX_S); netJoin(); }
      break;
    default:
      break;
  }
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
  it.via = VIA_RADIO;
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
  for (MeshPeer* L : LINKS) L->macSet = macIsSet(L->mac);
  mesh.directTimeout = WOKWI_SIM ? 6000 : 2500;
#if WOKWI_SIM
  WiFi.mode(WIFI_STA);
  WiFi.begin("Wokwi-GUEST", "", 6);
  mqtt.setServer(MQTT_BROKER, MQTT_PORT);
  mqtt.setCallback(onMqtt);
  mqtt.setBufferSize(512);
  mqtt.setSocketTimeout(2);
  radioReady = true;
#else
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(false);                // we choose when to scan: a scan takes the radio off the modules' channel
  WiFi.setSleep(false);                        // ESP-NOW must keep hearing the modules while Wi-Fi is connected
  WiFi.disconnect();
  netCh = prefs.getUChar("wifiCh", ESPNOW_DEFAULT_CHANNEL);
  if (netCh < 1 || netCh > 13) netCh = ESPNOW_DEFAULT_CHANNEL;
  esp_wifi_set_channel(netCh, WIFI_SECOND_CHAN_NONE);
  if (esp_now_init() != ESP_OK) { radioReady = false; return; }
  esp_now_register_recv_cb(onRecv);
  esp_now_set_pmk(ESPNOW_PMK);
  for (MeshPeer* L : RADIO_PEERS) addEncryptedPeer(*L);   // on failure that link uses signed broadcast
  esp_now_peer_info_t bc = {};
  memcpy(bc.peer_addr, BROADCAST, 6);
  bc.channel = 0;
  bc.ifidx   = WIFI_IF_STA;
  bc.encrypt = false;
  esp_now_add_peer(&bc);
  radioReady = true;
#endif
}

void rawSend(const MeshPeer& to, const LinkPacket& p) {      // one radio hop to a module
#if WOKWI_SIM
  if (mqtt.connected()) mqtt.publish(topicFor(to.node).c_str(), (const uint8_t*)&p, sizeof(p));
#else
  esp_now_send(to.encrypted ? to.mac : BROADCAST, (const uint8_t*)&p, sizeof(p));
#endif
}

// To a module: straight, and also through a relay while the direct link doesn't
// work both ways (same sequence number: the module keeps the first copy).
// To the server: over MQTT/TLS.
void linkSend(MeshPeer& L, uint8_t type, uint8_t code, uint8_t role, uint8_t result,
              uint32_t arg, uint32_t no, const char* text, uint32_t session, uint8_t target) {
  if (!radioReady || !linkUsable(L)) return;
  LinkPacket p = {};
  p.version = LINK_VERSION; p.src = NODE_GATEWAY; p.dst = L.node; p.type = type;
  p.via = 0; p.mesh = mesh.mask();
  p.bootId = myBoot; p.seq = ++mySeq;
  p.dstBoot = L.trk.synced ? L.trk.bootId : 0;
  p.logNo = no; p.state = gwState; p.priority = systemPriority(); p.resetReason = myReset;
  p.code = code; p.role = role; p.result = result; p.arg = arg; p.session = session; p.target = target;
  size_t n = text ? strnlen(text, LINK_TEXT_MAX) : 0;
  if (n) memcpy(p.text, text, n);
  p.textLen = n;
  linkSign(L.key, 32, p, p.sig);
  if (&L == &linkPc) {
#if WOKWI_SIM
    if (mqtt.connected()) mqtt.publish(topicFor(L.node).c_str(), (const uint8_t*)&p, sizeof(p));
#else
    serverSend(p);
#endif
    return;
  }
  uint8_t via = mesh.chooseRoute(L);
  if (!mesh.isCut(L)) rawSend(L, p);
  MeshPeer* R = via ? mesh.find(via) : nullptr;
  if (R && linkUsable(*R)) {
    p.via = via;
    linkSign(L.key, 32, p, p.sig);             // still this link's key: the relay can't make or change it
    rawSend(*R, p);
  }
}

String nodeName(uint8_t node) { return node == NODE_GATEWAY ? String("Gateway") : String("Module ") + nodeLetter(node); }

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
//  SYSTEM EVENT LOG  -> LittleFS + USB serial + server
//  Every line (gateway's own and the modules') gets a gateway number gw_no.
//  Stored as  gw_no,<line>  where <line> is in the module log format.
// =====================================================================
bool fsOk = false;
uint32_t logRotations = 0;
const char* LOG_HEADER = "gw_no,log_no,boot,uptime_ms,unix_time,module,priority,state,type,event,zone,user,result";

const uint8_t QSIZE = 32;                      // lines waiting to go to the server
char     pcQ[QSIZE][LINK_TEXT_MAX];
uint32_t pcQNo[QSIZE];
uint8_t  qHead = 0, qCount = 0;

void queuePc(uint32_t no, const String& line) {
  if (qCount == QSIZE) { qHead = (qHead + 1) % QSIZE; qCount--; }   // oldest dropped: the server asks again
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

// ---------------- giving the server lines it missed ----------------
bool     pcResendActive = false;
uint32_t pcResendFrom = 0, pcResendTo = 0, nextPcResendTo = 0;   // To 0 = no upper limit
uint8_t  pcResendFile = 0;
size_t   pcResendPos = 0;
uint16_t pcResendSent = 0;
uint32_t pcResendRot = 0;

void startPcResend(uint32_t from) {
  pcResendActive = fsOk; pcResendFrom = from; pcResendFile = 0; pcResendPos = 0; pcResendSent = 0;
  pcResendTo = nextPcResendTo; nextPcResendTo = 0;
  pcResendRot = logRotations;
}

void pcResendStep() {                          // sends at most one line per call
  if (pcResendRot != logRotations) {           // the log rotated: start the scan again
    pcResendRot = logRotations; pcResendFile = 0; pcResendPos = 0;   // (the server drops lines it already has)
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
      if (pcResendTo && no > pcResendTo) { pcResendActive = false; return; }   // the asked-for range is done
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
void scanLogTail(uint32_t& lastGw, uint32_t* lastMod) {        // lastMod: one per module
  lastGw = 0;
  for (uint8_t i = 0; i < MOD_COUNT; i++) lastMod[i] = 0;
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
      if (mod >= 'A' && mod <= 'D' && ln > lastMod[mod - 'A']) lastMod[mod - 'A'] = ln;
    }
    f.close();
  }
}

// =====================================================================
//  LINES FROM THE MODULES (with recovery of lines lost on the radio)
// =====================================================================
void saveTop(ModuleView& m) { prefs.putUInt(m.key("top").c_str(), m.top); m.savedTop = m.top; }
void saveMissing(ModuleView& m, uint32_t from) {          // where recovery stands, in case we restart
  if (from == m.savedMiss) return;
  m.savedMiss = from;
  prefs.putUInt(m.key("miss").c_str(), from);
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
//  COMMANDS: from the keypad (card + PIN) or the dashboard (logged-in session)
//  Sent to each target module, which answers OK / REFUSED / DENIED.
// =====================================================================
struct PendingCmd {
  bool     active = false;
  uint32_t id = 0;                 // the same on every retry, so a module never runs it twice
  uint8_t  cmd = 0, role = 0, targets = 0, done = 0;
  uint32_t arg = 0, pcSeq = 0, deadline = 0;
  bool     fromPc = false;
  String   who = "";
  uint8_t  res[MOD_COUNT] = {};
  String   why[MOD_COUNT];
  uint32_t firstSeq[MOD_COUNT] = {}, lastSeq[MOD_COUNT] = {}, nextTry[MOD_COUNT] = {};
  uint8_t  tries[MOD_COUNT] = {};
} pend;

uint32_t cmdCounter = 0;
uint32_t pcSessionId();

uint32_t sendModuleCmd(ModuleView& m, uint8_t cmd, uint8_t role, uint32_t arg, const String& who, uint32_t id, uint32_t to) {
  linkSend(*m.L, L_CMD, cmd, role, 0, arg, id, who.c_str(), to, 0);
  return mySeq;
}

// A dashboard command that arrives while a keypad command is still running waits
// for it (at most a few seconds), then runs: the dashboard goes next, ahead of the keypad.
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
    case CMD_TEST_CUT: return "CUT";
    default: return "CMD";
  }
}

// Final answer: to the log, the LCD, and the dashboard if it asked.
void report(bool fromPc, uint32_t pcSeq, uint8_t cmd, uint8_t res, const String& text, const String& who) {
  String msg = cmdName(cmd);
  if (text.length()) { msg += ": "; msg += text; }
  logEvent("CMD", msg, "-", resultName(res), -1, who);
  if (fromPc) linkSend(linkPc, L_CMD_RESULT, cmd, 0, res, pcSeq, 0, text.c_str(), 0, 0);
  String l1 = fromPc ? String("Web ") : String("");
  l1 += cmdShort(cmd);
  l1 += res == RES_OK ? " OK" : " FAILED";
  showMsg(l1, text, RESULT_SHOW_MS);
}

void finishPending(const String& extra) {
  String text = "";
  uint8_t overall = RES_OK;
  for (uint8_t i = 0; i < MOD_COUNT; i++) {
    ModuleView& m = *MODS[i];
    if (!(pend.targets & m.mask)) continue;
    String r;
    if (pend.done & m.mask) {
      if (pend.res[i] == RES_OK) r = pend.cmd == CMD_TEST_CUT && pend.why[i].length() ? pend.why[i] : String("OK");
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
  if (pcWait.active) {                                      // the dashboard command that was waiting
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
  for (uint8_t i = 0; i < MOD_COUNT; i++) {
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
  uint8_t i = m.idx;
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
    case CMD_MAINT_START: case CMD_CLEAR_FAULT: case CMD_TEST_CUT:         return R_MAINTENANCE;
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
  if (cmd == CMD_TEST_CUT && (target == NODE_GATEWAY || (arg >> 16) == NODE_GATEWAY)) {
    // a link of the gateway's own: cut (or restore) it here
    uint8_t other = target == NODE_GATEWAY ? (uint8_t)(arg >> 16) : target;
    MeshPeer* P = mesh.find(other);
    uint32_t secs = min(arg & 0xFFFF, TEST_CUT_MAX_S);
    if (!P) { report(fromPc, pcSeq, cmd, RES_BAD, "Not a module", who); return; }
    P->cutUntil = secs ? (millis() + secs * 1000) | 1 : 0;
    report(fromPc, pcSeq, cmd, RES_OK, secs ? "Direct link G-" + String(nodeLetter(other)) + " cut for " + String(secs) + " s (relay test)"
                                            : "Relay test ended: G-" + String(nodeLetter(other)) + " direct again", who);
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
  uint8_t targets = target == TARGET_ALL ? ALL_MODS : isModule(target) ? modFor(target)->mask : 0;
  if (!targets) { report(fromPc, pcSeq, cmd, RES_BAD, "Unknown target", who); return; }
  if (cmd == CMD_TEST_CUT && targets == ALL_MODS) { report(fromPc, pcSeq, cmd, RES_BAD, "Pick one link", who); return; }
  if (pend.active) {
    if (fromPc && !pend.fromPc && !pcWait.active) {          // dashboard goes next, right after the keypad command
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
  for (uint8_t i = 0; i < MOD_COUNT; i++) { pend.res[i] = 0; pend.why[i] = ""; pend.tries[i] = 0; pend.nextTry[i] = 0; pend.firstSeq[i] = pend.lastSeq[i] = 0; }
  logEvent("CMD", String(cmdName(cmd)) + " sent to " + maskText(targets), "-", "SENT", -1, who);
  pendingStep();
}

// =====================================================================
//  DASHBOARD LOGIN + SESSION
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
  logEvent("AUTH", "Dashboard session ended (" + why + ")", "-", "-", -1, sess.user + "@web");
  sess.active = false;
  sess.id = 0;                                     // a dashboard command still waiting won't run now
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
  String who = (u.length() ? u : String("?")) + "@web";

  if (ok) {
    pcLock.success();
    if (sess.active) endSession("new login", false);     // the new login's answer follows
    sess.active = true; sess.id = esp_random() | 1; sess.user = u; sess.role = pu->role;
    sess.lastUse = sess.started = millis();
    logEvent("AUTH", String("Dashboard login (") + roleName(pu->role) + ")", "-", "SUCCESS", -1, who);
    sendLoginResult(RES_OK, pu->role, sess.id, "Welcome " + u);
    showMsg("Web login", u);
    return;
  }
  uint32_t lockS = pcLock.fail();
  logEvent("AUTH", "Dashboard login failed", "-", "FAIL", -1, who);
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
  if (cmd == CMD_RESEND_LOG) nextPcResendTo = sid;                     // session field = last line wanted
  bool needsLogin = !(cmd == CMD_SET_TIME || cmd == CMD_RESEND_LOG);   // read-only / housekeeping
  if (!needsLogin) { runCommand(cmd, target, R_NONE, "server", arg, true, seq); return; }
  if (!sess.active || sid != sess.id) {
    logEvent("CMD", String(cmdName(cmd)) + " from dashboard refused: not logged in", "-", "DENIED", -1, "?@web");
    linkSend(linkPc, L_CMD_RESULT, cmd, 0, RES_DENIED, seq, 0, "Not logged in", 0, 0);
    return;
  }
  sess.lastUse = millis();
  if (kpBusy()) { logEvent("AUTH", "Keypad entry cancelled: dashboard command has priority"); kpLogout(); }
  runCommand(cmd, target, sess.role, sess.user + "@web", arg, true, seq);
}

void checkSession() {
  if (!sess.active) return;
  if (!linkPc.trk.online)                          endSession("server link lost", false);
  else if (millis() - sess.lastUse > SESSION_IDLE_MS) endSession("idle 5 min", true);
  else if (millis() - sess.started > SESSION_MAX_MS)  endSession("30 min limit", true);
}

// =====================================================================
//  PACKETS IN
// =====================================================================
void onLinkUp(MeshPeer& L) {
  ModuleView* m = modFor(L.node);
  if (m) { m->seenStatus = false; m->timeSent = false; }
}

void onLinkDown(MeshPeer& L) {
  ModuleView* m = modFor(L.node);
  L.loggedRoute = 0; L.routeSince = 0;
  if (m && m->top != m->savedTop) saveTop(*m);
  if (m && m->wasArmed) logEvent("COMM", String(L.name) + " LOST while armed (jammed or destroyed?)", "-", "-", 3);
  else                  logEvent("COMM", String(L.name) + " link DOWN");
  if (m) m->seenStatus = false;
}

void handlePacket(const RxItem& it) {
  LinkPacket p;
  memcpy(&p, it.data, sizeof(p));
  if (!linkWellFormed(p, it.len)) { reject(RJ_MALFORMED, "Malformed packet"); return; }     // T08
  if (p.dst != NODE_GATEWAY) {                     // between two modules: pass it on if it asks us to relay
#if !WOKWI_SIM
    if (it.via != VIA_RADIO) return;               // never from the server
#endif
    MeshPeer* to = mesh.forwardTo(p, WOKWI_SIM ? nullptr : it.src);
    if (to && linkUsable(*to)) rawSend(*to, p);    // unchanged: still signed by one module for the other
    return;
  }
  MeshPeer* L = linkFor(p.src);
  if (!L) { reject(RJ_UNKNOWN, "Unknown sender"); return; }
  MeshPeer* hop = L;                               // the board the radio frame came from
  if (p.via) {
    hop = mesh.find(p.via);
    if (!hop || hop == L || L == &linkPc) { reject(RJ_OTHER, String(L->name) + ": bad relay"); return; }
  }
  if (L != &linkPc && mesh.isCut(*hop)) return;    // relay test: this direct link counts as broken
  if (!linkUsable(*L) || !linkUsable(*hop)) { reject(RJ_OTHER, String(hop->name) + ": link not encrypted - set MACs"); return; }
#if !WOKWI_SIM
  if ((L == &linkPc) != (it.via == VIA_MQTT)) { reject(RJ_OTHER, String(L->name) + ": arrived on the wrong link"); return; }
  if (hop->macSet && memcmp(it.src, hop->mac, 6) != 0) { reject(RJ_MAC, String(hop->name) + ": MAC not allowed"); return; }
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
  if (tr == TR_DUP) return;                                  // the second copy (straight + relayed)
  if (tr == TR_UNSYNCED) {                                   // waiting for its HELLO: tell it who we are
    if (m) { L->trk.sendHello = false; linkSend(*L, L_HELLO, radioChannel(), 0, 0, unixNow(), 0, nullptr, 0, 0); }
    return;
  }
  if (tr == TR_OLD_BOOT) { reject(RJ_REPLAY, String(L->name) + ": older boot number refused (flash erased? restart the gateway)"); return; }
  if (tr == TR_REPLAY) {
    uint32_t b = p.bootId;
    if (m && b != L->trk.bootId && millis() - L->lastKick > 1000) {   // a module restarted and its HELLO
      L->lastKick = millis();                                         // was lost: nudge it to send another
      linkSend(*L, L_HELLO, radioChannel(), 0, 0, unixNow(), 0, nullptr, 0, 0);
    }
    reject(RJ_REPLAY, String(L->name) + ": replayed/old packet");
    return;
  }
  if (m) mesh.heard(*L, p, tr, it.via == VIA_RADIO ? it.rssi : 0);
  if (tr == TR_NEW_BOOT) {
    logEvent("COMM", String(L->name) + " restarted (" + resetReasonName(p.resetReason) + ")");
    if (m) m->seenStatus = false;                           // re-check its log numbering
    else   endSession("server restarted", true);
  }
  if (!L->trk.online) {
    L->trk.online = true;
    logEvent("COMM", String(L->name) + " link UP" + (p.via ? " (through " + nodeName(p.via) + ")" : String("")));
    onLinkUp(*L);
  }

  if (m) {
    switch (p.type) {
      case L_HELLO: case L_STATUS:
        if (tr == TR_LATE) break;                   // an older beat that came round the long way
        onModuleStatus(*m, p);
        {
          bool hello = ++L->beats % 10 == 1 || L->trk.sendHello;
          L->trk.sendHello = false;
          linkSend(*L, hello ? L_HELLO : L_ACK, radioChannel(), 0, 0, unixNow(), 0, nullptr, 0, 0);   // "link alive" + our channel
        }
        break;
      case L_LOG:        onModuleLog(*m, p); break;
      case L_CMD_RESULT: onModuleCmdResult(*m, p); break;
      case L_PEER_EVENT: case L_PEER_ALARM: break;  // module to module (a broadcast copy): not for us
      default:           reject(RJ_OTHER, String(L->name) + ": unexpected packet type " + String(p.type)); break;
    }
  } else {                                         // the server
    switch (p.type) {
      case L_HELLO: case L_STATUS: break;          // heartbeat
      case L_LOGIN_REQ:  onLoginReq(p); break;
      case L_LOGIN_RESP: onLoginResp(p); break;
      case L_PC_CMD:     onPcCommand(p); break;
      default:           reject(RJ_OTHER, String("Server: unexpected packet type ") + String(p.type)); break;
    }
  }
}

uint8_t radioChannel() {                         // told to the modules in every HELLO / ACK
#if WOKWI_SIM
  return 0;
#else
  return netCh;
#endif
}

void checkLinkTimeout(MeshPeer& L) {
#if WOKWI_SIM
  uint32_t limit = LINK_TIMEOUT_MS;
#else
  uint32_t limit = &L == &linkPc ? SERVER_TIMEOUT_MS : moduleLinkTimeout();
#endif
  if (L.trk.online && (int32_t)(millis() - L.trk.lastHeard) > (int32_t)limit) {
    L.trk.online = false;
    onLinkDown(L);                                                                         // T09
  }
}

// =====================================================================
//  STATUS TO THE SERVER + HOUSEKEEPING WITH THE MODULES
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
  s += String(",WIFI:") + (WiFi.status() == WL_CONNECTED ? String(WiFi.RSSI()) : String("-"));
  s += String(",CH:") + String(WiFi.channel());
  char net[MESH_SIZE + 1];
  mesh.netText(net);
  s += String(",NET:") + net;
  s += String(",FWD:") + String(mesh.forwarded);
  String cut = "";
  for (MeshPeer* P : RADIO_PEERS) if (mesh.isCut(*P)) cut += nodeLetter(P->node);
  if (cut.length()) s += ",CUT:" + cut;
  s += String(",FW:") + FIRMWARE_VERSION;
  return s;
}

// A module link switched between direct and relayed: logged once it has held 2 s.
void routeCheck(MeshPeer& L, uint32_t now) {
  if (!L.trk.online || L.route == L.loggedRoute) { L.routeSince = 0; return; }
  if (!L.routeSince) { L.routeSince = now; return; }
  if (now - L.routeSince < 2000) return;
  if (L.route) logEvent("COMM", String(L.name) + ": direct link lost, relayed through " + nodeName(L.route));
  else         logEvent("COMM", String(L.name) + ": direct link back");
  L.loggedRoute = L.route;
  L.routeSince = 0;
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
  for (MeshPeer* L : LINKS) checkLinkTimeout(*L);
  for (MeshPeer* L : RADIO_PEERS)
    if (L->cutUntil && !notYet(L->cutUntil)) { L->cutUntil = 0; logEvent("COMM", "Relay test over: direct link to " + String(L->name) + " back in use"); }
  pendingStep();

  if (now - lastStatus >= STATUS_EVERY_MS) {        // 1 s: five status lines to the server
    lastStatus = now;
    for (MeshPeer* L : RADIO_PEERS) { if (L->trk.online) mesh.chooseRoute(*L); routeCheck(*L, now); }
    sendPcStatus(NODE_GATEWAY, gwStatusText());
    for (ModuleView* m : MODS) {
      String st = m->status;
      if (!modOnline(*m)) { st = String(m->letter); st += ",OFFLINE"; }
      else if (m->L->rssi) { st += ",RSSI:"; st += String(m->L->rssi); }    // how well the gateway hears it
      sendPcStatus(m->L->node, st);
    }
    for (ModuleView* m : MODS) moduleHousekeeping(*m);
  } else if (linkPc.trk.online) {                   // log lines only while the server is listening
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
    bool linkProblem = false;
    for (ModuleView* m : MODS) if (!modOnline(*m)) linkProblem = true;
    if (attention) y = true; else if (linkProblem) y = slow;
    if (pr < 2) g = allIn(MS_ARMED) ? true : beat;   // steady = system armed, blinking = not
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
        case '1': kpLogout(); runCommand(CMD_ARM,       TARGET_ALL, role, who, 0, false, 0); break;   // T01
        case '2': kpLogout(); runCommand(CMD_DISARM,    TARGET_ALL, role, who, 0, false, 0); break;
        case '3': kpLogout(); runCommand(CMD_ACK_ALARM, TARGET_ALL, role, who, 0, false, 0); break;
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
      if (key >= '1' && key <= '4') t = NODE_MOD_A + (key - '1');
      else if (key == '5') t = TARGET_ALL;
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
      String mode = allIn(MS_ARMED) ? "ARMED" : allIn(MS_DISARMED) ? "DISARMED" : "MIXED";
      l1 = "SYS " + mode + " P" + String(systemPriority());
    }
    if ((millis() / 3000) % 2 == 0)                  // two pages: A B + server, C D + mesh
      l2 = modCell(modA) + " " + modCell(modB) + " PC:" + (sess.active ? "L" : linkPc.trk.online ? "Y" : "N");
    else {
      uint8_t relayed = 0;
      for (MeshPeer* L : RADIO_PEERS) if (L->trk.online && !mesh.directOk(*L)) relayed++;
      l2 = modCell(modC) + " " + modCell(modD) + (relayed ? " R:" + String(relayed) : String(" M:OK"));
    }
  }
  if (pend.active) { l1 = String("Sending ") + cmdShort(pend.cmd); l2 = "please wait"; }
  else if (kpStage == KP_MENU) {
    l1 = "1Arm 2Dis 3Ack";
    l2 = kpUser && kpUser->role == R_MAINTENANCE ? "4Mnt 5Clr 6End" : "6EndMnt *=out";
  } else if (kpStage == KP_TARGET) {
    l1 = String(cmdShort(kpCmd)) + " on which?";
    l2 = kpCmd == CMD_CLEAR_FAULT ? "1-4=A-D 5All 0GW" : "1-4=A-D 5=All";
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
  uint32_t fileGw = 0, fileMod[MOD_COUNT] = {};
  if (fsOk) scanLogTail(fileGw, fileMod);           // carry on exactly where the log file ends
  uint32_t savedGw = prefs.getUInt("logNo", 0);
  gwNo = fileGw ? max(fileGw, savedGw) : savedGw + 16;   // no file: skip ahead, never reuse a number
  prefs.putUInt("logNo", gwNo);
  uint32_t misses[MOD_COUNT];
  for (ModuleView* m : MODS) {
    m->top = max(fileMod[m->idx], (uint32_t)prefs.getUInt(m->key("top").c_str(), 0));
    misses[m->idx] = prefs.getUInt(m->key("miss").c_str(), 0);
    m->win.reset(m->top + 1); m->checkedTop = m->top; m->savedTop = m->top;
  }
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
  if (!rfid.online)    logEvent("COMM", "RFID reader not found - use the dashboard", "-", "ERROR");
#if !WOKWI_SIM
  uint8_t own[6];
  WiFi.macAddress(own);
  if (macIsSet(MAC_GATEWAY) && memcmp(own, MAC_GATEWAY, 6) != 0)
    logEvent("SYSTEM", "MAC differs from MAC_GATEWAY in secrets.h", "-", "WARN");
  for (MeshPeer* L : RADIO_PEERS) {
    if (linkUsable(*L) && L->encrypted) continue;
    String why = L->macSet ? " encryption setup FAILED" : " MAC not set in secrets.h";
    if (ALLOW_UNENCRYPTED) logEvent("COMM", String(L->name) + why + ": signed, NOT encrypted", "-", "WARN");
    else                   logEvent("COMM", String(L->name) + why + ": link OFF", "-", "ERROR");
  }
#endif
#if ENROLL_MODE
  logEvent("SYSTEM", "ENROLL MODE ON - card UIDs printed. Set 0 for the demo", "-", "WARN");
#endif
  for (uint8_t i = 0; i < MOD_COUNT; i++) {
    ModuleView& m = *MODS[i];
    m.savedMiss = misses[i];
    if (misses[i] && misses[i] <= m.top)                   // we restarted in the middle of fetching lines
      logEvent("COMM", String(m.L->name) + " log lines from " + String(misses[i]) + " to " + String(m.top) + " may be incomplete (gateway restarted)", "-", "LOST");
  }
  if (savedTamper) {
    gwState = GS_TAMPER;
    logEvent("TAMPER", "Gateway tamper restored after restart", "-", "-", 3);              // T10
  }
#if !WOKWI_SIM
  if (radioReady) netBegin();
#endif
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
    if (rfid.check())    logEvent("COMM", rfid.online ? "RFID reader online" : "RFID reader OFFLINE - use the dashboard", "-", "-", rfid.online ? -1 : 3);
    if (display.check()) logEvent("COMM", display.online ? "LCD online" : "LCD OFFLINE");
  }
  kpLock.tick();
  pcLock.tick();
#if !WOKWI_SIM
  netLoop();
#endif
  linkLoop();
  checkSession();
  handleUi(key);
  updateOutputs();
  renderLcd();
  delay(LOOP_MS);
}
