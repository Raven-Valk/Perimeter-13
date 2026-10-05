// =====================================================================
//  PINNACLE 1 — PROJECT 13 — SECURE PERIMETER INTRUSION DETECTION
//  NODE 1 : MAIN CONTROLLER (LEFT PIR + operator interface)
//
//  Hardware on this board:
//    HC-SR501 PIR (Zone 1, facing LEFT), MAGREED reed switch (enclosure tamper),
//    RC522 RFID, 4x4 keypad, LCD1602 I2C, active buzzer, R/G/Y LEDs.
//  Receives signed ESP-NOW messages from Node 2 (Zone 2 = RIGHT PIR, Zone 3 = IR later).
//
//  States: BOOT -> WAIT_AUTH -> MONITORING -> INTRUSION / TAMPER_FAULT
//          / MAINTENANCE -> RECOVERY -> MONITORING
//  Alert priority: P0 normal, P1 warning, P2 intrusion, P3 tamper/fault
//
//  Board : ESP32 Dev Module   |   Arduino-ESP32 core 3.x (2.x also works)
//  Libraries (Library Manager): MFRC522 (GithubCommunity / miguelbalboa),
//            Keypad (Mark Stanley, Alexander Brevig),
//            LiquidCrystal I2C (Frank de Brabander)
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
#include "common.h"

// ---------------- roles + user table type (used by secrets.h) ----------------
enum Role : uint8_t { R_NONE = 0, R_OPERATOR = 1, R_MAINTENANCE = 2 };
const char* ROLE_NAMES[] = { "NONE", "OPERATOR", "MAINTENANCE" };

struct User {
  const char* name;
  uint8_t     uid[10];
  uint8_t     uidLen;
  const char* pinHashHex;   // SHA-256(PIN_SALT + PIN), lowercase hex
  Role        role;
};
#include "secrets.h"

// 1 = print full card UIDs on Serial when scanned (for setting up secrets.h).
// Set back to 0 for the demo: full UIDs must not appear in logs.
#define ENROLL_MODE 0

// =====================================================================
//  PINS  (ESP32 DevKit V1, 30-pin — check against your own board)
// =====================================================================
const uint8_t PIN_SDA = 21, PIN_SCL = 22;
const uint8_t PIN_RFID_SCK = 18, PIN_RFID_MISO = 19, PIN_RFID_MOSI = 23;
const uint8_t PIN_RFID_SS = 5, PIN_RFID_RST = 4;
byte KP_ROWS[4] = { 13, 14, 27, 26 };
byte KP_COLS[4] = { 25, 33, 32, 16 };
const uint8_t PIN_BUZZER     = 17;
const uint8_t PIN_LED_GREEN  = 2;
const uint8_t PIN_LED_RED    = 15;
const uint8_t PIN_LED_YELLOW = 12;   // strapping pin: LED + resistor to GND keeps it LOW at boot
const uint8_t PIN_PIR        = 35;   // input-only: external 10k pull-up to 3.3 V
const uint8_t PIN_TAMPER     = 34;   // input-only: external 10k pull-up; reed to GND
const bool    BUZZER_ACTIVE_LOW = false;   // true if your module beeps when the pin is LOW
const uint8_t LCD_ADDR = 0x27;             // try 0x3F if the LCD stays blank

// =====================================================================
//  TIMING / LIMITS  (finalise at Design Review 1)
// =====================================================================
const uint32_t LOOP_MS            = 50;
const uint32_t PIR_WARMUP_MS      = 60000;
const uint32_t PIR_MAX_HIGH_MS    = 30000;
const uint32_t CORROBORATION_MS   = 20000;   // P1 window, counted from the first trigger
const uint8_t  REPEAT_TRIGGERS    = 3;       // same side firing this often in the window = sustained presence
const uint32_t NODE_TIMEOUT_MS    = 3000;
const uint8_t  MAX_ATTEMPTS       = 3;
const uint32_t BASE_LOCKOUT_S     = 60;      // 60, 120, 240, 480, 960
const uint8_t  MAX_LOCKOUT_LEVEL  = 4;
const uint32_t PIN_TIMEOUT_MS     = 20000;
const uint32_t DISARM_REQUEST_MS  = 20000;
const uint32_t MAINT_TIMEOUT_MS   = 300000;  // 5 minutes
const uint32_t PERIPH_CHECK_MS    = 5000;
const uint32_t FAULT_REMINDER_MS  = 60000;
const uint32_t MSG_SHOW_MS        = 1500;
const size_t   LOG_MAX_BYTES      = 32 * 1024;

// =====================================================================
//  STATE MACHINE
// =====================================================================
enum State : uint8_t { S_BOOT, S_WAIT_AUTH, S_MONITORING, S_INTRUSION,
                       S_TAMPER_FAULT, S_MAINTENANCE, S_RECOVERY };
const char* STATE_NAMES[] = { "BOOT", "WAIT_AUTH", "MONITORING", "INTRUSION",
                              "TAMPER_FAULT", "MAINTENANCE", "RECOVERY" };
#define B(s) (1 << (s))
// Allowed transitions. Anything else is rejected and logged.
const uint8_t ALLOWED[] = {
  /* BOOT         */ B(S_WAIT_AUTH) | B(S_MONITORING) | B(S_TAMPER_FAULT),
  /* WAIT_AUTH    */ B(S_MONITORING) | B(S_TAMPER_FAULT),
  /* MONITORING   */ B(S_INTRUSION) | B(S_TAMPER_FAULT) | B(S_MAINTENANCE) | B(S_WAIT_AUTH),
  /* INTRUSION    */ B(S_RECOVERY) | B(S_TAMPER_FAULT),
  /* TAMPER_FAULT */ B(S_RECOVERY),
  /* MAINTENANCE  */ B(S_RECOVERY) | B(S_TAMPER_FAULT),
  /* RECOVERY     */ B(S_MONITORING) | B(S_WAIT_AUTH) | B(S_TAMPER_FAULT),
};

State    state          = S_BOOT;
uint32_t stateEnteredAt = 0;
Role     sessionRole    = R_NONE;
String   faultReason    = "";
String   selfTestReason = "";

// =====================================================================
//  ZONES
// =====================================================================
struct Zone {
  uint8_t     id;
  const char* name;
  bool        remote;         // true = reported by Node 2
  uint8_t     health;
  bool        active;
  bool        eventPending;   // a new detection waiting to be processed
  uint8_t     loggedHealth;   // last health value written to the log
  uint8_t     hits;           // triggers inside the current P1 window
};
Zone zones[] = {
  { 1, "Z1-LEFT",  false, H_WARMUP,  false, false, 0xFF, 0 },   // Node 1 PIR, faces left
  { 2, "Z2-RIGHT", true,  H_OFFLINE, false, false, 0xFF, 0 },   // Node 2 PIR, faces right
  // { 3, "Z3-IR", true, H_OFFLINE, false, false, 0xFF, 0 },    // add when Node 2's IR is enabled
};
const uint8_t ZONE_COUNT = sizeof(zones) / sizeof(zones[0]);

uint32_t windowUntil = 0;      // P1 corroboration window end
uint8_t  windowZone  = 0;      // zone that opened the window

// =====================================================================
//  GLOBALS
// =====================================================================
Preferences       prefs;
MFRC522           rfid(PIN_RFID_SS, PIN_RFID_RST);
LiquidCrystal_I2C lcd(LCD_ADDR, 16, 2);
char KEYS[4][4] = { { '1', '2', '3', 'A' },
                    { '4', '5', '6', 'B' },
                    { '7', '8', '9', 'C' },
                    { '*', '0', '#', 'D' } };
Keypad keypad = Keypad(makeKeymap(KEYS), KP_ROWS, KP_COLS, 4, 4);

// persisted in NVS flash (survive power loss)
uint32_t bootNo = 0;
uint8_t  failedAttempts = 0;
uint8_t  lockoutLevel = 0;
uint32_t lockoutRemainingS = 0;
bool     wasArmed = false;

uint32_t lastLockTick = 0;
bool     fsOk = false, rfidOnline = false, lcdOnline = false;
bool     tamperOpen = false, tamperRaw = false;
uint8_t  tamperStable = 0;
bool     pirWasHigh = false;
uint32_t pirHighSince = 0;
uint32_t lastPeriphCheck = 0, lastFaultReminder = 0, lastRejectLog = 0;
uint32_t maintUntil = 0, chirpUntil = 0, outputTestUntil = 0;
bool     maintShowStatus = false;
bool     disarmRequested = false;
uint32_t disarmRequestAt = 0;

// LCD
String   screen1 = "", screen2 = "";     // what the current state wants to show
String   msg1 = "", msg2 = "";           // short pop-up message
uint32_t msgUntil = 0;
String   lcdCache1 = "", lcdCache2 = "";

// authentication entry
struct AuthEntry {
  bool     haveCard = false;
  uint8_t  uid[10];
  uint8_t  uidLen = 0;
  String   pin = "";
  uint32_t startedAt = 0;
} auth;

// Node 2 link
struct {
  bool     synced = false;
  bool     online = false;
  uint32_t bootId = 0;
  uint32_t lastSeq = 0;
  uint32_t lastHeard = 0;
} node2;

struct RxItem { int len; uint8_t data[sizeof(Packet)]; };
QueueHandle_t rxQueue;

// forward declarations
bool goTo(State next, const String& reason);
void chirp(uint32_t ms = 120);
void logEvent(const char* type, const String& event, const char* zone = "-",
              const char* result = "-", int prio = -1, int role = -1, const String& uid = "-");

// =====================================================================
//  SMALL HELPERS
// =====================================================================
Zone* findZone(uint8_t id) {
  for (uint8_t i = 0; i < ZONE_COUNT; i++) if (zones[i].id == id) return &zones[i];
  return nullptr;
}
const char* zoneName(uint8_t id) { Zone* z = findZone(id); return z ? z->name : "?"; }

void chirp(uint32_t ms) { chirpUntil = millis() + ms; }

void showMsg(const String& l1, const String& l2) {
  msg1 = l1; msg2 = l2; msgUntil = millis() + MSG_SHOW_MS;
}
void setScreen(const String& l1, const String& l2) { screen1 = l1; screen2 = l2; }

String sha256Hex(const String& s) {
  uint8_t out[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
             (const uint8_t*)s.c_str(), s.length(), out);
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", out[i]);
  hex[64] = 0;
  return String(hex);
}

// Only the last 2 bytes of a card UID ever reach the log.
String maskUid(const uint8_t* uid, uint8_t len) {
  if (len == 0) return "-";
  String s = "**";
  for (uint8_t i = (len > 2 ? len - 2 : 0); i < len; i++) {
    char b[4]; sprintf(b, ":%02X", uid[i]); s += b;
  }
  return s;
}

uint8_t currentPriority() {
  if (state == S_TAMPER_FAULT) return 3;
  if (state == S_INTRUSION)    return 2;
  if (state == S_MONITORING && notYet(windowUntil)) return 1;
  return 0;
}

void saveAuthCounters() {
  prefs.putUChar("failed", failedAttempts);
  prefs.putUChar("lockLvl", lockoutLevel);
  prefs.putUInt("lockRem", lockoutRemainingS);
}
void setArmed(bool armed) {
  wasArmed = armed;
  prefs.putBool("armed", armed);
}

// =====================================================================
//  EVENT LOG  (LittleFS /log.csv + Serial)
//  boot,uptime_ms,priority,state,type,event,zone,role,uid,result
// =====================================================================
void logEvent(const char* type, const String& event, const char* zone,
              const char* result, int prio, int role, const String& uid) {
  String ev = event; ev.replace(",", ";");
  String line = String(bootNo) + "," + String(millis()) + ",P" +
                String(prio < 0 ? currentPriority() : prio) + "," +
                STATE_NAMES[state] + "," + type + "," + ev + "," + zone + "," +
                ROLE_NAMES[role < 0 ? sessionRole : role] + "," + uid + "," + result;
  Serial.println(line);
  if (!fsOk) return;

  File f = LittleFS.open("/log.csv", FILE_APPEND);
  if (!f) return;
  if (f.size() > LOG_MAX_BYTES) {             // rotate: keep one old file
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

void rejectInput(const String& why) {               // T08
  logEvent("INPUT", why, "-", "REJECTED");
  showMsg("Invalid input", why);
  chirp();
}

// =====================================================================
//  STATE TRANSITIONS
// =====================================================================
void resetAuth() { auth.haveCard = false; auth.uidLen = 0; auth.pin = ""; auth.startedAt = 0; }

void onEnter(State s, const String& reason) {
  resetAuth();
  disarmRequested = false;
  switch (s) {
    case S_TAMPER_FAULT:
      faultReason = reason;
      lastFaultReminder = millis();
      break;
    case S_MAINTENANCE:
      maintUntil = millis() + MAINT_TIMEOUT_MS;
      maintShowStatus = false;
      break;
    case S_MONITORING:
      windowUntil = millis();
      for (uint8_t i = 0; i < ZONE_COUNT; i++) { zones[i].eventPending = false; zones[i].hits = 0; }
      break;
    case S_WAIT_AUTH:
      sessionRole = R_NONE;
      break;
    default: break;
  }
}

bool goTo(State next, const String& reason) {
  if (!(ALLOWED[state] & B(next))) {
    logEvent("STATE", String("Invalid ") + STATE_NAMES[state] + "->" + STATE_NAMES[next], "-", "REJECTED");
    return false;
  }
  logEvent("STATE", String(STATE_NAMES[state]) + "->" + STATE_NAMES[next] + " (" + reason + ")");
  state = next;
  stateEnteredAt = millis();
  onEnter(next, reason);
  return true;
}

// =====================================================================
//  RADIO: messages from Node 2
// =====================================================================
#if ESP_ARDUINO_VERSION_MAJOR >= 3
void onRecv(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
#else
void onRecv(const uint8_t* mac, const uint8_t* data, int len) {
#endif
  // Runs in the Wi-Fi task: just copy and queue, process in loop().
  RxItem it;
  it.len = len;
  memcpy(it.data, data, min(len, (int)sizeof(it.data)));
  xQueueSend(rxQueue, &it, 0);
}

void rejectPacket(const String& why) {
  if (millis() - lastRejectLog < 2000) return;        // avoid flooding the log
  lastRejectLog = millis();
  logEvent("COMM", why, "-", "REJECTED");
}

void processRadio() {
  RxItem it;
  while (xQueueReceive(rxQueue, &it, 0) == pdTRUE) {
    if (it.len != (int)sizeof(Packet)) { rejectPacket("Malformed packet len=" + String(it.len)); continue; }
    Packet p;
    memcpy(&p, it.data, sizeof(p));
    if (p.version != PROTO_VERSION || p.zoneCount > MAX_REMOTE_ZONES ||
        p.type < MSG_HELLO || p.type > MSG_EVENT) { rejectPacket("Malformed packet"); continue; }
    if (p.nodeId != 2) { rejectPacket("Unknown node " + String(p.nodeId)); continue; }

    uint8_t expected[SIG_LEN];
    signPacket(SHARED_KEY, sizeof(SHARED_KEY), p, expected);
    if (!sameBytes(expected, p.sig, SIG_LEN)) { rejectPacket("Bad signature (spoofed?)"); continue; }

    if (p.type == MSG_HELLO && (!node2.synced || p.bootId != node2.bootId)) {
      // Node 2 restarted (new random bootId). Node 2 repeats HELLO every
      // 10 s, so a lost HELLO only delays re-sync. A replayed old HELLO
      // breaks the link and shows up as "Node 2 lost" -> fault (fails safe).
      logEvent("COMM", String("Node 2 booted reason=") + resetReasonName(p.resetReason));
      node2.bootId = p.bootId; node2.lastSeq = p.seq; node2.synced = true;
    } else if (!node2.synced) {
      // Node 1 restarted while Node 2 kept running: adopt its current counter.
      node2.bootId = p.bootId; node2.lastSeq = p.seq; node2.synced = true;
      logEvent("COMM", "Node 2 link synchronised");
    } else if (p.bootId != node2.bootId || p.seq <= node2.lastSeq) {
      rejectPacket("Replayed/old packet seq=" + String(p.seq));
      continue;
    }
    node2.lastSeq   = p.seq;
    node2.lastHeard = millis();
    if (!node2.online) { node2.online = true; logEvent("COMM", "Node 2 online"); }

    if (p.type == MSG_HEARTBEAT || p.type == MSG_HELLO) {
      for (uint8_t i = 0; i < p.zoneCount; i++) {
        Zone* z = findZone(p.zones[i].zone);
        if (!z || !z->remote) continue;
        z->health = p.zones[i].health;
        z->active = p.zones[i].active && z->health == H_OK;
      }
    } else if (p.type == MSG_EVENT) {
      Zone* z = findZone(p.eventZone);
      if (z && z->remote) { z->health = H_OK; z->active = true; z->eventPending = true; }
    }
  }
}

void checkNodeTimeout() {
  if (node2.online && millis() - node2.lastHeard > NODE_TIMEOUT_MS) {
    node2.online = false;
    for (uint8_t i = 0; i < ZONE_COUNT; i++)
      if (zones[i].remote) { zones[i].health = H_OFFLINE; zones[i].active = false; }
    logEvent("COMM", "Node 2 lost (no heartbeat)");                       // T09
  }
}

// =====================================================================
//  LOCAL SENSORS: Zone 1 PIR + enclosure tamper
// =====================================================================
void readLocalPir() {
  Zone& z = zones[0];
  bool high = digitalRead(PIN_PIR) == HIGH;    // pulled up: unplugged PIR = HIGH
  uint32_t now = millis();

  if (now < PIR_WARMUP_MS) {                   // ignore while the PIR settles
    z.health = H_WARMUP; z.active = false;
    pirWasHigh = high; pirHighSince = now;
    return;
  }
  if (high && !pirWasHigh) {
    pirHighSince = now;
    if (z.health == H_OK) z.eventPending = true;
  }
  pirWasHigh = high;

  if (high && now - pirHighSince > PIR_MAX_HIGH_MS) z.health = H_STUCK;   // T06
  else if (!high || z.health == H_WARMUP)          z.health = H_OK;
  z.active = high && z.health == H_OK;
}

void readTamper() {
  // Reed switch to GND with pull-up: lid closed (magnet near) = LOW.
  // Lid open OR wire cut = HIGH. Needs 2 equal readings in a row (debounce).
  bool raw = digitalRead(PIN_TAMPER) == HIGH;
  if (raw == tamperRaw) { if (tamperStable < 2) tamperStable++; }
  else { tamperRaw = raw; tamperStable = 0; }
  if (tamperStable >= 2 && tamperOpen != tamperRaw) {
    tamperOpen = tamperRaw;
    logEvent("TAMPER", tamperOpen ? "Enclosure opened" : "Enclosure closed", "-", "-",
             tamperOpen && state != S_MAINTENANCE ? 3 : -1);
  }
}

void logHealthChanges() {
  for (uint8_t i = 0; i < ZONE_COUNT; i++) {
    Zone& z = zones[i];
    if (z.health != z.loggedHealth) {
      if (z.loggedHealth != 0xFF)
        logEvent("HEALTH", String(healthName(z.loggedHealth)) + "->" + healthName(z.health), z.name);
      z.loggedHealth = z.health;
    }
  }
}

// RC522 and LCD health (T09 for wired interfaces)
void checkPeripherals() {
  byte v = rfid.PCD_ReadRegister(MFRC522::VersionReg);   // 0x91 / 0x92 on a real RC522
  bool rOk = (v != 0x00 && v != 0xFF);
  if (rOk && !rfidOnline) rfid.PCD_Init();
  if (rOk != rfidOnline) {
    rfidOnline = rOk;
    logEvent("COMM", rOk ? "RFID reader online" : "RFID reader OFFLINE - PIN-only operator login");
  }

  Wire.beginTransmission(LCD_ADDR);
  bool lOk = Wire.endTransmission() == 0;
  if (lOk && !lcdOnline) { lcd.init(); lcd.backlight(); lcdCache1 = lcdCache2 = "#"; }
  if (lOk != lcdOnline) {
    lcdOnline = lOk;
    logEvent("COMM", lOk ? "LCD online" : "LCD OFFLINE - LEDs and buzzer only");
  }
}

// =====================================================================
//  AUTHENTICATION: card + PIN   (T02, T03, T08, T09)
//  Called every loop by any state that accepts a login.
//  Returns the role once on success, otherwise R_NONE.
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

  if (auth.haveCard) {                                  // normal: card + PIN
    const User* u = findUserByUid(auth.uid, auth.uidLen);
    if (u && h.equalsIgnoreCase(u->pinHashHex)) { who = u; role = u->role; }
  } else {                                              // RFID offline: PIN only,
    for (uint8_t i = 0; i < USER_COUNT; i++)            // OPERATOR rights at most
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
  logEvent("AUTH", "Login failed", "-", "FAIL", -1, R_NONE, uidMasked);          // T02
  chirp(300);
  if (failedAttempts >= MAX_ATTEMPTS) {                                         // T03
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

Role pollAuth(char key) {
  bool cardHere = rfidOnline && rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial();

  if (lockoutRemainingS > 0) {                    // input blocked; sensors keep running
    if (cardHere) rfid.PICC_HaltA();
    if (cardHere || (key && strchr("0123456789*#", key)))
      showMsg("LOCKED", String(lockoutRemainingS) + " s left");
    return R_NONE;
  }

  if (cardHere) {
    auth.haveCard = true;
    auth.uidLen = min((int)rfid.uid.size, 10);
    memcpy(auth.uid, rfid.uid.uidByte, auth.uidLen);
    auth.pin = "";
    auth.startedAt = millis();
    rfid.PICC_HaltA();
#if ENROLL_MODE
    Serial.print("ENROLL card UID: ");
    for (uint8_t i = 0; i < auth.uidLen; i++) Serial.printf("0x%02X%s", auth.uid[i], i + 1 < auth.uidLen ? ", " : "");
    Serial.printf("   (len %u)\n", auth.uidLen);
#endif
    chirp(40);
  }

  if (auth.startedAt && millis() - auth.startedAt > PIN_TIMEOUT_MS) {
    resetAuth();
    logEvent("AUTH", "PIN entry timeout");
    showMsg("Timed out", "Start again");
  }

  if (!key) return R_NONE;
  if (key >= '0' && key <= '9') {
    if (rfidOnline && !auth.haveCard) { showMsg("Scan card first", ""); return R_NONE; }
    if (auth.pin.length() >= 6) { rejectInput("PIN too long"); resetAuth(); return R_NONE; }
    if (!auth.startedAt) auth.startedAt = millis();
    auth.pin += key;
  } else if (key == '*') {
    auth.pin = "";
  } else if (key == '#') {
    if (auth.haveCard || auth.pin.length()) return checkCredentials();
  }
  return R_NONE;      // A-D are handled by the state handlers
}

bool authInProgress() { return auth.haveCard || auth.pin.length() > 0; }

// =====================================================================
//  SELF-TEST  (boot and recovery)
// =====================================================================
bool selfTest() {
  selfTestReason = "";
  if (tamperOpen) selfTestReason += "Lid open ";
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].health != H_OK && zones[i].health != H_WARMUP)
      selfTestReason += String(zones[i].name) + " " + healthName(zones[i].health) + " ";
  if (!rfidOnline) logEvent("TEST", "RFID offline - degraded (PIN-only operator)");
  outputTestUntil = millis() + 800;               // short lamp + buzzer test
  selfTestReason.trim();
  return selfTestReason.length() == 0;
}

// =====================================================================
//  STATE HANDLERS
// =====================================================================
void handleBoot() {
  uint32_t el = millis();
  if (el < PIR_WARMUP_MS) {
    setScreen("Warming up " + String((PIR_WARMUP_MS - el) / 1000) + "s",
              String("Node2: ") + (node2.online ? "OK" : "--"));
    return;
  }
  if (!selfTest()) {
    logEvent("TEST", "Self-test FAILED: " + selfTestReason, "-", "FAIL", 3);
    goTo(S_TAMPER_FAULT, selfTestReason);
    return;
  }
  logEvent("TEST", "Self-test OK", "-", "PASS");
  // TEAM DECISION: re-arm automatically after a power cut (prevents
  // "pull the plug to disarm"). Change to S_WAIT_AUTH to disable.
  if (wasArmed) goTo(S_MONITORING, "re-armed after power loss");
  else          goTo(S_WAIT_AUTH, "boot complete");
}

void handleWaitAuth(char key) {
  String warn = "Card + PIN, #";
  for (uint8_t i = 0; i < ZONE_COUNT; i++) {
    Zone& z = zones[i];
    if (z.eventPending) { z.eventPending = false; logEvent("SENSOR", "Motion (disarmed)", z.name, "-", 0); }
    if (z.health == H_STUCK || z.health == H_OFFLINE) warn = String(z.name) + " " + healthName(z.health);
  }
  setScreen("DISARMED", warn);

  if (key >= 'A' && key <= 'D') rejectInput("Key not valid now");
  Role r = pollAuth(key);
  if (r != R_NONE) {
    if (warn != "Card + PIN, #") {                     // never arm with a broken zone
      logEvent("STATE", "Arm refused: " + warn, "-", "REJECTED", -1, r);
      showMsg("Cannot arm", warn);
      return;
    }
    sessionRole = r;
    setArmed(true);
    goTo(S_MONITORING, String(ROLE_NAMES[r]) + " armed");
  }
}

void handleMonitoring(char key) {
  // 1) Sensor health first: a broken sensor is a FAULT, never an intrusion.
  for (uint8_t i = 0; i < ZONE_COUNT; i++) {
    if (zones[i].health == H_STUCK || zones[i].health == H_OFFLINE) {
      goTo(S_TAMPER_FAULT, String(zones[i].name) + " " + healthName(zones[i].health));   // T06 / T09
      return;
    }
  }

  // 2) New detections from healthy zones.
  //    The two PIRs face LEFT and RIGHT, so an intruder is usually seen by
  //    only one of them. Confirmed intrusion (P2) when, inside one window:
  //      a) BOTH sides detect (crossing over, or standing where the
  //         two views overlap), or
  //      b) the SAME side fires REPEAT_TRIGGERS times (someone moving
  //         around there, not a one-off flicker from heat or a pet).
  //    Anything less is a P1 warning.
  if (!notYet(windowUntil))                                  // window over: start fresh
    for (uint8_t i = 0; i < ZONE_COUNT; i++) zones[i].hits = 0;

  for (uint8_t i = 0; i < ZONE_COUNT; i++) {
    Zone& z = zones[i];
    if (!z.eventPending) continue;
    z.eventPending = false;
    if (z.health != H_OK) continue;

    bool firstInWindow = !notYet(windowUntil);
    if (firstInWindow) { windowUntil = millis() + CORROBORATION_MS; windowZone = z.id; }
    if (z.hits < 255) z.hits++;

    const char* otherSide = nullptr;
    for (uint8_t j = 0; j < ZONE_COUNT; j++)
      if (j != i && zones[j].hits > 0) otherSide = zones[j].name;

    if (otherSide) {                                                                 // T05 (a)
      logEvent("ALERT", String("Corroborated both sides ") + otherSide + "+" + z.name, z.name, "-", 2);
      goTo(S_INTRUSION, "both sides");
      return;
    }
    if (z.hits >= REPEAT_TRIGGERS) {                                                 // T05 (b)
      logEvent("ALERT", String("Sustained motion ") + z.name + " x" + z.hits, z.name, "-", 2);
      goTo(S_INTRUSION, "sustained motion one side");
      return;
    }
    chirp();                                                                         // T04
    logEvent("ALERT", "Motion warning " + String(z.hits) + "/" + String(REPEAT_TRIGGERS), z.name, "-", 1);
  }

  // 3) Screen
  if (disarmRequested && millis() - disarmRequestAt > DISARM_REQUEST_MS) disarmRequested = false;
  if (notYet(windowUntil))
  {
    Zone* wz = findZone(windowZone);
    setScreen("WARNING  P1 " + String((windowUntil - millis()) / 1000 + 1) + "s",
              String(zoneName(windowZone)) + " " + String(wz ? wz->hits : 0) + "/" + String(REPEAT_TRIGGERS));
  }
  else
    setScreen("ARMED    P0", disarmRequested ? "Disarm: card+PIN" : "All zones OK");

  // 4) Operator commands
  if (key == 'D') {
    disarmRequested = true; disarmRequestAt = millis();
    showMsg("Disarm request", "Card + PIN, #");
  } else if (key == 'A' || key == 'B' || key == 'C') {
    rejectInput("Key not valid armed");                                              // T08
  }

  Role r = pollAuth(key);
  if (r == R_NONE) return;
  if (disarmRequested) {
    sessionRole = r;
    setArmed(false);
    goTo(S_WAIT_AUTH, String(ROLE_NAMES[r]) + " disarmed");
  } else if (r == R_MAINTENANCE) {                                                    // T11
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
  Role r = pollAuth(key);                    // same lockout rules as any login
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
  // keep watching the zones that still work
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
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
  String status = "";
  for (uint8_t i = 0; i < ZONE_COUNT; i++) {
    const char* h = zones[i].health == H_OK ? "OK" : zones[i].health == H_STUCK ? "STK" :
                    zones[i].health == H_OFFLINE ? "OFF" : "WUP";
    status += "Z" + String(zones[i].id) + ":" + h + " ";
  }
  setScreen("MAINT " + String(left) + "s", maintShowStatus ? status : "1Tst 2Sts 3Log C");

  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].eventPending) { zones[i].eventPending = false; logEvent("MAINT", "Test trigger", zones[i].name); }

  if (!notYet(maintUntil)) {                                  // session expires
    logEvent("MAINT", "Session timed out");
    goTo(S_RECOVERY, "maintenance timeout");
    return;
  }
  if (!key) return;
  switch (key) {
    case '1': outputTestUntil = millis() + 1500; logEvent("MAINT", "Output test", "-", "OK"); break;
    case '2': maintShowStatus = !maintShowStatus; logEvent("MAINT", "Status view", "-", "OK"); break;
    case '3': dumpLogToSerial(); showMsg("Log sent to", "USB serial"); logEvent("MAINT", "Log exported", "-", "OK"); break;
    case 'C': logEvent("MAINT", "Maintenance ended", "-", "OK"); goTo(S_RECOVERY, "maintenance exit"); break;
    default:  rejectInput("Unknown command"); break;                                     // T08
  }
}

void handleRecovery() {
  setScreen("RECOVERY", "Revalidating...");
  if (millis() - stateEnteredAt < 1500) return;       // let a fresh heartbeat arrive
  if (selfTest()) {
    logEvent("TEST", "Recovery self-test OK", "-", "PASS");
    setArmed(true);
    goTo(S_MONITORING, "revalidated");                                                // T12
  } else {
    logEvent("TEST", "Recovery self-test FAILED: " + selfTestReason, "-", "FAIL", 3);
    goTo(S_TAMPER_FAULT, selfTestReason);
  }
}

// =====================================================================
//  OUTPUTS: LEDs, buzzer, LCD
// =====================================================================
void updateOutputs() {
  uint32_t now = millis();
  bool fast = (now / 250) % 2, slow = (now / 500) % 2, beat = (now / 1000) % 2;
  bool g = false, r = false, y = false, buz = false;

  switch (state) {
    case S_BOOT:         y = slow; break;
    case S_WAIT_AUTH:    g = beat; break;                        // slow green = disarmed
    case S_MONITORING:   if (currentPriority() == 1) y = true; else g = true; break;
    case S_INTRUSION:    r = true; buz = true; break;            // P2: continuous
    case S_TAMPER_FAULT: r = fast; buz = (now / 200) % 2; break; // P3: fast pulse
    case S_MAINTENANCE:  y = slow; break;                        // silent
    case S_RECOVERY:     y = true; break;
  }
  if (notYet(outputTestUntil)) { g = r = y = true; buz = (now / 300) % 2; }
  if (notYet(chirpUntil)) buz = true;

  digitalWrite(PIN_LED_GREEN, g);
  digitalWrite(PIN_LED_RED, r);
  digitalWrite(PIN_LED_YELLOW, y);
  digitalWrite(PIN_BUZZER, BUZZER_ACTIVE_LOW ? !buz : buz);
}

String pad16(String s) { if (s.length() > 16) s = s.substring(0, 16); while (s.length() < 16) s += ' '; return s; }

void renderLcd() {
  String l1 = screen1, l2 = screen2;
  if (authInProgress()) {
    l1 = auth.haveCard ? "Card read" : "PIN only";
    l2 = "PIN: ";
    for (unsigned i = 0; i < auth.pin.length(); i++) l2 += '*';      // never show digits
  }
  if (lockoutRemainingS > 0 && state != S_BOOT) l2 = "Locked " + String(lockoutRemainingS) + "s";
  if (notYet(msgUntil)) { l1 = msg1; l2 = msg2; }

  l1 = pad16(l1); l2 = pad16(l2);
  if (!lcdOnline) return;
  if (l1 != lcdCache1) { lcd.setCursor(0, 0); lcd.print(l1); lcdCache1 = l1; }
  if (l2 != lcdCache2) { lcd.setCursor(0, 1); lcd.print(l2); lcdCache2 = l2; }
}

// =====================================================================
//  SETUP + LOOP
// =====================================================================
void setup() {
  Serial.begin(115200);
  delay(200);

  pinMode(PIN_LED_GREEN, OUTPUT);  pinMode(PIN_LED_RED, OUTPUT);  pinMode(PIN_LED_YELLOW, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);     digitalWrite(PIN_BUZZER, BUZZER_ACTIVE_LOW ? HIGH : LOW);
  pinMode(PIN_PIR, INPUT);         // GPIO 34-39: no internal pull-ups -> external 10k
  pinMode(PIN_TAMPER, INPUT);

  // Persistent counters (survive power loss) — T03 / T10
  prefs.begin("pids", false);
  bootNo            = prefs.getUInt("boot", 0) + 1;  prefs.putUInt("boot", bootNo);
  failedAttempts    = prefs.getUChar("failed", 0);
  lockoutLevel      = prefs.getUChar("lockLvl", 0);
  lockoutRemainingS = prefs.getUInt("lockRem", 0);
  wasArmed          = prefs.getBool("armed", false);
  lastLockTick      = millis();

  fsOk = LittleFS.begin(true);     // formats on first use

  Wire.begin(PIN_SDA, PIN_SCL);
  lcd.init(); lcd.backlight();
  Wire.beginTransmission(LCD_ADDR);
  lcdOnline = Wire.endTransmission() == 0;

  SPI.begin(PIN_RFID_SCK, PIN_RFID_MISO, PIN_RFID_MOSI, PIN_RFID_SS);
  rfid.PCD_Init();
  byte v = rfid.PCD_ReadRegister(MFRC522::VersionReg);
  rfidOnline = (v != 0x00 && v != 0xFF);

  rxQueue = xQueueCreate(16, sizeof(RxItem));
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_channel(ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE);
  Serial.printf("\nNode 1 MAC: %s   <- put this in Node 2's secrets.h\n", WiFi.macAddress().c_str());
  if (esp_now_init() == ESP_OK) esp_now_register_recv_cb(onRecv);
  else Serial.println("ESP-NOW init failed");

  startWatchdog(5000);

  logEvent("SYSTEM", String("Boot #") + bootNo + " reason=" + resetReasonName(esp_reset_reason()));
  if (!fsOk)       logEvent("SYSTEM", "Log storage unavailable", "-", "ERROR");
  if (!lcdOnline)  logEvent("COMM", "LCD not found at boot");
  if (!rfidOnline) logEvent("COMM", "RFID reader not found at boot");
  if (lockoutRemainingS > 0) logEvent("AUTH", "Lockout restored after reboot: " + String(lockoutRemainingS) + " s");
  if (wasArmed)    logEvent("SYSTEM", "Was armed before restart");
  stateEnteredAt = millis();
}

void loop() {
  esp_task_wdt_reset();                  // "still alive" — else watchdog restarts the board
  char key = keypad.getKey();            // 0 when nothing pressed

  // ---- these run in EVERY state ----
  processRadio();
  checkNodeTimeout();
  readLocalPir();
  readTamper();
  if (millis() - lastPeriphCheck > PERIPH_CHECK_MS) { lastPeriphCheck = millis(); checkPeripherals(); }
  tickLockout();
  logHealthChanges();

  // Tamper overrides every state except BOOT (self-test catches it),
  // MAINTENANCE (lid may be opened; checked again on exit) and TAMPER_FAULT.
  if (tamperOpen && state != S_BOOT && state != S_MAINTENANCE && state != S_TAMPER_FAULT)
    goTo(S_TAMPER_FAULT, "Enclosure tamper");                                        // T07

  // ---- state machine ----
  switch (state) {
    case S_BOOT:         handleBoot();            break;
    case S_WAIT_AUTH:    handleWaitAuth(key);     break;
    case S_MONITORING:   handleMonitoring(key);   break;
    case S_INTRUSION:    handleIntrusion(key);    break;
    case S_TAMPER_FAULT: handleTamperFault(key);  break;
    case S_MAINTENANCE:  handleMaintenance(key);  break;
    case S_RECOVERY:     handleRecovery();        break;
  }

  updateOutputs();
  renderLcd();
  delay(LOOP_MS);
}
