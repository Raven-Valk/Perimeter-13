// =====================================================================
//  PINNACLE 1 — PROJECT 13 — SECURE PERIMETER INTRUSION DETECTION
//  SENSOR MODULE  (A, B, C or D)  —  ESP32 DevKitC 38-pin (WROOM-32)  —  firmware v6.1
//
//  Four of these sit at the corners of the site, the gateway in the middle:
//
//        A ---- zone 2 ---- B        Each protected wall (zone) has a PIR at both
//        |                  |        ends, on the OUTSIDE face of the wall, looking
//     zone 1      G      zone 3      along it. Set each HC-SR501 to low sensitivity
//        |                  |        and range (see README) so it only sees the
//        D ~~~~ zone 4 ~~~~~ C        strip just outside the wall.
//
//    A: PIRs A-Z1 (wall A-D) + A-Z2 (wall A-B), tamper reed, LCD, keypad, buzzer, 3 LEDs
//    B: PIRs B-Z2 (wall A-B) + B-Z3 (wall B-C), tamper reed, LCD, keypad, buzzer, 3 LEDs
//    C: PIR  C-Z3 (wall B-C), beam C-Z4 = IR RECEIVER (wall C-D), 3-pin buzzer, LCD, keypad
//    D: PIR  D-Z1 (wall A-D), IR SENDER for the beam (wall C-D),   3-pin buzzer, LCD, keypad
//       (C and D: tamper switch and LEDs optional)
//
//  v6.1 — zone 4, wall C-D: one infrared beam and no PIRs (beam.h). D's IR-08H
//  sends short bursts of 38 kHz infrared along the outside of the wall, C's
//  IR-08H receives them. With one sensor on the wall:
//    * beam broken once                        -> warning (P1)
//    * beam broken twice within 20 s           -> intrusion, zone 4
//    * beam broken during an active intrusion  -> zone 4 joins the alarm at once
//  Beam blocked for 30 s, or no signal from D at all = a FAULT (like a stuck PIR).
//
//  Zones 1-3: confirmed intrusion (P2) when, within 20 s:
//    * both PIRs of one wall fire (this module's and the module's at the other end), or
//    * both PIRs of this module fire (A or B: someone at the corner), or
//    * one PIR fires 3 times.
//  A single trigger is a warning (P1).
//  While an intrusion is active (not yet acknowledged), the 20 s / 3-hit rules are
//  off: ANY PIR firing anywhere is at once an intrusion in its zone.
//  On P2 every armed module goes to INTRUSION; the buzzer sounds on each module
//  standing on a wall in alarm (zone 1 -> A + D, zone 2 -> A + B, zone 3 -> B + C, zone 4 -> C + D).
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
#define MODULE_ID       'A'  // 'A', 'B', 'C' or 'D'. The line that differs between the four modules.
#define WOKWI_SIM       0    // 1 = Wokwi simulator: tone() buzzer, 5 s PIR warm-up, MQTT instead of ESP-NOW.
#define BENCH_COMMANDS  0    // 1 = type commands (arm, disarm, ...) in Serial Monitor to test
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
#define CD_BUZZER_FITTED 1   // 1 = 3-pin buzzer module (VCC, GND, I/O) on pin 16, as on A and B
#define CD_BUZZER_ACTIVE_LOW 0  // 1 if C/D's buzzer module beeps when its I/O pin is LOW
                             //     (many 3-pin modules do: it beeps at power-on and goes quiet in an alarm)
#define BEAM_FITTED      1   // 1 = zone 4, IR beam on wall C-D: D's IR-08H sends, C's IR-08H receives (pin 19)
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

#include "link_protocol.h"
#include "mesh.h"
struct PinUser { const char* name; const char* pinHashHex; Role role; };
#include "secrets.h"
#include "beam.h"

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
const uint8_t PIN_BUZZER     = 16;    // all four (C and D since v6.1)
const uint8_t PIN_LED_GREEN  = 18;
const uint8_t PIN_LED_YELLOW = 2;     // boot pin: the LED to GND keeps it LOW at boot, which is what it needs
const uint8_t PIN_LED_RED    = 15;    // boot pin: the LED to GND only hides the boot messages; may blink at power-on
const uint8_t PIN_PIR_1      = 17;    // A, B: the PIR on wall A-B (zone 2).   C, D: their only PIR
const uint8_t PIN_PIR_2      = 19;    // A: the PIR on wall A-D (zone 1).      B: on wall B-C (zone 3)
const uint8_t PIN_TAMPER     = 23;    // reed switch to GND; built-in pull-up
const uint8_t PIN_IR         = 19;    // C: IR-08H OUT (receiver).  D: IR-08H EN (switches its sender on/off).
                                      // (19 is A/B's second PIR; C and D have only one PIR, so it is free)

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
const bool    HAS_BUZZER  = FULL_CORNER || CD_BUZZER_FITTED;
const bool    BUZZ_LOW    = FULL_CORNER ? BUZZER_ACTIVE_LOW : CD_BUZZER_ACTIVE_LOW;
const bool    BEAM_RX     = BEAM_FITTED && MY_NODE == BEAM_RX_NODE;   // C: watches the beam
const bool    BEAM_TX     = BEAM_FITTED && MY_NODE == BEAM_TX_NODE;   // D: sends it
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
// =====================================================================
//  IR BEAM ON WALL C-D (v6.1, beam.h)
//  Zone 4. C counts D's bursts in an interrupt; the loop hands the count to
//  `beam`. To D (the other end of wall C-D) a break looks like the partner
//  PIR firing on zone 4.
// =====================================================================
BeamTracker beam;                                  // used on C only
const char* BEAM_NAME = "C-Z4";                    // its name in the log and on the dashboard
bool beamRecent(uint32_t now) { return BEAM_RX && beam.recent(now, CORROBORATION_MS); }

void clearPartners() { for (uint8_t z = 0; z <= SITE_ZONES; z++) partnerValid[z] = partnerNew[z] = false; }

#if !WOKWI_SIM
volatile uint32_t irLastPulseMs = 0, irPulseCount = 0;
void IRAM_ATTR onIrPulse() { irLastPulseMs = millis(); irPulseCount++; }   // one burst from D arrived
#endif

void beamBegin() {
  if (BEAM_RX) {
    pinMode(PIN_IR, INPUT_PULLUP);                 // OUT idles HIGH (Wokwi: the "beam" button, pressed = LOW)
#if !WOKWI_SIM
    attachInterrupt(digitalPinToInterrupt(PIN_IR), onIrPulse, FALLING);
#endif
  }
  if (BEAM_TX) {                                   // EN HIGH for 1 ms every 10 ms: the LEDC hardware does it
    const uint32_t hz = 1000 / BEAM_PERIOD_MS;     // 100 Hz
    const uint32_t duty = 4096 * BEAM_BURST_MS / BEAM_PERIOD_MS;   // 10 % of 12 bits
#if ESP_ARDUINO_VERSION_MAJOR >= 3
    ledcAttach(PIN_IR, hz, 12);
    ledcWrite(PIN_IR, duty);
#else
    ledcSetup(0, hz, 12);
    ledcAttachPin(PIN_IR, 0);
    ledcWrite(0, duty);
#endif
  }
}

void beamLoop(uint32_t now) {                      // every loop pass, every state
  if (!BEAM_RX) return;
#if WOKWI_SIM
  if (digitalRead(PIN_IR) == HIGH) beam.fakeSignal(now);   // button not pressed = beam arriving
  beam.update(now, false);
#else
  uint32_t n = irPulseCount, t = irLastPulseMs;    // 32-bit reads are atomic on the ESP32
  beam.sync(t, n);
  beam.update(now, digitalRead(PIN_IR) == LOW);
#endif
  if (beam.health != beam.loggedHealth) {
    if (beam.loggedHealth != 0xFF)
      logEvent("HEALTH", String(beamHealthName(beam.loggedHealth)) + "->" + beam.healthText(), BEAM_NAME);
    beam.loggedHealth = beam.health;
  }
}


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
  digitalWrite(PIN_BUZZER, BUZZ_LOW ? !on : on);   // active buzzer: steady on/off
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

// C: the beam was just broken. Count it and tell D (the other end of wall C-D).
void beamBroken(uint32_t now) {
  beam.addTrigger(now);
  MeshPeer* d = mesh.find(BEAM_TX_NODE);
  if (d) linkSend(*d, L_PEER_EVENT, BEAM_ZONE, 0, 0, 0, 0, nullptr);
}

// The module at the other end of one of our walls: its PIR on that wall fired.
// (Zone 4: module C, the beam on wall C-D was broken.)
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
  uint8_t  zones = p.code & ALL_ZONES;
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
  return anyPartnerRecent(now) || beamRecent(now);
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
    if (anyPartnerRecent(now) || beamRecent(now)) return 1;
    for (uint8_t i = 0; i < ZONE_COUNT; i++) if (zones[i].recent(now)) return 1;
  }
  return 0;
}

//  A,ARMED,P1,Z2:OK,Z1:OK,HIT:2,ALM:-,LID:SHUT,LCD:OK,LOCK:0,LOGNO:57,CH:6,NET:*DgDD,FWD:0,FW:6.1
//  C,ARMED,P0,Z3:OK,IR:OK,HIT:-,...    (C: the beam OK / BRK / WARMUP / STUCK / NOSIG;  D: IR:TX)
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
  if (beamRecent(now) && (state == S_ARMED || state == S_INTRUSION)) hit |= zoneBit(BEAM_ZONE);
  if (BEAM_RX) s += String(",IR:") + beam.stateText();
  else if (BEAM_TX) s += ",IR:TX";
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
      beam.clearWindow();
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
  if (BEAM_RX && beam.faulty()) selfTestReason += String("Beam ") + beam.healthText() + " ";
  if (!display.online)      logEvent("TEST", String("LCD missing - ") + (HAS_BUZZER ? "LEDs and buzzer only" : "LEDs only"));
  if (!gwLink.trk.online)   logEvent("TEST", "Gateway not connected - local log only");
  for (uint8_t i = 0; i < ZONE_COUNT; i++) {        // the module at the other end of each of our walls
    MeshPeer* P = mesh.find(zonePartner(zones[i].code, MY_NODE));
    if (P && !P->trk.online) logEvent("TEST", String(P->name) + " not connected - zone " + String(zones[i].code) + " on 3-hit rule");
  }
  if (BEAM_FITTED) {                                // the beam's other end
    MeshPeer* P = mesh.find(BEAM_RX ? BEAM_TX_NODE : BEAM_RX_NODE);
    if (P && !P->trk.online && (BEAM_RX || BEAM_TX)) logEvent("TEST", String(P->name) + " not connected - zone 4 beam still works at C");
  }
  outputTestUntil = millis() + 800;                 // short lamp + buzzer test
  selfTestReason.trim();
  return selfTestReason.length() == 0;
}

String armBlocker() {                               // "" = OK to arm
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].warming()) return String(zones[i].name) + " warming";
  if (BEAM_RX && beam.warming()) return "Beam: looking for D";
  return faultBlocker();
}

String faultBlocker() {                             // "" = no lid / sensor problem
  if (tamper.isOpen()) return "Lid open";
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].faulty()) return String(zones[i].name) + " " + healthName(zones[i].health);
  if (BEAM_RX && beam.faulty()) return String("Beam ") + beam.healthText();
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
  if (BEAM_RX && beam.eventPending) { beam.eventPending = false; logEvent("SENSOR", String(what) + " - beam broken", BEAM_NAME, "-", prio); }
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
  if (BEAM_RX && beam.faulty()) { goTo(S_TAMPER_FAULT, String("Beam ") + beam.healthText()); return; }

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

  // 2b) C: the beam on wall C-D (zone 4) was broken. The only sensor on that
  //     wall, so: twice in 20 s = intrusion, once = warning.
  if (BEAM_RX && beam.eventPending) {
    beam.eventPending = false;
    beamBroken(now);                               // counts it, tells D
    uint8_t hits = beam.recentCount(now, CORROBORATION_MS);
    uint8_t zb = zoneBit(BEAM_ZONE);
    const MeshPeer* inAlarm = moduleInAlarm();
    if (inAlarm) { confirmIntrusion(String(BEAM_NAME) + " beam while " + inAlarm->name + " is in alarm", BEAM_NAME, zb); return; }
    if (hits >= BEAM_REPEATS) { confirmIntrusion(String(BEAM_NAME) + " beam broken x" + String(hits), BEAM_NAME, zb); return; }
    chirp();
    logEvent("ALERT", "Beam broken " + String(hits) + "/" + String(BEAM_REPEATS), BEAM_NAME, "-", 1);
  }

  // 3) The PIR at the other end of one of our walls fired
  for (uint8_t zn = 1; zn <= SITE_ZONES; zn++) {
    if (!partnerNew[zn]) continue;
    partnerNew[zn] = false;
    ZoneSensor* mine = zoneSensor(zn);
    String other = partnerPir(zn);
    if (mine && mine->recent(now)) { confirmIntrusion(String(mine->name) + " + " + other, other.c_str(), zoneBit(zn)); return; }
    logEvent("ALERT", String(zn == BEAM_ZONE ? "Beam broken, seen by " : "Motion seen by ") + nodeName(zonePartner(zn, MY_NODE)),
             other.c_str(), "-", 1);
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
    setScreen(String(MY_LETTER) + " WARN P1", zn == BEAM_ZONE ? String("Beam C-D broken") : partnerPir(zn) + " motion");
  } else if (beamRecent(now)) {
    setScreen(String(MY_LETTER) + " WARN P1 " + String((CORROBORATION_MS - (now - beam.lastTrig())) / 1000 + 1) + "s",
              "Beam C-Z4 " + String(beam.recentCount(now, CORROBORATION_MS)) + "/" + String(BEAM_REPEATS));
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
  if (BEAM_RX && beam.eventPending) {              // C: the beam during the alarm
    beam.eventPending = false;
    beam.addTrigger(millis());
    uint8_t add = zoneBit(BEAM_ZONE) & ~alarmZones;
    if (!add) logEvent("ALERT", "Beam broken during intrusion", BEAM_NAME, "-", 2);
    else {
      alarmZones |= add;
      saveAlarmZones();
      String why = String(BEAM_NAME) + " beam during the alarm";
      logEvent("ALERT", "Intrusion zone " + zoneList(add) + " (escalated): " + why, BEAM_NAME, "-", 2);
      startPeerAlarm(why);
    }
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
  if (BEAM_RX && beam.eventPending) { beam.eventPending = false; logEvent("SENSOR", "Beam broken during fault", BEAM_NAME, "-", 3); }

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
  if (BEAM_RX) st += String("IR:") + beam.stateText() + " ";
  uint8_t up = 0;
  for (MeshPeer* P : PEERS) if (P->trk.online) up++;
  st += String(up) + "/" + String(PEER_COUNT);
  setScreen(String(MY_LETTER) + " MAINT " + String(left) + "s", maintShowStatus ? st : "1Tst 2Sts 3Log C");
  for (uint8_t i = 0; i < ZONE_COUNT; i++)
    if (zones[i].eventPending) { zones[i].eventPending = false; logEvent("MAINT", "Test trigger", zones[i].name); }
  if (BEAM_RX && beam.eventPending) { beam.eventPending = false; logEvent("MAINT", "Test trigger (beam broken)", BEAM_NAME); }

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
  if (BEAM_RX && beam.warming()) warming = true;
  setScreen(String(MY_LETTER) + " RECOVERY", warming ? "Sensors warming up" : "Revalidating...");
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
  if (HAS_BUZZER) { pinMode(PIN_BUZZER, OUTPUT); digitalWrite(PIN_BUZZER, BUZZ_LOW ? HIGH : LOW); }
  for (uint8_t i = 0; i < ZONE_COUNT; i++) zones[i].begin();
  tamper.begin();
  beamBegin();

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
  uint8_t savedZones = prefs.getUChar("azones", 0) & ALL_ZONES;
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
  Serial.printf("\nSensor Module %c (walls: zone %s), MAC %s%s\n", MY_LETTER, zoneList(MY_WALLS).c_str(), mac.c_str(),
                BEAM_RX ? ", IR beam receiver" : BEAM_TX ? ", IR beam sender" : "");
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
  beamLoop(now);
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
