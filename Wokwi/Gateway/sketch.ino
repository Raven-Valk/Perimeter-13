// SINGLE-FILE WOKWI VERSION of the GATEWAY (Board 2).
// In Wokwi you need only this sketch.ino + diagram.json + libraries.txt.
// =====================================================================
//  PINNACLE 1 — PROJECT 13 — SECURE PERIMETER INTRUSION DETECTION
//  BOARD 2 : GATEWAY (any ESP32, plugged into the PC by USB)  —  firmware v4
//
//  Receives signed packets from Board 1 over ESP-NOW, checks them, and
//  prints one line per event to the PC over USB serial (115200 baud):
//
//    LOG,<logNo>,<boot,uptime_ms,priority,state,type,event,zone,role,uid,result>
//    STATUS,<state>,<P#>,<zone:health>,...,LID:..,RFID:..,LCD:..
//    LINK,<message>           controller online / lost / restarted
//    GAP,<n>                  n log lines were lost on the radio
//    SEC,REJECTED,<reason>    malformed / unknown / bad signature / replay
//
//  It answers every status beat with a signed ACK, so Board 1 knows the
//  PC link is alive. It never sends commands: the PC cannot control the
//  alarm (smaller attack surface).
// =====================================================================
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
// Early declaration so the prototypes the Arduino IDE / Wokwi auto-insert compile.
struct RxItem;
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
// ===== secrets.h (built in for Wokwi) =====
// =====================================================================
//  secrets.h  —  Board 2 (gateway)
//  DEMO VALUE. Must be IDENTICAL to SHARED_KEY in Board1_Controller/secrets.h.
//  Do not upload this file to GitHub (it is listed in .gitignore).
// =====================================================================
#include <Arduino.h>

static const uint8_t SHARED_KEY[32] = {
  0xB7, 0xD8, 0xC0, 0x2C, 0xB9, 0x4B, 0x14, 0x9D, 0xC7, 0x7F, 0x70, 0x35, 0xDC, 0x25, 0x80, 0xCB,
  0x03, 0x10, 0xA5, 0x81, 0xF3, 0xE4, 0x05, 0x03, 0xE1, 0x81, 0x85, 0xF6, 0xB2, 0xBC, 0x86, 0xD6
};

// ===== end secrets.h =====

#define WOKWI_SIM 1   // 1 = Wokwi simulator: receive over MQTT instead of ESP-NOW. Keep 0 on the real board.

const uint32_t CONTROLLER_TIMEOUT_MS = WOKWI_SIM ? 8000 : 3000;
const uint32_t STATUS_PRINT_EVERY_MS = 30000;   // reprint unchanged status this often
const uint8_t  PIN_LED = 2;                     // on-board LED: on = controller online

struct RxItem { uint8_t src[6]; int len; uint8_t data[sizeof(LinkPacket)]; };
QueueHandle_t rxQueue;

#if WOKWI_SIM
#include <PubSubClient.h>
WiFiClient   mqttNet;
PubSubClient mqtt(mqttNet);
uint32_t     lastMqttTry = 0;
void onMqtt(char* topic, byte* payload, unsigned int len) {
  RxItem it;
  memset(it.src, 0, 6);
  it.len = len;
  memcpy(it.data, payload, min((int)len, (int)sizeof(it.data)));
  xQueueSend(rxQueue, &it, 0);
}
#endif

PeerTracker controller;
uint32_t bootId, seq = 0, acks = 0;
uint8_t  resetReason;
uint32_t lastLogNo = 0, lastRejectPrint = 0, lastStatusPrint = 0;
bool     haveLogNo = false, peerAdded = false;
uint8_t  controllerMac[6];
String   lastStatus = "";

#if ESP_ARDUINO_VERSION_MAJOR >= 3
void onRecv(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
  const uint8_t* src = info->src_addr;
#else
void onRecv(const uint8_t* src, const uint8_t* data, int len) {
#endif
  RxItem it;                                   // Wi-Fi task: copy + queue only
  memcpy(it.src, src, 6);
  it.len = len;
  memcpy(it.data, data, min(len, (int)sizeof(it.data)));
  xQueueSend(rxQueue, &it, 0);
}

void rejectPrint(const char* why) {
  if (millis() - lastRejectPrint < 1000) return;   // don't flood the PC
  lastRejectPrint = millis();
  Serial.printf("SEC,REJECTED,%s\n", why);
}

void sendAck() {
#if !WOKWI_SIM
  if (!peerAdded) return;
#endif
  LinkPacket p = {};
  p.version = LINK_VERSION; p.nodeId = NODE_GATEWAY;
  p.type = (++acks % 10 == 1) ? L_HELLO : L_ACK;    // HELLO lets Board 1 re-sync after we restart
  p.bootId = bootId; p.seq = ++seq; p.resetReason = resetReason;
  linkSign(SHARED_KEY, sizeof(SHARED_KEY), p, p.sig);
#if WOKWI_SIM
  if (mqtt.connected()) mqtt.publish(MQTT_TOPIC_GW, (const uint8_t*)&p, sizeof(p));
#else
  esp_now_send(controllerMac, (const uint8_t*)&p, sizeof(p));
#endif
}

void handlePacket(const RxItem& it) {
  LinkPacket p;
  memcpy(&p, it.data, sizeof(p));
  if (!linkWellFormed(p, it.len))     { rejectPrint("Malformed packet"); return; }
  if (p.nodeId != NODE_CONTROLLER)    { rejectPrint("Unknown sender");   return; }
  uint8_t exp[SIG_LEN];
  linkSign(SHARED_KEY, sizeof(SHARED_KEY), p, exp);
  if (!sameBytes(exp, p.sig, SIG_LEN)) { rejectPrint("Bad signature (spoofed?)"); return; }
  TrackResult tr = controller.accept(p);
  if (tr == TR_REPLAY)                 { rejectPrint("Replayed/old packet"); return; }

  // Only a verified packet may set where our ACKs go.
  if (!WOKWI_SIM && (!peerAdded || memcmp(controllerMac, it.src, 6) != 0)) {
    if (peerAdded) esp_now_del_peer(controllerMac);
    memcpy(controllerMac, it.src, 6);
    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, controllerMac, 6);
    peer.channel = ESPNOW_CHANNEL;
    peer.encrypt = false;
    peerAdded = esp_now_add_peer(&peer) == ESP_OK;
  }
  if (tr == TR_NEW_BOOT) {
    Serial.printf("LINK,Controller restarted reason=%s\n", resetReasonName(p.resetReason));
    haveLogNo = false;                         // its log counter starts again from 1
  }
  if (!controller.online) {
    controller.online = true;
    digitalWrite(PIN_LED, HIGH);
    Serial.println("LINK,Controller online");
  }

  char buf[LINK_TEXT_MAX + 1];                 // text[] is not NUL-terminated: copy by length
  memcpy(buf, p.text, p.textLen);
  buf[p.textLen] = 0;
  String text(buf);
  text.replace("\n", " ");
  if (p.type == L_LOG) {
    if (haveLogNo && p.logNo > lastLogNo + 1) Serial.printf("GAP,%lu\n", (unsigned long)(p.logNo - lastLogNo - 1));
    if (!haveLogNo || p.logNo > lastLogNo) { lastLogNo = p.logNo; haveLogNo = true; }
    Serial.printf("LOG,%lu,%s\n", (unsigned long)p.logNo, text.c_str());
  } else {                                     // L_STATUS or L_HELLO: both carry status
    sendAck();
    if (text != lastStatus || millis() - lastStatusPrint > STATUS_PRINT_EVERY_MS) {
      lastStatus = text; lastStatusPrint = millis();
      Serial.printf("STATUS,%s\n", text.c_str());
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(200);
  pinMode(PIN_LED, OUTPUT);
  bootId = esp_random();
  resetReason = (uint8_t)esp_reset_reason();
  rxQueue = xQueueCreate(16, sizeof(RxItem));

#if WOKWI_SIM
  WiFi.mode(WIFI_STA);
  WiFi.begin("Wokwi-GUEST", "", 6);
  mqtt.setServer(MQTT_BROKER, MQTT_PORT);
  mqtt.setCallback(onMqtt);
  mqtt.setBufferSize(512);
  mqtt.setSocketTimeout(2);
  startWatchdog(20000);
  Serial.printf("LINK,Gateway started (Wokwi/MQTT mode) reason=%s\n", resetReasonName(resetReason));
  return;
#endif
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_channel(ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE);
  if (esp_now_init() != ESP_OK) {
    Serial.println("LINK,ESP-NOW init failed - restarting");
    delay(1000);
    ESP.restart();
  }
  esp_now_register_recv_cb(onRecv);
  startWatchdog(5000);
  Serial.printf("LINK,Gateway started reason=%s mac=%s\n", resetReasonName(resetReason), WiFi.macAddress().c_str());
}

void loop() {
  esp_task_wdt_reset();
#if WOKWI_SIM
  if (WiFi.status() == WL_CONNECTED && !mqtt.connected() && millis() - lastMqttTry > 5000) {
    lastMqttTry = millis();
    esp_task_wdt_reset();
    String id = "p13-gw-" + String(bootId, HEX);
    if (mqtt.connect(id.c_str())) {
      static bool mixed = false;
      if (!mixed) { bootId ^= (uint32_t)micros(); mixed = true; }   // simulator RNG may repeat
      mqtt.subscribe(MQTT_TOPIC_CTRL);
      Serial.println("LINK,MQTT connected - waiting for controller");
    }
  }
  mqtt.loop();
#endif
  RxItem it;
  while (xQueueReceive(rxQueue, &it, 0) == pdTRUE) handlePacket(it);

  if (controller.online && millis() - controller.lastHeard > CONTROLLER_TIMEOUT_MS) {
    controller.online = false;
    digitalWrite(PIN_LED, LOW);
    Serial.printf("LINK,CONTROLLER LOST - no signed packets for %lu s\n", (unsigned long)(CONTROLLER_TIMEOUT_MS / 1000));   // unplugged, jammed or crashed
  }
  delay(5);
}
