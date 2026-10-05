// =====================================================================
//  PINNACLE 1 — PROJECT 13 — SECURE PERIMETER INTRUSION DETECTION
//  NODE 2 : SENSOR NODE (RIGHT-facing PIR)
//
//  Reads its sensors and sends signed messages to Node 1 over ESP-NOW:
//    HELLO      at boot and every 10 s (tells Node 1 this node's boot ID
//               and why it last restarted)
//    EVENT      immediately when a sensor starts detecting
//    HEARTBEAT  every second (alive + each sensor's state and health)
//  Node 2 makes no alarm decisions. Node 1 does all of that.
//
//  Board : ESP32 Dev Module   |   Arduino-ESP32 core 3.x (2.x also works)
// =====================================================================
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include "common.h"
#include "secrets.h"

// ---------------- configuration ----------------
const uint8_t  NODE_ID        = 2;
const uint32_t HEARTBEAT_MS   = 1000;
const uint32_t PIR_WARMUP_MS  = 60000;   // HC-SR501 needs ~60 s to settle
const uint8_t  PIN_STATUS_LED = 2;       // on-board LED blinks on every heartbeat

struct Sensor {
  uint8_t     zone;          // zone number reported to Node 1
  const char* type;          // "PIR" or "IR" (for Serial messages)
  uint8_t     pin;
  bool        activeHigh;    // PIR: HIGH = motion. FC-51 IR: LOW = object.
  bool        needsWarmup;   // PIR only
  bool        enabled;       // set true when the sensor is physically fitted
  uint32_t    maxActiveMs;   // active longer than this = stuck / blocked
  // runtime values
  bool        lastActive;
  uint32_t    activeSince;
  uint8_t     health;
};

Sensor sensors[] = {
  // zone type   pin  activeHigh warmup enabled maxActiveMs
  {  2,  "PIR",  27,  true,      true,  true,   30000 },
  {  3,  "IR",   26,  false,     false, false,  30000 },   // FC-51: set enabled=true when added
};
const uint8_t SENSOR_COUNT = sizeof(sensors) / sizeof(sensors[0]);

// ---------------- runtime ----------------
uint32_t bootId;
uint32_t seqNo = 0;
uint8_t  resetReason;
uint32_t lastHeartbeat = 0;

bool sendPacket(uint8_t type, uint8_t eventZone = 0);   // prototype (default argument lives here)

// ---------------------------------------------------------------------
bool sendPacket(uint8_t type, uint8_t eventZone) {
  Packet p = {};
  p.version     = PROTO_VERSION;
  p.nodeId      = NODE_ID;
  p.type        = type;
  p.bootId      = bootId;
  p.seq         = ++seqNo;
  p.resetReason = resetReason;
  p.eventZone   = eventZone;

  uint8_t n = 0;
  for (uint8_t i = 0; i < SENSOR_COUNT && n < MAX_REMOTE_ZONES; i++) {
    if (!sensors[i].enabled) continue;
    p.zones[n].zone   = sensors[i].zone;
    p.zones[n].active = sensors[i].lastActive ? 1 : 0;
    p.zones[n].health = sensors[i].health;
    n++;
  }
  p.zoneCount = n;
  signPacket(SHARED_KEY, sizeof(SHARED_KEY), p, p.sig);

  esp_err_t r = esp_now_send(NODE1_MAC, (const uint8_t*)&p, sizeof(p));
  if (r != ESP_OK) Serial.printf("send failed (%d)\n", r);
  return r == ESP_OK;
}

// ---------------------------------------------------------------------
void readSensors() {
  uint32_t now = millis();
  for (uint8_t i = 0; i < SENSOR_COUNT; i++) {
    Sensor& s = sensors[i];
    if (!s.enabled) continue;

    bool raw    = digitalRead(s.pin) == HIGH;
    bool active = s.activeHigh ? raw : !raw;

    if (s.needsWarmup && now < PIR_WARMUP_MS) {          // still settling
      s.health      = H_WARMUP;
      s.lastActive  = active;
      s.activeSince = now;
      continue;
    }

    bool risingEdge = active && !s.lastActive;
    if (risingEdge) s.activeSince = now;
    s.lastActive = active;

    // Health: a PIR in single-trigger (L) mode drops after ~3 s, and a
    // pull-up makes an unplugged PIR read HIGH forever. So "active for
    // too long" = stuck, disconnected or (for IR) deliberately blocked.
    if (active && now - s.activeSince > s.maxActiveMs) {
      if (s.health != H_STUCK) Serial.printf("Zone %u %s STUCK\n", s.zone, s.type);
      s.health = H_STUCK;
    } else if (!active || s.health == H_WARMUP) {
      if (s.health == H_STUCK) Serial.printf("Zone %u %s healthy again\n", s.zone, s.type);
      s.health = H_OK;
    }

    if (risingEdge && s.health == H_OK) {
      Serial.printf("Zone %u %s detection -> EVENT\n", s.zone, s.type);
      sendPacket(MSG_EVENT, s.zone);
    }
  }
}

// ---------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(200);
  pinMode(PIN_STATUS_LED, OUTPUT);
  for (uint8_t i = 0; i < SENSOR_COUNT; i++) {
    pinMode(sensors[i].pin, INPUT_PULLUP);   // unplugged sensor reads HIGH
    sensors[i].health = sensors[i].needsWarmup ? H_WARMUP : H_OK;
  }

  resetReason = (uint8_t)esp_reset_reason();
  bootId      = esp_random();                 // new random number each boot

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_channel(ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE);
  Serial.printf("\nNode 2 sensor node. MAC: %s  reset: %s\n",
                WiFi.macAddress().c_str(), resetReasonName(resetReason));

  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW init failed - restarting");
    delay(1000);
    ESP.restart();
  }
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, NODE1_MAC, 6);
  peer.channel = ESPNOW_CHANNEL;
  peer.encrypt = false;          // messages are signed (HMAC), not encrypted
  if (esp_now_add_peer(&peer) != ESP_OK) Serial.println("Could not add Node 1 as peer - check NODE1_MAC");

  startWatchdog(5000);
  sendPacket(MSG_HELLO);
}

void loop() {
  esp_task_wdt_reset();
  readSensors();

  if (millis() - lastHeartbeat >= HEARTBEAT_MS) {
    lastHeartbeat = millis();
    // Every 10th heartbeat is a HELLO, so Node 1 can re-sync if it missed
    // the first one (HELLO also carries the zone reports).
    static uint8_t beats = 0;
    sendPacket(++beats % 10 == 0 ? MSG_HELLO : MSG_HEARTBEAT);
    digitalWrite(PIN_STATUS_LED, HIGH);      // short blink = "alive"
  }
  if (millis() - lastHeartbeat > 50) digitalWrite(PIN_STATUS_LED, LOW);

  delay(20);
}
