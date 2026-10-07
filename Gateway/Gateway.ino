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
#include "link_protocol.h"
#include "secrets.h"

#define WOKWI_SIM 0   // 1 = Wokwi simulator: receive over MQTT instead of ESP-NOW. Keep 0 on the real board.

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
