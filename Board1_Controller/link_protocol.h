// =====================================================================
//  link_protocol.h  —  shared by Board 1 (controller) and Board 2 (gateway).
//  Keep this file IDENTICAL in both sketch folders.
// =====================================================================
#pragma once
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
