// =====================================================================
//  common.h  —  shared by Node 1 and Node 2.
//  Keep this file IDENTICAL in both sketch folders.
// =====================================================================
#pragma once
#include <Arduino.h>
#include <esp_task_wdt.h>
#include "mbedtls/md.h"

#define PROTO_VERSION     1
#define ESPNOW_CHANNEL    1     // both nodes must use the same Wi-Fi channel
#define MAX_REMOTE_ZONES  3
#define SIG_LEN           8     // bytes of HMAC-SHA256 kept in each packet

enum MsgType : uint8_t { MSG_HELLO = 1, MSG_HEARTBEAT = 2, MSG_EVENT = 3 };
enum Health  : uint8_t { H_OK = 0, H_WARMUP = 1, H_STUCK = 2, H_OFFLINE = 3 };

#pragma pack(push, 1)
struct ZoneReport {
  uint8_t zone;      // zone number (2, 3 ...)
  uint8_t active;    // 1 = sensor currently detecting
  uint8_t health;    // Health enum
};

struct Packet {
  uint8_t    version;       // PROTO_VERSION
  uint8_t    nodeId;        // sender node number
  uint8_t    type;          // MsgType
  uint32_t   bootId;        // random number chosen at sender boot
  uint32_t   seq;           // increases by 1 every packet (replay protection)
  uint8_t    resetReason;   // sender's last reset reason (HELLO only)
  uint8_t    eventZone;     // zone that fired (EVENT only)
  uint8_t    zoneCount;     // how many entries in zones[] are used
  ZoneReport zones[MAX_REMOTE_ZONES];
  uint8_t    sig[SIG_LEN];  // HMAC over every byte above
};
#pragma pack(pop)

static const size_t PACKET_SIGNED_LEN = offsetof(Packet, sig);

// HMAC-SHA256 over the packet (excluding the signature field), truncated.
inline void signPacket(const uint8_t* key, size_t keyLen, const Packet& p, uint8_t out[SIG_LEN]) {
  uint8_t full[32];
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                  key, keyLen, (const uint8_t*)&p, PACKET_SIGNED_LEN, full);
  memcpy(out, full, SIG_LEN);
}

// Constant-time compare (does not leak how many bytes matched).
inline bool sameBytes(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t diff = 0;
  for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
  return diff == 0;
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
    case ESP_RST_DEEPSLEEP:return "DEEPSLEEP";
    default:               return "OTHER";
  }
}

// Task watchdog: if loop() stops calling esp_task_wdt_reset() for
// timeoutMs, the chip restarts automatically.
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
  esp_task_wdt_add(NULL);   // watch the loop() task
}

// true while millis() has not yet reached t (safe across millis() overflow)
inline bool notYet(uint32_t t) { return (int32_t)(t - millis()) > 0; }
