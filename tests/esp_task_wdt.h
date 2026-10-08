#pragma once
#define ESP_ARDUINO_VERSION_MAJOR 3
typedef struct { uint32_t timeout_ms; uint32_t idle_core_mask; bool trigger_panic; } esp_task_wdt_config_t;
inline int esp_task_wdt_reconfigure(const esp_task_wdt_config_t*){return 0;}
inline int esp_task_wdt_init(const esp_task_wdt_config_t*){return 0;}
inline int esp_task_wdt_add(void*){return 0;}
#define ESP_OK 0
enum { ESP_RST_POWERON=1, ESP_RST_EXT, ESP_RST_SW, ESP_RST_PANIC, ESP_RST_INT_WDT, ESP_RST_TASK_WDT, ESP_RST_WDT, ESP_RST_DEEPSLEEP, ESP_RST_BROWNOUT };
