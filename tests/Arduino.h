#pragma once
#include <cstdint>
#include <cstring>
#include <cstddef>
static uint32_t g_millis = 0;
inline uint32_t millis() { return g_millis; }
