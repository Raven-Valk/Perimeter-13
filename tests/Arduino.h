#pragma once
#include <cstdint>
#include <cstring>
#include <cstddef>
#include <string>
static uint32_t g_millis = 0;
inline uint32_t millis() { return g_millis; }
// tiny stand-in for Arduino's String (only what link_protocol.h uses)
class String {
public:
  String() {}
  String(const char* c) : s(c) {}
  void reserve(size_t n) { s.reserve(n); }
  String& operator+=(char c) { s += c; return *this; }
  unsigned length() const { return (unsigned)s.size(); }
  char operator[](unsigned i) const { return s[i]; }
  const char* c_str() const { return s.c_str(); }
  bool operator==(const String& o) const { return s == o.s; }
  std::string s;
};
