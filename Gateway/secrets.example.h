// ---------------------------------------------------------------------------
// REPOSITORY COPY: demo values only. Copy this file to secrets.h (which git
// ignores) and put your own keys, MAC addresses, PIN hashes and passwords there.
// Never commit secrets.h.
// ---------------------------------------------------------------------------
// =====================================================================
//  secrets.h  —  Board 2 (gateway)
//  DEMO VALUE. Must be IDENTICAL to SHARED_KEY in Board1_Controller/secrets.h.
//  Do not upload this file to GitHub (it is listed in .gitignore).
// =====================================================================
#pragma once
#include <Arduino.h>

static const uint8_t SHARED_KEY[32] = {
  0xB7, 0xD8, 0xC0, 0x2C, 0xB9, 0x4B, 0x14, 0x9D, 0xC7, 0x7F, 0x70, 0x35, 0xDC, 0x25, 0x80, 0xCB,
  0x03, 0x10, 0xA5, 0x81, 0xF3, 0xE4, 0x05, 0x03, 0xE1, 0x81, 0x85, 0xF6, 0xB2, 0xBC, 0x86, 0xD6
};
