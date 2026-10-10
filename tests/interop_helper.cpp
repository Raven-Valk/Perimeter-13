// Builds and checks packets with the firmware's own link_protocol.h, so the
// server's Python version (Server/p13server/protocol.py) can be compared with it.
//   interop_helper sign   <keyhex> <src> <dst> <type> <via> <mesh> <boot> <seq> <dstBoot> <logNo> <state> <prio>
//                         <reset> <code> <role> <result> <arg> <session> <target> <text>
//   interop_helper verify <keyhex> <packethex>      -> fields, or BAD
//   interop_helper login  <pwhashhex> <noncehex> <user>   -> the answer the gateway expects
//   interop_helper track  [sim]   (stdin: "type bootId seq" per line) -> TrackResult per line
#include "Arduino.h"
#include "link_protocol.h"
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

static std::vector<uint8_t> unhex(const std::string& h) {
  std::vector<uint8_t> v;
  for (size_t i = 0; i + 1 < h.size(); i += 2) v.push_back((uint8_t)strtoul(h.substr(i, 2).c_str(), nullptr, 16));
  return v;
}
static unsigned long num(const char* s) { return strtoul(s, nullptr, 0); }

int main(int argc, char** argv) {
  if (argc < 2) return 2;
  std::string mode = argv[1];
  if (mode == "sign" && argc == 22) {
    auto key = unhex(argv[2]);
    LinkPacket p = {};
    p.version = LINK_VERSION; p.src = num(argv[3]); p.dst = num(argv[4]); p.type = num(argv[5]);
    p.via = num(argv[6]); p.mesh = num(argv[7]);
    p.bootId = num(argv[8]); p.seq = num(argv[9]); p.dstBoot = num(argv[10]); p.logNo = num(argv[11]);
    p.state = num(argv[12]); p.priority = num(argv[13]); p.resetReason = num(argv[14]);
    p.code = num(argv[15]); p.role = num(argv[16]); p.result = num(argv[17]);
    p.arg = num(argv[18]); p.session = num(argv[19]); p.target = num(argv[20]);
    size_t n = strnlen(argv[21], LINK_TEXT_MAX);
    memcpy(p.text, argv[21], n); p.textLen = n;
    linkSign(key.data(), key.size(), p, p.sig);
    const uint8_t* b = (const uint8_t*)&p;
    for (size_t i = 0; i < sizeof(p); i++) printf("%02x", b[i]);
    printf("\n");
    return 0;
  }
  if (mode == "verify" && argc == 4) {
    auto key = unhex(argv[2]);
    auto raw = unhex(argv[3]);
    LinkPacket p;
    if (raw.size() != sizeof(p)) { printf("BAD size\n"); return 0; }
    memcpy(&p, raw.data(), sizeof(p));
    if (!linkWellFormed(p, raw.size())) { printf("BAD form\n"); return 0; }
    uint8_t exp[SIG_LEN];
    linkSign(key.data(), key.size(), p, exp);
    if (!sameBytes(exp, p.sig, SIG_LEN)) { printf("BAD sig\n"); return 0; }
    printf("OK %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %.*s\n",
           p.src, p.dst, p.type, p.via, p.mesh, p.bootId, p.seq, p.dstBoot, p.logNo, p.state, p.priority, p.resetReason,
           p.code, p.role, p.result, p.arg, p.session, p.target, p.textLen, (int)p.textLen, p.text);
    return 0;
  }
  if (mode == "login" && argc == 5) {             // the same steps as Gateway.ino onLoginResp()
    auto key = unhex(argv[2]);
    auto nonce = unhex(argv[3]);
    std::string u = argv[4];
    uint8_t msg[16 + 32];
    size_t ul = u.size() < 32 ? u.size() : 32;
    memcpy(msg, nonce.data(), 16);
    memcpy(msg + 16, u.c_str(), ul);
    uint8_t exp[32];
    hmacSha256(key.data(), 32, msg, 16 + ul, exp);
    for (int i = 0; i < 32; i++) printf("%02x", exp[i]);
    printf("\n");
    return 0;
  }
  if (mode == "track") {
    PeerTracker t;
    unsigned type; unsigned long boot, seq;
    while (std::cin >> type >> boot >> seq) {
      LinkPacket p = {};
      p.type = type; p.bootId = boot; p.seq = seq;
      printf("%d\n", (int)t.accept(p));
    }
    return 0;
  }
  return 2;
}
