"""The radio/server packet format, kept identical to firmware link_protocol.h (v4).

Every packet is 206 bytes, little-endian, packed:

    version  src  dst  type  via  mesh | bootId  seq  dstBoot  logNo | state  priority
    resetReason  code  role  result | arg  session | target  textLen
    text[160] | sig[8]

via: the board asked to pass the packet on (0 = sent straight). mesh: the boards
the sender hears directly (bit 0..3 = modules A..D, bit 4 = gateway).

sig is the first 8 bytes of HMAC-SHA256(link key, every byte before it).
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field
from enum import IntEnum

LINK_VERSION = 4
SIG_LEN = 8
TEXT_MAX = 160

_LAYOUT = struct.Struct("<6B4I6B2I2B160s")   # everything the signature covers
PACKET_LEN = _LAYOUT.size + SIG_LEN
assert PACKET_LEN == 206


class Node(IntEnum):
    NONE = 0
    MOD_A = 1
    MOD_B = 2
    MOD_C = 3
    MOD_D = 4
    GATEWAY = 9
    SERVER = 10


class Type(IntEnum):
    HELLO = 1
    STATUS = 2
    LOG = 3
    ACK = 4
    PEER_EVENT = 5
    PEER_ALARM = 6
    CMD = 7
    CMD_RESULT = 8
    LOGIN_REQ = 9
    LOGIN_CHAL = 10
    LOGIN_RESP = 11
    LOGIN_RESULT = 12
    PC_CMD = 13


TYPE_MAX = max(Type)


class Cmd(IntEnum):
    ARM = 1
    DISARM = 2
    MAINT_START = 3
    MAINT_END = 4
    ACK_ALARM = 5
    CLEAR_FAULT = 6
    SET_TIME = 7
    RESEND_LOG = 8
    LOGOUT = 9
    TEST_CUT = 10      # relay test: arg = (other node << 16) | seconds


class Result(IntEnum):
    OK = 0
    REFUSED = 1
    DENIED = 2
    BAD = 3


class Role(IntEnum):
    NONE = 0
    OPERATOR = 1
    MAINTENANCE = 2


TARGET_ALL = 0
MODULES = "ABCD"
NODE_LETTERS = {Node.MOD_A: "A", Node.MOD_B: "B", Node.MOD_C: "C", Node.MOD_D: "D", Node.GATEWAY: "G"}
LETTER_NODES = {v: k for k, v in NODE_LETTERS.items()}
MESH_ORDER = "ABCDG"          # the order of the NET:xxxxx status field

# The site: zone n = a wall with a PIR at each end (firmware ZONE_END1/2)
ZONES = {1: ("A", "D"), 2: ("A", "B"), 3: ("B", "C")}
BUZZERS = ("A", "B")          # modules with a buzzer: they sound for alarms on their walls


def zones_of(module: str) -> list[int]:
    return [z for z, ends in ZONES.items() if module in ends]


def mesh_bit(letter: str) -> int:
    return 1 << MESH_ORDER.index(letter)

# Module states as sent in LinkPacket.state (firmware ModState)
MODULE_STATES = ("BOOT", "DISARMED", "ARMED", "INTRUSION", "TAMPER_FAULT", "MAINTENANCE", "RECOVERY")
GATEWAY_STATES = ("BOOT", "READY", "GW_TAMPER")


@dataclass
class Packet:
    src: int
    dst: int
    type: int
    via: int = 0
    mesh: int = 0
    boot_id: int = 0
    seq: int = 0
    dst_boot: int = 0
    log_no: int = 0
    state: int = 0
    priority: int = 0
    reset_reason: int = 0
    code: int = 0
    role: int = 0
    result: int = 0
    arg: int = 0
    session: int = 0
    target: int = 0
    text: str = ""
    sig: bytes = field(default=b"", repr=False)

    def _body(self) -> bytes:
        raw = self.text.encode("utf-8", "replace")[:TEXT_MAX]
        return _LAYOUT.pack(
            LINK_VERSION, self.src, self.dst, self.type, self.via, self.mesh,
            self.boot_id, self.seq, self.dst_boot, self.log_no,
            self.state, self.priority, self.reset_reason, self.code, self.role, self.result,
            self.arg, self.session,
            self.target, len(raw), raw,
        )

    def encode(self, key: bytes) -> bytes:
        body = self._body()
        self.sig = sign(key, body)
        return body + self.sig


class PacketError(ValueError):
    """The bytes are not a well-formed packet (checked before the signature)."""


def sign(key: bytes, body: bytes) -> bytes:
    return hmac.new(key, body, hashlib.sha256).digest()[:SIG_LEN]


def decode(data: bytes) -> tuple[Packet, bytes]:
    """Parse without trusting anything yet. Returns the packet and the signed bytes."""
    if len(data) != PACKET_LEN:
        raise PacketError(f"length {len(data)}, expected {PACKET_LEN}")
    body, sig = data[:-SIG_LEN], data[-SIG_LEN:]
    (version, src, dst, ptype, via, mesh, boot_id, seq, dst_boot, log_no, state, priority, reset_reason,
     code, role, result, arg, session, target, text_len, raw) = _LAYOUT.unpack(body)
    if version != LINK_VERSION:
        raise PacketError(f"version {version}")
    if not 1 <= ptype <= TYPE_MAX:
        raise PacketError(f"type {ptype}")
    if text_len > TEXT_MAX:
        raise PacketError(f"text length {text_len}")
    pkt = Packet(src, dst, ptype, via, mesh, boot_id, seq, dst_boot, log_no, state, priority, reset_reason,
                 code, role, result, arg, session, target,
                 raw[:text_len].decode("utf-8", "replace"), sig)
    return pkt, body


def verify(key: bytes, body: bytes, sig: bytes) -> bool:
    return hmac.compare_digest(sign(key, body), sig)


def needs_freshness(ptype: int) -> bool:
    """Types that must carry the receiver's current boot ID (firmware linkNeedsFreshness)."""
    return ptype in (Type.CMD, Type.PEER_EVENT, Type.PEER_ALARM, Type.PC_CMD, Type.LOGIN_RESP)


def make_boot_id(boot_no: int, rnd: int) -> int:
    return ((boot_no & 0xFFFF) << 16) | (rnd & 0xFFFF)


def boot_is_newer(a: int, b: int, simulator: bool = False) -> bool:
    """Is boot a later than boot b? Compares the 16-bit boot counters, wrapping."""
    if simulator:                       # Wokwi keeps no flash: every run's counter is 1
        return a != b
    diff = ((a >> 16) - (b >> 16)) & 0xFFFF
    return 0 < diff < 0x8000


class Track(IntEnum):
    OK = 0
    LATE = 1          # older than the newest, inside the window, first time: accepted
    SYNCED = 2
    NEW_BOOT = 3
    DUP = 4           # second copy (straight + relayed): dropped
    REPLAY = 5
    UNSYNCED = 6
    OLD_BOOT = 7


SEQ_WINDOW = 32


class PeerTracker:
    """One sender's boot ID and sequence numbers (firmware PeerTracker): the
    last 32 sequence numbers are remembered, each is accepted once."""

    def __init__(self, simulator: bool = False):
        self.simulator = simulator
        self.synced = False
        self.boot_id = 0
        self.last_seq = 0
        self.seen = 0
        self.send_hello = False

    def accept(self, p: Packet) -> Track:
        if p.type == Type.HELLO and self.synced and p.boot_id != self.boot_id:
            if not boot_is_newer(p.boot_id, self.boot_id, self.simulator):
                return Track.OLD_BOOT
            result = Track.NEW_BOOT
        elif not self.synced:
            if p.type != Type.HELLO:
                return Track.UNSYNCED
            result = Track.SYNCED
        elif p.boot_id != self.boot_id:
            return Track.REPLAY
        elif p.seq > self.last_seq:
            shift = p.seq - self.last_seq
            self.seen = 1 if shift >= SEQ_WINDOW else ((self.seen << shift) | 1) & 0xFFFFFFFF
            self.last_seq = p.seq
            return Track.OK
        else:
            back = self.last_seq - p.seq
            if back >= SEQ_WINDOW:
                return Track.REPLAY
            if self.seen & (1 << back):
                return Track.DUP
            self.seen |= 1 << back
            return Track.LATE
        self.boot_id, self.last_seq, self.seen, self.synced = p.boot_id, p.seq, 1, True
        return result


def password_hash(user: str, password: str) -> bytes:
    """What the gateway stores for a dashboard account: PBKDF2-HMAC-SHA256, 100 000 rounds."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"p13-pc:" + user.encode(), 100_000)


def login_response(pw_hash: bytes, nonce: bytes, user: str) -> str:
    """Answer to the gateway's challenge: HMAC-SHA256(pwHash, nonce || user[:32]), hex."""
    return hmac.new(pw_hash, nonce + user.encode()[:32], hashlib.sha256).hexdigest()


def parse_status(text: str) -> dict[str, str]:
    """'A,ARMED,P0,Z2:OK,...' -> {'node': 'A', 'state': 'ARMED', 'priority': '0', 'Z2': 'OK', ...}"""
    parts = text.split(",")
    out: dict[str, str] = {}
    if parts and parts[0]:
        out["node"] = parts[0]
    if len(parts) > 1:
        out["state"] = parts[1]
    if len(parts) > 2 and parts[2].startswith("P"):
        out["priority"] = parts[2][1:]
    for item in parts[3:]:
        key, sep, value = item.partition(":")
        if sep:
            out[key] = value
    return out


LOG_FIELDS = ("log_no", "boot", "uptime_ms", "unix_time", "module", "priority",
              "state", "type", "event", "zone", "user", "result")


def parse_net(text: str) -> dict[str, str]:
    """NET field 'xxxxx' (order A B C D G) -> {'B': 'D', 'C': 'g', ...} (self left out).
    'D' = direct both ways, a..d/g = relayed through that board, '?' = no route yet, '-' = not heard."""
    out: dict[str, str] = {}
    for letter, ch in zip(MESH_ORDER, text):
        if ch != "*":
            out[letter] = ch
    return out


def zone_digits(text: str) -> list[int]:
    """'1+3' or '13' -> [1, 3]; '-' -> []."""
    return sorted({int(c) for c in text if c.isdigit() and 1 <= int(c) <= 3})


def parse_log_line(line: str) -> dict[str, str] | None:
    """One event-log line in the module format. Commas inside the event text were
    already turned into ';' by the firmware, but be lenient anyway."""
    parts = line.rstrip("\r\n").split(",")
    if len(parts) < len(LOG_FIELDS):
        return None
    if len(parts) > len(LOG_FIELDS):
        extra = len(parts) - len(LOG_FIELDS)
        parts = parts[:8] + [",".join(parts[8:9 + extra])] + parts[9 + extra:]
    return dict(zip(LOG_FIELDS, parts))
