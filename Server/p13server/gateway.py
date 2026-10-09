"""The server's end of the gateway link.

Speaks the same signed packets as the boards (see protocol.py), over whatever
transport delivers them (MQTT in practice). It keeps the link alive with a beat
every second, relays dashboard logins and commands, keeps the latest status of
the gateway and both modules, and stores every event-log line, asking the
gateway again for any it missed.
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
from collections import Counter
from dataclasses import dataclass
from typing import Callable

from . import __version__
from .config import Config
from .hub import Hub
from .protocol import (GATEWAY_STATES, TARGET_BOTH, Cmd, Node, Packet, PacketError, PeerTracker, Result, Role,
                       Track, Type, boot_is_newer, decode, login_response, make_boot_id, parse_status, verify)
from .store import Store

log = logging.getLogger("p13.gateway")

BEAT_EVERY = 1.0            # our heartbeat (the gateway drops the link after 8 s of silence)
GATEWAY_TIMEOUT = 6.0       # the gateway beats every second
STEP_TIMEOUT = 5.0          # each step of a login
COMMAND_TIMEOUT = 15.0      # a dashboard command may wait behind a keypad command
TIME_RESYNC = 600.0
RESEND_WINDOW = 3000        # the gateway re-sends at most this many lines per request
GAP_GRACE = 2.0             # a line missing this long is asked for again
RESEND_IDLE = 6.0           # a re-send with no new lines for this long is over
RESEND_TRIES = 3
USER_RE = re.compile(r"[A-Za-z0-9._-]{1,31}")
NODE_LETTER = {Node.GATEWAY: "G", Node.MOD_A: "A", Node.MOD_B: "B"}


@dataclass
class Control:
    """The one dashboard session the gateway allows at a time."""
    session_id: int
    user: str
    role: int
    since: float

    def public(self) -> dict:
        return {"user": self.user, "role": Role(self.role).name, "since": self.since}


@dataclass
class LoginOutcome:
    ok: bool
    message: str
    role: int = 0
    session_id: int = 0


@dataclass
class CommandOutcome:
    result: str          # OK, REFUSED, DENIED, BAD, TIMEOUT, OFFLINE
    text: str


class GatewayLink:
    def __init__(self, cfg: Config, store: Store, hub: Hub):
        self.cfg = cfg
        self.key = cfg.gateway_key
        self.store = store
        self.hub = hub
        self.tracker = PeerTracker(cfg.simulator)
        self.boot_id = make_boot_id(store.next_boot_no(), secrets.randbits(16))
        self.seq = 0
        self.beats = 0
        self.send_hook: Callable[[bytes], None] | None = None
        self.transport_up = False
        self.presence: str | None = None      # what the broker last said: "online" / "offline"

        self.online = False
        self.online_since: float | None = None
        self.last_heard = 0.0
        self.nodes: dict[str, dict] = {"G": {}, "A": {}, "B": {}}
        self.control: Control | None = None
        self.rejects: Counter[str] = Counter()
        self._reject_logged: dict[str, float] = {}

        self._pending: dict[int, asyncio.Future] = {}
        self._login_lock = asyncio.Lock()
        self._login_wait: asyncio.Future | None = None
        self._login_user = ""
        self._last_login_req = 0.0
        self._time_sent = 0.0
        self._checked_series = False

        self.top = store.max_gw_no()          # highest gateway line number known to exist
        self._gap_since: dict[int, float] = {}
        self._resend_active = False
        self._resend_progress = 0.0
        self._resend_from = 0
        self._resend_tries = 0

    # ------------------------------------------------------------------ out
    def send(self, ptype: int, *, code: int = 0, arg: int = 0, session: int = 0, target: int = 0,
             text: str = "", log_no: int = 0) -> int:
        self.seq += 1
        p = Packet(Node.SERVER, Node.GATEWAY, ptype, boot_id=self.boot_id, seq=self.seq,
                   dst_boot=self.tracker.boot_id if self.tracker.synced else 0, log_no=log_no,
                   code=code, arg=arg & 0xFFFFFFFF, session=session, target=target, text=text)
        if self.send_hook:
            self.send_hook(p.encode(self.key))
        return self.seq

    async def run(self) -> None:
        while True:
            await asyncio.sleep(BEAT_EVERY)
            self.beats += 1
            hello = self.beats % 10 == 1 or self.tracker.send_hello
            self.tracker.send_hello = False
            self.send(Type.HELLO if hello else Type.STATUS, arg=int(time.time()), text=f"P,ONLINE,FW:{__version__}")
            if self.online and time.monotonic() - self.last_heard > GATEWAY_TIMEOUT:
                self._set_online(False, "no packets for 6 s")
            if self.online:
                self._keep_time()
                self._fill_gaps()

    # ------------------------------------------------------------------ in
    def on_bytes(self, data: bytes) -> None:
        try:
            p, body = decode(data)
        except PacketError as e:
            self._reject("malformed", f"Malformed packet ({e})")
            return
        if p.dst != Node.SERVER:
            return
        if p.src != Node.GATEWAY:
            self._reject("sender", "Packet from an unknown sender")
            return
        if not verify(self.key, body, p.sig):
            self._reject("signature", "Bad signature (wrong key, or forged)")
            return
        if p.dst_boot != self.boot_id:
            self.tracker.send_hello = True           # it hasn't seen our current boot yet
            if p.type in (Type.LOGIN_CHAL, Type.LOGIN_RESULT, Type.CMD_RESULT):
                self._reject("stale", "Stale answer (made before the server restarted)")
                return
        result = self.tracker.accept(p)
        if result == Track.UNSYNCED:
            return                                    # its HELLO follows within a second
        if result == Track.OLD_BOOT:
            self._reject("replay", "HELLO from an older gateway boot refused")
            return
        if result == Track.REPLAY:
            self._reject("replay", "Replayed or out-of-order packet")
            return
        if result in (Track.SYNCED, Track.NEW_BOOT) and not self._boot_allowed(p.boot_id):
            self.tracker.synced = False
            self._reject("replay", "Gateway boot older than one already seen")
            return
        if result == Track.NEW_BOOT:
            self._event("LINK", "Gateway restarted", outcome="NOTE")
            self._end_control("gateway restarted")
            self._checked_series = False
        self.last_heard = time.monotonic()
        if not self.online:
            self._set_online(True)

        if p.type in (Type.HELLO, Type.STATUS):
            self._on_status(p)
        elif p.type == Type.LOG:
            self._on_log(p)
        elif p.type in (Type.LOGIN_CHAL, Type.LOGIN_RESULT):
            self._on_login_packet(p)
        elif p.type == Type.CMD_RESULT:
            fut = self._pending.pop(p.arg, None)
            if fut and not fut.done():
                fut.set_result(p)
        else:
            self._reject("type", f"Unexpected packet type {p.type}")

    def _boot_allowed(self, boot_id: int) -> bool:
        known = int(self.store.get("gateway_boot", "0"))
        if known and boot_id != known and not boot_is_newer(boot_id, known, self.cfg.simulator):
            return False
        if boot_id != known:
            self.store.put("gateway_boot", str(boot_id))
        return True

    def _on_status(self, p: Packet) -> None:
        letter = NODE_LETTER.get(p.code)
        if not letter:
            return
        st = parse_status(p.text)
        view: dict = {"updated": time.time()}
        if letter == "G":
            view.update(st)
            view["state"] = GATEWAY_STATES[p.state] if p.state < len(GATEWAY_STATES) else "INVALID"
            view["system_priority"] = p.priority
            view["online"] = True
            self._check_series(int(st.get("LOGNO", "0") or 0))
            self.top = max(self.top, int(st.get("LOGNO", "0") or 0))
            user = st.get("USER", "-")
            if self.control and user != self.control.user:          # the gateway ended it without telling us
                self._end_control("ended on the gateway")
        else:
            view.update(st)
            view["online"] = st.get("state") != "OFFLINE" and bool(p.text)
        if view != {**self.nodes[letter], "updated": view["updated"]}:
            self.nodes[letter] = view
            self.hub.publish("node", {"node": letter, **view})
        else:
            self.nodes[letter]["updated"] = view["updated"]

    def _check_series(self, logno: int) -> None:
        if self._checked_series or not logno:
            return
        self._checked_series = True
        stored = self.store.max_gw_no()
        if logno < stored:            # its numbering went back (flash erased): keep the old lines apart
            self.store.new_series()
            self.top = logno
            self._event("LOG", f"Gateway log numbering restarted ({stored} -> {logno}); started a new log series",
                        outcome="NOTE")

    def _on_log(self, p: Packet) -> None:
        if not p.log_no:
            return
        self.top = max(self.top, p.log_no)
        row = self.store.add_line(p.log_no, p.text, p.code == 1)
        if row and p.code == 1:
            self._resend_progress = time.monotonic()    # only lines we were missing count as progress
        if row:
            self._gap_since.pop(p.log_no, None)
            self.hub.publish("event", row)

    # ------------------------------------------------------------------ login
    def _on_login_packet(self, p: Packet) -> None:
        if p.type == Type.LOGIN_RESULT and p.session == 0 and p.text.startswith("Session ended"):
            self._end_control(p.text.removeprefix("Session ended: ") or "ended on the gateway")
            return
        if p.type == Type.LOGIN_RESULT and p.result == Result.OK and p.text != f"Welcome {self._login_user}":
            self._reject("stale", "Login answer for another sign-in ignored")    # a late answer to a timed-out login
            return
        if self._login_wait and not self._login_wait.done():
            self._login_wait.set_result(p)

    async def login(self, user: str, pw_hash: bytes) -> LoginOutcome:
        if not USER_RE.fullmatch(user):
            return LoginOutcome(False, "User names are 1-31 letters, digits, '.', '_' or '-'")
        if not self.online:
            return LoginOutcome(False, "The gateway is offline")
        async with self._login_lock:
            pause = 1.05 - (time.monotonic() - self._last_login_req)   # the gateway allows 1 challenge a second
            if pause > 0:
                await asyncio.sleep(pause)
            self._last_login_req = time.monotonic()
            self._login_user = user
            try:
                p = await self._login_step(Type.LOGIN_REQ, user)
                if p.type == Type.LOGIN_RESULT:
                    return LoginOutcome(False, p.text or "Refused by the gateway")
                try:
                    nonce = bytes.fromhex(p.text)
                except ValueError:
                    nonce = b""
                if len(nonce) != 16:
                    return LoginOutcome(False, "The gateway sent a malformed challenge")
                p = await self._login_step(Type.LOGIN_RESP, f"{user}:{login_response(pw_hash, nonce, user)}")
            except asyncio.TimeoutError:
                return LoginOutcome(False, "The gateway did not answer")
            if p.type != Type.LOGIN_RESULT:
                return LoginOutcome(False, "Unexpected answer from the gateway")
            if p.result != Result.OK or not p.session:
                return LoginOutcome(False, p.text or "Refused by the gateway")
            self.control = Control(p.session, user, p.role, time.time())
            self.hub.publish("control", self.control.public())
            return LoginOutcome(True, p.text, p.role, p.session)

    async def _login_step(self, ptype: int, text: str) -> Packet:
        self._login_wait = asyncio.get_running_loop().create_future()
        try:
            self.send(ptype, text=text)
            return await asyncio.wait_for(self._login_wait, STEP_TIMEOUT)
        finally:
            self._login_wait = None

    def _end_control(self, why: str) -> None:
        if self.control:
            self._event("CONTROL", f"Control released ({why})", actor=self.control.user, outcome="NOTE")
            self.control = None
            self.hub.publish("control", None)

    # ------------------------------------------------------------------ commands
    async def command(self, cmd: int, target: int = TARGET_BOTH, arg: int = 0, session: int = 0) -> CommandOutcome:
        if not self.online:
            return CommandOutcome("OFFLINE", "The gateway is offline")
        fut = asyncio.get_running_loop().create_future()
        seq = self.send(Type.PC_CMD, code=cmd, target=target, arg=arg, session=session)
        self._pending[seq] = fut
        try:
            p = await asyncio.wait_for(fut, COMMAND_TIMEOUT)
        except asyncio.TimeoutError:
            return CommandOutcome("TIMEOUT", "No answer from the gateway")
        finally:
            self._pending.pop(seq, None)
        if p is None:
            return CommandOutcome("OFFLINE", "The gateway link dropped before it answered")
        if cmd == Cmd.LOGOUT and p.result == Result.OK:
            self.control = None
            self.hub.publish("control", None)
        return CommandOutcome(Result(p.result).name if p.result <= Result.BAD else "BAD", p.text)

    # ------------------------------------------------------------------ housekeeping
    def _keep_time(self) -> None:
        now = time.monotonic()
        unsynced = self.nodes["G"].get("TIME") == "N"
        if (unsynced and now - self._time_sent > 10) or now - self._time_sent > TIME_RESYNC:
            self._time_sent = now
            self.send(Type.PC_CMD, code=Cmd.SET_TIME, arg=int(time.time()))

    def _fill_gaps(self) -> None:
        if not self.top:
            return
        now = time.monotonic()
        if self._resend_active:
            if now - self._resend_progress < RESEND_IDLE:
                return
            self._resend_active = False
        low = max(1, self.top - RESEND_WINDOW + 1)
        have = self.store.have_numbers(low, self.top)
        missing = next((n for n in range(low, self.top + 1) if n not in have), 0)
        if not missing:
            self._gap_since.clear()
            return
        if now - self._gap_since.setdefault(missing, now) < GAP_GRACE:
            return
        if missing == self._resend_from:
            self._resend_tries += 1
        else:
            self._resend_from, self._resend_tries = missing, 1
        end = missing
        while end < self.top and end + 1 not in have:
            end += 1
        if self._resend_tries > RESEND_TRIES:
            self.store.mark_lost(missing, end)
            self._event("LOG", f"Log lines {missing}-{end} could not be fetched from the gateway", outcome="LOST")
            self._resend_from = self._resend_tries = 0
            return
        self.send(Type.PC_CMD, code=Cmd.RESEND_LOG, arg=missing, session=end)   # session = last line wanted
        self._resend_active = True
        self._resend_progress = now

    # ------------------------------------------------------------------ state for the dashboard
    def _set_online(self, up: bool, why: str = "") -> None:
        self.online = up
        self.online_since = time.time()
        if up:
            self._event("LINK", "Gateway link up", outcome="OK")
        else:
            self._event("LINK", f"Gateway link down ({why})", outcome="FAIL")
            for k in self.nodes:
                self.nodes[k] = {**self.nodes[k], "online": False}
            self._end_control("gateway link down")
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_result(None)
        self.hub.publish("link", self.link_info())

    def set_transport(self, up: bool, detail: str = "") -> None:
        if up != self.transport_up:
            self.transport_up = up
            self._event("LINK", ("Broker connected" if up else "Broker disconnected") + (f" ({detail})" if detail else ""),
                        outcome="OK" if up else "FAIL")
            self.hub.publish("link", self.link_info())

    def set_presence(self, value: str) -> None:
        if value != self.presence:
            self.presence = value
            self.hub.publish("link", self.link_info())

    def link_info(self) -> dict:
        return {
            "mode": self.cfg.mode,
            "site": self.cfg.site_id,
            "broker": self.transport_up,
            "gateway": self.online,
            "presence": self.presence,
            "since": self.online_since,
            "gateway_boot": f"{self.tracker.boot_id:08x}" if self.tracker.synced else None,
            "server_boot": f"{self.boot_id:08x}",
            "rejected": dict(self.rejects),
            "version": __version__,
        }

    def snapshot(self) -> dict:
        return {
            "link": self.link_info(),
            "nodes": self.nodes,
            "control": self.control.public() if self.control else None,
        }

    def _reject(self, kind: str, why: str) -> None:
        self.rejects[kind] += 1
        now = time.monotonic()
        if now - self._reject_logged.get(kind, -1e9) > 30:      # at most one audit line per kind per 30 s
            self._reject_logged[kind] = now
            self._event("REJECT", why, outcome="REJECTED")
        self.hub.publish("rejects", dict(self.rejects))

    def _event(self, action: str, detail: str, *, actor: str = "server", outcome: str = "") -> None:
        log.info("%s: %s", action, detail)
        row = self.store.audit(action, actor=actor, detail=detail, outcome=outcome)
        self.hub.publish("audit", row)


def command_from_name(name: str) -> int | None:
    return {"arm": Cmd.ARM, "disarm": Cmd.DISARM, "ack": Cmd.ACK_ALARM, "maint_start": Cmd.MAINT_START,
            "maint_end": Cmd.MAINT_END, "clear": Cmd.CLEAR_FAULT}.get(name)


# Smallest role the gateway accepts for each command (Gateway.ino roleNeeded)
ROLE_NEEDED = {Cmd.ARM: Role.OPERATOR, Cmd.DISARM: Role.OPERATOR, Cmd.ACK_ALARM: Role.OPERATOR,
               Cmd.MAINT_END: Role.OPERATOR, Cmd.MAINT_START: Role.MAINTENANCE, Cmd.CLEAR_FAULT: Role.MAINTENANCE}
