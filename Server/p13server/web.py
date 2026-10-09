"""The dashboard's web server: pages, a small JSON API, and a WebSocket with
live updates.

Who may do what is decided by the gateway, not here: a sign-in is relayed to
the gateway as a challenge-response, and every command carries the gateway
session it granted. The server only remembers who is signed in to *this*
website, and refuses commands it already knows the gateway would refuse.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import ssl
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from aiohttp import WSMsgType, web

from .config import SERVER_DIR, Config
from .gateway import ROLE_NEEDED, USER_RE, GatewayLink, command_from_name
from .hub import Hub
from .protocol import TARGET_BOTH, Cmd, Node, Role, password_hash
from .store import Store

log = logging.getLogger("p13.web")

WEB_DIR = SERVER_DIR / "web"
COOKIE = "p13_session"
TARGETS = {"both": TARGET_BOTH, "A": Node.MOD_A, "B": Node.MOD_B, "gateway": Node.GATEWAY}

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")


@dataclass
class WebSession:
    token: str
    user: str
    role: int
    ip: str
    gw_session: int | None          # the gateway session this sign-in was granted (None = view only)
    view_only_reason: str = ""
    created: float = field(default_factory=time.time)


class Sessions:
    def __init__(self, hours: int):
        self.ttl = hours * 3600
        self._by_token: dict[str, WebSession] = {}

    def create(self, **kw) -> WebSession:
        s = WebSession(token=secrets.token_urlsafe(32), **kw)
        self._by_token[s.token] = s
        return s

    def get(self, request: web.Request) -> WebSession | None:
        token = request.cookies.get(COOKIE, "")
        s = self._by_token.get(token)
        if s and time.time() - s.created > self.ttl:
            del self._by_token[token]
            return None
        return s

    def drop(self, s: WebSession) -> None:
        self._by_token.pop(s.token, None)


class RateLimit:
    """At most `count` events per key per `window` seconds."""

    def __init__(self, count: int = 5, window: float = 60):
        self.count, self.window = count, window
        self._hits: dict[str, deque] = defaultdict(deque)

    def peek(self, key: str) -> bool:
        """Would one more be allowed? (Doesn't count it.)"""
        now, q = time.monotonic(), self._hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return len(q) < self.count

    def allow(self, key: str) -> bool:
        if not self.peek(key):
            return False
        self._hits[key].append(time.monotonic())
        return True


def _error(status: int, message: str) -> web.Response:
    return web.json_response({"error": message}, status=status)


class Dashboard:
    def __init__(self, cfg: Config, store: Store, hub: Hub, link: GatewayLink):
        self.cfg, self.store, self.hub, self.link = cfg, store, hub, link
        self.sessions = Sessions(cfg.session_hours)
        self.limiter = RateLimit()                       # sign-in attempts per address
        # Wrong passwords per address. The gateway locks dashboard sign-in for
        # everyone after 3; this keeps one address from using them all up.
        self.failures = RateLimit(count=2, window=900)
        self.secure = cfg.tls_cert is not None
        self.sockets: set[web.WebSocketResponse] = set()

    # ---------------- app ----------------
    def app(self) -> web.Application:
        app = web.Application(middlewares=[self._headers, self._guard], client_max_size=16 * 1024)
        app.add_routes([
            web.get("/", self.index),
            web.get("/api/session", self.session_info),
            web.post("/api/session", self.sign_in),
            web.delete("/api/session", self.sign_out),
            web.post("/api/control", self.take_control),
            web.delete("/api/control", self.release_control),
            web.post("/api/commands", self.command),
            web.get("/api/events", self.events),
            web.get("/api/events.csv", self.events_csv),
            web.get("/api/audit", self.audit),
            web.get("/ws", self.socket),
            web.static("/assets", WEB_DIR / "assets", append_version=False),
        ])
        app.on_shutdown.append(self._close_sockets)
        return app

    @web.middleware
    async def _headers(self, request: web.Request, handler):
        resp = await handler(request)
        h = resp.headers
        h["Content-Security-Policy"] = CSP
        h["X-Content-Type-Options"] = "nosniff"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.path.startswith("/api/") or request.path == "/":
            h["Cache-Control"] = "no-store"
        if self.secure:
            h["Strict-Transport-Security"] = "max-age=31536000"
        return resp

    @web.middleware
    async def _guard(self, request: web.Request, handler):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            # Cross-site requests are refused: the cookie is SameSite=Strict, and the
            # browser's Origin must be this site.
            origin = request.headers.get("Origin")
            expected = f"{'https' if self.secure else 'http'}://{request.host}"
            if origin != expected:
                return _error(403, "Request from another site refused")
        public = (request.path == "/" or request.path.startswith("/assets/")
                  or (request.path == "/api/session" and request.method in ("GET", "POST")))
        if not public:
            s = self.sessions.get(request)
            if not s:
                return _error(401, "Sign in first")
            request["session"] = s
        return await handler(request)

    async def _close_sockets(self, _app) -> None:
        for ws in list(self.sockets):
            await ws.close()

    # ---------------- pages ----------------
    async def index(self, request: web.Request) -> web.StreamResponse:
        return web.FileResponse(WEB_DIR / "index.html")

    # ---------------- sign-in ----------------
    def _session_json(self, s: WebSession | None) -> dict:
        if not s:
            return {"signed_in": False, "gateway_online": self.link.online, "mode": self.cfg.mode}
        ctl = self.link.control
        has = bool(ctl and s.gw_session and ctl.session_id == s.gw_session)
        return {"signed_in": True, "user": s.user, "role": Role(s.role).name, "control": has,
                "view_only_reason": s.view_only_reason if not has else "",
                "gateway_online": self.link.online, "mode": self.cfg.mode, "expires": s.created + self.sessions.ttl}

    async def session_info(self, request: web.Request) -> web.Response:
        return web.json_response(self._session_json(self.sessions.get(request)))

    async def _credentials(self, request: web.Request, user: str | None = None) -> tuple[str, bytes] | web.Response:
        ip = request.remote or "-"
        if not self.limiter.allow(ip):
            return _error(429, "Too many sign-in attempts from this address. Wait a minute and try again.")
        if not self.failures.peek(ip):
            return _error(429, "Two wrong passwords from this address. Wait 15 minutes, or sign in from the gateway.")
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _error(400, "Expected JSON")
        user = user or str(body.get("user", "")).strip()
        password = str(body.get("password", ""))
        if not USER_RE.fullmatch(user) or not password or len(password) > 128:
            return _error(400, "Enter a user name and password")
        pw = await asyncio.get_running_loop().run_in_executor(None, password_hash, user, password)
        return user, pw

    async def sign_in(self, request: web.Request) -> web.Response:
        got = await self._credentials(request)
        if isinstance(got, web.Response):
            return got
        user, pw = got
        ip = request.remote or "-"
        if self.link.online:
            out = await self.link.login(user, pw)
            if not out.ok:
                if "tries left" in out.message or out.message.startswith("Locked"):
                    self.failures.allow(ip)
                self._audit("SIGN-IN", user, ip, "Refused by the gateway: " + out.message, "FAIL")
                return _error(401, out.message)
            self.store.remember_viewer(user, out.role, pw)
            s = self.sessions.create(user=user, role=out.role, ip=ip, gw_session=out.session_id)
            self._audit("SIGN-IN", user, ip, f"Gateway session granted ({Role(out.role).name})", "OK")
        else:
            role = self.store.check_viewer(user, pw)
            if role is None:
                self._audit("SIGN-IN", user, ip, "Gateway offline and no earlier sign-in to check against", "FAIL")
                return _error(503, "The gateway is offline. Only accounts that have signed in here before can "
                                   "sign in now, to view.")
            s = self.sessions.create(user=user, role=role, ip=ip, gw_session=None,
                                     view_only_reason="Signed in while the gateway was offline")
            self._audit("SIGN-IN", user, ip, "View only: gateway offline, checked against the last sign-in", "OK")
        resp = web.json_response(self._session_json(s))
        resp.set_cookie(COOKIE, s.token, httponly=True, secure=self.secure, samesite="Strict", path="/",
                        max_age=self.sessions.ttl)
        return resp

    async def sign_out(self, request: web.Request) -> web.Response:
        s: WebSession = request["session"]
        if self._has_control(s):
            await self.link.command(Cmd.LOGOUT, session=s.gw_session or 0)
        self.sessions.drop(s)
        self._audit("SIGN-OUT", s.user, request.remote or "-", "Signed out", "OK")
        resp = web.json_response({"signed_in": False})
        resp.del_cookie(COOKIE, path="/")
        return resp

    async def take_control(self, request: web.Request) -> web.Response:
        """Ask the gateway again (password needed): for a session whose control lapsed."""
        s: WebSession = request["session"]
        got = await self._credentials(request, user=s.user)
        if isinstance(got, web.Response):
            return got
        _, pw = got
        out = await self.link.login(s.user, pw)
        if not out.ok:
            if "tries left" in out.message or out.message.startswith("Locked"):
                self.failures.allow(request.remote or "-")
            self._audit("CONTROL", s.user, request.remote or "-", "Refused by the gateway: " + out.message, "FAIL")
            return _error(401, out.message)
        s.gw_session, s.role, s.view_only_reason = out.session_id, out.role, ""
        self.store.remember_viewer(s.user, out.role, pw)
        self._audit("CONTROL", s.user, request.remote or "-", f"Control taken ({Role(out.role).name})", "OK")
        return web.json_response(self._session_json(s))

    async def release_control(self, request: web.Request) -> web.Response:
        s: WebSession = request["session"]
        if self._has_control(s):
            out = await self.link.command(Cmd.LOGOUT, session=s.gw_session or 0)
            self._audit("CONTROL", s.user, request.remote or "-", "Control released", out.result)
        s.gw_session, s.view_only_reason = None, "You released control"
        return web.json_response(self._session_json(s))

    def _has_control(self, s: WebSession) -> bool:
        ctl = self.link.control
        return bool(ctl and s.gw_session and ctl.session_id == s.gw_session)

    # ---------------- commands ----------------
    async def command(self, request: web.Request) -> web.Response:
        s: WebSession = request["session"]
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _error(400, "Expected JSON")
        name, target_name = str(body.get("command", "")), str(body.get("target", "both"))
        cmd, target = command_from_name(name), TARGETS.get(target_name)
        if cmd is None or target is None:
            return _error(400, "Unknown command or target")
        if target == Node.GATEWAY and cmd != Cmd.CLEAR_FAULT:
            return _error(400, "Only a fault can be cleared on the gateway")
        arg = 0
        if cmd == Cmd.MAINT_START:
            try:
                arg = int(body.get("seconds", 300))
            except (TypeError, ValueError):
                return _error(400, "Maintenance time must be a number of seconds")
            if not 30 <= arg <= 900:
                return _error(400, "Maintenance time must be 30 to 900 seconds")
        if not self._has_control(s):
            return _error(409, "Sign in again to send commands: this session is view only")
        if s.role < ROLE_NEEDED[cmd]:
            return _error(403, f"Needs the {ROLE_NEEDED[cmd].name.lower()} role")
        out = await self.link.command(cmd, target, arg, s.gw_session or 0)
        detail = f"{name} on {target_name}" + (f" for {arg} s" if arg else "") + f": {out.text or out.result}"
        self._audit("COMMAND", s.user, request.remote or "-", detail, out.result)
        result = {"command": name, "target": target_name, "result": out.result, "text": out.text,
                  "by": s.user, "at": time.time()}
        self.hub.publish("command", result)
        return web.json_response(result, status=200)

    # ---------------- history ----------------
    async def events(self, request: web.Request) -> web.Response:
        q = request.query
        try:
            before = int(q["before"]) if q.get("before") else None
            limit = int(q.get("limit", 200))
            min_p = int(q.get("min_priority", 0))
        except ValueError:
            return _error(400, "before, limit and min_priority are numbers")
        module = q.get("module") if q.get("module") in ("A", "B", "G") else None
        types = [t for t in (q.get("types") or "").split(",") if t.isalpha() and t.isupper()][:12] or None
        rows = self.store.events(before=before, limit=limit, module=module, min_priority=min_p,
                                 text=(q.get("q") or "")[:64] or None, types=types)
        return web.json_response(rows)

    async def events_csv(self, request: web.Request) -> web.Response:
        s: WebSession = request["session"]
        self._audit("EXPORT", s.user, request.remote or "-", "Event log exported as CSV", "OK")
        stamp = time.strftime("%Y%m%d-%H%M%S")
        return web.Response(text=self.store.events_csv(), content_type="text/csv",
                            headers={"Content-Disposition": f'attachment; filename="p13-events-{stamp}.csv"'})

    async def audit(self, request: web.Request) -> web.Response:
        try:
            limit = int(request.query.get("limit", 100))
        except ValueError:
            return _error(400, "limit is a number")
        return web.json_response(self.store.audit_rows(max(1, min(limit, 500))))

    # ---------------- live updates ----------------
    def _snapshot(self, s: WebSession) -> dict:
        return {**self.link.snapshot(), "events": self.store.events(limit=300),
                "audit": self.store.audit_rows(60), "session": self._session_json(s)}

    async def socket(self, request: web.Request) -> web.StreamResponse:
        s: WebSession = request["session"]
        if request.headers.get("Origin") != f"{'https' if self.secure else 'http'}://{request.host}":
            return _error(403, "Request from another site refused")
        ws = web.WebSocketResponse(heartbeat=20, max_msg_size=4096)
        await ws.prepare(request)
        self.sockets.add(ws)
        q = self.hub.subscribe()
        reader = asyncio.create_task(self._drain(ws))
        try:
            await ws.send_json({"type": "snapshot", "data": self._snapshot(s)})
            while not ws.closed:
                getter = asyncio.create_task(q.get())
                done, _ = await asyncio.wait({getter, reader}, return_when=asyncio.FIRST_COMPLETED)
                if reader in done:
                    getter.cancel()
                    break
                msg = getter.result()
                if self.sessions.get(request) is not s:          # signed out or expired
                    await ws.close(code=4401, message=b"signed out")
                    break
                if msg["type"] == "resync":
                    msg = {"type": "snapshot", "data": self._snapshot(s)}
                elif msg["type"] == "control":
                    msg = {"type": "control", "data": {"control": msg["data"], "session": self._session_json(s)}}
                await ws.send_json(msg)
        except (ConnectionResetError, RuntimeError):
            pass
        finally:
            self.hub.unsubscribe(q)
            self.sockets.discard(ws)
            reader.cancel()
        return ws

    @staticmethod
    async def _drain(ws: web.WebSocketResponse) -> None:
        async for msg in ws:                     # the dashboard only listens; anything else is ignored
            if msg.type == WSMsgType.ERROR:
                break

    def _audit(self, action: str, actor: str, ip: str, detail: str, outcome: str) -> None:
        log.info("%s %s from %s: %s (%s)", action, actor, ip, detail, outcome)
        self.hub.publish("audit", self.store.audit(action, actor=actor, ip=ip, detail=detail, outcome=outcome))


def ssl_context(cfg: Config) -> ssl.SSLContext | None:
    if not cfg.tls_cert:
        return None
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(Path(cfg.tls_cert), Path(cfg.tls_key))  # type: ignore[arg-type]
    return ctx
