"""Settings, read from a TOML file (config/p13server.toml by default)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent

# The Wokwi projects publish to this public broker and topic base (link_protocol.h).
WOKWI_BROKER = ("broker.hivemq.com", 1883)
WOKWI_TOPIC_BASE = "pinnacle13/p13-2d386efc/v6"


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    site_id: str
    mode: str                  # "hardware", "wokwi" or "emulator"
    gateway_key: bytes
    mqtt_host: str
    mqtt_port: int
    mqtt_user: str
    mqtt_password: str
    web_host: str
    web_port: int
    tls_cert: Path | None
    tls_key: Path | None
    session_hours: int
    data_dir: Path

    @property
    def topic_base(self) -> str:
        return WOKWI_TOPIC_BASE if self.mode == "wokwi" else f"p13/{self.site_id}"

    @property
    def simulator(self) -> bool:
        """Wokwi boards keep no flash, so their boot counter is always 1."""
        return self.mode == "wokwi"


def _path(value: str | None) -> Path | None:
    if not value:
        return None
    p = Path(value)
    return p if p.is_absolute() else SERVER_DIR / p


def load(path: Path, mode_override: str | None = None) -> Config:
    try:
        raw = tomllib.loads(path.read_text())
    except FileNotFoundError:
        raise ConfigError(f"{path} not found: run scripts/setup.py first (or copy config/p13server.example.toml)")
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}")

    gw, mq, web, st = (raw.get(k, {}) for k in ("gateway", "mqtt", "web", "storage"))
    mode = mode_override or raw.get("mode", "hardware")
    if mode not in ("hardware", "wokwi", "emulator"):
        raise ConfigError(f"mode must be hardware, wokwi or emulator, not {mode!r}")
    try:
        key = bytes.fromhex(gw.get("key", ""))
    except ValueError:
        key = b""
    if len(key) != 32:
        raise ConfigError("[gateway] key must be 64 hex characters (KEY_GW_SERVER in Gateway/secrets.h)")

    host, port = (WOKWI_BROKER if mode == "wokwi" else (mq.get("host", "127.0.0.1"), int(mq.get("port", 1883))))
    cert, keyfile = _path(web.get("cert")), _path(web.get("key"))
    if (cert is None) != (keyfile is None):
        raise ConfigError("[web] needs both cert and key, or neither (plain HTTP, local testing only)")
    site = str(raw.get("site_id", "site1"))
    if not site.replace("-", "").replace("_", "").isalnum() or len(site) > 20:
        raise ConfigError("site_id: up to 20 letters, digits, '-' and '_' (it is part of the gateway's topics)")
    return Config(
        site_id=site,
        mode=mode,
        gateway_key=key,
        mqtt_host=host,
        mqtt_port=port,
        mqtt_user="" if mode == "wokwi" else mq.get("user", ""),
        mqtt_password="" if mode == "wokwi" else mq.get("password", ""),
        web_host=web.get("host", "0.0.0.0"),
        web_port=int(web.get("port", 8443)),
        tls_cert=cert,
        tls_key=keyfile,
        session_hours=int(web.get("session_hours", 12)),
        data_dir=_path(st.get("data_dir", "data")) or SERVER_DIR / "data",
    )
