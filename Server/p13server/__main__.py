"""python -m p13server [--config FILE] [--emulate]"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from aiohttp import web

from . import __version__
from .config import SERVER_DIR, Config, ConfigError, load
from .gateway import GatewayLink
from .hub import Hub
from .store import Store
from .web import Dashboard, ssl_context

log = logging.getLogger("p13")

# Gateway/secrets.h demo KEY_GW_SERVER: lets --emulate run before setup.
DEMO_KEY = bytes.fromhex("f23eaba527c7e035a8178ec427f504d091601abacc939e6a717d14e88dabb71e")


def emulator_config(base: Config | None) -> Config:
    """--emulate needs no setup: demo key, plain HTTP on this computer only, its own data folder."""
    if base:
        return Config(**{**base.__dict__, "mode": "emulator", "data_dir": base.data_dir / "emulator"})
    return Config(site_id="emulated", mode="emulator", gateway_key=DEMO_KEY, mqtt_host="", mqtt_port=0,
                  mqtt_user="", mqtt_password="", web_host="127.0.0.1", web_port=8080, tls_cert=None,
                  tls_key=None, session_hours=12, data_dir=SERVER_DIR / "data" / "emulator")


async def serve(cfg: Config) -> str | None:
    """Runs until stopped. Returns an error message if it couldn't start."""
    store = Store(cfg.data_dir)
    hub = Hub()
    link = GatewayLink(cfg, store, hub)

    runner = web.AppRunner(Dashboard(cfg, store, hub, link).app(), access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, cfg.web_host, cfg.web_port, ssl_context=ssl_context(cfg))
    try:
        await site.start()
    except OSError as e:
        await runner.cleanup()
        return f"Can't open port {cfg.web_port} ({e.strerror}). Is the server already running?"

    tasks = [asyncio.create_task(link.run(), name="beats")]
    if cfg.mode == "emulator":
        from .emulator import EmulatedGateway
        loop = asyncio.get_running_loop()
        emu = EmulatedGateway(cfg.gateway_key, send=lambda b: loop.call_soon(link.on_bytes, b))
        link.send_hook = lambda b: loop.call_soon(emu.on_bytes, b)
        link.set_transport(True, "emulated gateway in this process")
        tasks.append(asyncio.create_task(emu.run(), name="emulator"))
    else:
        from .transport import MqttTransport
        tasks.append(asyncio.create_task(MqttTransport(cfg, link).run(), name="mqtt"))

    scheme = "https" if cfg.tls_cert else "http"
    log.info("Project 13 server %s, %s mode, dashboard at %s://%s:%d", __version__, cfg.mode, scheme,
             cfg.web_host, cfg.web_port)

    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        except NotImplementedError:      # Windows: Ctrl+C still raises KeyboardInterrupt
            pass
    await stop.wait()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await runner.cleanup()
    return None


def main() -> int:
    ap = argparse.ArgumentParser(prog="p13server", description="Project 13 gateway bridge and dashboard")
    ap.add_argument("--config", type=Path, default=SERVER_DIR / "config" / "p13server.toml")
    ap.add_argument("--mode", choices=("hardware", "wokwi"), help="override the mode in the config file")
    ap.add_argument("--emulate", action="store_true", help="no hardware: run an emulated gateway in this process")
    ap.add_argument("--port", type=int, help="override the web port")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        if args.emulate:
            cfg = emulator_config(load(args.config) if args.config.exists() else None)
        else:
            cfg = load(args.config, args.mode)
    except ConfigError as e:
        print(f"config: {e}", file=sys.stderr)
        return 2
    if args.port:
        cfg = Config(**{**cfg.__dict__, "web_port": args.port})
    try:
        error = asyncio.run(serve(cfg))
    except KeyboardInterrupt:
        error = None
    if error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
