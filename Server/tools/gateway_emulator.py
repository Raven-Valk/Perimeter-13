#!/usr/bin/env python3
"""Pretend to be the gateway, over the real broker: TLS to port 8883 with the
gateway's own user, the same topics and signed packets. Tests the whole chain
(Mosquitto, certificates, access rules, server, dashboard) before the hardware
is ready. Reads the values setup.py made.

  python3 tools/gateway_emulator.py                  this computer's broker
  python3 tools/gateway_emulator.py --host 192.168.137.1
"""

from __future__ import annotations

import argparse
import asyncio
import ssl
import sys
import tomllib
from pathlib import Path

SERVER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SERVER))

import aiomqtt  # noqa: E402

from p13server.emulator import EmulatedGateway  # noqa: E402


async def run(host: str, port: int) -> None:
    cfg = tomllib.loads((SERVER / "config" / "p13server.toml").read_text())
    users = dict(line.split(" ", 1) for line in (SERVER / "config" / "mosquitto" / "passwords.txt").read_text().splitlines() if " " in line)
    key = bytes.fromhex(cfg["gateway"]["key"])
    base = f"p13/{cfg.get('site_id', 'site1')}"
    tls = ssl.create_default_context(cafile=str(SERVER / "certs" / "ca.crt"))   # checks the server's certificate
    out: asyncio.Queue[bytes] = asyncio.Queue(256)
    emu = EmulatedGateway(key, send=lambda b: out.put_nowait(b) if not out.full() else None)
    runner = asyncio.create_task(emu.run())
    will = aiomqtt.Will(f"{base}/state/G", b"offline", qos=1, retain=True)
    while True:
        try:
            async with aiomqtt.Client(host, port, username="gateway", password=users["gateway"].strip(),
                                      tls_context=tls, identifier="p13-gw-emulator", will=will, keepalive=10) as c:
                await c.subscribe(f"{base}/to/G")
                await c.publish(f"{base}/state/G", b"online", qos=1, retain=True)
                print(f"connected to {host}:{port} over TLS as the gateway ({base})", flush=True)

                async def sender():
                    while True:
                        await c.publish(f"{base}/to/P", await out.get())
                task = asyncio.create_task(sender())
                try:
                    async for msg in c.messages:
                        emu.on_bytes(bytes(msg.payload))
                finally:
                    task.cancel()
        except aiomqtt.MqttError as e:
            print(f"broker: {e}; retrying in 5 s", flush=True)
            await asyncio.sleep(5)
        if runner.done():
            raise runner.exception() or SystemExit(1)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8883)
    args = ap.parse_args()
    try:
        asyncio.run(run(args.host, args.port))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
