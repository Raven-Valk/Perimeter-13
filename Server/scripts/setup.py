#!/usr/bin/env python3
"""One-time setup for the Project 13 server. Run it on the server laptop.

Creates (in the Server folder):
  certs/ca.crt, ca.key           a private certificate authority, just for this system
  certs/server.crt, server.key   the server's certificate: the broker's TLS and the dashboard's HTTPS
  config/mosquitto/              broker config, user passwords and access rules
  config/p13server.toml          the server's settings
  gateway_secrets.txt            the values to paste into Gateway/secrets.h

Running it again keeps the CA, keys and passwords (so the gateway keeps
working) and only re-issues the server certificate, for example after the
laptop's address changed. --new-ca, --new-key and --new-passwords replace them.

  python3 scripts/setup.py --ip 192.168.137.1            laptop hotspot
  python3 scripts/setup.py --ip 192.168.1.50 --site lab  a router, another site name
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import os
import secrets
import socket
import stat
import sys
import tomllib
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError:
    sys.exit("Needs the 'cryptography' package: pip install -r requirements.txt")

SERVER = Path(__file__).resolve().parent.parent
CERTS = SERVER / "certs"
MOSQ = SERVER / "config" / "mosquitto"
TOML = SERVER / "config" / "p13server.toml"
SERVER_NAME = "p13-server"            # = SERVER_NAME in Gateway/secrets.h; the gateway checks it


def private(path: Path, data: bytes | str) -> None:
    """Write a file only its owner can read."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    if os.name != "nt":
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def public(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())     # small and fast for the ESP32's TLS


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def load_or_make_ca(force: bool):
    crt, key = CERTS / "ca.crt", CERTS / "ca.key"
    if crt.exists() and key.exists() and not force:
        return (x509.load_pem_x509_certificate(crt.read_bytes()),
                serialization.load_pem_private_key(key.read_bytes(), None), False)
    k = new_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Project 13 private CA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
            .sign(k, hashes.SHA256()))
    private(key, key_pem(k))
    public(crt, cert.public_bytes(serialization.Encoding.PEM).decode())
    return cert, k, True


def make_server_cert(ca_cert, ca_key, ips: list[str]) -> None:
    k = new_key()
    now = dt.datetime.now(dt.timezone.utc)
    names: list[x509.GeneralName] = [x509.DNSName(SERVER_NAME), x509.DNSName("localhost")]
    names += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in sorted(set(ips) | {"127.0.0.1"})]
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVER_NAME)]))
            .issuer_name(ca_cert.subject).public_key(k.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    private(CERTS / "server.key", key_pem(k))
    public(CERTS / "server.crt", cert.public_bytes(serialization.Encoding.PEM).decode())


def mosquitto_hash(password: str) -> str:
    """Mosquitto 2 password file entry: PBKDF2-SHA512, 101 rounds ($7$)."""
    salt = secrets.token_bytes(12)
    digest = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, 101, 64)
    return f"$7$101${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def local_ips() -> list[str]:
    found = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except OSError:
        pass
    try:                                       # the address used for the default route
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            found.add(s.getsockname()[0])
    except OSError:
        pass
    return sorted(ip for ip in found if not ip.startswith("127."))


def c_array(b: bytes) -> str:
    rows = [", ".join(f"0x{x:02X}" for x in b[i:i + 16]) for i in range(0, len(b), 16)]
    return "{\n  " + ",\n  ".join(rows) + "\n}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Set up certificates, broker and settings for the Project 13 server")
    ap.add_argument("--ip", action="append", default=[], help="the laptop's address the gateway uses (repeatable)")
    ap.add_argument("--site", default=None, help="site name, used in topic names (default: keep, or site1)")
    ap.add_argument("--web-port", type=int, default=8443)
    ap.add_argument("--mosquitto-dir", default=str(MOSQ),
                    help="where the broker will read its files from (install_linux.sh uses /etc/mosquitto/p13)")
    ap.add_argument("--new-ca", action="store_true", help="make a new CA (the gateway needs the new ca.crt)")
    ap.add_argument("--new-key", action="store_true", help="make a new gateway<->server key")
    ap.add_argument("--key-hex", help="use this gateway<->server key (64 hex characters), e.g. the Wokwi demo key")
    ap.add_argument("--new-passwords", action="store_true", help="make new broker passwords")
    args = ap.parse_args()

    old = tomllib.loads(TOML.read_text()) if TOML.exists() else {}
    site = args.site or old.get("site_id", "site1")
    if not site.replace("-", "").replace("_", "").isalnum() or len(site) > 20:
        sys.exit("--site: up to 20 letters, digits, '-' and '_'")

    ips = args.ip or (["192.168.137.1"] + local_ips())
    for ip in ips:
        ipaddress.ip_address(ip)

    ca_cert, ca_key, made_ca = load_or_make_ca(args.new_ca)
    make_server_cert(ca_cert, ca_key, ips)
    public(MOSQ / "server.crt", (CERTS / "server.crt").read_text())     # the broker's own copies
    private(MOSQ / "server.key", (CERTS / "server.key").read_bytes())

    pw_file = MOSQ / "passwords.txt"            # the plain passwords, kept so re-runs don't change them
    plain = {}
    if pw_file.exists() and not args.new_passwords:
        for line in pw_file.read_text().splitlines():
            user, _, pw = line.partition(" ")
            if pw:
                plain[user] = pw
    plain.setdefault("p13-server", secrets.token_urlsafe(18))
    plain.setdefault("gateway", secrets.token_urlsafe(18))
    private(pw_file, "".join(f"{u} {p}\n" for u, p in plain.items()))
    private(MOSQ / "passwd", "".join(f"{u}:{mosquitto_hash(p)}\n" for u, p in plain.items()))

    base = f"p13/{site}"
    public(MOSQ / "acl", f"""# Project 13: who may use which topic (written by scripts/setup.py)
user p13-server
topic read {base}/to/P
topic read {base}/state/G
topic write {base}/to/G

user gateway
topic read {base}/to/G
topic write {base}/to/P
topic write {base}/state/G
""")
    d = args.mosquitto_dir.rstrip("/\\")
    public(MOSQ / "p13.conf", f"""# Project 13 broker (written by scripts/setup.py)
per_listener_settings true

# The dashboard server, on this computer only
listener 1883 127.0.0.1
allow_anonymous false
password_file {d}/passwd
acl_file {d}/acl

# The gateway, from the Wi-Fi network: TLS only
listener 8883
certfile {d}/server.crt
keyfile {d}/server.key
tls_version tlsv1.2
allow_anonymous false
password_file {d}/passwd
acl_file {d}/acl
""")

    gw = old.get("gateway", {})
    if args.key_hex:
        try:
            key = bytes.fromhex(args.key_hex)
        except ValueError:
            key = b""
        if len(key) != 32:
            sys.exit("--key-hex: 64 hex characters")
    elif gw.get("key") and not args.new_key:
        key = bytes.fromhex(gw["key"])
    else:
        key = secrets.token_bytes(32)
    web = old.get("web", {})
    private(TOML, f"""# Project 13 server settings (written by scripts/setup.py; safe to edit)
site_id = "{site}"
mode = "hardware"                  # "hardware": the real gateway   "wokwi": the Wokwi simulator

[gateway]
key = "{key.hex()}"   # = KEY_GW_SERVER in Gateway/secrets.h

[mqtt]
host = "127.0.0.1"
port = 1883
user = "p13-server"
password = "{plain['p13-server']}"

[web]
host = "{web.get('host', '0.0.0.0')}"
port = {web.get('port', args.web_port)}
cert = "certs/server.crt"
key = "certs/server.key"
session_hours = {web.get('session_hours', 12)}

[storage]
data_dir = "data"
""")

    ca_pem = (CERTS / "ca.crt").read_text().strip()
    snippet = f"""// ---- paste into Gateway/secrets.h (replace the lines with the same names) ----
static const uint8_t KEY_GW_SERVER[32] = {c_array(key)};

#define WIFI_SSID      "your hotspot or router name"
#define WIFI_PASSWORD  "its password"
#define SERVER_HOST    "{ips[0]}"
#define SERVER_PORT    8883
#define SERVER_NAME    "{SERVER_NAME}"
#define MQTT_USER      "gateway"
#define MQTT_PASSWORD  "{plain['gateway']}"
#define SITE_ID        "{site}"

static const char SERVER_CA_PEM[] = R"PEM(
{ca_pem}
)PEM";
"""
    private(SERVER / "gateway_secrets.txt", snippet)

    print(f"Site {site}. Server certificate for {SERVER_NAME} and {', '.join(ips)}.")
    print("New CA made." if made_ca else "Existing CA kept.")
    print(f"Broker files:   {MOSQ}  (the broker reads them from {d})")
    print(f"Server config:  {TOML}")
    print(f"Gateway values: {SERVER / 'gateway_secrets.txt'}  <- paste into Gateway/secrets.h, then upload")
    print("Keep certs/ca.key, gateway_secrets.txt and config/ private: they are the system's keys.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
