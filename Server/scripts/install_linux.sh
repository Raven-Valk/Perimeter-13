#!/bin/sh
# Installs the Project 13 server on Debian / Ubuntu (Ubuntu Server 24.04 tested).
# Run from the Server folder as your normal user (it asks for sudo when needed):
#
#   sh scripts/install_linux.sh --ip 192.168.137.1
#
# --ip is the laptop's address on the gateway's Wi-Fi network (repeat it for
# more than one). Other options are passed to setup.py.
set -eu
cd "$(dirname "$0")/.."
SERVER_DIR=$(pwd)
RUN_AS=$(id -un)

echo "== packages"
sudo apt-get update -q
sudo apt-get install -y -q mosquitto python3-venv

echo "== Python environment"
python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt

echo "== certificates, broker users, settings"
.venv/bin/python scripts/setup.py --mosquitto-dir /etc/mosquitto/p13 "$@"

echo "== broker"
sudo install -d -o root -g mosquitto -m 750 /etc/mosquitto/p13
sudo install -o root -g mosquitto -m 640 config/mosquitto/passwd config/mosquitto/acl \
     config/mosquitto/server.crt config/mosquitto/server.key /etc/mosquitto/p13/
sudo install -o root -g root -m 644 config/mosquitto/p13.conf /etc/mosquitto/conf.d/p13.conf
sudo systemctl enable mosquitto >/dev/null 2>&1 || true
sudo systemctl restart mosquitto

mkdir -p data
echo "== dashboard service"
sed -e "s#@SERVER_DIR@#$SERVER_DIR#g" -e "s#@USER@#$RUN_AS#g" deploy/p13server.service |
  sudo tee /etc/systemd/system/p13server.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable p13server >/dev/null
sudo systemctl restart p13server

if command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -q "Status: active"; then
  echo "== firewall"
  sudo ufw allow 8883/tcp comment "Project 13 gateway (MQTT over TLS)"
  sudo ufw allow 8443/tcp comment "Project 13 dashboard (HTTPS)"
fi

echo
echo "Done. Dashboard: https://<this laptop's address>:8443"
echo "Next: paste gateway_secrets.txt into Gateway/secrets.h, add the Wi-Fi name and password, upload."
echo "Logs: journalctl -u p13server -f      Broker: journalctl -u mosquitto -f"
