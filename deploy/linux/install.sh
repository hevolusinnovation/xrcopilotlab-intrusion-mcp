#!/usr/bin/env bash
# Installs the intrusion MCP server on a Debian/Ubuntu host that already runs fail2ban.
# Run from the unpacked tarball, as root:  sudo ./install.sh
# The key is asked on the terminal and only its SHA-256 is stored; the clear key is the one to register in XRCopilotLab.
set -euo pipefail

APP_DIR=/opt/xrcopilotlab-intrusion-mcp
ETC_DIR=/etc/xrcopilotlab-intrusion-mcp
USER_NAME=xrcopilot-intrusion
HERE="$(cd "$(dirname "$0")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0" >&2; exit 1; }
command -v fail2ban-client >/dev/null || echo "warning: fail2ban is not installed; the server will only see sshd logins" >&2

id -u "$USER_NAME" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"

install -d -m 0755 "$APP_DIR" "$APP_DIR/geo"
cp -r "$HERE/bin/." "$APP_DIR/"
install -m 0644 "$HERE/appsettings.Production.json" "$APP_DIR/appsettings.Production.json"
chmod 0755 "$APP_DIR/XrCopilotLab.Intrusion.Mcp.Server"

install -d -m 0750 -g "$USER_NAME" "$ETC_DIR"
if [[ ! -f "$ETC_DIR/env" ]]; then
  read -rsp "API key XRCopilotLab will send (X-API-Key): " KEY; echo
  [[ ${#KEY} -ge 24 ]] || { echo "the key must be at least 24 characters" >&2; exit 1; }
  HASH=$(printf '%s' "$KEY" | sha256sum | cut -d' ' -f1)
  umask 027
  printf 'ApiKeys__Hash=%s\n' "$HASH" > "$ETC_DIR/env"
  chgrp "$USER_NAME" "$ETC_DIR/env"
  unset KEY
fi

install -m 0644 "$HERE/xrcopilotlab-intrusion-mcp.service" /etc/systemd/system/xrcopilotlab-intrusion-mcp.service
systemctl daemon-reload
systemctl enable --now xrcopilotlab-intrusion-mcp

sleep 2
curl -fsS http://127.0.0.1:8080/healthz && echo
cat <<'EOF'

Installed. The server listens on 127.0.0.1:8080 only: publish it through the nginx already on the host, with TLS,
and allow only XRCopilotLab's outbound addresses, for example:

  location /intrusion-mcp/ {
      allow <XRCopilotLab address>;
      deny  all;
      proxy_pass http://127.0.0.1:8080/;
      proxy_http_version 1.1;
      proxy_buffering off;
  }

Geolocation (optional): put the DB-IP "IP to City Lite" file in /opt/xrcopilotlab-intrusion-mcp/geo/dbip-city-lite.csv.gz
(https://db-ip.com/db/lite.php, CC BY 4.0) and run: systemctl restart xrcopilotlab-intrusion-mcp
EOF
