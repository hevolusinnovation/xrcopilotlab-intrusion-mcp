#!/usr/bin/env bash
# Installs the intrusion MCP server on a Debian/Ubuntu host that already runs fail2ban.
# Run from the unpacked tarball, as root:  sudo ./install.sh
# The key is asked on the terminal (or read from INTRUSION_MCP_API_KEY, for an unattended install) and only its
# SHA-256 is stored; the clear key is the one to register in XRCopilotLab.
#   --no-start   install and enable the service without starting it (an image build, where systemd is not running yet)
set -euo pipefail

START=1
for arg in "$@"; do
  case "$arg" in
    --no-start) START=0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

APP_DIR=/opt/xrcopilotlab-intrusion-mcp
ETC_DIR=/etc/xrcopilotlab-intrusion-mcp
USER_NAME=xrcopilot-intrusion
HERE="$(cd "$(dirname "$0")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0" >&2; exit 1; }
command -v fail2ban-client >/dev/null || echo "warning: fail2ban is not installed; the server will only see sshd logins" >&2

# The binary is self-contained but uses the system's ICU (dates, country names): a minimal image may not have it.
if ! ldconfig -p | grep -q 'libicuuc\.so'; then
  echo "libicu not found: installing it" >&2
  apt-get update -qq
  ICU_PKG="$(apt-cache pkgnames libicu | grep -E '^libicu[0-9]+$' | sort -V | tail -1)"
  [[ -n "$ICU_PKG" ]] || { echo "no libicu package found: install ICU, then run this script again" >&2; exit 1; }
  apt-get install -y -qq --no-install-recommends "$ICU_PKG"
fi

id -u "$USER_NAME" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"

install -d -m 0755 "$APP_DIR" "$APP_DIR/geo"
cp -r "$HERE/bin/." "$APP_DIR/"
install -m 0644 "$HERE/appsettings.Production.json" "$APP_DIR/appsettings.Production.json"
chmod 0755 "$APP_DIR/XrCopilotLab.Intrusion.Mcp.Server"

install -d -m 0750 -g "$USER_NAME" "$ETC_DIR"
if [[ ! -f "$ETC_DIR/env" && ( $START -eq 1 || -n "${INTRUSION_MCP_API_KEY:-}" ) ]]; then
  if [[ -n "${INTRUSION_MCP_API_KEY:-}" ]]; then KEY="$INTRUSION_MCP_API_KEY"; else read -rsp "API key XRCopilotLab will send (X-API-Key): " KEY; echo; fi
  [[ ${#KEY} -ge 24 ]] || { echo "the key must be at least 24 characters" >&2; exit 1; }
  HASH=$(printf '%s' "$KEY" | sha256sum | cut -d' ' -f1)
  umask 027
  printf 'ApiKeys__Hash=%s\n' "$HASH" > "$ETC_DIR/env"
  chgrp "$USER_NAME" "$ETC_DIR/env"
  unset KEY
fi

install -m 0644 "$HERE/xrcopilotlab-intrusion-mcp.service" /etc/systemd/system/xrcopilotlab-intrusion-mcp.service
if [[ $START -eq 1 ]]; then
  systemctl daemon-reload
  systemctl enable --now xrcopilotlab-intrusion-mcp
  sleep 2
  curl -fsS http://127.0.0.1:8080/healthz && echo
else
  systemctl enable xrcopilotlab-intrusion-mcp
  echo "installed, not started: write $ETC_DIR/env (ApiKeys__Hash=<sha256 of the key>) before the first start"
fi
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
