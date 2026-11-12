#!/usr/bin/env bash
# Installs the intrusion MCP server on a Debian/Ubuntu host that already runs fail2ban.
# Run from the unpacked tarball, as root:  sudo ./install.sh
# The key is asked on the terminal (or read from INTRUSION_MCP_API_KEY, for an unattended install) and only its
# SHA-256 is stored; the clear key is the one to register in XRCopilotLab.
#
# Idempotent: running it again (the same version or a newer one) gives the same result as a first install. It keeps
# the key, the customer's appsettings.Production.json and the geolocation file, replaces the program and restarts the
# service. A second run with nothing changed changes nothing but the restart.
#   --no-start   install and enable the service without starting it (an image build, where systemd is not running yet)
#   --new-key    replace the stored key (asked again, or INTRUSION_MCP_API_KEY): the old key stops working
set -euo pipefail

START=1
NEW_KEY=0
for arg in "$@"; do
  case "$arg" in
    --no-start) START=0 ;;
    --new-key)  NEW_KEY=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

APP_DIR=/opt/xrcopilotlab-intrusion-mcp
ETC_DIR=/etc/xrcopilotlab-intrusion-mcp
SERVICE=xrcopilotlab-intrusion-mcp
UNIT=/etc/systemd/system/$SERVICE.service
USER_NAME=xrcopilot-intrusion
HERE="$(cd "$(dirname "$0")" && pwd)"
NEW_VERSION="$(cat "$HERE/VERSION" 2>/dev/null || echo unknown)"
OLD_VERSION="$(cat "$APP_DIR/VERSION" 2>/dev/null || true)"
[[ -z "$OLD_VERSION" && -f "$APP_DIR/XrCopilotLab.Intrusion.Mcp.Server" ]] && OLD_VERSION="an earlier version"

[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0" >&2; exit 1; }
command -v fail2ban-client >/dev/null || echo "warning: fail2ban is not installed; the server will only see sshd logins" >&2

# A package for the wrong processor would replace a working install with one that cannot start: refuse it first.
PKG_RID="$(cat "$HERE/RID" 2>/dev/null || true)"
case "$(uname -m)" in x86_64) HOST_RID=linux-x64 ;; aarch64|arm64) HOST_RID=linux-arm64 ;; *) HOST_RID="$(uname -m)" ;; esac
[[ -z "$PKG_RID" || "$PKG_RID" == "$HOST_RID" ]] || { echo "this package is for $PKG_RID, this server is $HOST_RID: use the $HOST_RID package" >&2; exit 1; }

if [[ -n "$OLD_VERSION" ]]; then echo "upgrading $OLD_VERSION -> $NEW_VERSION"; else echo "installing $NEW_VERSION"; fi

# The binary is self-contained but uses the system's ICU (dates, country names): a minimal image may not have it.
if ! ldconfig -p | grep -q 'libicuuc\.so'; then
  echo "libicu not found: installing it" >&2
  apt-get update -qq
  ICU_PKG="$(apt-cache pkgnames libicu | grep -E '^libicu[0-9]+$' | sort -V | tail -1)"
  [[ -n "$ICU_PKG" ]] || { echo "no libicu package found: install ICU, then run this script again" >&2; exit 1; }
  apt-get install -y -qq --no-install-recommends "$ICU_PKG"
fi

id -u "$USER_NAME" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"

# The program: --remove-destination unlinks each file first, so a running service keeps its old copy until the
# restart below instead of failing with "Text file busy".
install -d -m 0755 "$APP_DIR" "$APP_DIR/geo"
cp -r --remove-destination "$HERE/bin/." "$APP_DIR/"
chmod 0755 "$APP_DIR/XrCopilotLab.Intrusion.Mcp.Server"
printf '%s\n' "$NEW_VERSION" > "$APP_DIR/VERSION"

# The production settings are the customer's once installed (allowed countries, log paths): never overwritten.
if [[ ! -f "$APP_DIR/appsettings.Production.json" ]]; then
  install -m 0644 "$HERE/appsettings.Production.json" "$APP_DIR/appsettings.Production.json"
elif ! cmp -s "$HERE/appsettings.Production.json" "$APP_DIR/appsettings.Production.json"; then
  install -m 0644 "$HERE/appsettings.Production.json" "$APP_DIR/appsettings.Production.json.new"
  echo "kept your appsettings.Production.json; this version's defaults are in appsettings.Production.json.new"
fi

install -d -m 0750 -g "$USER_NAME" "$ETC_DIR"
if [[ -f "$ETC_DIR/env" && $NEW_KEY -eq 0 ]]; then
  echo "key: kept the one already stored (--new-key to replace it)"
elif [[ $START -eq 1 || $NEW_KEY -eq 1 || -n "${INTRUSION_MCP_API_KEY:-}" ]]; then
  if [[ -n "${INTRUSION_MCP_API_KEY:-}" ]]; then KEY="$INTRUSION_MCP_API_KEY"; else read -rsp "API key XRCopilotLab will send (X-API-Key): " KEY; echo; fi
  [[ ${#KEY} -ge 24 ]] || { echo "the key must be at least 24 characters" >&2; exit 1; }
  HASH=$(printf '%s' "$KEY" | sha256sum | cut -d' ' -f1)
  ( umask 027 && printf 'ApiKeys__Hash=%s\n' "$HASH" > "$ETC_DIR/env.tmp" )
  chgrp "$USER_NAME" "$ETC_DIR/env.tmp"
  mv -f "$ETC_DIR/env.tmp" "$ETC_DIR/env"
  unset KEY
  echo "key: stored (its SHA-256 only)"
fi

install -m 0644 "$HERE/$SERVICE.service" "$UNIT"
if [[ $START -eq 1 ]]; then
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1
  # restart, not start: on a second run the new program and unit must take over.
  systemctl restart "$SERVICE"
  for _ in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1; then break; fi
    sleep 1
  done
  curl -fsS http://127.0.0.1:8080/healthz && echo || { echo "the service does not answer: journalctl -u $SERVICE -n 50" >&2; exit 1; }
else
  systemctl enable "$SERVICE"
  [[ -f "$ETC_DIR/env" ]] || echo "installed, not started: write $ETC_DIR/env (ApiKeys__Hash=<sha256 of the key>) before the first start"
fi

[[ -n "$OLD_VERSION" ]] && { echo "upgraded to $NEW_VERSION"; exit 0; }
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
