# The monitoring page, published by nginx on its own port (8471), over HTTPS, with a password, to the internal network
# only. Sourced by install.sh, as root. Idempotent: the certificate, the password and the page's key are made once and
# kept; the nginx site is rewritten on every run.
#   DASHBOARD_PORT      the port (default 8471): not 80 or 443, so the customer's sites are not touched
#   DASHBOARD_ALLOW     who may open it (default: loopback and the private ranges); space-separated addresses or networks
#   DASHBOARD_PASSWORD  the password of the user "admin" on the first install (default: generated and printed once)
# The page reads the package's API through this site, which adds a key of its own (Id "dashboard"): the browser never
# sees a key, and the key XRCopilotLab uses is not shared with the page.

DASHBOARD_PORT="${DASHBOARD_PORT:-8471}"
DASHBOARD_ALLOW="${DASHBOARD_ALLOW:-127.0.0.1 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7}"
DASHBOARD_DIR=/etc/nginx/xrcopilotlab-dashboard
DASHBOARD_ENV=/etc/xrcopilotlab-intrusion-mcp/dashboard.env
DASHBOARD_SITE=xrcopilotlab-dashboard
NGINX_MARKER=/etc/nginx/.xrcopilotlab-installed

dashboard_nginx() {
  if command -v nginx >/dev/null; then return 0; fi
  echo "dashboard: installing nginx (it serves the page on port $DASHBOARD_PORT only)"
  # Not started by the package: its default site takes port 80, which may belong to another web server.
  printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d
  apt_install nginx || { rm -f /usr/sbin/policy-rc.d; return 1; }
  rm -f /usr/sbin/policy-rc.d /etc/nginx/sites-enabled/default
  touch "$NGINX_MARKER"
}

dashboard_setup() {
  dashboard_nginx || return 1
  install -d -m 0750 "$DASHBOARD_DIR"

  # A self-signed certificate for the host's names and addresses: the browser warns once, the password travels encrypted.
  if [[ ! -f "$DASHBOARD_DIR/tls.crt" ]]; then
    local san="DNS:$(hostname),DNS:localhost" ip
    for ip in $(hostname -I 2>/dev/null) 127.0.0.1; do san="$san,IP:$ip"; done
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 -subj "/CN=$(hostname)" \
      -addext "subjectAltName=$san" -keyout "$DASHBOARD_DIR/tls.key" -out "$DASHBOARD_DIR/tls.crt" >/dev/null 2>&1
    chmod 0600 "$DASHBOARD_DIR/tls.key"
  fi

  # The password of "admin", hashed (apr1, as nginx reads it). Shown once, never stored in clear.
  if [[ ! -f "$DASHBOARD_DIR/htpasswd" ]]; then
    local password="${DASHBOARD_PASSWORD:-$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)}"
    printf 'admin:%s\n' "$(openssl passwd -apr1 "$password")" > "$DASHBOARD_DIR/htpasswd"
    [[ -n "${DASHBOARD_PASSWORD:-}" ]] || DASHBOARD_NEW_PASSWORD="$password"
  fi
  chgrp www-data "$DASHBOARD_DIR" "$DASHBOARD_DIR/htpasswd" 2>/dev/null && chmod 0640 "$DASHBOARD_DIR/htpasswd"
  chmod 0750 "$DASHBOARD_DIR"

  # The page's key: in clear for nginx only (root), its hash for the service.
  if [[ ! -f "$DASHBOARD_DIR/key.conf" || ! -f "$DASHBOARD_ENV" ]]; then
    local key; key="$(openssl rand -hex 24)"
    ( umask 077 && printf 'proxy_set_header X-API-Key "%s";\n' "$key" > "$DASHBOARD_DIR/key.conf" )
    ( umask 027 && printf 'ApiKeys__Keys__0__Id=dashboard\nApiKeys__Keys__0__Hash=%s\n' "$(printf '%s' "$key" | sha256sum | cut -d' ' -f1)" > "$DASHBOARD_ENV" )
    chgrp "$USER_NAME" "$DASHBOARD_ENV"
  fi

  local allow="" a
  for a in $DASHBOARD_ALLOW; do allow="$allow    allow $a;"$'\n'; done
  local site=/etc/nginx/sites-available/$DASHBOARD_SITE
  [[ -d /etc/nginx/sites-available ]] || site=/etc/nginx/conf.d/$DASHBOARD_SITE.conf
  cat > "$site" <<SITE
# Written by xrcopilotlab-intrusion-mcp (install.sh): the monitoring page, read-only, internal network only.
server {
    listen $DASHBOARD_PORT ssl;
    listen [::]:$DASHBOARD_PORT ssl;
    server_name _;
    ssl_certificate     $DASHBOARD_DIR/tls.crt;
    ssl_certificate_key $DASHBOARD_DIR/tls.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    # The page's own log: its requests every few seconds are not the sites' traffic the package reads.
    access_log /var/log/nginx/xrcopilotlab-dashboard.log;

$allow    deny all;
    auth_basic "Guardiano di rete";
    auth_basic_user_file $DASHBOARD_DIR/htpasswd;

    # The WAF watches the customer's sites, not the package's own page and API: otherwise its polling and XRCopilotLab's
    # calls would be inspected by the CRS and fill the audit log the package itself reads.
    modsecurity off;

    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'" always;

    location = / { proxy_pass http://127.0.0.1:8470; }
    location = /index.html { proxy_pass http://127.0.0.1:8470; }
    location = /hevolus-logo.svg { proxy_pass http://127.0.0.1:8470; }
    location /vendor/ { proxy_pass http://127.0.0.1:8470; }
    # Read routes only: GET, and never /mcp.
    location /api/ {
        limit_except GET { deny all; }
        include $DASHBOARD_DIR/key.conf;
        proxy_pass http://127.0.0.1:8470;
    }
    location / { return 404; }
}
SITE
  [[ -d /etc/nginx/sites-enabled ]] && ln -sf "$site" /etc/nginx/sites-enabled/$DASHBOARD_SITE
  if ! nginx -t >/dev/null 2>&1; then
    rm -f "$site" /etc/nginx/sites-enabled/$DASHBOARD_SITE
    echo "dashboard: nginx -t fails with the page's site: removed it, nginx unchanged" >&2
    nginx -t 2>&1 | tail -3 >&2
    return 1
  fi
  echo "dashboard: https://$(hostname -I 2>/dev/null | awk '{print $1}'):$DASHBOARD_PORT (user admin)"
}

dashboard_start() {
  systemctl enable nginx >/dev/null 2>&1 || true
  if systemctl is-active --quiet nginx; then systemctl reload nginx; else systemctl start nginx; fi
}
