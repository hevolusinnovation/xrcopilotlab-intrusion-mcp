# The security packages ("guardians") the toolkit reads, installed on request: install.sh --with fail2ban,crowdsec,suricata
# Sourced by install.sh, as root. Every function is idempotent: a package already there is configured, not reinstalled,
# and a configuration this script did not write is left alone. Everything runs in detection mode: nothing here blocks
# traffic that fail2ban would not already block. UFW is never switched on: a firewall turned on by a script can lock
# everyone out of SSH.

GUARDIANS_SUPPORTED="fail2ban crowdsec suricata"
SERVICE_DROPIN_DIR=/etc/systemd/system/xrcopilotlab-intrusion-mcp.service.d

installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }

apt_install() {
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@"
}

# fail2ban with the sshd jail (on by default on Debian and Ubuntu).
guardian_fail2ban() {
  if installed fail2ban; then echo "fail2ban: already installed"; else echo "fail2ban: installing"; apt_install fail2ban; fi
  if [[ ! -f /etc/fail2ban/jail.d/defaults-debian.conf && ! -f /etc/fail2ban/jail.d/xrcopilotlab.conf ]]; then
    printf '[sshd]\nenabled = true\n' > /etc/fail2ban/jail.d/xrcopilotlab.conf
  fi
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
}

# CrowdSec from its own repository (Ubuntu's is years old), detection only: no bouncer is installed.
guardian_crowdsec() {
  if installed crowdsec; then
    echo "crowdsec: already installed"
  else
    echo "crowdsec: installing from packagecloud.io/crowdsec (detection only, no bouncer)"
    . /etc/os-release
    apt_install ca-certificates curl gnupg
    install -d -m 0755 /etc/apt/keyrings
    [[ -f /etc/apt/keyrings/crowdsec.gpg ]] || curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey | gpg --dearmor -o /etc/apt/keyrings/crowdsec.gpg
    printf 'deb [signed-by=/etc/apt/keyrings/crowdsec.gpg] https://packagecloud.io/crowdsec/crowdsec/%s/ %s main\n' "$ID" "$VERSION_CODENAME" \
      > /etc/apt/sources.list.d/crowdsec.list
    apt_install crowdsec
  fi
  systemctl enable --now crowdsec >/dev/null 2>&1 || true
  # CrowdSec writes its log 0600 root; its rotation keeps the mode of the file it replaces, so this holds.
  [[ -f /var/log/crowdsec.log ]] && chgrp adm /var/log/crowdsec.log && chmod 0640 /var/log/crowdsec.log
  return 0
}

# Suricata from the OISF repository (Ubuntu's 7.0 is out of support), as an IDS: it watches, it does not drop.
# Its configuration is changed only when this script installed it (marker file): the customer's own Suricata is read as
# it is.
SURICATA_YAML=/etc/suricata/suricata.yaml
SURICATA_MARKER=/etc/suricata/.xrcopilotlab-managed

guardian_suricata() {
  if installed suricata; then
    echo "suricata: already installed"
  else
    echo "suricata: installing (IDS mode, ET Open rules)"
    . /etc/os-release
    if [[ "$ID" == "ubuntu" ]]; then
      apt_install software-properties-common gpg-agent
      grep -rqs "oisf/suricata-stable" /etc/apt/sources.list.d/ || add-apt-repository -y ppa:oisf/suricata-stable >/dev/null
    fi
    apt_install suricata
    touch "$SURICATA_MARKER"
  fi

  if [[ -f "$SURICATA_MARKER" ]]; then suricata_configure; else echo "suricata: configuration not written by this script, left as it is"; fi

  # The toolkit reads /var/log/suricata (group suricata, 0770) through a group of its own service: no ACL, no chmod.
  if getent group suricata >/dev/null; then
    install -d -m 0755 "$SERVICE_DROPIN_DIR"
    printf '# Written by install.sh --with suricata: read /var/log/suricata.\n[Service]\nSupplementaryGroups=suricata\n' \
      > "$SERVICE_DROPIN_DIR/suricata.conf"
  fi
}

suricata_configure() {
  local iface home
  iface="${SURICATA_INTERFACE:-$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')}"
  [[ -n "$iface" ]] || { echo "suricata: no default route: set SURICATA_INTERFACE and run again" >&2; return 1; }
  # HOME_NET: this server's addresses and the private ranges. With the default (private ranges only) the rules that
  # protect $HOME_NET never fire on a server with a public address.
  home="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' | grep -v ':' | sed 's|$|/32|' | paste -sd, -)"
  home="[${home:+$home,}192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"

  # Rules: ET Open first, so the new configuration can be tested with them; then every night.
  suricata-update -q --no-test >/dev/null 2>&1 || echo "suricata: suricata-update failed (no internet?): run it again later" >&2

  # Rewritten on every run from the package's file, so a second run gives the same file.
  [[ -f "$SURICATA_YAML.dist" ]] || cp "$SURICATA_YAML" "$SURICATA_YAML.dist"
  awk -v home="$home" -v iface="$iface" '
    BEGIN { homeDone = 0; inAf = 0; ifaceDone = 0; inOutputs = 0; evePending = 0 }
    # HOME_NET: the first, uncommented definition.
    !homeDone && /^    HOME_NET:/ { print "    HOME_NET: \"" home "\""; homeDone = 1; next }
    # af-packet: the first interface of the section is the one Suricata listens on.
    /^af-packet:/ { inAf = 1 }
    inAf && !ifaceDone && /^  - interface:/ { print "  - interface: " iface; ifaceDone = 1; next }
    /^[a-z]/ && !/^af-packet:/ { inAf = 0 }
    # outputs: an alert-only eve.json first, and the package default (every flow, DNS, TLS... in the same file) off.
    /^outputs:/ { print; print "  # xrcopilotlab-intrusion: alerts only, read by the toolkit"; print "  - eve-log:"; print "      enabled: yes";
                  print "      filetype: regular"; print "      filename: eve.json"; print "      types:"; print "        - alert"; inOutputs = 1; next }
    inOutputs && /^  - eve-log:/ { evePending = 1; inOutputs = 0; print; next }
    evePending && /^      enabled:/ { print "      enabled: no"; evePending = 0; next }
    { print }
  ' "$SURICATA_YAML.dist" > "$SURICATA_YAML.new"
  # The test writes its logs elsewhere: run as root in /var/log/suricata it would leave files Suricata (user suricata)
  # can no longer open.
  local testlogs; testlogs="$(mktemp -d)"
  if suricata -T -c "$SURICATA_YAML.new" -l "$testlogs" >/dev/null 2>&1 || [[ ! -s /var/lib/suricata/rules/suricata.rules ]]; then
    mv -f "$SURICATA_YAML.new" "$SURICATA_YAML"
  else
    rm -rf "$SURICATA_YAML.new" "$testlogs"; echo "suricata: the new configuration does not pass suricata -T: kept the current one" >&2; return 1
  fi
  rm -rf "$testlogs"
  # Logs left by root (an earlier test, a manual run) are given back to Suricata.
  find /var/log/suricata -maxdepth 1 -type f -user root -exec chown suricata:suricata {} + 2>/dev/null || true
  echo "suricata: listening on $iface, HOME_NET $home"

  cat > /etc/systemd/system/xrcopilotlab-suricata-update.service <<'UNIT'
[Unit]
Description=Update Suricata's ET Open rules (installed by xrcopilotlab-intrusion-mcp)
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/suricata-update -q
ExecStartPost=-/usr/bin/suricatasc -c reload-rules
UNIT
  cat > /etc/systemd/system/xrcopilotlab-suricata-update.timer <<'UNIT'
[Unit]
Description=Nightly update of Suricata's ET Open rules
[Timer]
OnCalendar=*-*-* 04:20
RandomizedDelaySec=30m
Persistent=true
[Install]
WantedBy=timers.target
UNIT
  # The package rotates nothing: one week of alerts, compressed; Suricata reopens its files on HUP.
  cat > /etc/logrotate.d/xrcopilotlab-suricata <<'ROTATE'
/var/log/suricata/*.json /var/log/suricata/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        systemctl kill -s HUP suricata.service >/dev/null 2>&1 || true
    endscript
}
ROTATE
}

# The start of whatever was configured; called by install.sh once systemd is up (not with --no-start).
guardians_start() {
  local g
  for g in "$@"; do
    case "$g" in
      suricata)
        systemctl daemon-reload
        systemctl enable --now xrcopilotlab-suricata-update.timer >/dev/null 2>&1 || true
        systemctl enable suricata >/dev/null 2>&1 || true
        systemctl restart suricata ;;
      *) ;;
    esac
  done
}
