# The security packages ("guardians") the toolkit reads, installed on request: install.sh --with fail2ban,crowdsec,suricata,falco,modsecurity,wireguard,audit
# Sourced by install.sh, as root. Every function is idempotent: a package already there is configured, not reinstalled,
# and a configuration this script did not write is left alone. Everything runs in detection mode: nothing here blocks
# traffic that fail2ban would not already block. UFW is never switched on: a firewall turned on by a script can lock
# everyone out of SSH.

GUARDIANS_SUPPORTED="fail2ban crowdsec suricata falco modsecurity wireguard audit"
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
    # crowdsec's postinst runs `cscli setup`, which calls `systemctl show` by absolute path; during an image build there
    # is no running systemd (install.sh --no-start), so that returns an error and dpkg aborts the whole build. When
    # systemd is not running, swap systemctl for a no-op just for this install, then restore it. (`systemctl enable`,
    # used elsewhere at build, works offline on the real binary; only `show` needs a running bus, so this is safe.)
    if [[ -d /run/systemd/system ]]; then
      apt_install crowdsec
    else
      local sc saved="" rc=0
      sc="$(command -v systemctl || true)"
      if [[ -n "$sc" ]]; then
        saved="$sc.xrc-real"; mv "$sc" "$saved"
        printf '#!/bin/sh\nexit 0\n' > "$sc" && chmod +x "$sc"
      fi
      apt_install crowdsec || rc=$?
      [[ -n "$saved" ]] && mv -f "$saved" "$sc"
      [[ $rc -eq 0 ]] || return 1
    fi
  fi
  systemctl enable --now crowdsec >/dev/null 2>&1 || true
  # The toolkit reads CrowdSec's log as group adm. CrowdSec writes it 0600 root and may not have created it yet at
  # install time (install.sh --no-start, before it ever runs), so create it now with the right mode; CrowdSec then
  # appends and keeps it, and its rotation keeps the mode of the file it replaces. Never truncate an existing log.
  [[ -f /var/log/crowdsec.log ]] || install -m 0640 -g adm /dev/null /var/log/crowdsec.log
  chgrp adm /var/log/crowdsec.log 2>/dev/null && chmod 0640 /var/log/crowdsec.log 2>/dev/null || true
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
    if [[ "$ID" == "ubuntu" ]]; then suricata_ppa || return 1; fi
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

# The OISF PPA, added by hand: add-apt-repository goes through Launchpad's API, which answers 500 for hours at a time.
# The keys are fetched by their full fingerprint from Ubuntu's keyserver and checked: InRelease is signed by both.
SURICATA_PPA_KEYS="121504ADE276E141AD704A75AC10378CF205C960 9F6FC9DDB1324714B78062CBD7F87B2966EB736F"
suricata_ppa() {
  # Already there, by this script or by add-apt-repository: a second entry with another key would break apt.
  grep -rqs "oisf/suricata-stable" /etc/apt/sources.list.d/ && return 0
  apt_install ca-certificates curl gnupg
  install -d -m 0755 /etc/apt/keyrings
  local fp tmp; tmp="$(mktemp -d)"
  for fp in $SURICATA_PPA_KEYS; do
    curl -fsSL --retry 3 "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x$fp" -o "$tmp/$fp.asc"
    gpg --show-keys --with-colons "$tmp/$fp.asc" 2>/dev/null | grep -q "^fpr:::::::::$fp:" \
      || { echo "suricata: the key from keyserver.ubuntu.com is not $fp" >&2; rm -rf "$tmp"; return 1; }
  done
  cat "$tmp"/*.asc | gpg --dearmor > /etc/apt/keyrings/oisf-suricata.gpg
  rm -rf "$tmp"
  . /etc/os-release
  printf 'deb [signed-by=/etc/apt/keyrings/oisf-suricata.gpg] https://ppa.launchpadcontent.net/oisf/suricata-stable/ubuntu %s main\n' "$VERSION_CODENAME" \
    > /etc/apt/sources.list.d/oisf-suricata-stable.list
}

suricata_configure() {
  local iface home
  iface="${SURICATA_INTERFACE:-$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')}"
  # No default route (a server on internal networks only): the first interface that is up and has an IPv4 address,
  # not loopback. Said, so it can be changed with SURICATA_INTERFACE.
  if [[ -z "$iface" ]]; then
    iface="$(ip -o -4 addr show up 2>/dev/null | awk '$2 != "lo" { print $2; exit }')"
    [[ -n "$iface" ]] && echo "suricata: no default route: listening on $iface, the first interface with an address (SURICATA_INTERFACE=… to choose another)"
  fi
  [[ -n "$iface" ]] || { echo "suricata: no network interface with an address: set SURICATA_INTERFACE and run again" >&2; return 1; }
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

# Falco from its own repository, with the modern eBPF probe (no kernel module, no DKMS, no compiler): it watches what
# processes do on the host and blocks nothing. As for Suricata, its configuration is written only when this script
# installed it; a Falco already there is read if it writes JSON to FALCO_LOG.
FALCO_MARKER=/etc/falco/.xrcopilotlab-managed
FALCO_LOG=/var/log/falco/events.json
FALCO_SERVICE=falco-modern-bpf

guardian_falco() {
  if installed falco; then
    echo "falco: already installed"
  else
    echo "falco: installing from download.falco.org (modern eBPF, detection only)"
    [[ -r /sys/kernel/btf/vmlinux ]] || echo "falco: this kernel has no BTF (/sys/kernel/btf/vmlinux): the modern eBPF probe needs it (kernel 5.8+)" >&2
    apt_install ca-certificates curl gnupg
    install -d -m 0755 /etc/apt/keyrings
    [[ -f /etc/apt/keyrings/falco.gpg ]] || curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /etc/apt/keyrings/falco.gpg
    printf 'deb [signed-by=/etc/apt/keyrings/falco.gpg] https://download.falco.org/packages/deb stable main\n' > /etc/apt/sources.list.d/falcosecurity.list
    # The package asks which driver to use and starts it: no question, the modern eBPF probe; started by guardians_start.
    FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf apt_install falco
    touch "$FALCO_MARKER"
  fi
  if [[ -f "$FALCO_MARKER" ]]; then falco_configure; else echo "falco: configuration not written by this script: set json_output and file_output to $FALCO_LOG for the toolkit"; fi
}

falco_configure() {
  # One file of our own in config.d: falco.yaml stays the package's, so its upgrades apply cleanly.
  cat > /etc/falco/config.d/xrcopilotlab.yaml <<'YAML'
# Written by xrcopilotlab-intrusion-mcp (install.sh --with falco): JSON alerts in a file the toolkit reads.
json_output: true
json_include_output_property: true
json_include_tags_property: true
# Notice and above: informational rules say nothing about an attack.
priority: notice
file_output:
  enabled: true
  # Opened at every alert: a rotated file is replaced without signalling Falco.
  keep_alive: false
  filename: /var/log/falco/events.json
append_output:
  # Where the session came from and who logged in, and the process tree: the toolkit ties an alert to the SSH session
  # (SSH_CLIENT is the client's address; sudo clears it and sets SUDO_USER) or to the web server it came from.
  - match:
      source: syscall
    extra_fields:
      - user.loginname
      - proc.env[SSH_CLIENT]
      - proc.env[SUDO_USER]
      - proc.aname[2]
      - proc.aname[3]
      - proc.aname[4]
YAML
  # Three rules Falco's default set has not got on a host without containers. Self-contained: they use no macro of
  # the default set, so an upgrade of it cannot break them.
  cat > /etc/falco/rules.d/xrcopilotlab.yaml <<'YAML'
# Written by xrcopilotlab-intrusion-mcp (install.sh --with falco).
- list: xrc_account_binaries
  items: [useradd, adduser, usermod, chpasswd, gpasswd, newusers]

- list: xrc_miner_binaries
  items: [xmrig, xmr-stak, minerd, cpuminer, ethminer, nbminer, t-rex, kdevtmpfsi, kinsing]

- rule: XRC SSH authorized keys changed
  desc: A process wrote an SSH authorized_keys file. A key added there lets its owner back in without a password.
  condition: >
    evt.type in (open, openat, openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0
    and (fd.name endswith "/.ssh/authorized_keys" or fd.name endswith "/.ssh/authorized_keys2")
  output: SSH authorized_keys written | file=%fd.name user=%user.name login=%user.loginname command=%proc.cmdline parent=%proc.pname
  priority: WARNING
  tags: [host, filesystem, mitre_persistence, T1098.004]

- rule: XRC Account created or changed
  desc: An account was created or changed (useradd, usermod, chpasswd…). Expected from an administrator, not at 3 am.
  # useradd starts helpers under its own name: the first one only.
  condition: evt.type in (execve, execveat) and proc.name in (xrc_account_binaries) and not proc.pname in (xrc_account_binaries)
  output: Account created or changed | user=%user.name login=%user.loginname command=%proc.cmdline parent=%proc.pname
  priority: WARNING
  tags: [host, process, mitre_persistence, T1136]

- rule: XRC Crypto miner started
  desc: A crypto-currency miner started, by its name or by a mining pool address on its command line.
  condition: >
    evt.type in (execve, execveat) and not proc.pname in (xrc_miner_binaries)
    and (proc.name in (xrc_miner_binaries) or proc.cmdline contains "stratum+tcp://" or proc.cmdline contains "stratum+ssl://")
  output: Crypto miner started | user=%user.name login=%user.loginname command=%proc.cmdline parent=%proc.pname
  priority: CRITICAL
  tags: [host, process, mitre_impact, T1496]
YAML
  # Falco creates the file 0600: created first, 0640 group adm, for the toolkit; opening it in append keeps the mode.
  install -d -m 0750 -g adm /var/log/falco
  [[ -f "$FALCO_LOG" ]] || install -m 0640 -g adm /dev/null "$FALCO_LOG"
  chgrp adm "$FALCO_LOG" && chmod 0640 "$FALCO_LOG"
  cat > /etc/logrotate.d/xrcopilotlab-falco <<'ROTATE'
/var/log/falco/events.json {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
ROTATE
  # Rules that do not load would stop Falco: checked now, not at the next restart.
  if ! falco -V /etc/falco/rules.d/xrcopilotlab.yaml >/dev/null 2>&1; then
    echo "falco: the rules do not validate: removed /etc/falco/rules.d/xrcopilotlab.yaml" >&2
    rm -f /etc/falco/rules.d/xrcopilotlab.yaml
  fi
  echo "falco: alerts in $FALCO_LOG (notice and above)"
}

# ModSecurity v3 with the OWASP Core Rule Set, in nginx, in detection only (SecRuleEngine DetectionOnly): it reads every
# request, bodies included, and writes the ones the CRS would block to a JSON audit log; it blocks nothing. Switched on
# for every site with one file in /etc/nginx/conf.d (http level): the sites' own files are not touched, and a site
# with "modsecurity off;" stays off. nginx is checked with nginx -t before and after: if it fails, the file is removed
# and nginx is left as it was.
MODSEC_DIR=/etc/modsecurity/xrcopilotlab
MODSEC_NGINX=/etc/nginx/conf.d/xrcopilotlab-modsecurity.conf
MODSEC_LOG=/var/log/modsecurity/audit.json

guardian_modsecurity() {
  command -v nginx >/dev/null || { echo "modsecurity: nginx is not installed: ModSecurity works inside nginx" >&2; return 1; }
  if ! nginx -t >/dev/null 2>&1; then
    echo "modsecurity: nginx -t already fails before any change: fix nginx first, nothing changed" >&2; return 1
  fi
  if installed libnginx-mod-http-modsecurity && installed modsecurity-crs; then
    echo "modsecurity: already installed"
  else
    echo "modsecurity: installing (nginx module, OWASP CRS, detection only)"
    apt_install libnginx-mod-http-modsecurity modsecurity-crs
  fi

  install -d -m 0755 "$MODSEC_DIR"
  # Our own main file: Ubuntu's modsecurity.conf keeps response bodies, audits only 4xx/5xx answers (in detection only
  # an attack is answered 200: it would never be written) and turns on the status engine.
  cat > "$MODSEC_DIR/main.conf" <<'CONF'
# Written by xrcopilotlab-intrusion-mcp (install.sh --with modsecurity). Detection only: nothing is blocked.
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
# A body larger than the limit is inspected up to the limit, not refused.
SecRequestBodyLimitAction ProcessPartial
SecRequestBodyJsonDepthLimit 512
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecResponseBodyAccess Off
SecPcreMatchLimit 1000
SecPcreMatchLimitRecursion 1000
SecTmpDir /tmp/
SecDataDir /tmp/
SecArgumentSeparator &
SecCookieFormat 0
SecUnicodeMapFile /etc/nginx/unicode.mapping 20127
SecStatusEngine Off
# The transactions a rule logged (an attack), as one JSON line each. Parts A, H, Z: client, request line, rules matched;
# no headers (cookies, Authorization) and no bodies.
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^5"
SecAuditLogParts AHZ
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLog /var/log/modsecurity/audit.json
# The OWASP CRS, file by file: the package's owasp-crs.load uses IncludeOptional, which ModSecurity v3 rejects.
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
# Ours, before the CRS rules so they count in the same anomaly score: text written for an AI (prompt injection).
Include /etc/modsecurity/xrcopilotlab/ai.conf
Include /usr/share/modsecurity-crs/rules/*.conf
Include /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
CONF

  # Text written for an AI, in what is sent to the site: a chatbot's message, a form a model will summarise, a query
  # string. The same rules the toolkit applies to the logs (UntrustedText), minus "a message to the AI", which is what
  # a chatbot's users write anyway, and minus zero-width characters, which emoji use. Each adds a critical score, so
  # the CRS's 949110 logs the request; the message names the rule for the toolkit ("AI prompt injection: <rule>").
  # Detection only, like everything here. Ids 200100-200199.
  cat > "$MODSEC_DIR/ai.conf" <<'CONF'
# Written by xrcopilotlab-intrusion-mcp (install.sh --with modsecurity): text written for an AI. Detection only.
SecRule REQUEST_BODY|ARGS_GET "@rx (?i)\b(?:ignore|disregard|forget|override|bypass)[\s_+.-]+(?:(?:all|any|the|your)[\s_+.-]+)*(?:(?:previous|prior|above|earlier|system|original)[\s_+.-]+)?(?:instructions?|prompts?|rules|guidelines|directives)\b|\b(?:ignora|dimentica|trascura)\w*[\s_+.-]+(?:(?:tutte|le)[\s_+.-]+)*(?:istruzioni|regole|indicazioni)\b|\b(?:system[\s_+.-]+prompt|new[\s_+.-]+instructions?|nuove[\s_+.-]+istruzioni|developer[\s_+.-]+mode|jailbreak)\b" \
    "id:200101,phase:2,pass,log,t:none,t:urlDecodeUni,msg:'AI prompt injection: instruction-override',tag:'attack-prompt-injection',tag:'xrcopilotlab',severity:'CRITICAL',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
SecRule REQUEST_BODY|ARGS_GET "@rx (?i)<\|(?:im_start|im_end|system|endoftext)\|>|\[/?INST\]|<</?SYS>>" \
    "id:200102,phase:2,pass,log,t:none,t:urlDecodeUni,msg:'AI prompt injection: role-marker',tag:'attack-prompt-injection',tag:'xrcopilotlab',severity:'CRITICAL',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
SecRule REQUEST_BODY|ARGS_GET "@rx \xf3\xa0[\x80\x81][\x80-\xbf]|(?i)\\udb40\\udc[0-7][0-9a-f]" \
    "id:200103,phase:2,pass,log,t:none,t:urlDecodeUni,msg:'AI prompt injection: hidden-unicode',tag:'attack-prompt-injection',tag:'xrcopilotlab',severity:'CRITICAL',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
CONF

  # nginx's master (root) opens the log and its workers write it: created first, 0640 group adm, for the toolkit.
  install -d -m 0750 -g adm /var/log/modsecurity
  [[ -f "$MODSEC_LOG" ]] || install -m 0640 -g adm /dev/null "$MODSEC_LOG"
  chgrp adm "$MODSEC_LOG" && chmod 0640 "$MODSEC_LOG"
  # copytruncate: ModSecurity keeps the log open by name and nginx -s reload does not reopen it.
  cat > /etc/logrotate.d/xrcopilotlab-modsecurity <<'ROTATE'
/var/log/modsecurity/audit.json {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
ROTATE

  cat > "$MODSEC_NGINX" <<CONF
# Written by xrcopilotlab-intrusion-mcp (install.sh --with modsecurity): ModSecurity + OWASP CRS, detection only, on every site.
modsecurity on;
modsecurity_rules_file $MODSEC_DIR/main.conf;
CONF
  if ! nginx -t >/dev/null 2>&1; then
    rm -f "$MODSEC_NGINX"
    echo "modsecurity: nginx -t fails with ModSecurity on (is it already on in a site of yours?): removed $MODSEC_NGINX, nginx unchanged" >&2
    nginx -t 2>&1 | tail -3 >&2
    return 1
  fi
  echo "modsecurity: on for every nginx site, detection only, attacks in $MODSEC_LOG"
}

# WireGuard, the customer's VPN: their people (phone, laptop) and their other sites (a router) reach the internal
# network, and nobody else, since WireGuard does not even answer a packet without a known key. The customer manages
# the users with xrc-vpn (root, or the group vpn-admin through sudo); this script installs and wires it, adds no user.
# The server's key is made by xrcopilotlab-vpn-init at the first start, never here: an image built with --no-start
# would otherwise give every customer the same key. Opt-in like the rest, but it is not only a watcher: it opens UDP
# VPN_PORT and routes the VPN to the internal network (to that network only, never to the internet).
#   VPN_ENDPOINT  the public IPv4, IPv6 or name the users connect to (xrc-vpn endpoint later, if unknown now)
#   VPN_SUBNET    the VPN's own IPv4 network, a /24 that no site uses (default 10.88.0.0/24)
#   VPN_SUBNET6   its IPv6 network, a /64 (default: a ULA made at the first start, unique to the site), or "off"
#   VPN_PORT      UDP port (default 51820); the office router forwards it to this server (on a VPS: open it in the
#                 provider's firewall)
#   VPN_LAN       the internal network(s) it opens, IPv4 and IPv6, comma separated (default: those of the interface
#                 with the default route; printed at the end of the install, xrc-vpn lan to change them), or "none"
#                 for a central server (a VPS) with no network of its own: the sites' routers and the users meet there
#   VPN_DNS       a DNS server the users get (optional, e.g. the office's 192.168.1.1)
VPN_DIR=/etc/xrcopilotlab-vpn
VPN_IFACE=wgxrc

guardian_wireguard() {
  if installed wireguard-tools && installed qrencode && command -v iptables >/dev/null; then
    echo "wireguard: already installed"
  else
    echo "wireguard: installing (VPN, users managed by the customer with xrc-vpn)"
    apt_install wireguard-tools qrencode iptables
  fi
  if [[ -f /etc/wireguard/$VPN_IFACE.conf ]] && ! grep -q "Written by xrc-vpn" "/etc/wireguard/$VPN_IFACE.conf"; then
    echo "wireguard: /etc/wireguard/$VPN_IFACE.conf was not written by xrc-vpn: left as it is" >&2; return 1
  fi
  install -m 0755 "$HERE/xrc-vpn" /usr/local/sbin/xrc-vpn
  install -d -m 0750 "$VPN_DIR" && install -d -m 0700 "$VPN_DIR/peers"

  # The settings given now are written; those not given keep what an earlier run wrote.
  local k v var re
  for k in ENDPOINT SUBNET SUBNET6 PORT LAN DNS; do
    var="VPN_$k"; v="${!var:-}"
    [[ -n "$v" ]] || continue
    case "$k" in
      ENDPOINT) re='^[][A-Za-z0-9.:-]{1,260}$'; [[ "$v" =~ $re ]] || { echo "wireguard: VPN_ENDPOINT is not an address or a name" >&2; return 1; } ;;
      SUBNET)   [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.0/24$ ]] || { echo "wireguard: VPN_SUBNET must be a /24 (10.88.0.0/24)" >&2; return 1; } ;;
      SUBNET6)  [[ "$v" == off || "$v" =~ ^[0-9a-f:]+::/64$ ]] || { echo "wireguard: VPN_SUBNET6 must be a /64 ending in :: (fd12:3456:789a::/64) or off" >&2; return 1; } ;;
      PORT)     [[ "$v" =~ ^[0-9]{1,5}$ ]] || { echo "wireguard: VPN_PORT is not a port" >&2; return 1; } ;;
      LAN)      [[ "$v" == none || "$v" =~ ^[0-9a-fA-F.:/,]+$ ]] || { echo "wireguard: VPN_LAN must be networks like 192.168.1.0/24 or 2001:db8:1::/64, or none" >&2; return 1; } ;;
      DNS)      [[ "$v" =~ ^[0-9a-fA-F.:,]+$ ]] || { echo "wireguard: VPN_DNS must be addresses" >&2; return 1; } ;;
    esac
    touch "$VPN_DIR/vpn.env"
    { grep -v "^WG_$k=" "$VPN_DIR/vpn.env" || true; printf 'WG_%s=%s\n' "$k" "$v"; } > "$VPN_DIR/vpn.env.tmp"
    chmod 0640 "$VPN_DIR/vpn.env.tmp" && mv -f "$VPN_DIR/vpn.env.tmp" "$VPN_DIR/vpn.env"
  done

  # Who may manage the users: the group vpn-admin, through sudo with their own password, for xrc-vpn only.
  getent group vpn-admin >/dev/null || groupadd --system vpn-admin
  printf '# Written by xrcopilotlab-intrusion-mcp (install.sh --with wireguard): the VPN users, managed by the customer.\n%%vpn-admin ALL=(root) /usr/local/sbin/xrc-vpn\n' \
    > /etc/sudoers.d/xrcopilotlab-vpn.tmp
  if visudo -cqf /etc/sudoers.d/xrcopilotlab-vpn.tmp; then
    chmod 0440 /etc/sudoers.d/xrcopilotlab-vpn.tmp && mv -f /etc/sudoers.d/xrcopilotlab-vpn.tmp /etc/sudoers.d/xrcopilotlab-vpn
  else
    rm -f /etc/sudoers.d/xrcopilotlab-vpn.tmp; echo "wireguard: the sudo rule does not validate: only root can run xrc-vpn" >&2
  fi

  # The key and the configuration at every start (the key only the first time), before the interface comes up.
  cat > /etc/systemd/system/xrcopilotlab-vpn-init.service <<UNIT
[Unit]
Description=VPN key (first start) and configuration (installed by xrcopilotlab-intrusion-mcp)
After=network-online.target
Wants=network-online.target
Before=wg-quick@$VPN_IFACE.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xrc-vpn init
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
  install -d -m 0755 "/etc/systemd/system/wg-quick@$VPN_IFACE.service.d"
  printf '# Written by install.sh --with wireguard.\n[Unit]\nRequires=xrcopilotlab-vpn-init.service\nAfter=xrcopilotlab-vpn-init.service\n[Service]\nExecStartPost=-/usr/local/sbin/xrc-vpn state\nExecStopPost=-/usr/local/sbin/xrc-vpn state\n' \
    > "/etc/systemd/system/wg-quick@$VPN_IFACE.service.d/xrcopilotlab.conf"
  # Who is connected, for the toolkit (names and places, no key), every minute.
  cat > /etc/systemd/system/xrcopilotlab-vpn-state.service <<'UNIT'
[Unit]
Description=Write who is connected to the VPN for the toolkit (no key)
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xrc-vpn state
UNIT
  cat > /etc/systemd/system/xrcopilotlab-vpn-state.timer <<'UNIT'
[Unit]
Description=Every minute: who is connected to the VPN
[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=5s
[Install]
WantedBy=timers.target
UNIT
  # Enabled now, so an image built with --no-start makes its key and comes up at its first start.
  systemctl enable xrcopilotlab-vpn-init.service "wg-quick@$VPN_IFACE" xrcopilotlab-vpn-state.timer >/dev/null 2>&1 || true
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "^Status: active"; then
    echo "wireguard: UFW is on and this script never changes it: allow the VPN yourself, e.g." >&2
    echo "  sudo ufw allow ${VPN_PORT:-51820}/udp" >&2
  fi
  echo "wireguard: installed. The users are added by the customer: sudo usermod -aG vpn-admin <their account>, then xrc-vpn add <name>"
}

# The host's audit: the toolkit's own program, started as root every 15 minutes with nothing writable but its state
# directory and no network. It reads accounts, SSH keys, scheduled jobs, services and running programs, and writes
# what the toolkit's service (which cannot read them) shows as posture findings. Nothing is installed from outside.
guardian_audit() {
  local user=xrcopilot-intrusion
  id -u "$user" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  install -m 0755 "$HERE/xrc-audit" /usr/local/sbin/xrc-audit
  # Setgid: the state file takes the directory's group, the one the toolkit's service reads it with.
  install -d -m 2750 -o root -g "$user" /var/lib/xrcopilotlab-audit
  cat > /etc/systemd/system/xrcopilotlab-audit.service <<'UNIT'
[Unit]
Description=XRCopilotLab host audit: accounts, SSH keys, what starts by itself, odd processes (read-only)
[Service]
Type=oneshot
ExecStart=/opt/xrcopilotlab-intrusion-mcp/XrCopilotLab.Intrusion.Mcp.Server audit
Group=xrcopilot-intrusion
UMask=0027
Environment=DOTNET_gcServer=0
Nice=10
# Root, to read /etc/shadow, the users' homes and every process; and nothing else of root: it can read, not write.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/xrcopilotlab-audit
PrivateTmp=true
PrivateDevices=true
PrivateNetwork=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX
RestrictSUIDSGID=true
LockPersonality=true
UNIT
  cat > /etc/systemd/system/xrcopilotlab-audit.timer <<'UNIT'
[Unit]
Description=Every 15 minutes: the host's audit
[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
AccuracySec=30s
[Install]
WantedBy=timers.target
UNIT
  systemctl enable xrcopilotlab-audit.timer >/dev/null 2>&1 || true
  echo "audit: installed. The first run takes the baseline (the host as it is now); later changes are shown until you accept them: xrc-audit status, xrc-audit accept"
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
      falco)
        systemctl daemon-reload
        systemctl enable "$FALCO_SERVICE" >/dev/null 2>&1 || true
        systemctl restart "$FALCO_SERVICE" ;;
      modsecurity)
        # A restart, not a reload: ModSecurity opens its audit log once, when nginx starts.
        [[ -f "$MODSEC_NGINX" ]] && systemctl restart nginx ;;
      wireguard)
        systemctl daemon-reload
        systemctl restart xrcopilotlab-vpn-init.service
        systemctl restart "wg-quick@$VPN_IFACE"
        systemctl start xrcopilotlab-vpn-state.timer
        # What the VPN opens, found on its own: said now, so a server with more networks is checked at once.
        /usr/local/sbin/xrc-vpn show | sed 's/^/wireguard: /'
        [[ -n "${VPN_LAN:-}" ]] || echo "wireguard: the internal network above was found on its own (no VPN_LAN): check it; xrc-vpn lan <networks> changes it" ;;
      audit)
        systemctl daemon-reload
        systemctl start xrcopilotlab-audit.timer
        # Now, not in 15 minutes: the first run is the baseline, a later one shows at once what this install changed.
        systemctl start xrcopilotlab-audit.service || echo "audit: the first run failed: journalctl -u xrcopilotlab-audit" >&2 ;;
      *) ;;
    esac
  done
}
