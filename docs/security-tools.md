# Which security tools to read next

Research note for `xrcopilotlab-intrusion-mcp`, November 2026: which open-source security tools the toolkit could read next. Facts marked "not verified" in section 6 must be checked on a real host.

**Today the toolkit reads** fail2ban, sshd `auth.log`, UFW, nginx `access.log` and the CrowdSec log. It runs as an
unprivileged user in group `adm`, reads only, and never blocks. Its catalogue has 11 attack types (`SshBruteForce` …
`LoginAfterFailures`), see README "Attack types" and `Core/Analysis/AttackCatalog.cs`.

**Short answer:** read **Suricata** next (EVE JSON). Add **Falco** (or auditd if we want only Ubuntu packages) for
"what happened after the login". Then add **ModSecurity + OWASP CRS** on nginx for deeper web attacks. Before any of
these there are some cheap wins that need no new software: Apache logs, `mail.log`, `sudo` lines in `auth.log`, and sshguard.

---

## 1. Something to know first: where the toolkit runs

The toolkit runs on **one internet-facing server**, so a network tool there sees only that server's own traffic.

- **Industrial protocols:** on a public server, Modbus/S7/IEC 104/DNP3 probes hit closed ports. UFW already sees them
  (`IndustrialProtocolProbe`). Suricata or Zeek **cannot read Modbus or S7 content** on a closed port, because the TCP
  handshake never completes. Their ICS parsers help only when the sensor watches the **plant network** (a SPAN/mirror
  port on an OT switch). That is a different install, a "sensor box", and not the customer's web server. On a public
  server they add only "ICS service actually answered" (an exposed PLC gateway) and ICS-specific signatures.
- **"Did anybody get in?"** Today we answer with `LoginAfterFailures`. To say *what they did* after the login we need a
  host tool (Falco, auditd, AIDE, osquery). A network tool does not see it.

---

## 2. Tool by tool

Legend: **Effort** is integration effort in our code: S = one parser plus catalogue entries (about 1–3 days), M = a new
format and new attack types (about 1–2 weeks), L = a new kind of data or a new deployment (weeks).

### Suricata (network IDS)
- **Detects:** known attacks in network traffic on *any* port: exploit attempts against any service, scanners, malware
  and C2 traffic leaving the server (a strong sign of compromise), bad TLS/DNS, and protocol anomalies. It has built-in
  Modbus, DNP3 and ENIP/CIP parsers and rule keywords (DNP3 and ENIP are off by default in the shipped config).
- **License:** GPL-2.0 ([GitHub](https://github.com/OISF/suricata)). Commercial use is fine: we only *read* its output
  and do not ship it. Rules: ET Open is free (mostly BSD, some ranges GPL,
  [ET community](https://community.emergingthreats.net/t/licensing-of-third-party-rules/2396)). ET Pro is paid and
  licensed per sensor ([Proofpoint](https://www.proofpoint.com/us/resources/white-papers/proofpoint-etpro-subscription-overview)).
- **Writes:** `/var/log/suricata/eve.json`, one JSON object per line (`event_type`: alert, anomaly, http, dns, tls,
  flow…) ([docs](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)).
  - *Permissions:* not verified. A per-output `filemode` setting exists
    ([commit](https://git.morozoff.pro/aiden/suricata/commit/005a700e543b65db510243814d85f432cc0912d6)). The install
    script can set `filemode: 640` and make the group `adm`, or add an ACL. Check with `ls -l` on a real host.
- **Cost:** the heaviest tool in this list. On a small VM with low traffic plan for 1 core and 0.5–1 GB RAM with ET Open
  loaded (rule of thumb, not measured). eve.json grows fast unless we keep only `alert` and `anomaly`.
- **Install on Ubuntu 24.04:** the archive has 7.0.3 in universe
  ([packages.ubuntu.com](https://packages.ubuntu.com/noble/suricata)). 7.x has reached end of life, so use the OISF
  PPA `ppa:oisf/suricata-stable`, which supports noble and ships 8.0.x
  ([forum](https://forum.suricata.io/t/suricata-7-0-17-and-8-0-6-packages-are-now-available-for-ubuntu-on-ubuntu-ppa-launchpad/6397)).
  `apt install suricata` and `suricata-update` run again safely. Steps to watch: choose the capture interface, and run
  `suricata-update` from a timer.
- **New attack types:** `NetworkExploitAttempt` (an ET signature on a non-web service), `MalwareCommunication` /
  `CommandAndControl` (alert on *outbound* traffic: Critical, the server may be compromised), `ProtocolAnomaly`,
  `IndustrialProtocolCommand` (Modbus write, DNP3 control, only on an OT sensor), `ExposedService`. Use the signature's
  `classtype` and `severity`, and the rule's MITRE metadata when it has it.
- **Overlap:** web exploits (nginx regex, CrowdSec), port scans (UFW). We must deduplicate by source IP and time, as we
  already do for fail2ban and nginx.
- **Effort:** **M**. JSON is easy (`System.Text.Json`), but we need new types, dedup rules, and size limits for a big
  file (read from the end, filter `event_type`).

### Zeek (network monitor) + CISA ICSNPP parsers
- **Detects:** Zeek is less a signature IDS and more a full record of network activity (`conn.log`, `http.log`,
  `dns.log`, `ssl.log`, plus `notice.log` and `weird.log` for detections). CISA's ICSNPP packages add deep logs for
  S7comm/S7comm-plus/COTP, ENIP/CIP, BACnet, PROFINET, and better Modbus and DNP3
  ([ICSNPP](https://github.com/cisagov/ICSNPP), [icsnpp-s7comm](https://github.com/cisagov/icsnpp-s7comm)). IEC 104:
  community Spicy parsers ([cert-lv/spicy-iec104](https://github.com/cert-lv/spicy-iec104),
  [zeek-iec104](https://github.com/georgemakrakis/zeek-iec104)), not CISA.
- **License:** Zeek is BSD ([GitHub](https://github.com/zeek/zeek)), ICSNPP is BSD-3-Clause. Commercial use is fine.
- **Writes:** `/opt/zeek/logs/current/*.log`. The default is TSV. JSON comes from the `policy/tuning/json-logs` script
  (from memory, not re-checked). One file per protocol, rotated by `zeekctl`.
- **Cost:** similar to or above Suricata. It also needs disk for `conn.log`.
- **Install on Ubuntu 24.04:** not in the Ubuntu archive (only `zeek-aux`,
  [packages.ubuntu.com](https://packages.ubuntu.com/search?keywords=zeek&searchon=names&suite=noble&section=all)).
  Official OBS repo `security:zeek/xUbuntu_24.04` ([docs](https://docs.zeek.org/en/current/install/install.html)), then
  `zkg install icsnpp-…`, which needs build tools. Idempotent install is possible but has more moving parts than Suricata.
- **New attack types:** `IndustrialProtocolCommand` (S7 program upload/download, stop CPU, Modbus write), `IndustrialRecon`
  (S7 `read_szl`, which reads the PLC identity). It also gives a fact we cannot see today: "a PLC talked to an outside address".
- **Overlap:** Suricata, if both run. Zeek is better for ICS *visibility*, Suricata for *alerts*.
- **Effort:** **L**. Many log schemas, and its real value needs the OT-sensor install, not the web server.

### Malcolm (INL/CISA) and GRASSMARLIN
- **Malcolm:** a full stack (Zeek, Suricata, Arkime, OpenSearch, dashboards) for ICS traffic analysis. Apache-2.0
  ([GitHub](https://github.com/cisagov/Malcolm), [INL](https://inl.gov/ics-malcolm/)). It is far too heavy for a
  customer server: it is a SOC appliance. It is worth knowing as the place where ICSNPP is already bundled. We could read
  its OpenSearch later, but that is a different product.
- **GRASSMARLIN (NSA):** archived, last push February 2020, license "other"
  ([ecosyste.ms](https://awesome.ecosyste.ms/projects/github.com%2Fnsacyber%2FGRASSMARLIN)). Do not integrate it.

### Snort 3
- **Detects:** the same family as Suricata (signature IDS).
- **License:** the engine is GPLv2 (from the repo's COPYING; the page did not state it clearly when fetched). Rules:
  Community rules are GPLv2. **Subscriber (Talos) rules need a separate commercial agreement for "Commercial Purpose"**
  ([license text](https://scancode-licensedb.aboutcode.org/snort-subscriber-rules-3.1.html)).
- **Writes:** `alert_json` exists in Snort 3 (from memory, not re-checked).
- **Install on Ubuntu 24.04:** the archive has only **Snort 2.9.20** (universe,
  [packages.ubuntu.com](https://packages.ubuntu.com/search?keywords=snort&searchon=names&suite=noble&section=all)).
  Snort 3 must be built from source ([GitHub](https://github.com/snort3/snort3)). It is not friendly to idempotent apt
  installs.
- **Effort:** M, but **not recommended**: Suricata does the same job with an apt package, EVE JSON and no rules-licence trap.

### Wazuh (and OSSEC)
- **Detects:** a host IDS: log analysis with ~thousands of rules, file integrity (FIM), rootcheck, vulnerability and
  configuration checks, and active response.
- **License:** GPLv2, a fork of OSSEC ([GitHub](https://github.com/wazuh/wazuh)). Wazuh 5.0 was at RC1 in October 2026,
  and its license has not been checked
  ([computingforgeeks](https://computingforgeeks.com/install-wazuh-5-ubuntu/),
  [mailing list](https://groups.google.com/g/wazuh/c/aD4iCWMN4Yc)).
- **Writes:** alerts are written **on the manager**, `/var/ossec/logs/alerts/alerts.json`, owned by the `wazuh` group
  ([SOC Prime](https://socprime.com/?p=57517), third-party). The agent alone produces no alerts file.
- **Cost:** the agent is light. The manager plus indexer is heavy (several GB of RAM).
- **Install:** Wazuh apt repo `packages.wazuh.com/4.x/apt`, and the agent expects a manager
  ([docs](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html)).
- **Fit:** a customer with Wazuh already has a SIEM. For them the right job is to *read the manager's alerts.json*
  (Effort M), which gives FIM, rootkit and auth alerts with MITRE tags. **We should not install Wazuh ourselves.**
  OSSEC: still exists (Atomicorp), and its maintenance pace in 2026 was not checked. Same remark.

### Falco (runtime security, eBPF)
- **Detects:** suspicious behaviour inside the server as it happens: a shell spawned by nginx/php, a reverse shell,
  writes to `/etc` or binaries, reads of `/etc/shadow`, new privileged containers, crypto-miner patterns. This is the
  "after login / after exploit" view.
- **License:** Apache-2.0, a CNCF graduated project since February 2024
  ([CNCF](https://cncf.io/announcements/2024/02/29/cloud-native-computing-foundation-announces-falco-graduation)).
  Commercial use is fine.
- **Writes:** `file_output` with `filename`, and `json_output: true` gives one JSON object per line with `rule`,
  `priority`, `output_fields` and tags ([docs](https://falco.org/docs/concepts/outputs/channels/)). We choose the path
  (for example `/var/log/falco/events.json`) and set group `adm` through logrotate `create 0640 root adm`. It also goes
  to syslog/journal.
- **Cost:** moderate (eBPF probe; tens to a couple of hundred MB RAM, not measured). Needs a recent kernel. Ubuntu
  24.04's 6.8 is fine.
- **Install:** Falco's own apt repo `download.falco.org/packages/deb`, then
  `FALCO_DRIVER_CHOICE=modern_ebpf apt-get install -y falco`, which is non-interactive and needs no DKMS
  ([docs](https://falco.org/docs/setup/packages/)).
- **New attack types:** `PostExploitActivity` / `SuspiciousProcess` (Critical when tied to an IP that had a
  `LoginAfterFailures` or a `WebExploitAttempt`), `SensitiveFileAccess`, `PrivilegeEscalation`, `CryptoMining`.
  Falco events often have **no source IP**, so we link them by time and user, not by IP.
- **Overlap:** none with what we read today.
- **Effort:** **M**. The JSON is easy. New: events without an IP and with no map point, and a "host compromise"
  section in the answers.

### auditd (Linux audit)
- **Detects:** whatever the rules ask for: commands run (`execve`), changes to `/etc/passwd`, `sudoers`, SSH keys,
  kernel modules loaded. It is exhaustive and noisy unless the rules are tight.
- **License:** GPL (linux-audit userspace), in Ubuntu main: `auditd` 1:3.1.2
  ([packages.ubuntu.com](https://packages.ubuntu.com/search?keywords=auditd&searchon=names&suite=noble&section=all)).
- **Writes:** `/var/log/audit/audit.log`, **mode 0600 root by default**. With `log_group = adm` in `auditd.conf` it
  becomes 0640 ([auditd.conf(5)](https://man7.org/linux/man-pages/man5/auditd.conf.5.html),
  [linux-audit list](https://listman.redhat.com/archives/linux-audit/2013-August/007949.html)). Format: `key=value`
  records, several lines per event (SYSCALL, EXECVE, PATH…) joined by a serial number, and some values in hex.
- **Cost:** low with a small rule set. High with broad `execve` logging on a busy host.
- **Install:** `apt install auditd`, plus our rules file in `/etc/audit/rules.d/`. Idempotent and easy.
- **New attack types:** the same idea as Falco (`SuspiciousCommand`, `AccountTampering`, `SshKeyAdded`), with less
  context.
- **Effort:** **L** for a good result. Joining the records, decoding hex, and writing our own rule set is real work.
  Pick it over Falco only if "Ubuntu packages only" is a hard rule.

### osquery
- **Detects:** nothing by itself. It answers SQL questions about the host (listening ports, users, crontabs, SSH keys,
  processes), on a schedule, and logs the *differences*.
- **License:** Apache-2.0 OR GPL-2.0 ([GitHub](https://github.com/osquery/osquery)).
- **Writes:** `/var/log/osquery/osqueryd.results.log`, JSON lines (from memory, not re-checked). Permissions not checked.
- **Install:** not in Ubuntu noble
  ([packages.ubuntu.com](https://packages.ubuntu.com/search?keywords=osquery&searchon=names&suite=noble&section=all));
  use osquery's own apt repo.
- **Fit:** good for questions like "is there a new user, a new listening port, a new cron job?" We would have to write
  and ship the query pack. **Effort M.** It overlaps with Falco/AIDE. Keep it for later.

### AIDE (and Tripwire Open Source)
- **Detects:** files that changed since a baseline (binaries, `/etc`, SSH keys). This catches a rootkit or a backdoor
  *after the fact*.
- **License:** GPL. In Ubuntu: `aide` 0.18.6
  ([packages.ubuntu.com](https://packages.ubuntu.com/search?keywords=aide&searchon=names&suite=noble&section=all&exact=1)).
- **Writes:** a text report, usually `/var/log/aide/aide.log` (set by `report_url`), produced by a daily check
  ([guide](https://oneuptime.com/blog/post/2026-03-02-how-to-install-and-configure-aide-advanced-intrusion-detection-on-ubuntu/markdown)).
  Permissions on Ubuntu not checked. Plain text, and its layout changes between versions.
- **Cost:** CPU and disk spike once a day. Otherwise zero.
- **Install:** `apt install aide` plus `aideinit`. The first baseline must be taken on a clean host, and it must be
  updated after every legitimate upgrade. Otherwise it is very noisy.
- **New attack types:** `FileIntegrityChange` (Critical when the file is in `/bin`, `/usr/sbin`, `authorized_keys`).
- **Effort:** S–M. Tripwire Open Source: last checked as barely maintained, so prefer AIDE (not re-checked).

### Lynis
- **Detects:** no attacks. It is a hardening audit (hardening index, warnings, suggestions).
- **License:** GPLv3 (from memory). In Ubuntu: `lynis` 3.0.9, universe
  ([packages.ubuntu.com](https://packages.ubuntu.com/search?keywords=lynis&searchon=names&suite=noble&section=all)).
- **Writes:** `/var/log/lynis-report.dat` (`key=value`) and `/var/log/lynis.log`
  ([guide](https://oneuptime.com/blog/post/2026-01-07-ubuntu-lynis-security-audit/markdown)).
- **Fit:** nice for an `intrusion_posture` answer ("how exposed is this server?"), not for attacks. **Effort S.**
  Low priority.

### rkhunter / chkrootkit
- **Detects:** known rootkits, suspicious files and hidden processes.
- **License:** GPL. `rkhunter` 1.4.6 in universe
  ([packages.ubuntu.com](https://packages.ubuntu.com/search?keywords=rkhunter&searchon=names&suite=noble&section=all)).
  Upstream has been quiet for years, and chkrootkit's maintenance in 2026 was not checked.
- **Writes:** `/var/log/rkhunter.log`, text. Many false positives after package upgrades.
- **Effort:** S. Low value: AIDE plus Falco cover it better.

### ClamAV
- **Detects:** malware files (web shells in upload folders, Linux malware).
- **License:** GPLv2 (Cisco Talos). In Ubuntu: `clamav-daemon` 1.5.4 through security updates
  ([packages.ubuntu.com](https://packages.ubuntu.com/search?keywords=clamav-daemon&searchon=names&suite=noble&section=all)).
- **Writes:** `/var/log/clamav/clamav.log` and `freshclam.log`. Debian's logrotate creates them `clamav:adm 0640`
  (from memory, not re-checked).
- **Cost:** **clamd needs about 1–1.5 GB RAM** for its signatures. Too much for a small server. On-demand `clamscan`
  from a timer avoids that.
- **New attack types:** `MalwareFile` / `WebShell` (Critical in a web root).
- **Effort:** S. A useful add-on for web servers with uploads, not first priority.

### ModSecurity v3 + OWASP CRS (and Coraza)
- **Detects:** web attacks inside the full request (headers, POST bodies), with OWASP CRS rule IDs and an anomaly
  score: SQLi, XSS, RCE, LFI/RFI, protocol violations. In detection-only mode (`SecRuleEngine DetectionOnly`) it blocks
  nothing, which fits our "never block".
- **License:** ModSecurity is Apache-2.0, now under OWASP
  ([GitHub](https://github.com/owasp-modsecurity/ModSecurity)). Trustwave's commercial support ended 1 July 2024
  ([LevelBlue](https://www.levelblue.com/blogs/spiderlabs-blog/fare-thee-well-modsecurity-end-of-life-and-last-commercial-rules-update-for-june-2024)).
  F5 ended its NGINX ModSecurity product
  ([F5](https://www.f5.com/company/blog/nginx/f5-nginx-modsecurity-waf-transitioning-to-eol)). Coraza is Apache-2.0,
  but its nginx connector is still experimental ([GitHub](https://github.com/corazawaf/coraza)).
- **Writes:** an audit log at a path we choose. `SecAuditLogFormat JSON` (needs YAJL) and `SecAuditLogType Serial` give
  one JSON per transaction ([reference manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x))).
  Short messages also go to the nginx `error.log`.
- **Cost:** a few ms of CPU per request plus RAM in nginx workers. Fine on small sites.
- **Install on Ubuntu 24.04:** all in universe: `libnginx-mod-http-modsecurity`, `libmodsecurity3t64` 3.0.12,
  `modsecurity-crs` 3.3.5
  ([packages.ubuntu.com](https://packages.ubuntu.com/search?keywords=modsecurity&searchon=names&suite=noble&section=all)).
  CRS 3.3.5 is older than upstream CRS 4. **It touches the customer's nginx config**, which is a bigger change than
  "install a tool".
- **New attack types:** finer `WebExploitAttempt` subtypes (`Xss`, `RemoteFileInclusion`, `ProtocolViolation`), with
  the CRS rule ID as evidence.
- **Overlap:** high with our nginx regex and CrowdSec AppSec. **Effort M.** Our `WebProbeRules` stays as the fallback.

### sshguard
- **Detects:** brute force on SSH and some mail/FTP services, and blocks the attacker (like fail2ban).
- **License:** BSD-style (from memory). In Ubuntu: `sshguard` 2.4.2, universe
  ([packages.ubuntu.com](https://packages.ubuntu.com/search?keywords=sshguard&searchon=names&suite=noble&section=all)).
- **Writes:** to syslog/journal (`auth.log`), lines like `Attack from "x" on service 22 …` / `Blocking "x/32" for 120 secs …`
  (from memory, check against `sshguard(8)`).
- **Fit:** only for customers who use it *instead of* fail2ban. **Effort S** (new lines in a log we already read).

### Apache httpd logs
- `/var/log/apache2/access.log` uses the same combined format as nginx. On Debian/Ubuntu the files are `root:adm 0640`
  (from memory). **Effort S**: reuse `NginxAccessLogParser` plus `WebProbeRules`. We already map the `apache-*` jails.
  It is already listed in README "Out of scope".

### Postfix / Dovecot
- `/var/log/mail.log`, written by rsyslog as `syslog:adm 0640` (Ubuntu default, from memory). SASL authentication
  failures (`SASL LOGIN authentication failed`), Dovecot `auth failed`, relay-denied attempts.
- **New attack types:** we already have `MailLoginBruteForce` (today only from fail2ban jails). Add `MailRelayAttempt`.
  **Effort S.** The same `SyslogLine` helper applies.

### OpenVPN / WireGuard
- **OpenVPN:** logs to syslog/journal or its own file: `TLS Error`, `AUTH_FAILED`, `TLS handshake failed`.
  `VpnLoginBruteForce` is possible. **Effort S.** Licence GPLv2 (from memory).
- **WireGuard:** logs **nothing** by design (silent to unauthenticated packets; only kernel dynamic debug). It cannot
  be integrated in a useful way.

### Other ideas worth one line each
- **Sudo, su, useradd, passwd and new SSH keys in `auth.log`:** we already read this file. `sudo: … COMMAND=`,
  `useradd[…]: new user`, `passwd`, `usermod` give a cheap first answer to "what did they do after the login".
  **Effort S, no new software.** Best value per day of work.
- **journald-only hosts:** recent Ubuntu minimal images may have no rsyslog, so there is no `auth.log`. Reading the
  journal (`journalctl -o json`, group `systemd-journal` or `adm`) protects what we already have. Effort M.
- **CrowdSec AppSec and CrowdSec reading Suricata:** CrowdSec can parse eve.json itself, and its AppSec WAF puts alerts
  in the log we already read. It is a cheaper path for customers who already run CrowdSec, but we see only the
  scenario name.
- **nftables/iptables raw logs** (hosts without UFW): the kernel line looks the same as UFW's. Effort S.
- **Conpot (ICS honeypot, GPLv2):** it fakes Modbus/S7 and logs real ICS commands sent by attackers. That is a strong
  demo for energy customers, but it means running a honeypot on their server, and its maintenance in 2026 was not
  checked. Discuss before doing anything.

---

## 3. Comparison table

| Tool | Main value | License (commercial use) | Output | Readable by `adm` | Small-server cost | Ubuntu 24.04 apt | New types | Overlap | Effort |
|---|---|---|---|---|---|---|---|---|---|
| **Suricata** | Signatures on all traffic, outbound C2, ICS keywords | GPL-2.0, ET Open free (yes) | EVE JSON | With `filemode`/ACL (to check) | Medium–high | Universe 7.0.3 (EOL), OISF PPA 8.0.x | Network exploit, C2, anomaly, ICS command | nginx, UFW, CrowdSec | M |
| **Zeek + ICSNPP** | Deep ICS visibility (S7, Modbus, DNP3, ENIP) | BSD (yes) | TSV or JSON, many files | Configurable | High | No, OBS repo + zkg | ICS command / recon | Suricata | L |
| Malcolm | Full ICS SOC stack | Apache-2.0 (yes) | OpenSearch | n/a | Very high | No | (via Zeek/Suricata) | — | L, separate product |
| Snort 3 | Signatures | GPLv2, **Talos rules need a commercial licence** | alert_json | Configurable | Medium | No (only Snort 2.9) | as Suricata | Suricata | M (not recommended) |
| Wazuh / OSSEC | SIEM + HIDS | GPLv2 (yes) | alerts.json on the manager | No (group `wazuh`) | Agent low, manager high | Own repo | FIM, rootkit, many | High | M (read only if present) |
| **Falco** | Behaviour after a break-in | Apache-2.0 (yes) | JSON lines (path we choose) | Yes, via logrotate | Medium | Own repo, non-interactive | Post-exploit, sensitive file, privesc | None | M |
| auditd | Syscall audit | GPL (yes) | key=value, multi-line | With `log_group = adm` | Low–medium | Main | Account tampering, command | auth.log sudo | L |
| osquery | Host state diffs | Apache-2.0/GPL-2.0 (yes) | JSON lines | Not checked | Low–medium | Own repo | New user/port/cron | Falco, AIDE | M |
| AIDE | File integrity | GPL (yes) | Text report, daily | Not checked | Daily spike | Yes | File integrity change | — | S–M |
| Lynis | Hardening audit | GPLv3 (yes) | key=value report | Not checked | Low | Universe | (posture, not attacks) | — | S |
| rkhunter / chkrootkit | Rootkit check | GPL (yes) | Text | Not checked | Low | Universe | Rootkit suspicion | AIDE, Falco | S |
| ClamAV | Malware files | GPLv2 (yes) | Text | `adm` (from memory) | **clamd ~1 GB+** | Yes | Malware file, web shell | — | S |
| **ModSecurity + CRS** | Full-request web attacks | Apache-2.0, CRS Apache-2.0 (yes) | JSON audit log | Configurable | Low–medium | Universe (nginx module) | Finer web exploit types | nginx regex, CrowdSec | M |
| sshguard | SSH brute force + ban | BSD-style (yes) | syslog | Yes (`auth.log`) | Very low | Universe | (existing) | fail2ban | S |
| Apache logs | Web attacks on Apache | (the server itself) | Combined log | Yes | — | — | (existing) | nginx | S |
| Postfix/Dovecot | Mail brute force, relay | (yes) | syslog `mail.log` | Yes | — | — | Mail relay attempt | fail2ban mail jails | S |
| OpenVPN | VPN brute force | GPLv2 (yes) | syslog | Yes | — | — | VPN login brute force | — | S |
| WireGuard | — | — | Silent by design | — | — | — | — | — | not feasible |

---

## 4. Recommended order

**Step 0: quick wins, no new software (S, about 1 week in total).** Add `sudo`/`useradd`/`passwd` lines in `auth.log`,
`mail.log`, Apache access logs and sshguard lines. These widen coverage for the customers we have today with almost no
risk, and partly answer "what did they do after logging in".

**1. Suricata (EVE JSON).** Intrusions and industrial protocols.
- The biggest jump in coverage: attacks on *any* service, not only those that write a log.
- Outbound C2/malware alerts are the best network sign of a compromised server.
- It has an apt path (OISF PPA) and clean JSON.
- The same parser serves an OT-network sensor later, with Modbus/DNP3/ENIP keywords, which is the path to the energy
  customers' real need.
- README already names it as next.

**2. Falco (or auditd if only Ubuntu packages are allowed).** Integrity and compromise after login.
- Today we can say "someone logged in after failures". Falco adds what they did: a shell from nginx, a write to
  `/etc`, a read of `/etc/shadow`.
- JSON output with named rules, Apache-2.0, a non-interactive apt install with modern eBPF.
- AIDE is a cheap daily complement once this is in place.

**3. ModSecurity v3 + OWASP CRS in DetectionOnly.** Web attacks.
- It sees what `access.log` cannot (POST bodies, headers) and labels each hit with a CRS rule ID. The agent can cite
  that rule ID as evidence.
- All packages are in Ubuntu noble.
- It comes third because it changes the customer's nginx config and overlaps with what we already detect.

**Later, for industrial customers with a plant network:** a separate "OT sensor" deployment with Zeek + ICSNPP (S7,
Modbus, DNP3, ENIP, IEC 104 via Spicy) on a SPAN port. That is a product decision, not a new parser for the web server.

**Read if present, never install:** Wazuh `alerts.json` (customers with an existing SIEM).

---

## 5. Risks

- **Root-only logs:** auditd (0600 unless `log_group = adm`), Wazuh (group `wazuh`), possibly Suricata and osquery.
  Never run the toolkit as root. Fix the permission at the source (`log_group`, `filemode`, logrotate `create 0640 root
  adm`, or `setfacl -m g:adm:r`) and write the fix in the install script, so it survives rotation. auditd is known to
  reset the mode on rotation if only an ACL is used
  ([Red Hat](https://access.redhat.com/solutions/905243)).
- **Noise and size:** eve.json with all event types and auditd with `execve` grow by GBs per day. Filter at the
  source (only `alert`/`anomaly`, a tight rule set) and read only the period asked, from the end of the file.
  AIDE and rkhunter flag every package upgrade unless the baseline is refreshed.
- **Licences:** Snort Subscriber (Talos) rules need a commercial agreement for commercial purposes. ET Pro is paid per
  sensor. We stay safe by recommending **ET Open + Suricata** and **OWASP CRS**. GPL tools are fine because we read their
  output and never ship or link them. Wazuh 5.0's licence was not checked.
- **We change the host:** installing an IDS or WAF is no longer "read only". Suricata on the wrong interface, or in
  IPS mode, can break traffic. ModSecurity in blocking mode can break the customer's site. Always install in detection
  mode, as an opt-in step with the customer's OK, separate from the toolkit package.
- **Resources:** clamd (~1 GB+), Suricata with big rule sets, and Zeek on busy links can hurt a small VM.
- **Maintenance:** Ubuntu's Suricata 7.0.3 is past end of life (use the PPA). ModSecurity lost its commercial sponsor.
  Snort 3 is not packaged. GRASSMARLIN is dead. rkhunter and chkrootkit are quiet upstream.
- **False sense of ICS coverage:** on a public server, network tools see only probes on closed ports. Say this clearly
  to energy customers.

---

## 6. What I could not verify

- The default owner and mode of `eve.json` in the Ubuntu and PPA packages. The exact latest Suricata 8.0.x point
  release (8.0.6 confirmed, 8.0.8 claimed by a third-party blog).
- Snort 3 engine licence on the official page (GPLv2 from memory/COPYING). That Snort 3 has `alert_json` (from memory).
- Wazuh 5.0 GA date and licence. Exact permissions of `alerts.json`. OSSEC maintenance in 2026.
- osquery's default log path and permissions (from memory). Zeek's JSON switch (from memory).
- Permissions of the AIDE, Lynis, rkhunter, ClamAV, Apache and `mail.log` files on Ubuntu 24.04 (the `adm`/0640
  values come from memory of Debian defaults). Check them with `ls -l` in the lab image.
- sshguard log line format and licence. OpenVPN licence. Conpot and chkrootkit maintenance in 2026. Tripwire Open
  Source status.
- Resource numbers are rules of thumb, not measured. Measure them in the Docker lab before promising anything to a
  customer.
