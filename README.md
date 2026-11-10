# xrcopilotlab-intrusion-mcp

A small, **read-only** MCP server that lets an XRCopilotLab agent watch the intrusion attempts on a Linux host:
who is trying to get in, from where, with which attack, what has been banned, which plant protocols somebody is
looking for, and which successful logins a person should check.

The host's own tools do the detection and the blocking. This server blocks nothing: it reads the logs they write,
classifies what they say, geolocates the source addresses, and answers the agent's questions.

| Detector | Log | What it adds |
|---|---|---|
| **fail2ban** | `/var/log/fail2ban.log` | Bans and unbans per jail, the `recidive` jail |
| **sshd** | `/var/log/auth.log` | Failed and successful logins, the accounts tried |
| **UFW** | `/var/log/ufw.log` | Connections to closed ports: port scans, industrial protocol probes |
| **nginx** | `/var/log/nginx/access.log` | What a web attacker asked for: scans, SQL injection, path traversal, Log4Shell… |
| **CrowdSec** | `/var/log/crowdsec.log` | Scenarios from the CrowdSec hub, including slow brute force that fail2ban misses |

A detector the host does not have is simply absent from the answers.

| Mode | Where it runs | What it reads | Use |
|---|---|---|---|
| `simulated` | Our Azure Container App `hev-intrusion-mcp` | A synthetic host generated in memory | Demos (ALVEO) |
| `logs` | The customer's host, next to its detectors | The five logs above | Production |

Two faces, same key, same answers: **MCP** on `/mcp` (for whoever registers the server in XRCopilotLab by hand) and
**REST** on `/api` (for a blueprint, which provisions it as a `kind: builder` server with no manual step).

Both modes go through the same parsers and rules: the simulated host writes real-format log lines, and the server
reads them exactly as it reads a real host.

---

## Tools

All tools are read-only (`readOnlyHint: true`). Every answer carries `simulated` and the geolocation attribution.
The period is the last 24 hours by default (`hours`, max 720), or `since`/`until` in ISO 8601.

| Tool | Answers |
|---|---|
| `intrusion_status` | Active jails, addresses banned now per jail, bans and attempts in the last 24 h, latest event. |
| `intrusion_banned_ips` | Addresses banned now: jail, attack type, since when, location. Filter by `jail`. |
| `intrusion_attempts` | One row per source address, most serious first: attempts, bans, accounts tried, attack types, severity, location. Filters: `jail`, `attackType`, `country`, `top`. |
| `intrusion_ip_detail` | Everything one address did: summary, suspicious logins, timeline (up to 200 events). |
| `intrusion_suspicious_logins` | Successful SSH logins after repeated failures (Critical) or from an unexpected country (High). |
| `intrusion_summary` | Totals, by attack type, by country, most targeted closed ports, top attackers, distributed campaigns, suspicious logins, map points (lat/lon/severity) for a map. |

REST, same parameters as query strings: `GET /api/status`, `/api/banned?jail=`, `/api/attempts?hours=&jail=&attackType=&country=&top=`,
`/api/ips/{ip}?hours=`, `/api/suspicious-logins?hours=`, `/api/summary?hours=&top=`.

### Attack types

| Type | From |
|---|---|
| `SshBruteForce` | sshd failures from one address (3 or more, or an sshd ban) |
| `DistributedSshBruteForce` | One account tried by 8+ addresses, each with 4 failures at most, trying nothing else: fail2ban alone never bans them |
| `WebLoginBruteForce` | Jails `nginx-http-auth`, `apache-auth`, `wordpress`, …; nginx 401; CrowdSec `http-*-bf` |
| `WebVulnerabilityScan` | Jails `nginx-botsearch`, …; nginx requests for `/.env`, `/.git/`, WordPress, phpMyAdmin, admin consoles, backups, web shells, `cgi-bin`, scanner user agents; CrowdSec `http-probing`, `http-sensitive-files`, … |
| `WebExploitAttempt` | nginx requests with SQL injection, path traversal, command injection, Log4Shell, PHPUnit RCE; CrowdSec `*-cve-*`, `http-sqli-probing`, … |
| `RequestFlood` | Jails `nginx-limit-req`, `apache-modsecurity`; nginx 429 |
| `MailLoginBruteForce` | Jails `postfix-sasl`, `dovecot`, … |
| `PortScan` | 10+ distinct closed ports from one address (UFW); CrowdSec `iptables-scan-multi_ports` |
| `IndustrialProtocolProbe` | Any connection to Modbus 502, S7 102, IEC 104 2404, DNP3 20000, EtherNet/IP 44818, OPC UA 4840, BACnet 47808, Niagara Fox 1911 |
| `RepeatOffender` | Banned by the `recidive` jail |
| `LoginAfterFailures` | An `Accepted …` login after 3+ failures from the same address in the previous 24 h: possible compromise |

Severity: `Critical` (login after failures), `High` (repeat offender, industrial probe, web exploit, login from an
unexpected country), `Medium` (any ban, a CrowdSec alert, 10+ attempts, campaign, flood, web login brute force, port
scan), `Low` (the rest). A user who mistypes once and then logs in is not reported, nor are ordinary web visitors or
a few stray packets on the firewall.

One attempt is counted once: sshd failures from `auth.log` (fail2ban's `Found` only when `auth.log` is missing), web
requests from whichever of fail2ban and nginx saw more. Firewall blocks and CrowdSec alerts are reported apart.

---

## The simulated host

`bastion-01`, an SSH and nginx host in Europe/Rome behind UFW, protected by fail2ban with `sshd` (5 tries in 10 min,
1 h ban), `nginx-http-auth`, `nginx-botsearch`, `nginx-limit-req` and `recidive` (3 bans in a day, 1 week), with
**CrowdSec in detection mode** (it alerts and decides, but no bouncer enforces). Each day it has:

- SSH brute force from 25-45 addresses, most of them banned; web vulnerability scans; web login brute force; web
  exploit attempts (SQL injection, path traversal, Log4Shell, PHPUnit, command injection);
- every fourth day, a request flood;
- firewall noise on closed ports (Telnet, RDP, SMB…), 2-4 port scans, and one probe of the industrial control ports;
- a **distributed campaign** on one account (`admin`, `scada`, `engineer`, `vpn` in rotation) from 14-25 home
  connections, none banned;
- one address banned three times, then by `recidive` for a week;
- **the intrusion**, from `198.51.100.213` (Chișinău): at 00:31 a port scan; from 00:52 one SSH try every 160-230 s on
  `operatore`, slow enough that fail2ban never bans it; around 01:25 CrowdSec raises `ssh-slow-bf`, which nothing
  enforces; around 02:50 a successful password login. The agent sees the whole sequence, and could have acted at
  00:31 or at 01:25;
- legitimate logins: the nightly `backup` key from the office (03:00), the `deploy` key in working hours, the
  administrator `m.ferri` who mistypes once at 09:xx; ordinary web visitors and a crawler.

Deterministic: the same seed and day give the same lines on every replica and after every restart. Today is cut at
the current time, so new attacks appear during the day. Settings: `Simulation:Hostname`, `Seed`, `Days` (30),
`TimeZone`, `IncidentEveryDays` (1).

**All data is synthetic.** Every address is in a documentation range (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`), which no real host uses, with an invented city; networks carry documentation AS numbers
(RFC 5398). A test fails if a simulated address is anything else.

---

## Authentication

XRCopilotLab sends the key in the `X-API-Key` header. The server stores only its SHA-256 (`ApiKeys:Hash`, hex
lowercase); a second key for a rotation goes in `ApiKeys:Keys:n:Hash`. The key is accepted in the header only, never
in the query string, so it never ends up in the MCP server's address. `/healthz` answers 503 while no key is
configured; `/livez` answers when the process is up. 120 calls per minute per key.

---

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `Server:Mode` | `logs` | `logs` or `simulated` |
| `ApiKeys:Hash` | — | SHA-256 of the key |
| `Logs:Fail2banFiles` | `/var/log/fail2ban.log*` | fail2ban logs; `*` takes the rotated copies, `.gz` included |
| `Logs:AuthFiles` | `/var/log/auth.log*` | sshd logs (`/var/log/secure*` on RHEL) |
| `Logs:FirewallFiles` | `/var/log/ufw.log*` | UFW logs (`ufw logging low` or higher) |
| `Logs:WebAccessFiles` | `/var/log/nginx/access.log*` | nginx access logs, `combined` format |
| `Logs:CrowdsecFiles` | `/var/log/crowdsec.log*` | CrowdSec logs |
| `Logs:TimeZone` | system zone | IANA id; fail2ban writes local time |
| `Logs:MaxDays` | 30 | how far back to read |
| `Geo:DbIpCityLiteCsv` | — | DB-IP "IP to City Lite" CSV (`.csv` or `.csv.gz`); without it, no geolocation in the `logs` mode |
| `Policy:AllowedCountries` | `["IT"]` | countries a login is expected from |
| `Policy:FailuresBeforeLogin` | 3 | failures before a login that make it suspicious |
| `Policy:CampaignMinIps` / `CampaignMaxPerIp` | 8 / 4 | distributed campaign thresholds |
| `Policy:PortScanMinPorts` | 10 | distinct closed ports that make a port scan |

Geolocation in the `logs` mode uses **DB-IP Lite** (https://db-ip.com/db/lite.php, CC BY 4.0: commercial use allowed,
attribution returned in every answer). The file is not in the repository: download it on the host. The DB-IP CSV
column order (`ip_start,ip_end,continent,country,stateprov,city,latitude,longitude`) is the one documented by DB-IP
and has not yet been checked against a downloaded file.

---

## Build, test, run locally

```bash
make test
export INTRUSION_MCP_API_KEY=...   # any local key, never committed
make run                           # simulated mode on http://localhost:5290
curl -s http://localhost:5290/mcp -H "X-API-Key: $INTRUSION_MCP_API_KEY" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"intrusion_summary","arguments":{}}}'
```

## Deploy the demo (simulated mode)

```bash
az acr login -n crhevoluscoi
make docker-push TAG=0.1.0
export INTRUSION_MCP_API_KEY=$(az keyvault secret show --vault-name <vault> -n intrusion-mcp-apikey --query value -o tsv)
make deploy TAG=0.1.0
make smoke
```

Container App `hev-intrusion-mcp` on `hev-coi-mcp-env`, `minReplicas: 0` with the HTTP scale rule. The key's hash is
a Container App secret; the clear key stays in Key Vault and is the value to register in XRCopilotLab.

## Install on a real host (logs mode)

```bash
make package VERSION=0.1.0          # out/xrcopilotlab-intrusion-mcp-0.1.0-linux-x64.tar.gz
# on the host (Debian/Ubuntu with fail2ban):
tar -xzf xrcopilotlab-intrusion-mcp-0.1.0-linux-x64.tar.gz && cd xrcopilotlab-intrusion-mcp-0.1.0-linux-x64
sudo ./install.sh
```

The tarball holds a self-contained single binary (no .NET to install), the systemd unit and the install script. The
service runs as `xrcopilot-intrusion` in group `adm` (to read `/var/log`), with a read-only system
(`ProtectSystem=strict`), and listens on `127.0.0.1:8080` only: publish it through the host's nginx with TLS and an
allowlist of XRCopilotLab's addresses (the script prints an example). **Not yet tried on a real host.** Two things to
check there: that `/var/log/crowdsec.log` is readable by the group `adm` (its default mode is not verified), and the
exact line formats of the host's CrowdSec version, which here come from its documentation, not from a real log.

## Register it in XRCopilotLab

- **From a blueprint** (no manual step): a `webhook` connection with `baseUrl: https://<host>/api`, `CustomHeaders`
  `X-API-Key` from a secret of the tag, and an `mcpServers` entry `kind: builder` with one GET tool per route.
- **By hand**: Administration › MCP, a new server with address `https://<host>/mcp` and the key in a `X-API-Key`
  header (custom headers), then assign it to the agent; a blueprint then cites it as `kind: existing`.

---

## Repository layout

```
src/XrCopilotLab.Intrusion.Mcp.Core/     pure logic, no I/O
  Parsing/      fail2ban, auth.log, ufw.log, nginx access.log, crowdsec.log parsers; web attack patterns
  Analysis/     attack catalogue, threat analyzer, policy
  Geo/          reserved ranges, range table (DB-IP), locator interface
  Simulation/   synthetic host and its invented geography
  Sources/      log source interface, simulated source
  Queries/      the answers behind the tools
src/XrCopilotLab.Intrusion.Mcp.Server/   ASP.NET host: MCP tools, REST face, API key, file source, DB-IP loader
tests/                                   parsers, analyzer, geo, the simulated story
deploy/linux/                            systemd unit, install script, production settings
infra/                                   Container App of the demo
```

## Out of scope for now

- Writing actions (ban, unban, whitelist): possible later, always with a person's confirmation.
- Suricata (network IDS: signatures on any service, not only the ones with a log): next to discuss.
- Windows hosts (Event Log), Apache access logs, nginx in a custom log format.
- Reputation data (AbuseIPDB, CrowdSec CTI): commercial plans needed.
