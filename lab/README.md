# Intrusion lab

A Docker lab for demos and tests: an Ubuntu 24.04 server (`lab-01`) with sshd, nginx, fail2ban and a firewall, on
which the **customer package** is installed by its own `install.sh` (same tarball as `make package`), and an attacker
that also serves the console on **http://localhost:8090** (attack buttons, tunnel, server to test). What the package on
`lab-01` detects is `lab-01`'s own monitoring page. The server is not published on a local port: the page opens through
the Dev Tunnel with the Microsoft login (see below), or on the customer's domain, no password of its own. With `PUBLIC_DOMAIN` in `lab/.env` (see
`lab/.env.example`) the lab uses that domain instead of a tunnel: DNS, TLS proxy and firewall must already be in place
(README › "The lab on a domain").

![The lab console](../docs/images/console.jpg)

What each part of the console shows, and how to give the lab a public address for XRCopilotLab, in plain words:
[README › The test console](../README.md#the-test-console-docker-lab).

```bash
make lab-up      # builds and starts; creates lab/.env with the lab key on the first run
make lab-down    # stops the lab (keeps the tunnel login: same public address)
make lab-reset   # stops the lab and deletes all its state, tunnel login included
```

## What runs

The `make` commands use the service names (`make lab-shell SVC=attacker`); plain Docker uses the container names
(`docker exec -it intrusion-lab-server bash`, `docker logs -f intrusion-lab-tunnel`).

| Service (container) | What | Notes |
|---|---|---|
| `server` (`intrusion-lab-server`, host `lab-01`) | Ubuntu 24.04 with systemd: sshd (password login, user `operatore`, in the `sudo` group), nginx (site, `/admin/` with basic auth, the package's API under `/intrusion-mcp/`), fail2ban (`sshd`, `nginx-http-auth`, `nginx-botsearch`, `nginx-limit-req`, `recidive`, times shortened), a UFW-like firewall, **Suricata 8** with the ET Open rules (installed by the package's own `install.sh --with suricata` at build, the only moment lab-01 reaches the internet; it listens on all four interfaces with `--pcap=any -k none`), **Falco 0.45** with the modern eBPF probe (same `install.sh --with falco`; two container-only rules are turned off in `/etc/falco/rules.d/lab.yaml`, since lab-01 is itself a container), **ModSecurity 3 + OWASP CRS** in nginx (`install.sh --with modsecurity`, detection only; the toolkit's own API and the monitoring page are excluded), the package's read-only **monitoring page** (opened through the Dev Tunnel, port 8093; the package's own 8471 site stays unused inside the container), the package (`xrcopilotlab-intrusion-mcp.service`, logs mode) | privileged: systemd as PID 1, iptables. A lab container, never a pattern for production. Its networks are all internal: it is reached only through the `tunnel` container (Dev Tunnel) or the customer's domain, never a local port |
| `attacker` (`intrusion-lab-attacker`) | nmap, ssh, Python: fixed scenarios against `lab-01`, the console, a **"Server da testare"** field that runs the web scenarios against another server once its API key proves you can already read it, and (when the Metasploit container answers) three **Metasploit** scenarios it drives over msfrpcd | its lab networks are `internal`: no attack reaches the internet |
| `metasploit` (`intrusion-lab-metasploit`) | official Metasploit image running `msfrpcd`; the console drives it. Starts with `make lab-up`; `make lab-down-msf` stops it alone, `make lab-up-msf` starts it again | on the same `internal` networks as the attacker; reaches `lab-01` only, never the internet |
| `tunnel` (`intrusion-lab-tunnel`) | Dev Tunnels CLI, socat, a small controller driven by the console | the only container that goes out to the internet, for the tunnel |

UFW logs through the kernel LOG target, which a container cannot read: the lab's firewall uses NFLOG, ulogd2 and
rsyslog to write **the same line** to `/var/log/ufw.log`, so the package's parser is the one a real host uses.

## Public address for XRCopilotLab (Dev Tunnels)

The `tunnel` container gives lab-01's API a public HTTPS address with Microsoft Dev Tunnels, so that a connection
in XRCopilotLab can call the lab running on a laptop. Nothing is installed on the Mac.

1. In the console, **Collegamento a XRCopilotLab › Accedi con l'account Microsoft**: the console shows Microsoft's
   link and a code; sign in there with an Entra ID (Hevolus), Microsoft or GitHub account.
2. The tunnel opens by itself (persistent, anonymous access, expires after 30 days unused) and the console shows its
   addresses: `…/api` for a connection with HTTP tools, `…/mcp` for an MCP client, and a button that copies the
   `X-API-Key`.
3. **Verifica dall'indirizzo pubblico** calls the package through the public address, as XRCopilotLab will.

What the tunnel reaches, two ports of lab-01 (their own nginx logs; the firewall allows only the tunnel container):
- **8091**, `/api/` and `/mcp` and nothing else, with **anonymous access**: XRCopilotLab cannot log in to Dev Tunnels,
  and every call still needs the key.
- **8093**, the **monitoring page** (Hevolus header, map and list of the attacks), read only, **without anonymous
  access**: Dev Tunnels asks for the Microsoft login, and lets in only the account that opened the tunnel and the
  users of its Entra tenant (Hevolus). That login is the only way in: the page has no password of its own, and nginx
  adds the page's key. The console shows its address (*Pagina di monitoraggio*) and the button *Mappa e lista degli
  attacchi*. The access rules are rewritten at every start of the tunnel. The login and the tunnel id live in the `tunnel-login` volume:
`make lab-down` keeps them (same address next time), `make lab-reset` deletes them.

Dev Tunnels has no price list; the limits are 5 GB of traffic and 10 tunnels per user per month. It is a preview
service for development and tests, not for a customer's server.

## Addresses and places

Three networks with documentation addresses (RFC 5737). The attacker adds its personas' addresses, and the package
places documentation addresses in the invented cities of the simulated mode (`DocumentationAwareGeo`); every other
address goes to DB-IP. So the map has cities, and no real address is ever involved.

| Scenario | From | Expected detection |
|---|---|---|
| Scansione delle porte | 203.0.113.6 (Moscow) | PortScan |
| Protocolli industriali | 203.0.113.7 (Seoul) | IndustrialProtocolProbe, High |
| Forza bruta SSH veloce | 203.0.113.20 (Shenzhen) | SshBruteForce, banned by `sshd` |
| Intrusione lenta e accesso | 198.51.100.213 (Chișinău) | PortScan, SshBruteForce, LoginAfterFailures, Critical |
| Scansione del sito | 203.0.113.14 (Hong Kong) | WebVulnerabilityScan, banned by `nginx-botsearch` |
| Exploit web | 203.0.113.9 (Saint Petersburg) | WebExploitAttempt, High (nginx access log + ModSecurity) |
| Attacco nascosto nel modulo contatti | 203.0.113.41 (Hanoi) | SQL injection, XSS and command injection in the body of a `POST /contatti.html`: the access log shows only `POST /contatti.html 200`; **ModSecurity** sees them (`WebExploitAttempt`). The first message is a legitimate enquiry and is not reported |
| Forza bruta area riservata | 203.0.113.18 (São Paulo) | WebLoginBruteForce, banned by `nginx-http-auth` |
| Flood | 203.0.113.15 (Dallas) | RequestFlood, banned by `nginx-limit-req` |
| Campagna distribuita | 192.0.2.11–22 (12 cities) | DistributedSshBruteForce on `scada`, no ban |
| L'intruso dentro il server | 198.51.100.213 (Chișinău) | Falco: Search Private Keys, Read sensitive file untrusted (`sudo cat /etc/shadow`), XRC SSH authorized keys changed, a "miner" (`xmrig` with a `stratum+tcp://` pool), Clear Log Activities (`wtmp`). All tied to 198.51.100.213 (`ssh-session`): SensitiveFileAccess, Persistence, CryptoMining, LogTampering, Critical |
| Backdoor che chiama casa | 203.0.113.66 (Moscow) | lab-01 calls the attacker's controller: CommandAndControl, Critical (Suricata: the lab's own rule and ET Open's `ET MALWARE Generic Request to gate.php Dotted-Quad`) |

### Metasploit scenarios

To prove the guardians catch a **real** attack engine, not only our hand-written requests, the lab can run
[Metasploit](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html) in its **own
container** (the official image, ~2 GB). It starts with the lab (`make lab-up` pulls the image on the first run;
msfrpcd answers after ~30 s):

```bash
make lab-down-msf    # stops just the Metasploit container, leaves the rest running
make lab-up-msf      # starts it again
```

The console drives the container over **msfrpcd** (the attacker image only carries the small `pymetasploit3` client).
Three extra scenarios then appear in the console (greyed out until the Metasploit container answers):

| Scenario | Metasploit module(s) | Expected detection |
|---|---|---|
| Metasploit · scansione web | `scanner/http/http_version`, `robots_txt`, `dir_scanner` | WebVulnerabilityScan (Suricata + ModSecurity) |
| Metasploit · forza bruta SSH | `scanner/ssh/ssh_login`, seven passwords | SshBruteForce, banned by fail2ban |
| Metasploit · sonda Modbus | `scanner/scada/modbusdetect`, `modbus_findunitid` | IndustrialProtocolProbe (needs port 502 open) |

Metasploit does **not** spoof the source address, so these attacks arrive from the Metasploit container's own lab
address, fixed at **203.0.113.72** (Ashburn, United States, on the map), and lab-01's guardians attribute them to it —
which is the point of the test. After *forza bruta SSH* fail2ban bans that address for a few minutes, so the other two
Metasploit scenarios get no answer until the ban expires. They are
lab-only: the container sits on the lab's internal networks, it runs against lab-01, and the console refuses these
scenarios against an external server under test.

All verified on 2026-11-11 with `make lab-up`, one scenario after the other; the backdoor and Suricata on 2026-11-12;
the intruder inside and Falco on 2026-11-12; ModSecurity, the monitoring page and the external-target flow on 2026-11-12 (full night: five Falco alerts, all tied to 198.51.100.213, none left
without an address).

**Falco sees every container on the Docker machine**, not only lab-01: Docker Desktop runs them all on one kernel. The
attacker's commands go on `ssh`'s standard input for this reason; on its command line they would have shown up as a
miner started in the attacker's container.

What Suricata adds to the other scenarios, with the real ET Open rules (2026-11-12): `ET SCAN Suspicious inbound to
mySQL/MSSQL/Oracle/PostgreSQL port` on the port scans, `ET WEB_SERVER SELECT USER SQL Injection Attempt in URI` and
`ET EXPLOIT Apache log4j RCE Attempt` on the web exploits. Nothing on the industrial probe: the ports are closed, so no
Modbus or S7 conversation ever starts (see [docs/security-tools.md](../docs/security-tools.md)).

## What the lab found in the package

- The single binary aborted at start on a host without ICU (`libicu`): `install.sh` now installs it when missing.
- CrowdSec's local API listens on `127.0.0.1:8080`, the toolkit's old port: on any server with CrowdSec the toolkit did
  not start. The toolkit now listens on `127.0.0.1:8470`.
- CrowdSec writes `/var/log/crowdsec.log` as `0600 root`: unreadable. `--with crowdsec` gives it to the group `adm`
  (`0640`); CrowdSec's rotation keeps the mode.
- Suricata 8 runs as the user `suricata` and keeps its logs in a `0770` folder: the toolkit's service gets the group
  `suricata` (systemd drop-in). Its configuration test (`suricata -T`), run as root, left `eve.json` owned by root, and
  Suricata could no longer write it: the test now writes elsewhere.
- The service's hardening (`RestrictAddressFamilies`) blocked netlink, so the toolkit could not list its own
  addresses and took the server's call to the malware controller for an attack *from* the server's address. Netlink
  is now allowed.
- Falco creates its file output `0600 root`: `--with falco` creates `/var/log/falco/events.json` first, `0640` group
  `adm`, and logrotate recreates it the same way. Falco opens it at every alert (`keep_alive: false`), so a rotation
  needs no signal.
- Falco's `user.loginname` is empty when the kernel has no audit (Docker Desktop's, some cloud kernels): an alert could
  not be tied to its SSH session. `--with falco` now appends `SSH_CLIENT` (the client's exact address) and `SUDO_USER`
  (who ran `sudo`) to every alert.
- A rule of ours fired seven times for one `useradd`, which starts helpers under its own name: the rules now skip a
  process whose parent has the same name.
- Launchpad's API failed for over an hour (`GPGKeyTemporarilyNotFoundError`) and `add-apt-repository` with it, so
  `--with suricata` could not install. The OISF repository is now added by hand, with its two signing keys fetched by
  fingerprint from keyserver.ubuntu.com and checked.
- The OWASP CRS package's own rule loader (`owasp-crs.load`) uses `IncludeOptional`, which libmodsecurity v3 rejects:
  `nginx -t` failed and nginx would not start. `--with modsecurity` includes the CRS files one by one, and runs
  `nginx -t` before and after, removing its file if it fails.
- ModSecurity inspected the toolkit's own API and monitoring page too (`modsecurity on` at the `http` level), filling
  the audit log the toolkit reads with its own polling. Those locations now carry `modsecurity off;`.
- That `modsecurity off;` broke the build: the lab's sites were copied before `install.sh`, when nginx did not know the
  directive yet, so `--with modsecurity` found `nginx -t` already failing and stopped. The sites
  (`lab/server/nginx-sites/`) are now copied after the package, followed by `nginx -t`.
- The monitoring page returned 500: nginx (`www-data`) could not traverse the service's `0750` config folder to read
  the page's `htpasswd`. The page's files moved to `/etc/nginx/xrcopilotlab-dashboard`, which nginx can reach.
- With the default settings every log was read twice (the configuration list is appended to the defaults), so every
  attempt was counted twice: the file list is now de-duplicated.

## Secrets

`lab/.env` (git-ignored) holds `LAB_API_KEY`; `lab-01` stores only its hash, as `install.sh` does at a customer's, and
the console adds it to its calls, so the browser never sees it. `operatore`'s password and `/admin/`'s are lab values,
written in the scenarios on purpose: they exist only inside the lab.
