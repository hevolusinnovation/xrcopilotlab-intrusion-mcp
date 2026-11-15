"""The lab's public address: Microsoft Dev Tunnels, driven from the console.

- Login with a device code, with any account: Entra ID or Microsoft account, or GitHub. The page shows the link and
  the code. Every login starts from a clean cache, and "Cambia account" signs out and in again: the saved login is
  only reused until someone chooses another account.
- Once logged in: a persistent tunnel with two ports, hosted here; socat forwards each to lab-01.
  - 8091, lab-01's API-only port, with anonymous access: XRCopilotLab cannot log in to Dev Tunnels; the package's
    X-API-Key still guards every call.
  - 8093, the monitoring page (map and attacks), with no anonymous access: the browser asks for the Microsoft login,
    and only the tunnel's owner and the users of the owner's Entra tenant get in. No password of its own: this
    login is the only way in.
- The login and one tunnel id per account live in /root (a volume): the address stays the same across restarts, and
  each account gets its own tunnel back when it signs in again, until the tunnel is unused for 30 days.

With PUBLIC_DOMAIN set (lab/.env) there is no Dev Tunnel: the same two ports are published on the machine, for the
reverse proxy the domain points to, and the console shows the domain's addresses (phase "domain").

Listens on :8092, on the console network only; the console proxies it.

While the tunnel is open its address is written to URL_FILE (a volume lab-01 mounts read-only), where the package
reads it: the monitoring page then shows it as XRCopilotLab's temporary test address. Removed when the tunnel closes.
"""
import json
import os
import re
import subprocess
import threading
import time
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

PORT = 8091
PAGE_PORT = 8093
LAB_API = os.environ.get("LAB_API", "10.77.0.20:8091")
LAB_PAGE = os.environ.get("LAB_PAGE", "10.77.0.20:8093")
DOMAIN = os.environ.get("PUBLIC_DOMAIN", "").strip().strip("/")
PAGE_PUBLIC_PORT = os.environ.get("PUBLIC_PAGE_PORT", "8443").strip()
LOCAL_PAGE_PORT = 8089   # published on this container (localhost:8089): local access to lab-01's page
LAB_API_KEY = os.environ.get("LAB_API_KEY", "")  # the test key, shown on lab-01's page (test mode only)
ID_DIR = "/root/tunnels"        # one tunnel id per account: a tunnel belongs to the account that created it
LEGACY_ID_FILE = "/root/tunnel-id"
TOKEN_DIR = "/root/DevTunnels"  # devtunnel's login cache (it runs from /root)
PROVIDERS = {"microsoft": "-e", "github": "-g"}
URL_FILE = os.environ.get("TUNNEL_URL_FILE", "/state/url")
LOCATION_FILE = os.environ.get("TUNNEL_LOCATION_FILE", "/state/location.json")
DEVICE = re.compile(r"open the page (?P<url>https://\S+) and enter the code (?P<code>[A-Z0-9-]+)")
WEB_URL = re.compile(r"https://\S+?-%d\.\S+?devtunnels\.ms\S*" % PORT)

state = {"phase": "starting", "user": None, "login": None, "url": None, "pageUrl": None, "tunnelId": None, "error": None, "since": None}
lock = threading.Lock()
host_process = None
login_process = None


def set_state(**kw):
    with lock:
        state.update(kw)
        url = state["url"] if state["phase"] == "online" else None
    publish(url)


def publish(url):
    """The address for the package on lab-01: written atomically, removed when there is none."""
    try:
        if url:
            os.makedirs(os.path.dirname(URL_FILE), exist_ok=True)
            with open(URL_FILE + ".tmp", "w") as f:
                f.write(url + "\n")
            os.chmod(URL_FILE + ".tmp", 0o644)
            os.replace(URL_FILE + ".tmp", URL_FILE)
        elif os.path.exists(URL_FILE):
            os.remove(URL_FILE)
    except OSError as ex:
        print("cannot publish the tunnel address:", ex)


def devtunnel(*args, timeout=60):
    r = subprocess.run(["devtunnel", *args], capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def logged_in_user():
    code, out = devtunnel("user", "show")
    m = re.search(r"Logged in as (\S+)", out)
    return m.group(1) if code == 0 and m else None


def forget_login():
    """Signs out and drops the cached tokens, so the next login asks for an account instead of reusing the last one."""
    devtunnel("user", "logout")
    if os.path.isdir(TOKEN_DIR):
        for name in os.listdir(TOKEN_DIR):
            if name.startswith("devtunnels-tokens"):
                os.remove(os.path.join(TOKEN_DIR, name))


def login(provider="microsoft"):
    """Device-code login with the chosen provider, from a clean cache: the page shows the link and the code; this waits
    for the person to finish."""
    global login_process
    set_state(phase="login-pending", login=None, error=None, user=None, url=None, pageUrl=None)
    stop_host()
    forget_login()
    p = login_process = subprocess.Popen(["devtunnel", "user", "login", "-d", PROVIDERS[provider]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in p.stdout:
        m = DEVICE.search(line)
        if m:
            set_state(login={"url": m.group("url"), "code": m.group("code")})
    p.wait()
    if p is not login_process:
        return  # replaced by a newer login: that one owns the state
    user = logged_in_user()
    if user:
        set_state(phase="logged-in", user=user, login=None)
        start_tunnel()
    else:
        set_state(phase="logged-out", login=None, error="accesso non completato: riprova")


def id_file(user):
    return os.path.join(ID_DIR, re.sub(r"[^A-Za-z0-9@._-]", "_", user or "unknown"))


def ensure_tunnel(user):
    """The account's tunnel for this lab, created once: anonymous access, 30 days of inactivity before it expires."""
    os.makedirs(ID_DIR, exist_ok=True)
    if os.path.exists(LEGACY_ID_FILE):
        if not os.listdir(ID_DIR):
            os.replace(LEGACY_ID_FILE, id_file(user))  # the single id of earlier versions: it was this login's
        else:
            os.remove(LEGACY_ID_FILE)
    ID_FILE = id_file(user)
    tunnel_id = open(ID_FILE).read().strip() if os.path.exists(ID_FILE) else None
    if tunnel_id and devtunnel("show", tunnel_id)[0] != 0:
        tunnel_id = None  # expired or deleted: a new one, with a new address
    if not tunnel_id:
        code, out = devtunnel("create", "-a", "-e", "30d", "-d", "XRCopilotLab intrusion lab", "-j")
        if code != 0:
            raise RuntimeError(out.strip().splitlines()[-1] if out.strip() else "devtunnel create failed")
        m = re.search(r'"tunnelId"\s*:\s*"([^"]+)"', out)
        if not m:
            raise RuntimeError("devtunnel create: tunnel id not found in the answer")
        tunnel_id = m.group(1)
        with open(ID_FILE, "w") as f:
            f.write(tunnel_id)
    for port in (PORT, PAGE_PORT):
        devtunnel("port", "create", tunnel_id, "-p", str(port), "--protocol", "http")  # already there: harmless error
    # Access, rewritten on every start (a tunnel made before the page port was anonymous for every port): anonymous on
    # the API port only; the page's port is left to the owner, plus the owner's Entra tenant (fails harmlessly for a
    # Microsoft or GitHub account, which has no tenant: then the owner alone).
    for port in (None, PORT, PAGE_PORT):
        devtunnel("access", "reset", tunnel_id, *(["-p", str(port)] if port else []))
    code, out = devtunnel("access", "create", tunnel_id, "-p", str(PORT), "-a")
    if code != 0:
        raise RuntimeError("devtunnel access: " + (out.strip().splitlines()[-1] if out.strip() else "failed"))
    devtunnel("access", "create", tunnel_id, "-p", str(PAGE_PORT), "--tenant")
    return tunnel_id


def start_tunnel():
    global host_process
    try:
        set_state(phase="tunnel-starting", error=None)
        tunnel_id = ensure_tunnel(state["user"])
        set_state(tunnelId=tunnel_id)
        host_process = subprocess.Popen(["devtunnel", "host", tunnel_id], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        threading.Thread(target=watch_host, args=(host_process,), daemon=True).start()
    except Exception as ex:  # shown in the console, never swallowed
        set_state(phase="error", error=str(ex))


def watch_host(p):
    last = []
    for line in p.stdout:
        last = (last + [line.strip()])[-5:]
        m = WEB_URL.search(line)
        if m:
            url = m.group(0).rstrip("/")
            set_state(phase="online", url=url, pageUrl=url.replace(f"-{PORT}.", f"-{PAGE_PORT}.", 1), since=time.strftime("%H:%M:%S"))
    p.wait()
    if p is host_process:  # not stopped on purpose (restart, logout, another account)
        set_state(phase="error", url=None, pageUrl=None, error="il tunnel si è chiuso: " + " ".join(last[-2:]))


def stop_host():
    global host_process
    if host_process and host_process.poll() is None:
        host_process.terminate()
    host_process = None


def logout():
    stop_host()
    forget_login()
    set_state(phase="logged-out", user=None, url=None, pageUrl=None, tunnelId=None, login=None, error=None)


def write_server_location():
    """lab-01 is isolated; this container has internet. Geolocate our own public IP (the machine running the lab) and
    write it to the shared volume, so the toolkit places the server on the map the same way a real one does from its IP.
    ipapi.co/json returns the caller's own location directly, so no geo database is needed for the marker."""
    import urllib.request
    services = ["https://ipwho.is/", "https://ipapi.co/json/"]
    while True:
        loc = None
        for url in services:
            try:
                with urllib.request.urlopen(url, timeout=8) as r:
                    d = json.loads(r.read())
                if d.get("success") is False or d.get("error") or d.get("status") == "fail":
                    continue
                lat = d.get("latitude", d.get("lat"))
                if lat is None:
                    continue
                loc = {"latitude": lat, "longitude": d.get("longitude", d.get("lon")),
                       "city": d.get("city") or d.get("cityName"),
                       "country": d.get("country_name") or d.get("country") or d.get("countryName")}
                break
            except Exception as ex:
                print(f"location service {url} failed:", ex)
        if loc:
            try:
                os.makedirs(os.path.dirname(LOCATION_FILE), exist_ok=True)
                with open(LOCATION_FILE + ".tmp", "w") as f:
                    json.dump(loc, f)
                os.chmod(LOCATION_FILE + ".tmp", 0o644)
                os.replace(LOCATION_FILE + ".tmp", LOCATION_FILE)
            except OSError as ex:
                print("cannot write the location file:", ex)
        time.sleep(1800)


def boot():
    threading.Thread(target=write_server_location, daemon=True).start()
    # lab-01's ports, reachable through this container's localhost: devtunnel hosts local ports only.
    subprocess.Popen(["socat", f"TCP-LISTEN:{PORT},fork,reuseaddr", f"TCP:{LAB_API}"])
    subprocess.Popen(["socat", f"TCP-LISTEN:{PAGE_PORT},fork,reuseaddr", f"TCP:{LAB_PAGE}"])
    # Local access to lab-01's page (localhost:8089 → lab-01:8093): lab-01 itself publishes nothing.
    subprocess.Popen(["socat", f"TCP-LISTEN:{LOCAL_PAGE_PORT},fork,reuseaddr", f"TCP:{LAB_PAGE}"])
    if DOMAIN:
        page = f"https://{DOMAIN}" + ("" if PAGE_PUBLIC_PORT in ("", "443") else f":{PAGE_PUBLIC_PORT}")
        set_state(phase="domain", url=f"https://{DOMAIN}", pageUrl=page, since=time.strftime("%H:%M:%S"))
        return
    user = logged_in_user()
    if user:
        set_state(phase="logged-in", user=user)
        start_tunnel()
    else:
        set_state(phase="logged-out")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status, body):
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _check(self):
        """Calls the package through the public address, as XRCopilotLab will: proves the whole path works."""
        with lock:
            url = state["url"] if state["phase"] == "online" else None
        if not url:
            return self._send(200, {"ok": False, "error": "il tunnel non è aperto"})
        import urllib.request, urllib.error
        try:
            req = urllib.request.Request(url + "/api/status", headers={"X-API-Key": LAB_API_KEY})
            with urllib.request.urlopen(req, timeout=30) as resp:
                status = json.loads(resp.read())
            return self._send(200, {"ok": True, "host": status.get("host"),
                                    "detectors": [d["detector"] for d in status.get("detectors", [])]})
        except urllib.error.HTTPError as ex:
            return self._send(200, {"ok": False, "error": f"risposta {ex.code} dall'indirizzo pubblico"})
        except OSError as ex:
            return self._send(200, {"ok": False, "error": f"indirizzo pubblico non raggiungibile: {ex}"})

    def do_GET(self):
        if self.path == "/status":
            with lock:
                return self._send(200, dict(state))
        if self.path == "/key":
            # The test key, for lab-01's page to show and copy (test mode only). Reachable through lab-01's own nginx,
            # which only the page's visitors reach; a real server has no tunnel container and keeps only the hash.
            return self._send(200, {"key": LAB_API_KEY})
        if self.path == "/check":
            return self._check()
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if DOMAIN:
            return self._send(409, {"error": "il laboratorio usa il dominio " + DOMAIN + ": nessun tunnel"})
        path, _, query = self.path.partition("?")
        if path == "/login":
            provider = urllib.parse.parse_qs(query).get("provider", ["microsoft"])[0]
            if provider not in PROVIDERS:
                return self._send(400, {"error": "provider: microsoft o github"})
            if state["phase"] == "login-pending" and state["login"] is None:
                return self._send(409, {"error": "accesso già in corso"})
            # A code already shown can be replaced (another account or provider): the waiting login is dropped.
            if login_process and login_process.poll() is None:
                login_process.terminate()
            threading.Thread(target=login, args=(provider,), daemon=True).start()
            return self._send(202, {"phase": "login-pending"})
        if path == "/logout":
            logout()
            return self._send(200, {"phase": "logged-out"})
        if path == "/restart":
            stop_host()
            threading.Thread(target=start_tunnel, daemon=True).start()
            return self._send(202, {"phase": "tunnel-starting"})
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    threading.Thread(target=boot, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8092), Handler).serve_forever()
