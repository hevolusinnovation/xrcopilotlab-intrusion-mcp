"""The lab's public address: Microsoft Dev Tunnels, driven from the console.

- Login with a device code (Entra ID / Microsoft account): the console shows the link and the code.
- Once logged in: a persistent tunnel with anonymous access (XRCopilotLab cannot log in to Dev Tunnels; the package's
  X-API-Key still guards every call), port 8091, hosted here. socat forwards that port to lab-01's API-only port.
- The tunnel id and the login live in /root (a volume): the address stays the same across restarts, until the tunnel
  is unused for 30 days.

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
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

PORT = 8091
LAB_API = os.environ.get("LAB_API", "10.77.0.20:8091")
ID_FILE = "/root/tunnel-id"
URL_FILE = os.environ.get("TUNNEL_URL_FILE", "/state/url")
DEVICE = re.compile(r"open the page (?P<url>https://\S+) and enter the code (?P<code>[A-Z0-9-]+)")
WEB_URL = re.compile(r"https://\S+?-%d\.\S+?devtunnels\.ms\S*" % PORT)

state = {"phase": "starting", "user": None, "login": None, "url": None, "tunnelId": None, "error": None, "since": None}
lock = threading.Lock()
host_process = None


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


def login():
    """Device-code login: the console shows the link and the code; this waits for the person to finish."""
    set_state(phase="login-pending", login=None, error=None)
    p = subprocess.Popen(["devtunnel", "user", "login", "-d", "-e"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in p.stdout:
        m = DEVICE.search(line)
        if m:
            set_state(login={"url": m.group("url"), "code": m.group("code")})
    p.wait()
    user = logged_in_user()
    if user:
        set_state(phase="logged-in", user=user, login=None)
        start_tunnel()
    else:
        set_state(phase="logged-out", login=None, error="accesso non completato: riprova")


def ensure_tunnel():
    """The tunnel of this lab, created once: anonymous access, 30 days of inactivity before it expires."""
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
    devtunnel("port", "create", tunnel_id, "-p", str(PORT), "--protocol", "http")  # already there: harmless error
    return tunnel_id


def start_tunnel():
    global host_process
    try:
        set_state(phase="tunnel-starting", error=None)
        tunnel_id = ensure_tunnel()
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
            set_state(phase="online", url=m.group(0).rstrip("/"), since=time.strftime("%H:%M:%S"))
    p.wait()
    if state["phase"] != "logged-out":
        set_state(phase="error", url=None, error="il tunnel si è chiuso: " + " ".join(last[-2:]))


def stop_host():
    global host_process
    if host_process and host_process.poll() is None:
        host_process.terminate()
    host_process = None


def logout():
    stop_host()
    devtunnel("user", "logout")
    set_state(phase="logged-out", user=None, url=None, login=None, error=None)


def boot():
    # lab-01's API port, reachable through this container's localhost: devtunnel hosts local ports only.
    subprocess.Popen(["socat", f"TCP-LISTEN:{PORT},fork,reuseaddr", f"TCP:{LAB_API}"])
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

    def do_GET(self):
        if self.path == "/status":
            with lock:
                return self._send(200, dict(state))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/login":
            if state["phase"] == "login-pending":
                return self._send(409, {"error": "accesso già in corso"})
            threading.Thread(target=login, daemon=True).start()
            return self._send(202, {"phase": "login-pending"})
        if self.path == "/logout":
            logout()
            return self._send(200, {"phase": "logged-out"})
        if self.path == "/restart":
            stop_host()
            threading.Thread(target=start_tunnel, daemon=True).start()
            return self._send(202, {"phase": "tunnel-starting"})
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    threading.Thread(target=boot, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8092), Handler).serve_forever()
