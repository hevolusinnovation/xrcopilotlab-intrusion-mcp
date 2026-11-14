"""The lab console: the attack buttons, on http://localhost:8090. What the intrusion package sees (map and attacks) is
lab-01's own monitoring page, opened through the Dev Tunnel (Microsoft login).

By default the target is lab-01.

A different server running the package can be tested instead ("Server da testare"): you give its API address and its
API key, and the console attacks it only after GET {url}/status answers 200 with that key. The key is proof that you
administer that server (only its owner has it): the console refuses to attack a server you cannot already read. Against
an external server only the web-layer scenarios run, from this container's own address.
"""
import json
import os
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

import scenarios

LAB_API = f"http://{os.environ.get('TARGET_IT', '198.51.100.20')}/intrusion-mcp/api/"
KEY = os.environ["LAB_API_KEY"]
STATIC = Path(__file__).parent / "static"
TUNNEL = os.environ.get("TUNNEL_CONTROLLER", "http://tunnel:8092")
runner = scenarios.Runner()
scenarios.start_c2()

# The server under test. None = lab-01 (the default). Otherwise {"api": base, "key": key, "host": hostname, "web": host}
# after its key has been verified. Guarded by a lock: the HTTP server is threaded.
_target_lock = threading.Lock()
external = None


def current_target():
    with _target_lock:
        if external is None:
            return {"mode": "lab", "api": LAB_API, "key": KEY}
        return {"mode": "external", **external}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status, body, content_type="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path in ("/", "/index.html"):
            return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
        if url.path == "/api/scenarios":
            return self._send(200, scenarios.describe())
        if url.path == "/api/runs":
            return self._send(200, {"current": runner.current["id"] if runner.current else None, "runs": runner.runs[::-1]})
        if url.path == "/api/tunnel/status":
            return self._forward(TUNNEL + "/status", "GET")
        if url.path == "/api/tunnel/key":
            # The console is published on the Mac's localhost only: the key goes to the person who copies it into
            # the XRCopilotLab connection, and nowhere else.
            return self._send(200, {"key": KEY})
        if url.path == "/api/tunnel/check":
            return self._check_tunnel()
        if url.path == "/api/target":
            t = current_target()
            return self._send(200, {"mode": t["mode"], "host": t.get("host"), "api": None if t["mode"] == "lab" else t["api"]})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        parts = urllib.parse.urlsplit(self.path).path.strip("/").split("/")
        if len(parts) == 4 and parts[:2] == ["api", "scenarios"] and parts[3] == "run":
            run, error = runner.start(parts[2], current_target())
            return self._send(202, run) if run else self._send(409, {"error": error})
        if len(parts) == 3 and parts[:2] == ["api", "tunnel"] and parts[2] in ("login", "logout", "restart"):
            query = urllib.parse.urlsplit(self.path).query  # login?provider=microsoft|github
            return self._forward(f"{TUNNEL}/{parts[2]}" + (f"?{query}" if query else ""), "POST")
        if url_path(self.path) == "/api/target":
            return self._set_target()
        if url_path(self.path) == "/api/target/clear":
            global external
            with _target_lock:
                external = None
            return self._send(200, {"mode": "lab"})
        return self._send(404, {"error": "not found"})

    def _set_target(self):
        """Arms an external server, after its key proves the caller may read (and so may test) it."""
        global external
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._send(400, {"error": "richiesta non valida"})
        raw, key = str(body.get("url", "")).strip(), str(body.get("key", "")).strip()
        if not raw or not key:
            return self._send(400, {"error": "servono l'indirizzo e la chiave del server"})
        # Any of the addresses the page shows works: the server's base, its …/api or its …/mcp (listed first).
        base = re.sub(r"/(api|mcp)$", "", raw.rstrip("/")) + "/api"
        parsed = urllib.parse.urlsplit(base)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return self._send(400, {"error": "l'indirizzo deve essere http(s)://…"})
        try:
            request = urllib.request.Request(base + "/status", headers={"X-API-Key": key})
            with urllib.request.urlopen(request, timeout=15) as response:
                status = json.loads(response.read())
        except urllib.error.HTTPError as ex:
            msg = "chiave rifiutata dal server" if ex.code in (401, 403) else f"il server risponde {ex.code}"
            return self._send(400, {"error": msg})
        except json.JSONDecodeError:
            return self._send(400, {"error": "a questo indirizzo non risponde l'API del toolkit: usa l'indirizzo MCP o API "
                                             "(nel Dev Tunnel quello con -8091, non la pagina di monitoraggio -8093)"})
        except OSError as ex:
            return self._send(400, {"error": f"il server non risponde: {ex}"})
        with _target_lock:
            external = {"api": base + "/", "key": key, "host": status.get("host", parsed.hostname), "web": parsed.hostname}
        return self._send(200, {"mode": "external", "host": status.get("host"),
                                "detectors": [d["detector"] for d in status.get("detectors", [])]})

    def _forward(self, target, method):
        request = urllib.request.Request(target, method=method, data=b"" if method == "POST" else None)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return self._send(response.status, response.read())
        except urllib.error.HTTPError as ex:
            return self._send(ex.code, ex.read() or {"error": f"tunnel answered {ex.code}"})
        except OSError as ex:
            return self._send(502, {"error": f"tunnel unreachable: {ex}"})

    def _check_tunnel(self):
        """Calls the package through the public address, as XRCopilotLab will: proves the whole path works."""
        try:
            with urllib.request.urlopen(TUNNEL + "/status", timeout=10) as response:
                url = json.loads(response.read()).get("url")
            if not url:
                return self._send(409, {"ok": False, "error": "il tunnel non è aperto"})
            request = urllib.request.Request(url + "/api/status", headers={"X-API-Key": KEY})
            with urllib.request.urlopen(request, timeout=30) as response:
                status = json.loads(response.read())
            return self._send(200, {"ok": True, "host": status.get("host"), "detectors": [d["detector"] for d in status.get("detectors", [])]})
        except urllib.error.HTTPError as ex:
            return self._send(200, {"ok": False, "error": f"risposta {ex.code} dall'indirizzo pubblico"})
        except OSError as ex:
            return self._send(200, {"ok": False, "error": f"indirizzo pubblico non raggiungibile: {ex}"})


def url_path(path):
    return urllib.parse.urlsplit(path).path


if __name__ == "__main__":
    print("console on :8090, default target", LAB_API)
    ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
