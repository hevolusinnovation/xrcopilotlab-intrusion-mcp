"""The lab console: the attack buttons and what lab-01's intrusion package sees, on http://localhost:8090.

The package's API is read through lab-01's nginx (/intrusion-mcp/), as XRCopilotLab would read it at a customer's,
with the lab key added here: the browser never sees it. Only GET is forwarded, only to the package's read routes.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

import scenarios

API = f"http://{os.environ.get('TARGET_IT', '198.51.100.20')}/intrusion-mcp/api/"
KEY = os.environ["LAB_API_KEY"]
STATIC = Path(__file__).parent / "static"
READ_ROUTES = {"status", "summary", "banned", "suspicious-logins", "attempts"}
runner = scenarios.Runner()


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
        if url.path.startswith("/api/lab/"):
            route = url.path[len("/api/lab/"):]
            if route not in READ_ROUTES:
                return self._send(404, {"error": "unknown route"})
            return self._proxy(route, url.query)
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        parts = urllib.parse.urlsplit(self.path).path.strip("/").split("/")
        if len(parts) == 4 and parts[:2] == ["api", "scenarios"] and parts[3] == "run":
            run, error = runner.start(parts[2])
            return self._send(202, run) if run else self._send(409, {"error": error})
        return self._send(404, {"error": "not found"})

    def _proxy(self, route, query):
        request = urllib.request.Request(API + route + (f"?{query}" if query else ""), headers={"X-API-Key": KEY})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return self._send(response.status, response.read())
        except urllib.error.HTTPError as ex:
            return self._send(ex.code, {"error": f"lab-01 answered {ex.code}"})
        except OSError as ex:
            return self._send(502, {"error": f"lab-01 unreachable: {ex}"})


if __name__ == "__main__":
    print("console on :8090, package API at", API)
    ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
