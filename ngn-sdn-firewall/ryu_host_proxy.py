#!/usr/bin/env python3
"""
ryu_host_proxy.py – Proxy HTTP sull'host.
Inoltra /api/firewall/* al controller Ryu nel container Docker.
"""

import json
import socketserver
import subprocess
import sys
from http.server import BaseHTTPRequestHandler

HOST = "127.0.0.1"
PORT = 18080
CTRL_PORT = 8080
TIMEOUT = 8


def find_ctrl_container():
    try:
        out = subprocess.check_output(
            ["docker", "ps", "--format", "{{.Names}}"],
            text=True, timeout=TIMEOUT)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    for line in out.splitlines():
        if "_ctrl_" in line:
            return line.strip()
    return None


def call_inside_ctrl(container, method, path, body):
    url = f"http://127.0.0.1:{CTRL_PORT}{path}"
    env_body = body.decode() if body else ""
    cmd = ["docker", "exec", "-e", f"RYU_PROXY_BODY={env_body}",
           "-i", container, "python", "-", method, url]
    try:
        proc = subprocess.run(cmd, input=INNER_SCRIPT.encode(),
                              capture_output=True, timeout=TIMEOUT)
    except FileNotFoundError:
        return None, b"docker non trovato"
    except subprocess.TimeoutExpired:
        return None, b"timeout"
    if proc.returncode != 0:
        return None, proc.stderr or proc.stdout or b"errore"
    lines = proc.stdout.split(b"\n", 1)
    if not lines:
        return None, b"risposta vuota"
    try:
        status = int(lines[0].decode().strip())
    except ValueError:
        return None, proc.stdout
    body_bytes = lines[1] if len(lines) > 1 else b""
    return status, body_bytes


INNER_SCRIPT = r"""
import sys, os, urllib.request
method, url = sys.argv[1], sys.argv[2]
data = os.environ.get("RYU_PROXY_BODY", "").encode() or None
req = urllib.request.Request(url, data=data, method=method)
req.add_header("Content-Type", "application/json")
try:
    with urllib.request.urlopen(req, timeout=6) as resp:
        sys.stdout.write(str(resp.getcode()) + "\n")
        sys.stdout.buffer.write(resp.read())
except Exception as e:
    sys.stderr.write(str(e)); sys.exit(1)
"""


class ProxyHandler(BaseHTTPRequestHandler):
    def _proxy(self, method):
        if not self.path.startswith("/api/firewall/"):
            self.send_response(404); self.end_headers()
            self.wfile.write(b'{"error":"Not found"}'); return
        container = find_ctrl_container()
        if not container:
            self.send_response(502); self.end_headers()
            self.wfile.write(b'{"error":"Container ctrl non trovato"}'); return
        body = b""
        if method in ("POST", "PUT", "PATCH"):
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                body = self.rfile.read(length)
        status, resp = call_inside_ctrl(container, method, self.path, body)
        if status is None:
            self.send_response(502); self.end_headers()
            self.wfile.write(json.dumps({"error": resp.decode(errors="ignore")}).encode())
            return
        self.send_response(status)
        self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(resp)

    def do_GET(self): self._proxy("GET")
    def do_POST(self): self._proxy("POST")
    def log_message(self, fmt, *args): return


def main():
    if not find_ctrl_container():
        print("Container ctrl non trovato. Avvia il lab.")
        return 1
    server = socketserver.ThreadingTCPServer((HOST, PORT), ProxyHandler)
    print(f"Proxy in ascolto su http://{HOST}:{PORT}/api/firewall/*")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStop")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
