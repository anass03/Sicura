#!/usr/bin/env python3
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
            ["docker", "ps", "--format", "{{.Names}}"], text=True, timeout=TIMEOUT
        )
    except subprocess.CalledProcessError:
        return None
    except FileNotFoundError:
        return None
    for line in out.splitlines():
        if "_ctrl_" in line:
            return line.strip()
    return None


def call_inside_ctrl(container, method, path, body):
    """
    Execs a tiny Python snippet inside the ctrl container to reach Ryu via urllib.
    Returns (status_code, response_bytes) or (None, error_message_bytes).
    """
    url = f"http://127.0.0.1:{CTRL_PORT}{path}"
    env_body = body.decode() if body else ""
    cmd = [
        "docker",
        "exec",
        "-e",
        f"RYU_PROXY_BODY={env_body}",
        "-i",
        container,
        "python",
        "-",
        method,
        url,
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=INNER_SCRIPT.encode(),
            capture_output=True,
            timeout=TIMEOUT,
        )
    except FileNotFoundError:
        return None, b"docker non trovato: installalo e avvia il lab"
    except subprocess.TimeoutExpired:
        return None, b"timeout contattando il container ctrl"

    if proc.returncode != 0:
        # stderr likely has the message
        err = proc.stderr if proc.stderr else proc.stdout
        return None, err or b"errore sconosciuto dal container ctrl"

    # The inner script prints status code in first line, then raw body.
    lines = proc.stdout.split(b"\n", 1)
    if not lines:
        return None, b"risposta vuota dal container ctrl"
    try:
        status_code = int(lines[0].decode().strip())
    except ValueError:
        return None, proc.stdout
    body_bytes = lines[1] if len(lines) > 1 else b""
    return status_code, body_bytes


INNER_SCRIPT = r"""
import sys
import urllib.request
import os

method = sys.argv[1]
url = sys.argv[2]
data = os.environ.get("RYU_PROXY_BODY", "").encode()
if not data:
    data = None

req = urllib.request.Request(url, data=data, method=method)
req.add_header("Content-Type", "application/json")

try:
    with urllib.request.urlopen(req, timeout=6) as resp:
        sys.stdout.write(str(resp.getcode()) + "\n")
        sys.stdout.buffer.write(resp.read())
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
"""


class ProxyHandler(BaseHTTPRequestHandler):
    def _proxy(self, method):
        path = self.path
        # Only allow the firewall API paths
        if not path.startswith("/api/firewall/"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error":"Not found"}')
            return

        container = find_ctrl_container()
        if not container:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(
                b'{"error":"Container ctrl non trovato. Avvia la lab con kathara lstart."}'
            )
            return

        body = b""
        if method in ("POST", "PUT", "PATCH"):
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                body = self.rfile.read(length)

        status_code, resp_body = call_inside_ctrl(container, method, path, body)
        if status_code is None:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {"error": "Impossibile contattare Ryu nel container", "details": resp_body.decode(errors="ignore")}
                ).encode()
            )
            return

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(resp_body)

    def do_GET(self):
        self._proxy("GET")

    def do_POST(self):
        self._proxy("POST")

    def log_message(self, fmt, *args):
        # quieter
        return


def main():
    # Pre-load ctrl detection to fail fast with a clear message.
    if not find_ctrl_container():
        print("Container ctrl non trovato. Avvia prima il lab (kathara lstart).")
        return 1
    server = socketserver.ThreadingTCPServer((HOST, PORT), ProxyHandler)
    print(f"Host proxy Ryu in ascolto su http://{HOST}:{PORT}/api/firewall/*")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArresto proxy")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
