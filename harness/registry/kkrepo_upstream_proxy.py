"""Loopback-only path adapter for kkRepo's Docker Hub proxy repository.

The existing Registry remains the shared pull-through cache. Its upstream is
this adapter; sandbox image references stay unchanged.
"""
from __future__ import annotations

import argparse
import http.client
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
})


class KkRepoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write(f"[kkrepo-upstream] {fmt % args}\n")
        sys.stderr.flush()

    def do_GET(self) -> None:
        self.forward("GET")

    def do_HEAD(self) -> None:
        self.forward("HEAD")

    def forward(self, method: str) -> None:
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path = self.path
        if path.startswith("/v2/") and not path.startswith("/v2/docker-hub/"):
            path = "/v2/docker-hub/" + path[len("/v2/"):]
        headers = {key: value for key, value in self.headers.items()
                   if key.lower() not in HOP_HEADERS}
        connection = http.client.HTTPConnection("100.102.49.114", 19091, timeout=300)
        try:
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() in HOP_HEADERS:
                    continue
                if key.lower() == "location" and value.startswith("/v2/docker-hub/"):
                    value = "/v2/" + value[len("/v2/docker-hub/"):]
                self.send_header(key, value)
            self.end_headers()
            if method == "GET":
                while chunk := response.read(1024 * 1024):
                    self.wfile.write(chunk)
        except (OSError, http.client.HTTPException) as exc:
            if not self.wfile.closed:
                try:
                    self.send_error(502, f"kkRepo upstream failed: {exc}")
                except (BrokenPipeError, ConnectionResetError):
                    pass
        finally:
            connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5001)
    args = parser.parse_args()
    if args.listen != "127.0.0.1":
        parser.error("kkRepo adapter must only listen on loopback")
    server = ThreadingHTTPServer((args.listen, args.port), KkRepoHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
