#!/usr/bin/env python3
"""Minimal reverse proxy emulating the API-gateway routing of a Supabase stack.

Supabase clients call ``{SUPABASE_URL}/rest/v1/...``; in a real stack Kong
strips the prefix and forwards to PostgREST. This does only that, so the
no-Docker stack (scripts/no_docker_stack.sh) presents the same URL shape as
``supabase start``. Stdlib only; never used in production.
"""

import http.client
import http.server
import os

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = int(os.environ.get("PROXY_PORT", "54321"))
UPSTREAM_HOST = os.environ.get("PGRST_HOST", "127.0.0.1")
UPSTREAM_PORT = int(os.environ.get("PGRST_PORT", "3001"))
PREFIX = "/rest/v1"

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}


class PrefixStrippingHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _upstream_path(self) -> str:
        path = self.path
        if path == PREFIX or path == PREFIX + "/":
            return "/"
        if path.startswith(PREFIX + "/"):
            return path[len(PREFIX) :]
        if path.startswith(PREFIX + "?"):
            return "/" + path[len(PREFIX) :]
        return path

    def _forward(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}

        upstream = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=30)
        try:
            upstream.request(self.command, self._upstream_path(), body=body, headers=headers)
            response = upstream.getresponse()
            payload = response.read()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() in HOP_BY_HOP or key.lower() == "content-length":
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        finally:
            upstream.close()

    do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = _forward

    def log_message(self, *_args) -> None:  # keep test output clean
        pass


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), PrefixStrippingHandler)
    print(f"rest_prefix_proxy: {LISTEN_HOST}:{LISTEN_PORT} -> {UPSTREAM_HOST}:{UPSTREAM_PORT}")
    server.serve_forever()
