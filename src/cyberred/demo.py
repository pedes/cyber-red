"""A tiny, deliberately misconfigured web app bound to 127.0.0.1 for demos and tests.

Nothing here is a real vulnerability: it *simulates* common weaknesses with static responses so CyberRed's
checks have something to find without needing Docker or an external lab.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

INDEX = """<!doctype html><html><head><title>Acme Intranet (demo)</title>
<meta name="generator" content="WordPress 5.0"></head><body>
<!-- TODO: remove admin password from this page before launch -->
<h1>Acme Intranet</h1>
<a href="/search?q=hello">Search</a> · <a href="/item?id=1">Item</a> · <a href="/about">About</a>
<form method="post" action="/login"><input name="username"><input type="password" name="password"></form>
</body></html>"""


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49 (Unix)"
    sys_version = ""

    def log_message(self, *a: object) -> None:  # silence
        pass

    def _send(self, body: str, status: int = 200, ctype: str = "text/html", extra: dict[str, str] | None = None) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "PHP/7.2.34")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send("", 200, extra={"Allow": "GET, POST, OPTIONS, PUT, DELETE"})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        self._send("<html><body>invalid credentials</body></html>", 200)

    def do_GET(self) -> None:  # noqa: N802
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        origin = self.headers.get("Origin")
        cors = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"} if origin else {}
        if u.path == "/":
            self._send(INDEX, extra={**cors, "Set-Cookie": "PHPSESSID=abc123; Path=/"})
        elif u.path == "/robots.txt":
            self._send("User-agent: *\nDisallow: /admin-panel/\nDisallow: /internal/\n", ctype="text/plain")
        elif u.path == "/.git/HEAD":
            self._send("ref: refs/heads/main\n", ctype="text/plain")
        elif u.path == "/.env":
            self._send("DB_HOST=localhost\nDB_PASSWORD=hunter2-demo\nAPI_KEY=demo-not-a-real-key\n", ctype="text/plain")
        elif u.path == "/search":
            term = q.get("q", [""])[0]
            self._send(f"<html><body><h2>Results for {term}</h2></body></html>")
        elif u.path == "/item":
            raw = q.get("id", ["1"])[0]
            if "'" in raw:
                self._send("<html><body>You have an error in your SQL syntax; check the manual near ''' at line 1</body></html>", 500)
            else:
                self._send(f"<html><body>Item {raw}</body></html>")
        elif u.path == "/redirect-out":  # points at TEST-NET-3 (RFC 5737, never routable) to exercise the redirect guard
            self.send_response(302)
            self.send_header("Location", "http://203.0.113.9/landing")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif u.path == "/about":
            self._send("<html><head><title>About</title></head><body><a href='/'>home</a></body></html>")
        else:
            self._send("<html><body>not found</body></html>", 404)


@contextmanager
def demo_server() -> Iterator[int]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
