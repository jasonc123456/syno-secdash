#!/usr/bin/env python3
"""Local dev server: the real UI + API against dev/demo.db, DSM auth bypassed.

    python3 dev/seed.py && python3 dev/serve.py   # http://127.0.0.1:8765/
"""
import argparse
import json
import os
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "package", "lib"))
import api  # noqa: E402
import store  # noqa: E402

UI = os.path.join(ROOT, "package", "ui")
PREFIX = "/webman/3rdparty/SecDash/"


class Handler(SimpleHTTPRequestHandler):
    db = None

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=UI, **kw)

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path in ("/", "/index.html"):
            self.send_response(302)
            self.send_header("Location", PREFIX + "index.html")
            self.end_headers()
            return
        if not url.path.startswith(PREFIX):
            self.send_error(404)
            return
        if url.path == PREFIX + "api.cgi":
            con = store.connect(self.db, readonly=True)
            try:
                code, body = api.handle(con, dict(parse_qsl(url.query)),
                                        pkg_dir=os.path.join(ROOT, "package"), db_path=self.db)
            finally:
                con.close()
            out = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return
        self.path = "/" + url.path[len(PREFIX):]
        super().do_GET()

    def log_message(self, fmt, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=os.path.join(ROOT, "dev", "demo.db"))
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    if not os.path.exists(a.db):
        sys.exit("%s not found: run python3 dev/seed.py first" % a.db)
    Handler.db = a.db
    print("SecDash dev server on http://%s:%d/  (db: %s)" % (a.host, a.port, a.db))
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
