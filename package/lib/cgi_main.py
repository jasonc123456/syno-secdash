"""CGI entry point, exec'd by ui/api.cgi after the DSM admin check passed."""
import json
import os
import sqlite3
import sys
from urllib.parse import parse_qsl

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import api  # noqa: E402

PKG = os.path.normpath(os.path.join(HERE, ".."))
VAR = os.environ.get("SECDASH_VAR", "/var/packages/SecDash/var")
DB = os.path.join(VAR, "secdash.db")


def respond(code, body):
    reason = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
              500: "Internal Server Error", 502: "Bad Gateway",
              503: "Service Unavailable"}.get(code, "")
    out = json.dumps(body, separators=(",", ":")).encode("utf-8")
    sys.stdout.write("Status: %d %s\r\nContent-Type: application/json\r\n"
                     "Cache-Control: no-store\r\nContent-Length: %d\r\n\r\n"
                     % (code, reason, len(out)))
    sys.stdout.flush()
    sys.stdout.buffer.write(out)
    sys.stdout.flush()


def main():
    params = dict(parse_qsl(os.environ.get("QUERY_STRING", ""), keep_blank_values=False))
    params.pop("SynoToken", None)
    if not os.path.exists(DB):
        respond(503, {"error": "no data yet: the collector task has not delivered a batch"})
        return
    # Reads use a read-only connection. Only the few settings/prune endpoints get a
    # writable one, and only for POST (api.cgi requires a page-supplied SynoToken).
    write = os.environ.get("REQUEST_METHOD") == "POST" and params.get("q") in api.WRITE_ENDPOINTS
    try:
        if write:
            con = sqlite3.connect(DB, timeout=15)
        else:
            con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("SELECT 1 FROM meta LIMIT 1")
    except sqlite3.Error as e:
        respond(500, {"error": "cannot open database as uid %d: %s" % (os.getuid(), e)})
        return
    try:
        code, body = api.handle(con, params, pkg_dir=PKG, db_path=DB, write=write)
    except sqlite3.OperationalError as e:
        code, body = 500, {"error": "database error as uid %d: %s" % (os.getuid(), e)}
    except Exception as e:  # keep the UI informative instead of a bare 500 page
        code, body = 500, {"error": "%s: %s" % (type(e).__name__, e)}
    finally:
        con.close()
    respond(code, body)


if __name__ == "__main__":
    main()
