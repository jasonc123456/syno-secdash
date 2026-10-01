"""DSM 7.3 log layouts, taken from a real NAS (IPs replaced with documentation ranges)."""
import os
import shutil
import sqlite3
import tempfile
import time
import unittest
from unittest import mock

from tests.helpers import make_autoblock_db

import api
import common
import ingest_connlog
import ingest_syslog
import secdashd
import store

PAM_NO_USER = ("2026-10-01T13:50:28-07:00 nas synoscgi_SYNO.API.Auth_6_login[30930]:"
               " pam_unix(webui:auth): authentication failure; logname= uid=0 euid=0 tty="
               " ruser= rhost=203.0.113.50")
PAM_USER = ("2026-10-01T13:51:06-07:00 nas synoscgi_SYNO.API.Auth_6_login[32050]:"
            " pam_unix(webui:auth): authentication failure; logname= uid=0 euid=0 tty="
            " ruser= rhost=203.0.113.51  user=postgres")


def make_connlog73(path, rows):
    """rows: (time, msg, user, ip, protocol). The DSM 7.3 .SYNOCONNDB layout."""
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE logs(id INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER,"
                " level TEXT, username TEXT, msg TEXT, user TEXT, uid TEXT, ip TEXT,"
                " protocol TEXT, token TEXT, useragent TEXT)")
    con.executemany("INSERT INTO logs(time, level, username, msg, user, uid, ip, protocol,"
                    " token, useragent) VALUES (?, 'info', ?, ?, ?, '1026', ?, ?, '', '')",
                    [(t, u, m, u, ip, proto) for t, m, u, ip, proto in rows])
    con.commit()
    con.close()


def make_sysdb(path, rows):
    """rows: (id, time, msg). What the collector extracts from .SYNOSYSDB."""
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE logs(id INTEGER PRIMARY KEY, time INTEGER, msg TEXT)")
    con.executemany("INSERT INTO logs VALUES (?, ?, ?)", rows)
    con.commit()
    con.close()


class ParserTest(unittest.TestCase):
    def test_pam_webui_failure(self):
        e = ingest_syslog.parse_line(PAM_NO_USER)
        self.assertEqual((e["result"], e["service"], e["ip"], e["user"]),
                         ("fail", "DSM", "203.0.113.50", None))
        self.assertEqual(e["ts"], common.utc_ts(2026, 10, 1, 20, 50, 28))
        e = ingest_syslog.parse_line(PAM_USER)
        self.assertEqual((e["ip"], e["user"]), ("203.0.113.51", "postgres"))

    def test_service_from_protocol_column(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.db")
            make_connlog73(p, [
                (1790888186, "User [Administrator] from [203.0.113.60] failed to sign in to"
                             " [DSM] via [password] due to authorization failure.",
                 "Administrator", "203.0.113.60", "DSM"),
                (1790888200, "User [Administrator] from [203.0.113.61] signed in"
                             " successfully via [password].",
                 "Administrator", "203.0.113.61", "SMB"),
            ])
            evs = [e for _, e in ingest_connlog.read(p)]
            self.assertEqual([(e["result"], e["service"]) for e in evs],
                             [("fail", "DSM"), ("success", "SMB")])

    def test_sysdb_blocked_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.db")
            make_sysdb(p, [(6691, 1790887829, "Host [203.0.113.50] was blocked via [DSM]."),
                           (6692, 1790887830, "Failed to update package [x]."),
                           (6693, 1790887866, "Host [203.0.113.51] was blocked via [DSM].")])
            evs = [e for _, e in ingest_connlog.read(p, 6691, blocked_only=True,
                                                     source="sysdb")]
            self.assertEqual([(e["ip"], e["result"], e["service"], e["source"]) for e in evs],
                             [("203.0.113.51", "blocked", "DSM", "sysdb")])


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.var = os.path.join(self.tmp, "var")
        self.d = secdashd.Daemon(self.var, os.path.join(os.path.dirname(__file__), "..",
                                                        "package"))

    def tearDown(self):
        if self.d.geo:
            self.d.geo.close()
        shutil.rmtree(self.tmp)

    def batch(self, n, conn_rows, sys_rows, auth_lines):
        b = os.path.join(self.var, "inbox", "batch-%d" % n)
        os.makedirs(os.path.join(b, "syslog"))
        make_autoblock_db(os.path.join(b, "autoblock.db"), [
            ("203.0.113.50", n - 50, 0, 1, "", 0),
            ("203.0.113.60", n - 40, 0, 1, "", 0),
        ])
        make_connlog73(os.path.join(b, "connlog.db"), conn_rows)
        make_sysdb(os.path.join(b, "sysdb.db"), sys_rows)
        with open(os.path.join(b, "syslog", "auth.log.log"), "w") as f:
            f.write("".join(line + "\n" for line in auth_lines))

    def run_cycle(self):
        with mock.patch.object(secdashd.geo_mod, "update", return_value=[]):
            self.d.run_once()

    def test_blocks_get_service_and_failures(self):
        n = int(time.time())
        iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(t))  # noqa: E731
        pam = " nas synoscgi_SYNO.API.Auth_6_login[1]: pam_unix(webui:auth): authentication" \
              " failure; logname= uid=0 euid=0 tty= ruser= rhost=%s"
        self.batch(n, [
            (n - 40, "User [Administrator] from [203.0.113.60] failed to sign in to [DSM] via"
                     " [password] due to authorization failure.",
             "Administrator", "203.0.113.60", "DSM"),
        ], [
            (1, n - 50, "Host [203.0.113.50] was blocked via [DSM]."),
            (2, n - 40, "Host [203.0.113.60] was blocked via [DSM]."),
        ], [
            iso(n - 50) + pam % "203.0.113.50",  # nonexistent user: only in auth.log
            iso(n - 41) + pam % "203.0.113.60",  # same failure the connlog has: not counted twice
        ])
        self.run_cycle()
        con = store.connect(self.d.db_path)
        _, body = api.handle(con, {"q": "blocks", "range": "all"})
        got = {r["ip"]: (r["via"], r["attempts"]) for r in body["rows"]}
        self.assertEqual(got, {"203.0.113.50": ("DSM", 1), "203.0.113.60": ("DSM", 1)})
        con.close()

    def test_rescan_fills_missing_services(self):
        n = int(time.time())
        msg = "User [Administrator] from [203.0.113.61] signed in successfully via [password]."
        os.makedirs(self.var, exist_ok=True)
        con = store.connect(self.d.db_path)
        with con:  # stored by an older version that ignored the protocol column
            store.add_auth_events(con, [{
                "ts": n - 10, "ip": "203.0.113.61", "user": "Administrator", "service": None,
                "result": "success", "source": "connlog",
                "hash": common.event_hash("connlog", n - 10, msg)}])
            store.set_meta(con, "connlog_rowid", 99)
        con.close()
        self.batch(n, [(n - 10, msg, "Administrator", "203.0.113.61", "DSM")], [], [])
        self.run_cycle()
        con = store.connect(self.d.db_path)
        rows = con.execute("SELECT service FROM auth_events WHERE result='success'").fetchall()
        self.assertEqual([r[0] for r in rows], ["DSM"])
        con.close()


if __name__ == "__main__":
    unittest.main()
