import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from tests.helpers import FIXTURES, ROOT, make_autoblock_db, make_connlog_db

import api
import secdashd
import store


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.var = os.path.join(self.tmp, "var")
        self.pkg = os.path.join(ROOT, "package")
        self.d = secdashd.Daemon(self.var, self.pkg)
        self.now = int(time.time())

    def tearDown(self):
        if self.d.geo:
            self.d.geo.close()
        shutil.rmtree(self.tmp)

    def drop_batch(self, name, ab_rows, conn_rows):
        b = os.path.join(self.var, "inbox", name)
        os.makedirs(os.path.join(b, "syslog"))
        os.makedirs(os.path.join(b, "nginx"))
        make_autoblock_db(os.path.join(b, "autoblock.db"), ab_rows)
        make_connlog_db(os.path.join(b, "connlog.db"), conn_rows)
        shutil.copy(os.path.join(FIXTURES, "auth.log"), os.path.join(b, "syslog", "auth.log.log"))
        shutil.copy(os.path.join(FIXTURES, "access.log"), os.path.join(b, "nginx", "access.log"))
        with open(os.path.join(b, "collector.txt"), "w") as f:
            f.write("collected=test\n")

    def run_cycle(self):
        with mock.patch.object(secdashd.geo_mod, "update", return_value=[]):
            self.d.run_once()

    def test_end_to_end(self):
        n = self.now
        self.drop_batch("batch-%d" % (n - 60), [
            ("203.0.113.7", n - 3600, 0, 1, "", 0),
            ("198.51.100.9", n - 7200, n + 3600, 1, "", 0),
        ], [
            (n - 100, "User [admin] from [203.0.113.7] failed to sign in to [DSM] via"
                      " [password] due to authorization failure."),
            (n - 90, "User [admin] from [1.1.1.1] signed in to [DSM] successfully via"
                     " [password]."),
            # 1-failure threshold: DSM logs only the block, not the failure
            (n - 80, "Host [198.51.100.9] was blocked via [SSH]."),
        ])
        self.run_cycle()
        self.assertEqual(self.d.pending_batches(), [])

        con = store.connect(self.d.db_path)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM blocks").fetchone()[0], 2)
        self.assertEqual(con.execute(
            "SELECT COUNT(*) FROM auth_events WHERE source='connlog'").fetchone()[0], 3)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM http_events").fetchone()[0], 4)
        # private IP marked LAN; public IP gets some geo row (bundled DB may be absent in CI)
        self.assertEqual(con.execute(
            "SELECT cc FROM geo WHERE ip='192.168.1.20'").fetchone()[0], "LAN")
        self.assertIsNotNone(con.execute("SELECT 1 FROM geo WHERE ip='203.0.113.7'").fetchone())

        # second batch: one IP unblocked, same connlog rows plus one new, same logs again
        self.drop_batch("batch-%d" % n, [("203.0.113.7", n - 3600, 0, 1, "", 0)], [
            (n - 100, "User [admin] from [203.0.113.7] failed to sign in to [DSM] via"
                      " [password] due to authorization failure."),
            (n - 90, "User [admin] from [1.1.1.1] signed in to [DSM] successfully via"
                     " [password]."),
            (n - 10, "Host [203.0.113.7] was blocked via [DSM]."),
        ])
        self.run_cycle()
        self.assertEqual(con.execute(
            "SELECT COUNT(*) FROM auth_events WHERE source='connlog'").fetchone()[0], 3)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM http_events").fetchone()[0], 4)
        self.assertEqual(con.execute(
            "SELECT active FROM blocks WHERE ip='198.51.100.9'").fetchone()[0], 0)

        # every endpoint answers
        for q in ("summary", "timeline", "geo", "blocks", "logins", "web", "status"):
            for rng in ("24h", "7d", "all"):
                code, body = api.handle(con, {"q": q, "range": rng, "tz": "-480"},
                                        pkg_dir=self.pkg, db_path=self.d.db_path)
                self.assertEqual(code, 200, (q, rng, body))
        code, body = api.handle(con, {"q": "summary", "range": "24h"})
        self.assertEqual(body["current"]["new_blocks"], 2)
        self.assertEqual(body["active_blocks"], 1)
        code, body = api.handle(con, {"q": "blocks", "range": "24h"})
        self.assertEqual(body["total"], 2)
        code, body = api.handle(con, {"q": "blocks", "range": "24h", "search": "198.51"})
        self.assertEqual([(r["ip"], r["via"], r["attempts"]) for r in body["rows"]],
                         [("198.51.100.9", "SSH", 1)])
        code, body = api.handle(con, {"q": "ip", "ip": "203.0.113.7"})
        self.assertEqual(code, 200)
        self.assertEqual(body["counts"].get("fail"), 3)
        code, body = api.handle(con, {"q": "logins", "range": "24h"})
        self.assertEqual(len(body["unusual"]), 1)
        self.assertTrue(body["unusual"][0]["new_network"])
        code, body = api.handle(con, {"q": "status"}, pkg_dir=self.pkg)
        self.assertIn("sudo -u", body["collector_script"])
        con.close()

    def test_bad_requests(self):
        con = store.connect(os.path.join(self.tmp, "x.db"))
        self.assertEqual(api.handle(con, {"q": "nope"})[0], 404)
        self.assertEqual(api.handle(con, {"q": "summary", "range": "5y"})[0], 400)
        self.assertEqual(api.handle(con, {"q": "blocks", "cc": "x'; --"})[0], 400)
        self.assertEqual(api.handle(con, {"q": "ip", "ip": "1.2.3"})[0], 400)
        self.assertEqual(api.handle(con, {"q": "blocks", "sort": "ip; DROP"})[0], 200)
        con.close()

    def test_unusual_ignores_ip_changes_within_a_network(self):
        con = store.connect(os.path.join(self.tmp, "u.db"))
        n = self.now
        def ok(ts, ip, h):
            return {"ts": ts, "ip": ip, "user": "admin", "service": "DSM",
                    "result": "success", "source": "connlog", "hash": h}
        store.add_auth_events(con, [
            ok(n - 300, "8.8.8.1", "a"),   # first ever: new country + network
            ok(n - 200, "8.8.8.2", "b"),   # same carrier, new IP: not flagged
            ok(n - 100, "9.9.9.9", "c"),   # different carrier, same country
            ok(n - 50, "1.1.1.1", "d"),    # different country
        ])
        for ip, cc, asn in (("8.8.8.1", "US", 701), ("8.8.8.2", "US", 701),
                            ("9.9.9.9", "US", 7922), ("1.1.1.1", "JP", 2516)):
            store.put_geo(con, ip, {"cc": cc, "asn": asn})
        _, body = api.handle(con, {"q": "logins", "range": "24h"})
        got = {u["ip"]: (bool(u["new_country"]), bool(u["new_network"])) for u in body["unusual"]}
        self.assertEqual(got, {"8.8.8.1": (True, True), "9.9.9.9": (False, True),
                               "1.1.1.1": (True, True)})
        con.close()

    def test_retention(self):
        con = store.connect(os.path.join(self.tmp, "r.db"))
        store.add_auth_events(con, [
            {"ts": self.now - 400 * 86400, "ip": "192.0.2.1", "result": "fail",
             "source": "syslog", "hash": "a"},
            {"ts": self.now, "ip": "192.0.2.2", "result": "fail", "source": "syslog", "hash": "b"},
        ])
        store.put_geo(con, "192.0.2.1", {"cc": "LAN"})
        store.apply_retention(con, 365, now=self.now)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0], 1)
        self.assertIsNone(con.execute("SELECT 1 FROM geo WHERE ip='192.0.2.1'").fetchone())
        con.close()


if __name__ == "__main__":
    unittest.main()
