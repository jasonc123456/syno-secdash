import os
import shutil
import subprocess
import tempfile
import time
import unittest

from tests.helpers import ROOT

import api
import secdashd
import store

DAY = 86400


class RetentionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "secdash.db")
        self.now = int(time.time())
        con = store.connect(self.db)
        n = self.now
        with con:
            store.add_auth_events(con, [
                {"ts": n - d * DAY, "ip": "8.8.8.%d" % d, "user": "u", "service": "DSM",
                 "result": "fail", "source": "connlog", "hash": "h%d" % d}
                for d in (1, 40, 400)])
            con.executemany(
                "INSERT INTO blocks(ip, first_seen, last_seen, expire, deny, type, active)"
                " VALUES (?, ?, ?, 0, 1, 0, ?)",
                [("9.9.9.1", n - 500 * DAY, n - 500 * DAY, 1),   # still blocked by DSM: kept
                 ("9.9.9.2", n - 500 * DAY, n - 500 * DAY, 0)])  # released long ago
        con.close()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def handle(self, params, write=False):
        con = store.connect(self.db)
        try:
            return api.handle(con, params, now=self.now, write=write)
        finally:
            con.close()

    def test_writes_need_post(self):
        self.assertEqual(self.handle({"q": "settings", "retention_days": "30"})[0], 405)
        self.assertEqual(self.handle({"q": "prune", "days": "1"})[0], 405)

    def test_settings(self):
        self.assertEqual(self.handle({"q": "settings", "retention_days": "45"}, True)[0], 400)
        self.assertEqual(self.handle({"q": "settings", "retention_days": "x"}, True)[0], 400)
        code, body = self.handle({"q": "settings", "retention_days": "730"}, True)
        self.assertEqual((code, body), (200, {"retention_days": 730}))
        _, st = self.handle({"q": "status"})
        self.assertEqual(st["retention_days"], 730)

    def test_preview_and_prune(self):
        _, body = self.handle({"q": "prune_preview", "days": "30"})
        self.assertEqual(body["counts"], {"auth_events": 2, "http_events": 0, "blocks": 1})
        code, body = self.handle({"q": "prune", "days": "30"}, True)
        self.assertEqual(body["deleted"], {"auth_events": 2, "http_events": 0, "blocks": 1})
        con = store.connect(self.db)
        self.assertEqual([r[0] for r in con.execute("SELECT ip FROM blocks")], ["9.9.9.1"])
        self.assertEqual(con.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0], 1)
        con.close()

    def test_daemon_uses_setting_and_forever(self):
        d = secdashd.Daemon(os.path.join(self.tmp, "var"), os.path.join(ROOT, "package"))
        d.db_path = self.db
        self.handle({"q": "settings", "retention_days": "0"}, True)
        d.maybe_retention()
        con = store.connect(self.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0], 3)
        con.close()
        self.handle({"q": "settings", "retention_days": "30"}, True)  # applied on next pass
        d.maybe_retention()
        con = store.connect(self.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0], 1)
        con.close()


class CgiCsrfTest(unittest.TestCase):
    def test_post_without_page_token_is_refused(self):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "REQUEST_METHOD": "POST",
               "QUERY_STRING": "q=prune&days=1", "HTTP_COOKIE": "id=x"}
        out = subprocess.run(["sh", os.path.join(ROOT, "package", "ui", "api.cgi")], env=env,
                             stdout=subprocess.PIPE, check=True).stdout.decode()
        self.assertIn("403", out.splitlines()[0])
        self.assertIn("missing SynoToken", out)


if __name__ == "__main__":
    unittest.main()
