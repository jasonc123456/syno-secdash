import os
import tempfile
import unittest

from tests.helpers import FIXTURES, make_autoblock_db, make_connlog_db

import common
import ingest_autoblock
import ingest_connlog
import ingest_nginx
import ingest_syslog


class CommonTest(unittest.TestCase):
    def test_norm_ip(self):
        self.assertEqual(common.norm_ip("::ffff:203.0.113.5"), "203.0.113.5")
        self.assertEqual(common.norm_ip("2001:0db8:0000:0000:0000:0000:0000:0001"), "2001:db8::1")
        self.assertEqual(common.norm_ip("[2001:db8::1]"), "2001:db8::1")
        self.assertIsNone(common.norm_ip("not-an-ip"))
        self.assertIsNone(common.norm_ip(None))

    def test_parse_ts(self):
        ts, _ = common.parse_ts("2026-09-30T10:00:01+08:00 rest")
        self.assertEqual(ts, common.utc_ts(2026, 9, 30, 2, 0, 1))
        ts, _ = common.parse_ts("30/Sep/2026:10:00:00 +0800")
        self.assertEqual(ts, common.utc_ts(2026, 9, 30, 2, 0, 0))
        ts, rest = common.parse_ts("Sep 30 10:07:00 nas", now=common.utc_ts(2026, 10, 1))
        self.assertIsNotNone(ts)
        self.assertEqual(rest, " nas")

    def test_bsd_year_rollover(self):
        now = common.utc_ts(2027, 1, 1, 12)
        ts, _ = common.parse_ts("Dec 31 23:00:00 nas", now=now)
        self.assertLess(ts, now)
        self.assertGreater(ts, now - 3 * 86400)


class AutoblockTest(unittest.TestCase):
    def test_read(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ab.db")
            make_autoblock_db(p, [
                ("203.0.113.7", 1790000000, 0, 1, "0000:0000:0000:0000:0000:ffff:cb00:7107", 0),
                ("", 1790000100, 1790086500, 1, "2001:0db8:0000:0000:0000:0000:0000:0077", 0),
                ("192.0.2.1", 1790000200, 0, 0, "", 1),
            ])
            rows = ingest_autoblock.read(p)
        self.assertEqual([r["ip"] for r in rows], ["203.0.113.7", "2001:db8::77", "192.0.2.1"])
        self.assertEqual(rows[1]["expire"], 1790086500)
        self.assertEqual(rows[2]["deny"], 0)
        self.assertEqual(rows[2]["type"], "manual")


class ConnlogTest(unittest.TestCase):
    CASES = [
        ("User [admin] from [203.0.113.5] signed in to [DSM] successfully via [password].",
         ("success", "admin", "203.0.113.5", "DSM")),
        ("User [admin] from [203.0.113.5] failed to sign in to [DSM] via [password] due to"
         " authorization failure.", ("fail", "admin", "203.0.113.5", "DSM")),
        ("User [root] from [198.51.100.2] failed to log in via [SSH] due to authorization"
         " failure.", ("fail", "root", "198.51.100.2", "SSH")),
        ("Host [198.51.100.2] was blocked via [SSH].", ("blocked", None, "198.51.100.2", "SSH")),
        ("User [bob] from [2001:db8::5] failed to log in via [SMB] due to authorization"
         " failure.", ("fail", "bob", "2001:db8::5", "SMB")),
        ("User [bob] from [192.0.2.4] logged out the server via [DSM].", None),
    ]

    def test_classify(self):
        for msg, want in self.CASES:
            self.assertEqual(ingest_connlog.classify(msg), want, msg)

    def test_read_incremental(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.db")
            make_connlog_db(p, [(1790000000 + i, m) for i, (m, _) in enumerate(self.CASES)])
            all_rows = list(ingest_connlog.read(p, 0))
            self.assertEqual(len(all_rows), 5)
            self.assertEqual(ingest_connlog.max_rowid(p), 6)
            later = list(ingest_connlog.read(p, 3))
            self.assertEqual([r for r, _ in later], [4, 5])
            self.assertEqual(all_rows[0][1]["source"], "connlog")


class SyslogTest(unittest.TestCase):
    def test_read(self):
        now = common.utc_ts(2026, 10, 1)
        evs = list(ingest_syslog.read(os.path.join(FIXTURES, "auth.log"), now=now))
        got = [(e["result"], e["user"], e["ip"]) for e in evs]
        self.assertEqual(got, [
            ("fail", "root", "203.0.113.7"),
            ("fail", "oracle", "203.0.113.7"),
            ("success", "admin", "192.168.1.20"),
            ("fail", "test", "2001:db8::77"),
            ("fail", "admin", "198.51.100.9"),
        ])
        self.assertEqual(evs[0]["ts"], common.utc_ts(2026, 9, 30, 2, 0, 1))
        self.assertEqual(len({e["hash"] for e in evs}), len(evs))


class NginxTest(unittest.TestCase):
    def test_read(self):
        evs = list(ingest_nginx.read(os.path.join(FIXTURES, "access.log")))
        self.assertEqual(len(evs), 4)
        self.assertEqual(evs[1]["path"], "/.env")
        self.assertEqual(evs[1]["status"], 404)
        self.assertEqual(evs[2]["host"], "files.example.com")
        self.assertEqual(evs[2]["method"], "POST")
        self.assertIsNone(evs[0]["host"])
        self.assertEqual(evs[3]["bytes"], 5120)


if __name__ == "__main__":
    unittest.main()
