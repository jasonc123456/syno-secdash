#!/usr/bin/env python3
"""SecDash daemon: ingest collector batches, enrich with GeoIP, apply retention.

Runs unprivileged as the package user. The root collector (Task Scheduler)
drops snapshots into <var>/inbox/batch-<epoch>/:

    autoblock.db      copy of /etc/synoautoblock.db
    connlog.db        copy of /var/log/synolog/.SYNOCONNDB
    syslog/*.log      sshd/ftpd lines from auth.log / messages
    nginx/*.log       tail of reverse-proxy access logs
"""
import argparse
import logging
import logging.handlers
import os
import shutil
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))

import geo as geo_mod  # noqa: E402
import ingest_autoblock  # noqa: E402
import ingest_connlog  # noqa: E402
import ingest_nginx  # noqa: E402
import ingest_syslog  # noqa: E402
import store  # noqa: E402

log = logging.getLogger("secdash")

POLL_SECONDS = 60
GEO_STALE_DAYS = 30
DEFAULT_RETENTION_DAYS = 365


class Daemon:
    def __init__(self, var_dir, pkg_dir):
        self.var = var_dir
        self.inbox = os.path.join(var_dir, "inbox")
        self.geo_dir = os.path.join(var_dir, "geo")
        self.bundled_geo = os.path.join(pkg_dir, "geo")
        self.db_path = os.path.join(var_dir, "secdash.db")
        os.makedirs(self.inbox, exist_ok=True)
        os.makedirs(self.geo_dir, exist_ok=True)
        self.geo = None
        self.stop = False

    # -- batches ---------------------------------------------------------
    def pending_batches(self):
        out = []
        for n in sorted(os.listdir(self.inbox)):
            p = os.path.join(self.inbox, n)
            if os.path.islink(p) or not os.path.isdir(p):
                continue
            if n.startswith("batch-"):
                out.append(p)
            elif n.startswith(".incoming.") and time.time() - os.path.getmtime(p) > 3600:
                shutil.rmtree(p, ignore_errors=True)  # interrupted collector run
        return out

    def ingest_batch(self, con, batch):
        stats = {}
        p = os.path.join(batch, "autoblock.db")
        if os.path.exists(p):
            try:
                rows = ingest_autoblock.read(p)
                stats["blocks_new"] = store.sync_blocks(con, rows)
                stats["blocks_total"] = len(rows)
            except Exception as e:
                log.warning("autoblock %s: %s", p, e)

        # connlog: sign-ins; sysdb: "Host [ip] was blocked via [service]" lines
        for name, key, blocked_only in (("connlog", "connlog_rowid", False),
                                        ("sysdb", "sysdb_rowid", True)):
            p = os.path.join(batch, name + ".db")
            if not os.path.exists(p):
                continue
            try:
                since = int(store.get_meta(con, key, 0))
                if name == "connlog" and store.get_meta(con, "connlog_rescan") != "2":
                    since = 0  # one-time re-read to fill in services missed before 0.1.3
                    store.set_meta(con, "connlog_rescan", "2")
                top = ingest_connlog.max_rowid(p)
                if top < since:
                    since = 0  # DSM cleared the log and rowids restarted
                events = [ev for _, ev in ingest_connlog.read(
                    p, since, blocked_only=blocked_only, source=name)]
                stats["auth_" + name] = store.add_auth_events(con, events)
                store.set_meta(con, key, top)
            except Exception as e:
                log.warning("%s %s: %s", name, p, e)

        for sub, reader, adder, key in (
                ("syslog", ingest_syslog.read, store.add_syslog_auth_events, "auth_syslog"),
                ("nginx", ingest_nginx.read, store.add_http_events, "http")):
            d = os.path.join(batch, sub)
            if not os.path.isdir(d):
                continue
            for name in sorted(os.listdir(d)):
                path = os.path.join(d, name)
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                try:
                    stats[key] = stats.get(key, 0) + adder(con, reader(path))
                except Exception as e:
                    log.warning("%s %s: %s", sub, path, e)

        info = os.path.join(batch, "collector.txt")
        ts = os.path.basename(batch).split("-", 1)[-1]
        store.set_meta(con, "collector_last_run", ts if ts.isdigit() else int(time.time()))
        if os.path.exists(info):
            with open(info, encoding="utf-8", errors="replace") as f:
                store.set_meta(con, "collector_info", f.read(2000))
        return stats

    def process_inbox(self):
        batches = self.pending_batches()
        if not batches:
            return False
        con = store.connect(self.db_path)
        try:
            for b in batches:
                with con:
                    stats = self.ingest_batch(con, b)
                log.info("ingested %s %s", os.path.basename(b), stats)
                shutil.rmtree(b, ignore_errors=True)
        finally:
            con.close()
        return True

    # -- geo -------------------------------------------------------------
    def open_geo(self):
        if self.geo:
            self.geo.close()
        self.geo = geo_mod.Geo([self.geo_dir, self.bundled_geo])

    def enrich(self, full=False):
        if self.geo is None:
            self.open_geo()
        con = store.connect(self.db_path)
        try:
            now = int(time.time())
            stale = now + 1 if full else now - GEO_STALE_DAYS * 86400
            total = 0
            while not self.stop:
                ips = store.ips_missing_geo(con, stale, limit=2000)
                if not ips:
                    break
                with con:
                    for ip in ips:
                        store.put_geo(con, ip, self.geo.lookup(ip), now=now)
                total += len(ips)
                if full:
                    stale = now  # rows just written have looked_up == now
            with con:
                store.set_meta(con, "geo_db_date", self.geo.db_date() or "")
            if total:
                log.info("geo: enriched %d IPs", total)
        finally:
            con.close()

    def maybe_update_geo(self):
        con = store.connect(self.db_path)
        try:
            month = time.strftime("%Y-%m", time.gmtime())
            if store.get_meta(con, "geo_update_month") == month:
                return
            last_try = int(store.get_meta(con, "geo_update_try", 0))
            if time.time() - last_try < 6 * 3600:
                return
            with con:
                store.set_meta(con, "geo_update_try", int(time.time()))
            updated = geo_mod.update(self.geo_dir, log=log.info)
            if set(updated) == set(geo_mod.KINDS):
                with con:
                    store.set_meta(con, "geo_update_month", month)
        finally:
            con.close()
        if updated:
            self.open_geo()
            self.enrich(full=True)

    def maybe_retention(self):
        con = store.connect(self.db_path)
        try:
            last = int(store.get_meta(con, "retention_last", 0))
            if time.time() - last < 86400:
                return
            days = int(store.get_meta(con, "retention_days", DEFAULT_RETENTION_DAYS))
            with con:
                store.apply_retention(con, days)
                store.set_meta(con, "retention_last", int(time.time()))
            con.execute("PRAGMA optimize")
        finally:
            con.close()

    # -- main loop -------------------------------------------------------
    def run_once(self):
        self.process_inbox()
        self.enrich()
        self.maybe_retention()
        try:
            self.maybe_update_geo()
        except Exception as e:
            log.warning("geo update: %s", e)

    def run(self):
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "stop", True))
        log.info("started (var=%s)", self.var)
        while not self.stop:
            try:
                self.run_once()
            except Exception:
                log.exception("cycle failed")
            for _ in range(POLL_SECONDS):
                if self.stop:
                    break
                time.sleep(1)
        log.info("stopped")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--var", default=os.environ.get("SYNOPKG_PKGVAR", "/var/packages/SecDash/var"))
    ap.add_argument("--pkg", default=os.path.normpath(os.path.join(HERE, "..")))
    ap.add_argument("--once", action="store_true", help="run one cycle and exit")
    ap.add_argument("--log", help="log file (default: stderr)")
    args = ap.parse_args()

    handler = (logging.handlers.RotatingFileHandler(args.log, maxBytes=1 << 20, backupCount=2)
               if args.log else logging.StreamHandler())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)

    d = Daemon(args.var, args.pkg)
    if args.once:
        d.run_once()
    else:
        d.run()


if __name__ == "__main__":
    main()
