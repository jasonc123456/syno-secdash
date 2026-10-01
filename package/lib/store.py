"""SQLite storage shared by the daemon (writer) and api.cgi (reader).

All timestamps are integer Unix seconds (UTC).
"""
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    ip          TEXT PRIMARY KEY,
    first_seen  INTEGER NOT NULL,
    expire      INTEGER NOT NULL DEFAULT 0,   -- 0 = never
    deny        INTEGER NOT NULL DEFAULT 1,   -- 1 = block list, 0 = allow list
    type        TEXT,
    active      INTEGER NOT NULL DEFAULT 1,   -- 0 once it disappears from DSM's list
    last_seen   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS blocks_first ON blocks(first_seen);

CREATE TABLE IF NOT EXISTS auth_events (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,
    ip       TEXT,
    user     TEXT,
    service  TEXT,
    result   TEXT NOT NULL,                   -- fail | success | blocked
    source   TEXT NOT NULL,                   -- connlog | syslog
    hash     TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS auth_ts ON auth_events(ts);
CREATE INDEX IF NOT EXISTS auth_ip ON auth_events(ip);

CREATE TABLE IF NOT EXISTS http_events (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    ip      TEXT NOT NULL,
    host    TEXT,
    method  TEXT,
    path    TEXT,
    status  INTEGER,
    bytes   INTEGER,
    ua      TEXT,
    hash    TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS http_ts ON http_events(ts);
CREATE INDEX IF NOT EXISTS http_ip ON http_events(ip);

CREATE TABLE IF NOT EXISTS geo (
    ip         TEXT PRIMARY KEY,
    cc         TEXT,                          -- ISO country code, 'LAN' for private
    country    TEXT,
    region     TEXT,
    city       TEXT,
    lat        REAL,
    lon        REAL,
    asn        INTEGER,
    org        TEXT,
    looked_up  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key    TEXT PRIMARY KEY,
    value  TEXT
);
"""


def connect(path, readonly=False):
    if readonly:
        con = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=10)
    else:
        con = sqlite3.connect(path, timeout=30)
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript(SCHEMA)
    con.row_factory = sqlite3.Row
    return con


def get_meta(con, key, default=None):
    row = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def set_meta(con, key, value):
    con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, str(value)))


def sync_blocks(con, rows, now=None):
    """Merge a full snapshot of DSM's auto-block list.

    rows: iterable of dicts with ip, first_seen, expire, deny, type.
    IPs no longer in the snapshot are kept for history but marked inactive.
    Returns the number of newly seen IPs.
    """
    now = now or int(time.time())
    seen = set()
    new = 0
    for r in rows:
        seen.add(r["ip"])
        cur = con.execute(
            "UPDATE blocks SET expire=?, deny=?, type=?, active=1, last_seen=? WHERE ip=?",
            (r["expire"], r["deny"], r["type"], now, r["ip"]))
        if cur.rowcount == 0:
            con.execute(
                "INSERT INTO blocks(ip, first_seen, expire, deny, type, active, last_seen)"
                " VALUES (?, ?, ?, ?, ?, 1, ?)",
                (r["ip"], r["first_seen"] or now, r["expire"], r["deny"], r["type"], now))
            new += 1
    active = [row[0] for row in con.execute("SELECT ip FROM blocks WHERE active=1")]
    gone = [ip for ip in active if ip not in seen]
    con.executemany("UPDATE blocks SET active=0 WHERE ip=?", [(ip,) for ip in gone])
    return new


def add_auth_events(con, events):
    n = 0
    for e in events:
        cur = con.execute(
            "INSERT OR IGNORE INTO auth_events(ts, ip, user, service, result, source, hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (e["ts"], e.get("ip"), e.get("user"), e.get("service"), e["result"],
             e["source"], e["hash"]))
        n += cur.rowcount
        if not cur.rowcount and e.get("service"):
            # seen before: fill in a service that older versions couldn't parse
            con.execute("UPDATE auth_events SET service=? WHERE hash=? AND service IS NULL",
                        (e["service"], e["hash"]))
    return n


def add_syslog_auth_events(con, events):
    """Like add_auth_events, but skips DSM failures the connection log already has."""
    def fresh(e):
        if e["service"] != "DSM":
            return True
        return con.execute(
            "SELECT 1 FROM auth_events WHERE source='connlog' AND result=? AND ip=?"
            " AND ts BETWEEN ? AND ? LIMIT 1",
            (e["result"], e["ip"], e["ts"] - 5, e["ts"] + 5)).fetchone() is None
    return add_auth_events(con, (e for e in events if fresh(e)))


def add_http_events(con, events):
    n = 0
    for e in events:
        cur = con.execute(
            "INSERT OR IGNORE INTO http_events(ts, ip, host, method, path, status, bytes, ua, hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (e["ts"], e["ip"], e.get("host"), e.get("method"), e.get("path"),
             e.get("status"), e.get("bytes"), e.get("ua"), e["hash"]))
        n += cur.rowcount
    return n


def ips_missing_geo(con, stale_before, limit=5000):
    """IPs referenced anywhere that have no geo row, or one older than stale_before."""
    return [r[0] for r in con.execute(
        """
        SELECT ip FROM (
            SELECT ip FROM blocks
            UNION SELECT ip FROM auth_events WHERE ip IS NOT NULL
            UNION SELECT ip FROM http_events
        ) AS a
        WHERE NOT EXISTS (SELECT 1 FROM geo g WHERE g.ip = a.ip AND g.looked_up >= ?)
        LIMIT ?
        """, (stale_before, limit))]


def put_geo(con, ip, info, now=None):
    con.execute(
        "INSERT OR REPLACE INTO geo(ip, cc, country, region, city, lat, lon, asn, org, looked_up)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (ip, info.get("cc"), info.get("country"), info.get("region"), info.get("city"),
         info.get("lat"), info.get("lon"), info.get("asn"), info.get("org"),
         now or int(time.time())))


# What retention removes. Active blocks are never removed: they mirror DSM's
# current block list.
_OLD = (("auth_events", "ts < ?"),
        ("http_events", "ts < ?"),
        ("blocks", "active=0 AND last_seen < ?"))


def count_older(con, cutoff):
    return {t: con.execute("SELECT COUNT(*) FROM %s WHERE %s" % (t, w), (cutoff,)).fetchone()[0]
            for t, w in _OLD}


def apply_retention(con, days, now=None):
    """Delete records older than `days`; returns {table: rows deleted}."""
    cutoff = (now or int(time.time())) - days * 86400
    deleted = {t: con.execute("DELETE FROM %s WHERE %s" % (t, w), (cutoff,)).rowcount
               for t, w in _OLD}
    con.execute(
        """DELETE FROM geo WHERE ip NOT IN (
               SELECT ip FROM blocks
               UNION SELECT ip FROM auth_events WHERE ip IS NOT NULL
               UNION SELECT ip FROM http_events)""")
    return deleted
