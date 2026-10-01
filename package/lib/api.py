"""Read-only query layer behind api.cgi (and dev/serve.py).

handle(con, params) -> (http_status, dict). All SQL is parameterized.
"""
import os
import time

RANGES = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400,
          "1y": 365 * 86400, "all": None}
# bucket sizes chosen to keep ~24-120 points per chart
BUCKETS = {"24h": 3600, "7d": 6 * 3600, "30d": 86400, "90d": 86400,
           "1y": 7 * 86400, "all": 7 * 86400}



def _version():
    if os.environ.get("SYNOPKG_PKGVER"):
        return os.environ["SYNOPKG_PKGVER"]
    try:  # CGIs don't get SYNOPKG_* variables; read the installed INFO file
        with open("/var/packages/SecDash/INFO", encoding="utf-8") as f:
            for line in f:
                if line.startswith("version="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "dev"


VERSION = _version()


class BadRequest(Exception):
    pass


def _range(params, now):
    r = params.get("range", "7d")
    if r not in RANGES:
        raise BadRequest("range must be one of %s" % ", ".join(RANGES))
    span = RANGES[r]
    return r, (now - span if span else 0)


def _tzoff(params):
    """Browser UTC offset in seconds (JS getTimezoneOffset() is minutes, inverted)."""
    try:
        m = int(params.get("tz", 0))
    except ValueError:
        raise BadRequest("tz must be an integer")
    if not -900 <= m <= 900:
        raise BadRequest("tz out of range")
    return -m * 60


def _int(params, key, default, lo, hi):
    try:
        v = int(params.get(key, default))
    except ValueError:
        raise BadRequest("%s must be an integer" % key)
    return max(lo, min(hi, v))


def _cc_filter(params, alias="g"):
    cc = params.get("cc")
    if not cc:
        return "", ()
    if not (cc == "LAN" or (len(cc) == 2 and cc.isalpha())):
        raise BadRequest("bad country code")
    return " AND %s.cc = ?" % alias, (cc.upper() if cc != "LAN" else cc,)


def _rows(cur):
    return [dict(r) for r in cur]


# -- endpoints -----------------------------------------------------------------

def summary(con, p, now):
    rng, start = _range(p, now)
    span = RANGES[rng]
    ccw, cca = _cc_filter(p)

    def period(a, b):
        q = lambda sql, args=(): con.execute(sql, args).fetchone()[0]  # noqa: E731
        return {
            "new_blocks": q("SELECT COUNT(*) FROM blocks b LEFT JOIN geo g ON g.ip=b.ip"
                            " WHERE b.deny=1 AND b.first_seen>=? AND b.first_seen<?" + ccw,
                            (a, b) + cca),
            "fails": q("SELECT COUNT(*) FROM auth_events e LEFT JOIN geo g ON g.ip=e.ip"
                       " WHERE e.result='fail' AND e.ts>=? AND e.ts<?" + ccw, (a, b) + cca),
            "successes": q("SELECT COUNT(*) FROM auth_events e LEFT JOIN geo g ON g.ip=e.ip"
                           " WHERE e.result='success' AND e.ts>=? AND e.ts<?" + ccw,
                           (a, b) + cca),
            "attackers": q("SELECT COUNT(DISTINCT e.ip) FROM auth_events e"
                           " LEFT JOIN geo g ON g.ip=e.ip"
                           " WHERE e.result IN ('fail','blocked') AND e.ts>=? AND e.ts<?" + ccw,
                           (a, b) + cca),
            "http_errors": q("SELECT COUNT(*) FROM http_events h LEFT JOIN geo g ON g.ip=h.ip"
                             " WHERE h.status>=400 AND h.ts>=? AND h.ts<?" + ccw, (a, b) + cca),
        }

    cur = period(start, now + 1)
    prev = period(start - span, start) if span else None
    active = con.execute(
        "SELECT COUNT(*) FROM blocks b LEFT JOIN geo g ON g.ip=b.ip"
        " WHERE b.deny=1 AND b.active=1 AND (b.expire=0 OR b.expire>?)" + ccw,
        (now,) + cca).fetchone()[0]
    countries = con.execute(
        """SELECT COUNT(DISTINCT g.cc) FROM geo g WHERE g.cc IS NOT NULL AND g.cc != 'LAN'
           AND (g.ip IN (SELECT ip FROM blocks WHERE deny=1 AND first_seen>=?)
                OR g.ip IN (SELECT ip FROM auth_events WHERE result IN ('fail','blocked')
                            AND ts>=?))""" + ccw, (start, start) + cca).fetchone()[0]
    return {"range": rng, "current": cur, "previous": prev,
            "active_blocks": active, "countries": countries}


def timeline(con, p, now):
    rng, start = _range(p, now)
    off = _tzoff(p)
    size = BUCKETS[rng]
    ccw, cca = _cc_filter(p)
    if rng == "all":
        first = con.execute("SELECT MIN(ts) FROM auth_events").fetchone()[0]
        first_b = con.execute("SELECT MIN(first_seen) FROM blocks").fetchone()[0]
        start = min(x for x in (first, first_b, now) if x is not None)
    bucket = "((%s + ?) / ? * ? - ?)"
    series = {}
    for name, sql, args in (
        ("fail", "SELECT %s AS t, COUNT(*) FROM auth_events e LEFT JOIN geo g ON g.ip=e.ip"
                 " WHERE e.result='fail' AND e.ts>=?%s GROUP BY t" % (bucket % "e.ts", ccw),
         (off, size, size, off, start) + cca),
        ("success", "SELECT %s AS t, COUNT(*) FROM auth_events e LEFT JOIN geo g ON g.ip=e.ip"
                    " WHERE e.result='success' AND e.ts>=?%s GROUP BY t" % (bucket % "e.ts", ccw),
         (off, size, size, off, start) + cca),
        ("blocked", "SELECT %s AS t, COUNT(*) FROM blocks b LEFT JOIN geo g ON g.ip=b.ip"
                    " WHERE b.deny=1 AND b.first_seen>=?%s GROUP BY t"
                    % (bucket % "b.first_seen", ccw),
         (off, size, size, off, start) + cca),
        ("http_errors", "SELECT %s AS t, COUNT(*) FROM http_events h LEFT JOIN geo g ON g.ip=h.ip"
                        " WHERE h.status>=400 AND h.ts>=?%s GROUP BY t" % (bucket % "h.ts", ccw),
         (off, size, size, off, start) + cca),
    ):
        series[name] = dict(con.execute(sql, args).fetchall())
    first = (start + off) // size * size - off
    buckets = list(range(first, now + 1, size))
    return {"range": rng, "bucket": size, "t": buckets,
            "series": {k: [v.get(b, 0) for b in buckets] for k, v in series.items()}}


def geo(con, p, now):
    rng, start = _range(p, now)
    countries = _rows(con.execute(
        """
        SELECT g.cc, MAX(g.country) AS country,
               SUM(src='block') AS blocks, SUM(src='fail') AS fails,
               SUM(src='success') AS successes, SUM(src='http') AS http_errors
        FROM (
            SELECT ip, 'block' AS src FROM blocks WHERE deny=1 AND first_seen>=?
            UNION ALL SELECT ip, result FROM auth_events
                WHERE result IN ('fail','success') AND ts>=?
            UNION ALL SELECT ip, 'http' FROM http_events WHERE status>=400 AND ts>=?
        ) x JOIN geo g ON g.ip = x.ip
        WHERE g.cc IS NOT NULL
        GROUP BY g.cc ORDER BY blocks + fails DESC
        """, (start, start, start)))
    cities = _rows(con.execute(
        """
        SELECT g.city, g.cc, ROUND(g.lat, 2) AS lat, ROUND(g.lon, 2) AS lon,
               COUNT(DISTINCT x.ip) AS ips
        FROM (
            SELECT ip FROM blocks WHERE deny=1 AND first_seen>=?
            UNION SELECT ip FROM auth_events WHERE result IN ('fail','blocked') AND ts>=?
        ) x JOIN geo g ON g.ip = x.ip
        WHERE g.lat IS NOT NULL AND g.cc != 'LAN'
        GROUP BY g.city, g.cc, ROUND(g.lat, 2), ROUND(g.lon, 2)
        ORDER BY ips DESC LIMIT 300
        """, (start, start)))
    return {"range": rng, "countries": countries, "cities": cities}


BLOCK_SORTS = {"first_seen": "b.first_seen", "ip": "b.ip", "country": "g.country",
               "org": "g.org", "attempts": "attempts", "expire": "b.expire", "via": "via"}


def blocks(con, p, now):
    rng, start = _range(p, now)
    ccw, cca = _cc_filter(p)
    where = " WHERE b.deny=1 AND b.first_seen>=?" + ccw
    args = (start,) + cca
    if p.get("active") == "1":
        where += " AND b.active=1 AND (b.expire=0 OR b.expire>?)"
        args += (now,)
    q = (p.get("search") or "").strip()
    if q:
        where += " AND (b.ip LIKE ? OR g.country LIKE ? OR g.org LIKE ? OR g.city LIKE ?)"
        like = "%" + q.replace("%", "") + "%"
        args += (like, like, like, like)
    sort = BLOCK_SORTS.get(p.get("sort", "first_seen"), "b.first_seen")
    order = "ASC" if p.get("dir") == "asc" else "DESC"
    limit = _int(p, "limit", 100, 1, 5000)
    offset = _int(p, "offset", 0, 0, 10 ** 7)
    total = con.execute("SELECT COUNT(*) FROM blocks b LEFT JOIN geo g ON g.ip=b.ip" + where,
                        args).fetchone()[0]
    rows = _rows(con.execute(
        """SELECT b.ip, b.first_seen, b.expire, b.type, b.active,
                  g.cc, g.country, g.city, g.asn, g.org,
                  (SELECT COUNT(*) FROM auth_events e WHERE e.ip=b.ip AND e.result='fail')
                      AS attempts,
                  (SELECT e.service FROM auth_events e
                    WHERE e.ip=b.ip AND e.result IN ('blocked','fail') AND e.service IS NOT NULL
                    ORDER BY e.result='blocked' DESC, e.ts DESC LIMIT 1) AS via
           FROM blocks b LEFT JOIN geo g ON g.ip=b.ip""" + where +
        " ORDER BY %s %s LIMIT ? OFFSET ?" % (sort, order), args + (limit, offset)))
    return {"range": rng, "total": total, "rows": rows}


def logins(con, p, now):
    rng, start = _range(p, now)
    off = _tzoff(p)
    ccw, cca = _cc_filter(p)
    base = " FROM auth_events e LEFT JOIN geo g ON g.ip=e.ip WHERE e.ts>=?" + ccw
    args = (start,) + cca
    by_service = _rows(con.execute(
        "SELECT COALESCE(e.service,'?') AS service, SUM(e.result='fail') AS fails,"
        " SUM(e.result='success') AS successes, SUM(e.result='blocked') AS blocked"
        + base + " GROUP BY 1 ORDER BY fails DESC", args))
    by_user = _rows(con.execute(
        "SELECT COALESCE(e.user,'(unknown)') AS user, COUNT(*) AS fails,"
        " COUNT(DISTINCT e.ip) AS ips" + base + " AND e.result='fail'"
        " GROUP BY 1 ORDER BY fails DESC LIMIT 20", args))
    heat = con.execute(
        "SELECT ((e.ts + ?) / 86400 + 4) % 7 AS dow, ((e.ts + ?) % 86400) / 3600 AS hr,"
        " COUNT(*)" + base + " AND e.result='fail' GROUP BY 1, 2", (off, off) + args).fetchall()
    heatmap = [[0] * 24 for _ in range(7)]  # [dow 0=Sun][hour]
    for dow, hr, n in heat:
        heatmap[dow][hr] = n
    recent = _rows(con.execute(
        "SELECT e.ts, e.ip, e.user, e.service, e.result, e.source, g.cc, g.country, g.org"
        + base + " ORDER BY e.ts DESC LIMIT 200", args))
    # Successful sign-ins from a country or network (ASN) this user has never
    # signed in from before. Changing IPs within one carrier (mobile, CGNAT)
    # are normal and not flagged.
    unusual = _rows(con.execute(
        """SELECT e.ts, e.ip, e.user, e.service, g.cc, g.country, g.city, g.asn, g.org,
                  NOT EXISTS (SELECT 1 FROM auth_events o LEFT JOIN geo og ON og.ip=o.ip
                              WHERE o.result='success' AND o.ts<e.ts
                                AND COALESCE(o.user,'')=COALESCE(e.user,'') AND og.cc=g.cc)
                      AS new_country,
                  NOT EXISTS (SELECT 1 FROM auth_events o LEFT JOIN geo og ON og.ip=o.ip
                              WHERE o.result='success' AND o.ts<e.ts
                                AND COALESCE(o.user,'')=COALESCE(e.user,'')
                                AND COALESCE(og.asn, og.org, o.ip)=COALESCE(g.asn, g.org, e.ip))
                      AS new_network
           FROM auth_events e LEFT JOIN geo g ON g.ip=e.ip
           WHERE e.result='success' AND e.ts>=? AND COALESCE(g.cc,'') != 'LAN'""" + ccw +
        " ORDER BY e.ts DESC LIMIT 1000", args))
    unusual = [u for u in unusual if u["new_country"] or u["new_network"]][:50]
    return {"range": rng, "by_service": by_service, "by_user": by_user,
            "heatmap": heatmap, "recent": recent, "unusual": unusual}


def web(con, p, now):
    rng, start = _range(p, now)
    off = _tzoff(p)
    size = BUCKETS[rng]
    ccw, cca = _cc_filter(p)
    base = " FROM http_events h LEFT JOIN geo g ON g.ip=h.ip WHERE h.ts>=?" + ccw
    args = (start,) + cca
    totals = dict(con.execute(
        "SELECT h.status/100 AS cls, COUNT(*)" + base + " GROUP BY 1", args).fetchall())
    top_ips = _rows(con.execute(
        "SELECT h.ip, g.cc, g.country, g.org, COUNT(*) AS errors,"
        " COUNT(DISTINCT h.path) AS paths" + base + " AND h.status>=400"
        " GROUP BY h.ip ORDER BY errors DESC LIMIT 25", args))
    top_paths = _rows(con.execute(
        "SELECT h.path, COUNT(*) AS hits, COUNT(DISTINCT h.ip) AS ips" + base +
        " AND h.status>=400 GROUP BY h.path ORDER BY hits DESC LIMIT 25", args))
    top_ua = _rows(con.execute(
        "SELECT COALESCE(h.ua,'(none)') AS ua, COUNT(*) AS hits, COUNT(DISTINCT h.ip) AS ips"
        + base + " AND h.status>=400 GROUP BY 1 ORDER BY hits DESC LIMIT 15", args))
    rows = con.execute(
        "SELECT ((h.ts + ?) / ? * ? - ?) AS t, h.status/100 AS cls, COUNT(*)" + base +
        " GROUP BY 1, 2", (off, size, size, off) + args).fetchall()
    first = (start + off) // size * size - off if start else (rows[0][0] if rows else now)
    buckets = list(range(min([first] + [r[0] for r in rows]), now + 1, size))
    idx = {b: i for i, b in enumerate(buckets)}
    status = {str(c): [0] * len(buckets) for c in (2, 3, 4, 5)}
    for t, cls, n in rows:
        if str(cls) in status and t in idx:
            status[str(cls)][idx[t]] = n
    return {"range": rng, "totals": {str(k): v for k, v in totals.items()},
            "top_ips": top_ips, "top_paths": top_paths, "top_ua": top_ua,
            "t": buckets, "status": status}


def ip_detail(con, p, now):
    from common import norm_ip
    ip = norm_ip(p.get("ip"))
    if not ip:
        raise BadRequest("ip is required")
    g = con.execute("SELECT * FROM geo WHERE ip=?", (ip,)).fetchone()
    b = con.execute("SELECT * FROM blocks WHERE ip=?", (ip,)).fetchone()
    auth = _rows(con.execute(
        "SELECT ts, user, service, result, source FROM auth_events WHERE ip=?"
        " ORDER BY ts DESC LIMIT 500", (ip,)))
    http = _rows(con.execute(
        "SELECT ts, host, method, path, status, ua FROM http_events WHERE ip=?"
        " ORDER BY ts DESC LIMIT 500", (ip,)))
    counts = dict(con.execute(
        "SELECT result, COUNT(*) FROM auth_events WHERE ip=? GROUP BY result", (ip,)).fetchall())
    return {"ip": ip, "geo": dict(g) if g else None, "block": dict(b) if b else None,
            "counts": counts, "auth": auth, "http": http}


def status(con, p, now, pkg_dir=None, db_path=None):
    meta = {r[0]: r[1] for r in con.execute("SELECT key, value FROM meta")}
    counts = {t: con.execute("SELECT COUNT(*) FROM %s" % t).fetchone()[0]
              for t in ("blocks", "auth_events", "http_events", "geo")}
    collector = None
    if pkg_dir:
        try:
            with open(os.path.join(pkg_dir, "bin", "collector.sh"), encoding="utf-8") as f:
                collector = f.read()
        except OSError:
            pass
    return {
        "version": VERSION,
        "collector_last_run": int(meta["collector_last_run"])
        if meta.get("collector_last_run", "").isdigit() else None,
        "collector_info": meta.get("collector_info"),
        "geo_db_date": meta.get("geo_db_date"),
        "geo_update_month": meta.get("geo_update_month"),
        "retention_days": int(meta.get("retention_days", 365)),
        "counts": counts,
        "db_bytes": os.path.getsize(db_path) if db_path and os.path.exists(db_path) else None,
        "collector_script": collector,
    }


ENDPOINTS = {"summary": summary, "timeline": timeline, "geo": geo, "blocks": blocks,
             "logins": logins, "web": web, "ip": ip_detail}


def handle(con, params, pkg_dir=None, db_path=None, now=None):
    now = int(now or time.time())
    name = params.get("q", "")
    try:
        if name == "status":
            return 200, status(con, params, now, pkg_dir=pkg_dir, db_path=db_path)
        fn = ENDPOINTS.get(name)
        if fn is None:
            return 404, {"error": "unknown endpoint %r" % name}
        return 200, fn(con, params, now)
    except BadRequest as e:
        return 400, {"error": str(e)}
