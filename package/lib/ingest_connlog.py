"""Read login events from DSM's connection log database (Log Center > Connection).

DSM stores these in /var/log/synolog/.SYNOCONNDB. The table holds one free-text
message per row, e.g.

  User [admin] from [203.0.113.5] signed in to [DSM] successfully via [password].
  User [admin] from [203.0.113.5] failed to sign in to [DSM] via [password] due to authorization failure.
  User [admin] from [203.0.113.5] failed to log in via [SSH] due to authorization failure.
  Host [203.0.113.5] was blocked via [SSH].

The table and column names differ between DSM versions, so they are detected.
"""
import re
import sqlite3

from common import event_hash, norm_ip

_USER = re.compile(r"User \[([^\]]*)\]", re.I)
_IP = re.compile(r"(?:from|Host|IP address|IP)\s*\[([^\]]+)\]", re.I)
_SERVICE = re.compile(
    r"(?:sign(?:ed)? in to|log(?:ged)? in(?: to)?|logged into|blocked|via)\s*\[([^\]]+)\]", re.I)

TIME_COLS = ("utcsec", "time", "timestamp", "logtime", "date")
MSG_COLS = ("msg", "message", "event", "content")


def classify(msg):
    """Return (result, user, ip, service) for a connection-log message, or None."""
    low = msg.lower()
    if "blocked" in low:
        result = "blocked"
    elif "fail" in low or "denied" in low or "invalid" in low:
        result = "fail"
    elif "successfully" in low or "signed in" in low or "logged in" in low:
        result = "success"
    else:
        return None
    m_user = _USER.search(msg)
    m_ip = _IP.search(msg)
    services = _SERVICE.findall(msg)
    # "signed in to [DSM] successfully via [password]": the service is the first
    # bracket after "to"; "[password]" is the auth method.
    service = None
    for s in services:
        if s.lower() not in ("password", "passkey", "2fa", "otp", "sso", "certificate"):
            service = s
            break
    return (result,
            m_user.group(1) if m_user else None,
            norm_ip(m_ip.group(1)) if m_ip else None,
            service)


def _find_table(con):
    for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        cols = [r[1].lower() for r in con.execute('PRAGMA table_info("%s")' % name)]
        msg = next((c for c in MSG_COLS if c in cols), None)
        tcol = next((c for c in TIME_COLS if c in cols), None)
        if msg and tcol:
            return name, cols, msg, tcol
    return None


def max_rowid(path):
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    try:
        found = _find_table(con)
        if not found:
            return 0
        return con.execute('SELECT COALESCE(MAX(rowid), 0) FROM "%s"' % found[0]).fetchone()[0]
    finally:
        con.close()


def read(path, since_id=0):
    """Yield (row_id, event) for rows with rowid > since_id."""
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    try:
        found = _find_table(con)
        if not found:
            raise ValueError("no connection-log table with message/time columns in %s" % path)
        table, cols, msg_col, time_col = found
        user_col = next((c for c in ("username", "user", "who") if c in cols), None)
        ip_col = next((c for c in ("ip", "ipaddr", "host") if c in cols), None)
        sql = 'SELECT rowid, "%s", "%s"%s%s FROM "%s" WHERE rowid > ? ORDER BY rowid' % (
            time_col, msg_col,
            ', "%s"' % user_col if user_col else ", NULL",
            ', "%s"' % ip_col if ip_col else ", NULL",
            table)
        for rowid, ts, msg, col_user, col_ip in con.execute(sql, (since_id,)):
            if not msg or ts is None:
                continue
            parsed = classify(str(msg))
            if parsed is None:
                continue
            result, user, ip, service = parsed
            try:
                ts = int(ts)
            except (TypeError, ValueError):
                continue
            ip = ip or norm_ip(col_ip)
            user = user or col_user
            yield rowid, {
                "ts": ts, "ip": ip, "user": user, "service": service,
                "result": result, "source": "connlog",
                "hash": event_hash("connlog", ts, msg),
            }
    finally:
        con.close()
