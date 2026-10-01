"""Read a snapshot of DSM's auto-block database (/etc/synoautoblock.db).

Known DSM 7 layout: table AutoBlockIP(IP, RecordTime, ExpireTime, Deny, IPStd,
Type, Meta). Column names are matched case-insensitively so small schema
differences between DSM builds don't break ingestion.
"""
import sqlite3

from common import norm_ip

_TYPES = {0: "auto", 1: "manual"}


def _pick(cols, *names):
    for n in names:
        if n.lower() in cols:
            return cols[n.lower()]
    return None


def read(path):
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    try:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        table = next((t for t in tables if t.lower() == "autoblockip"), None)
        if table is None:
            raise ValueError("no AutoBlockIP table in %s (tables: %s)" % (path, tables))
        cur = con.execute('SELECT * FROM "%s"' % table)
        cols = {d[0].lower(): i for i, d in enumerate(cur.description)}
        c_ip = _pick(cols, "IP")
        c_std = _pick(cols, "IPStd")
        c_rec = _pick(cols, "RecordTime")
        c_exp = _pick(cols, "ExpireTime")
        c_deny = _pick(cols, "Deny")
        c_type = _pick(cols, "Type")
        out = []
        for row in cur:
            ip = norm_ip(row[c_ip]) if c_ip is not None else None
            if ip is None and c_std is not None:
                ip = norm_ip(row[c_std])
            if ip is None:
                continue
            t = row[c_type] if c_type is not None else None
            out.append({
                "ip": ip,
                "first_seen": int(row[c_rec] or 0) if c_rec is not None else 0,
                "expire": int(row[c_exp] or 0) if c_exp is not None else 0,
                "deny": int(row[c_deny]) if c_deny is not None and row[c_deny] is not None else 1,
                "type": _TYPES.get(t, str(t) if t is not None else None),
            })
        return out
    finally:
        con.close()
