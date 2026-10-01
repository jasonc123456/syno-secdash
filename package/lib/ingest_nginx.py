"""Parse nginx access logs ("combined" format, optionally with a trailing host field)."""
import re

from common import event_hash, norm_ip, parse_ts

LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<req>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
    r'(?P<rest>.*)$')
_HOST = re.compile(r'(?:^|\s)"?(?:host=)?(?P<host>[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d+)?)"?\s*$')

MAX_PATH = 300
MAX_UA = 300


def parse_line(line):
    m = LINE.match(line.rstrip("\n"))
    if not m:
        return None
    ip = norm_ip(m.group("ip"))
    ts, _ = parse_ts(m.group("time"))
    if ip is None or ts is None:
        return None
    parts = m.group("req").split(" ")
    method, path = (parts[0], parts[1]) if len(parts) >= 2 else (None, m.group("req") or None)
    if path:
        path = path.split("?", 1)[0][:MAX_PATH]
    host = None
    hm = _HOST.search(m.group("rest") or "")
    if hm:
        host = hm.group("host")
    b = m.group("bytes")
    return {
        "ts": ts, "ip": ip, "host": host, "method": method, "path": path,
        "status": int(m.group("status")), "bytes": 0 if b == "-" else int(b),
        "ua": (m.group("ua") or "")[:MAX_UA] or None,
        "hash": event_hash("nginx", line.rstrip("\n")),
    }


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ev = parse_line(line)
            if ev:
                yield ev
