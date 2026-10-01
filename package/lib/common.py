"""Helpers shared by the ingesters."""
import calendar
import hashlib
import ipaddress
import re
import time
from datetime import datetime, timedelta, timezone


def norm_ip(value):
    """Return a canonical IP string, or None if value is not an IP.

    DSM stores some addresses in expanded IPv6 form (IPStd) and IPv4 as
    ::ffff:a.b.c.d; both collapse to the short form here.
    """
    if not value:
        return None
    value = str(value).strip().strip("[]")
    if "%" in value:
        value = value.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def event_hash(*parts):
    h = hashlib.sha1()
    for p in parts:
        h.update(str(p).encode("utf-8", "replace"))
        h.update(b"\x1f")
    return h.hexdigest()


_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_ISO_RE = re.compile(
    r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.\d+)?\s*(Z|[+-]\d\d:?\d\d)?")
_BSD_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)")
_CLF_RE = re.compile(r"^(\d\d)/([A-Z][a-z]{2})/(\d{4}):(\d\d):(\d\d):(\d\d)\s*([+-]\d{4})?")


def _tz(tzs):
    if not tzs or tzs == "Z":
        return timezone.utc
    tzs = tzs.replace(":", "")
    sign = -1 if tzs[0] == "-" else 1
    return timezone(sign * timedelta(hours=int(tzs[1:3]), minutes=int(tzs[3:5])))


def local_offset():
    """Current local UTC offset in seconds (the NAS timezone)."""
    return -time.altzone if time.localtime().tm_isdst > 0 else -time.timezone


def parse_ts(text, now=None):
    """Parse the timestamp formats DSM logs use. Returns (unix_ts, rest) or (None, text).

    Supports ISO 8601 (DSM 7 syslog), BSD syslog "Sep 30 23:40:01" (no year,
    local time) and nginx "30/Sep/2026:23:40:01 +0800".
    """
    m = _ISO_RE.match(text)
    if m:
        y, mo, d, hh, mi, ss, tzs = m.groups()
        dt = datetime(int(y), int(mo), int(d), int(hh), int(mi), int(ss))
        if tzs:
            ts = int(dt.replace(tzinfo=_tz(tzs)).timestamp())
        else:
            ts = int(time.mktime(dt.timetuple()))
        return ts, text[m.end():]
    m = _CLF_RE.match(text)
    if m:
        d, mon, y, hh, mi, ss, tzs = m.groups()
        dt = datetime(int(y), _MONTHS.get(mon, 1), int(d), int(hh), int(mi), int(ss))
        if tzs:
            ts = int(dt.replace(tzinfo=_tz(tzs)).timestamp())
        else:
            ts = int(time.mktime(dt.timetuple()))
        return ts, text[m.end():]
    m = _BSD_RE.match(text)
    if m and m.group(1) in _MONTHS:
        now = now or time.time()
        year = time.localtime(now).tm_year
        mon, d, hh, mi, ss = m.groups()
        tt = (year, _MONTHS[mon], int(d), int(hh), int(mi), int(ss), 0, 0, -1)
        ts = int(time.mktime(tt))
        if ts > now + 86400:  # December log line read in January
            ts = int(time.mktime((year - 1,) + tt[1:]))
        return ts, text[m.end():]
    return None, text


def utc_ts(y, mo, d, hh=0, mi=0, ss=0):
    return calendar.timegm((y, mo, d, hh, mi, ss, 0, 0, 0))
