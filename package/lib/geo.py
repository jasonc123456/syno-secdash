"""IP → country / city / ASN using DB-IP Lite .mmdb files (CC BY 4.0).

Lookup order: City Lite (if downloaded) else Country Lite (bundled), plus ASN
Lite when present. Databases are refreshed monthly by update().
"""
import gzip
import os
import shutil
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))
import maxminddb  # noqa: E402

from common import is_public  # noqa: E402

DB_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
KINDS = ("city", "asn")


def _name(rec, key):
    try:
        return rec[key]["names"]["en"]
    except (KeyError, TypeError):
        return None


class Geo:
    def __init__(self, dirs):
        """dirs: directories searched in order for dbip-*-lite.mmdb files."""
        self.dirs = dirs
        self.city = self._open("city") or self._open("country")
        self.asn = self._open("asn")

    def _open(self, kind):
        for d in self.dirs:
            p = os.path.join(d, "dbip-%s-lite.mmdb" % kind)
            if os.path.exists(p):
                try:
                    return maxminddb.open_database(p, maxminddb.MODE_MMAP)
                except Exception:
                    continue
        return None

    def close(self):
        for r in (self.city, self.asn):
            if r:
                r.close()

    def lookup(self, ip):
        if not is_public(ip):
            return {"cc": "LAN", "country": "Private network"}
        info = {}
        if self.city:
            rec = self.city.get(ip) or {}
            country = rec.get("country") or {}
            info["cc"] = country.get("iso_code")
            info["country"] = _name(rec, "country")
            info["city"] = _name(rec, "city")
            subs = rec.get("subdivisions") or []
            if subs:
                info["region"] = (subs[0].get("names") or {}).get("en")
            loc = rec.get("location") or {}
            info["lat"] = loc.get("latitude")
            info["lon"] = loc.get("longitude")
        if self.asn:
            rec = self.asn.get(ip) or {}
            info["asn"] = rec.get("autonomous_system_number")
            info["org"] = rec.get("autonomous_system_organization")
        return info

    def db_date(self):
        if not self.city:
            return None
        return time.strftime("%Y-%m-%d", time.gmtime(self.city.metadata().build_epoch))


def _months_to_try(now=None):
    t = time.gmtime(now or time.time())
    y, m = t.tm_year, t.tm_mon
    prev = (y - 1, 12) if m == 1 else (y, m - 1)
    return ["%04d-%02d" % (y, m), "%04d-%02d" % prev]


def update(dest_dir, log=print, now=None):
    """Download the current City Lite and ASN Lite databases into dest_dir.

    Falls back to last month's file early in the month. Returns the list of
    kinds that were updated.
    """
    os.makedirs(dest_dir, exist_ok=True)
    updated = []
    for kind in KINDS:
        for month in _months_to_try(now):
            url = DB_URL.format(kind=kind, month=month)
            tmp = os.path.join(dest_dir, ".dbip-%s.tmp" % kind)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "syno-secdash"})
                with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as out:
                    with gzip.GzipFile(fileobj=resp) as gz:
                        shutil.copyfileobj(gz, out, 1 << 20)
                # validate before swapping in
                maxminddb.open_database(tmp, maxminddb.MODE_FILE).close()
                os.replace(tmp, os.path.join(dest_dir, "dbip-%s-lite.mmdb" % kind))
                log("geo: updated %s from %s" % (kind, month))
                updated.append(kind)
                break
            except Exception as e:
                log("geo: %s %s failed: %s" % (kind, month, e))
                if os.path.exists(tmp):
                    os.remove(tmp)
    return updated
