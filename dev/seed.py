#!/usr/bin/env python3
"""Create dev/demo.db with a year of synthetic but realistic-looking data.

Only documentation address space (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24, 2001:db8::/32) and documentation ASNs (64496-64511) are used,
so screenshots never show a real address. Geo rows are written directly.
"""
import os
import random
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "package", "lib"))
import store  # noqa: E402
from common import event_hash  # noqa: E402

DB = os.path.join(ROOT, "dev", "demo.db")

# (cc, country, weight, [(city, lat, lon), ...])
PLACES = [
    ("CN", "China", 22, [("Beijing", 39.9, 116.4), ("Shanghai", 31.2, 121.5), ("Shenzhen", 22.5, 114.1)]),
    ("US", "United States", 14, [("Ashburn", 39.0, -77.5), ("San Jose", 37.3, -121.9), ("Dallas", 32.8, -96.8)]),
    ("RU", "Russia", 10, [("Moscow", 55.8, 37.6), ("Saint Petersburg", 59.9, 30.3)]),
    ("NL", "Netherlands", 7, [("Amsterdam", 52.4, 4.9)]),
    ("DE", "Germany", 6, [("Frankfurt am Main", 50.1, 8.7), ("Nuremberg", 49.5, 11.1)]),
    ("VN", "Vietnam", 6, [("Hanoi", 21.0, 105.8), ("Ho Chi Minh City", 10.8, 106.7)]),
    ("IN", "India", 5, [("Mumbai", 19.1, 72.9), ("Bengaluru", 12.97, 77.6)]),
    ("BR", "Brazil", 5, [("São Paulo", -23.5, -46.6)]),
    ("KR", "South Korea", 4, [("Seoul", 37.6, 127.0)]),
    ("SG", "Singapore", 4, [("Singapore", 1.35, 103.8)]),
    ("HK", "Hong Kong", 3, [("Hong Kong", 22.3, 114.2)]),
    ("FR", "France", 3, [("Paris", 48.9, 2.35)]),
    ("GB", "United Kingdom", 3, [("London", 51.5, -0.13)]),
    ("ID", "Indonesia", 3, [("Jakarta", -6.2, 106.8)]),
    ("IR", "Iran", 2, [("Tehran", 35.7, 51.4)]),
    ("UA", "Ukraine", 2, [("Kyiv", 50.45, 30.5)]),
    ("TW", "Taiwan", 2, [("Taipei", 25.0, 121.5)]),
    ("TR", "Turkey", 2, [("Istanbul", 41.0, 28.98)]),
    ("RO", "Romania", 1, [("Bucharest", 44.4, 26.1)]),
    ("ZA", "South Africa", 1, [("Johannesburg", -26.2, 28.0)]),
    ("AR", "Argentina", 1, [("Buenos Aires", -34.6, -58.4)]),
    ("CA", "Canada", 1, [("Toronto", 43.65, -79.4)]),
]
ORGS = ["ExampleNet Hosting", "Doc Cloud Ltd", "Sample Telecom", "Placeholder VPS", "Demo Broadband",
        "Test Datacenter", "Illustrative ISP", "Mock Networks"]
USERS = ["admin", "root", "administrator", "test", "user", "guest", "ubuntu", "oracle", "support",
         "postgres", "ftpuser", "pi", "backup", "nas"]
PATHS = ["/wp-login.php", "/.env", "/xmlrpc.php", "/admin/", "/phpmyadmin/", "/.git/config",
         "/cgi-bin/luci", "/boaform/admin/formLogin", "/api/v1/login", "/owa/auth/logon.aspx",
         "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/HNAP1/", "/manager/html",
         "/actuator/env", "/server-status", "/solr/admin/info/system"]
UAS = ["Mozilla/5.0 zgrab/0.x", "python-requests/2.31", "curl/7.88.1", "Go-http-client/1.1",
       "Mozilla/5.0 (compatible; CensysInspect/1.1)", "masscan/1.3", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]


def main():
    rnd = random.Random(42)
    if os.path.exists(DB):
        os.remove(DB)
    con = store.connect(DB)
    now = int(time.time())
    weights = [p[2] for p in PLACES]

    ip_pool = ["192.0.2.%d" % i for i in range(1, 255)] + ["198.51.100.%d" % i for i in range(1, 255)] + \
              ["203.0.113.%d" % i for i in range(1, 255)] + \
              ["2001:db8:%x:%x::%x" % (rnd.randrange(65536), rnd.randrange(65536), rnd.randrange(1, 65536))
               for _ in range(1400)]
    rnd.shuffle(ip_pool)
    geo = {}
    for ip in ip_pool:
        cc, country, _, cities = rnd.choices(PLACES, weights)[0]
        city, lat, lon = rnd.choice(cities)
        geo[ip] = {"cc": cc, "country": country, "city": city, "region": None,
                   "lat": lat + rnd.uniform(-0.2, 0.2), "lon": lon + rnd.uniform(-0.2, 0.2),
                   "asn": 64496 + rnd.randrange(16), "org": rnd.choice(ORGS)}

    # attack intensity grows a little over the year, with bursts
    def when(days=365):
        age = rnd.random() ** 1.6 * days * 86400
        return now - int(age)

    blocks, auth, http = [], [], []
    attackers = ip_pool[:1800]
    for ip in attackers:
        t0 = when()
        n = rnd.choice([3, 5, 5, 8, 12, 30]) if rnd.random() < 0.9 else rnd.randrange(50, 400)
        svc = rnd.choices(["SSH", "DSM", "FTP", "SMB"], [60, 25, 10, 5])[0]
        for k in range(n):
            ts = t0 - rnd.randrange(0, 1800) + k * rnd.randrange(1, 20)
            # nights are busier (in the NAS's timezone)
            if rnd.random() < 0.35:
                ts -= (time.localtime(ts).tm_hour - rnd.choice([1, 2, 3, 4])) * 3600
            user = rnd.choice(USERS)
            auth.append({"ts": ts, "ip": ip, "user": user, "service": svc, "result": "fail",
                         "source": "connlog" if svc != "SSH" else "syslog",
                         "hash": event_hash("demo", ip, ts, k)})
        auth.append({"ts": t0 + 5, "ip": ip, "user": None, "service": svc, "result": "blocked",
                     "source": "connlog", "hash": event_hash("demo-b", ip, t0)})
        blocks.append({"ip": ip, "first_seen": t0 + 5,
                       "expire": 0 if rnd.random() < 0.7 else t0 + 86400 * rnd.choice([1, 7, 30]),
                       "deny": 1, "type": "auto"})

    # legitimate sign-ins from home + phone, plus two from new places recently
    home = "192.0.2.10"
    geo[home] = {"cc": "CA", "country": "Canada", "city": "Toronto", "lat": 43.65, "lon": -79.4,
                 "asn": 64510, "org": "Illustrative ISP"}
    for day in range(365):
        for _ in range(rnd.randrange(0, 4)):
            ts = now - day * 86400 - rnd.randrange(8 * 3600, 22 * 3600)
            auth.append({"ts": ts, "ip": home, "user": "nasadmin", "service": rnd.choice(["DSM", "DSM", "SMB"]),
                         "result": "success", "source": "connlog", "hash": event_hash("ok", ts)})
    for ip, cc, country, city, lat, lon, ago in (
            ("198.51.100.200", "JP", "Japan", "Tokyo", 35.7, 139.7, 3 * 3600),
            ("198.51.100.201", "CA", "Canada", "Montreal", 45.5, -73.6, 2 * 86400)):
        geo[ip] = {"cc": cc, "country": country, "city": city, "lat": lat, "lon": lon,
                   "asn": 64511, "org": "Sample Telecom"}
        auth.append({"ts": now - ago, "ip": ip, "user": "nasadmin", "service": "DSM", "result": "success",
                     "source": "connlog", "hash": event_hash("new", ip)})

    # reverse proxy: normal traffic + scanners
    for i in range(12000):
        ts = when(120)
        if rnd.random() < 0.55:
            ip, path, status, ua = home, rnd.choice(["/", "/photo/", "/api/entry.cgi", "/drive/"]), \
                rnd.choices([200, 304, 302], [80, 15, 5])[0], "Mozilla/5.0 (X11; Linux x86_64)"
        else:
            ip = rnd.choice(attackers[:400])
            path = rnd.choice(PATHS)
            status = rnd.choices([404, 403, 401, 400, 502, 200], [70, 12, 8, 5, 3, 2])[0]
            ua = rnd.choice(UAS)
        http.append({"ts": ts, "ip": ip, "host": "nas.example.com", "method": rnd.choice(["GET", "GET", "POST"]),
                     "path": path, "status": status, "bytes": rnd.randrange(100, 9000), "ua": ua,
                     "hash": event_hash("http", i)})

    with con:
        store.sync_blocks(con, blocks, now=now)
        # older blocks that DSM has since released
        for b in blocks[: len(blocks) // 5]:
            con.execute("UPDATE blocks SET active=0 WHERE ip=?", (b["ip"],))
        store.add_auth_events(con, auth)
        store.add_http_events(con, http)
        for ip, g in geo.items():
            store.put_geo(con, ip, g, now=now)
        store.set_meta(con, "collector_last_run", now - 140)
        store.set_meta(con, "collector_info", "collected=demo\ndsm=7.2.2\nautoblock=yes\nconnlog=yes\n"
                       "syslog_files=auth.log.log messages.log\nnginx_files=access.log")
        store.set_meta(con, "geo_db_date", time.strftime("%Y-%m-01"))
        store.set_meta(con, "geo_update_month", time.strftime("%Y-%m"))
    con.close()
    print("wrote %s: %d blocks, %d auth events, %d http events" % (DB, len(blocks), len(auth), len(http)))


if __name__ == "__main__":
    main()
