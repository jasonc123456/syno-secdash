#!/bin/sh
# SecDash discovery probe. READ-ONLY: prints where DSM keeps the security data
# SecDash needs and what it looks like, so the parsers can match your DSM build.
#
#   sudo sh discover.sh            # prints to screen and writes discover-<host>.txt
#
# IPv4 addresses are masked to a.b.x.x, IPv6 to their first two groups, and
# usernames are replaced with "user".
# Nothing on the system is modified.

[ "$(id -u)" = "0" ] || { echo "Run as root: sudo sh $0" >&2; exit 1; }

OUT="discover-$(hostname).txt"
PY=$(command -v python3 || echo /usr/bin/python3)

mask() {
    sed -E \
        -e 's/\b([0-9]{1,3}\.[0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}\b/\1.x.x/g' \
        -e 's/\b([0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4})(:[0-9a-fA-F]{0,4}){2,}::?[0-9a-fA-F]{0,4}\b/\1:x:x/g' \
        -e 's/\b([0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4})::[0-9a-fA-F:]*\b/\1:x:x/g' \
        -e 's/User \[[^]]*\]/User [user]/g' \
        -e 's/(for (invalid user )?)[A-Za-z0-9._-]+ from/\1user from/g'
}

section() { printf '\n===== %s =====\n' "$1"; }

sqlite_probe() {
    # $1 = db path; prints schema, row count and 5 newest rows of each table
    "$PY" - "$1" <<'PYEOF'
import sqlite3, sys
db = sys.argv[1]
con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
for (name, sql) in con.execute("SELECT name, sql FROM sqlite_master WHERE type='table'"):
    print("-- table %s" % name)
    print(sql)
    try:
        n = con.execute('SELECT COUNT(*) FROM "%s"' % name).fetchone()[0]
        print("-- rows: %d" % n)
        cur = con.execute('SELECT * FROM "%s" ORDER BY rowid DESC LIMIT 5' % name)
        print("-- columns: %s" % [d[0] for d in cur.description])
        for row in cur:
            print(row)
    except Exception as e:
        print("-- error: %s" % e)
PYEOF
}

{
section "system"
cat /etc.defaults/VERSION 2>/dev/null | grep -E 'productversion|buildnumber|majorversion'
uname -m
echo "python3: $("$PY" --version 2>&1) at $PY"
for t in sqlite3 sudo su tar gzip; do printf '%s: %s\n' "$t" "$(command -v $t || echo MISSING)"; done
ls -d /var/packages/Python3* 2>/dev/null

section "auto block db"
for f in /etc/synoautoblock.db /etc.defaults/synoautoblock.db; do
    [ -f "$f" ] && { ls -la "$f"; sqlite_probe "$f"; }
done

section "synolog directory"
ls -la /var/log/synolog/ 2>/dev/null

section "connection log dbs"
for f in /var/log/synolog/.SYNOCONNDB /var/log/synolog/.SYNOSYSDB; do
    [ -f "$f" ] && { echo "### $f"; ls -la "$f"*; sqlite_probe "$f"; }
done

section "syslog ssh/ftp/smb auth lines"
for f in /var/log/auth.log /var/log/messages /var/log/secure; do
    [ -f "$f" ] || continue
    echo "### $f ($(wc -c <"$f") bytes)"
    grep -aE 'sshd|ftpd|smbd|Failed|Accepted|Invalid user|authentication failure' "$f" | tail -n 15
done
ls -la /var/log/*.log 2>/dev/null | head -40

section "nginx / reverse proxy"
ls -la /var/log/nginx/ 2>/dev/null
for f in /var/log/nginx/*access*; do
    [ -f "$f" ] && { echo "### $f"; tail -n 5 "$f"; }
done
grep -rhoE '^\s*(access_log|log_format)[^;]*;' /etc/nginx/nginx.conf /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null | sort | uniq -c | head -20
ls /etc/nginx/sites-enabled/ /usr/local/etc/nginx/conf.d/ /usr/local/etc/nginx/sites-enabled/ 2>/dev/null
grep -l -r 'proxy_pass' /etc/nginx/ 2>/dev/null | head -5

section "done"
echo "Written to $OUT. Check it looks masked, then share it."
} 2>&1 | mask | tee "$OUT"
