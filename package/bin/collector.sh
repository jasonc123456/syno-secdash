#!/bin/sh
# SecDash collector. Paste this into DSM Task Scheduler as a root
# "User-defined script" task that runs every 5 minutes.
#
# It only READS security data that needs root and hands a copy to the
# unprivileged SecDash package. Files are staged in a private root-owned temp
# dir, then unpacked *as the package user*, so nothing is ever written as root
# into a directory the package can modify.

PKG_USER=sc-secdash
INBOX=/var/packages/SecDash/var/inbox
MAX_LOG_BYTES=5000000
# Reverse-proxy access logs in nginx "combined" format. Add more globs
# (space-separated) if your proxy logs elsewhere.
NGINX_LOGS="/var/log/nginx/*access*.log"

# Package not installed (or uninstalled): do nothing.
[ -d "$INBOX" ] && id "$PKG_USER" >/dev/null 2>&1 || exit 0

STAGE=$(mktemp -d /tmp/secdash.XXXXXX) || exit 1
trap 'rm -rf "$STAGE"' EXIT INT TERM
mkdir "$STAGE/syslog" "$STAGE/nginx"

snapshot_db() {  # consistent copy of a live SQLite DB (handles WAL)
    [ -f "$1" ] || return 0
    /usr/bin/python3 -c 'import sqlite3,sys
s=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True); d=sqlite3.connect(sys.argv[2])
s.backup(d); d.close(); s.close()' "$1" "$2" 2>/dev/null || cp "$1" "$2"
}

snapshot_db /etc/synoautoblock.db "$STAGE/autoblock.db"
snapshot_db /var/log/synolog/.SYNOCONNDB "$STAGE/connlog.db"

# System log: copy only the "Host [ip] was blocked via [service]" lines.
[ -f /var/log/synolog/.SYNOSYSDB ] && /usr/bin/python3 -c 'import sqlite3,sys
s=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True); d=sqlite3.connect(sys.argv[2])
d.execute("CREATE TABLE logs(id INTEGER PRIMARY KEY, time INTEGER, msg TEXT)")
d.executemany("INSERT INTO logs VALUES (?,?,?)", s.execute("SELECT id, time, msg FROM logs"
  " WHERE msg LIKE '"'"'Host [%] was blocked via%'"'"'"))
d.commit(); d.close(); s.close()' /var/log/synolog/.SYNOSYSDB "$STAGE/sysdb.db" 2>/dev/null

for f in /var/log/auth.log /var/log/messages; do
    [ -f "$f" ] || continue
    tail -c "$MAX_LOG_BYTES" "$f" | grep -aE 'sshd\[|ftpd\[|pam_unix\(webui:auth\)' \
        > "$STAGE/syslog/$(basename "$f").log"
done

n=0
for f in $NGINX_LOGS; do
    [ -f "$f" ] || continue
    n=$((n + 1))
    tail -c "$MAX_LOG_BYTES" "$f" > "$STAGE/nginx/$n-$(basename "$f")"
done

{
    echo "collected=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "dsm=$(sed -n 's/^productversion="\(.*\)"/\1/p' /etc.defaults/VERSION)"
    echo "autoblock=$( [ -f "$STAGE/autoblock.db" ] && echo yes || echo missing)"
    echo "connlog=$( [ -f "$STAGE/connlog.db" ] && echo yes || echo missing)"
    echo "sysdb=$( [ -f "$STAGE/sysdb.db" ] && echo yes || echo missing)"
    echo "syslog_files=$(ls "$STAGE/syslog" | tr '\n' ' ')"
    echo "nginx_files=$(ls "$STAGE/nginx" | tr '\n' ' ')"
} > "$STAGE/collector.txt"

BATCH="batch-$(date +%s)"
# $INBOX and $BATCH are fixed strings/digits, so inlining them is safe.
UNPACK="umask 077; t=\$(mktemp -d '$INBOX/.incoming.XXXXXX') && tar -xf - -C \"\$t\" --no-same-owner && mv \"\$t\" '$INBOX/$BATCH'"
if command -v sudo >/dev/null 2>&1; then
    tar -cf - -C "$STAGE" . | sudo -u "$PKG_USER" /bin/sh -c "$UNPACK"
else
    tar -cf - -C "$STAGE" . | su -s /bin/sh -c "$UNPACK" "$PKG_USER"
fi
