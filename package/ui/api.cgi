#!/bin/sh
# SecDash API. DSM runs this with the viewer's session cookie; only members of
# the DSM "administrators" group (gid 101) get data.
PKG=/var/packages/SecDash/target

deny() {
    printf 'Status: %s\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\r\n' "$1"
    printf '{"error":"%s"}\n' "$2"
    exit 0
}

# login.cgi/authenticate.cgi only evaluate GET requests.
ORIG_METHOD=$REQUEST_METHOD
REQUEST_METHOD=GET
export REQUEST_METHOD

login=$(/usr/syno/synoman/webman/login.cgi 2>/dev/null)
token=$(printf '%s\n' "$login" | sed -n 's/.*"SynoToken" *: *"\([^"]*\)".*/\1/p' | head -n 1)
[ -n "$token" ] || deny "401 Unauthorized" "not signed in to DSM"
QUERY_STRING="${QUERY_STRING:+$QUERY_STRING&}SynoToken=$token"
export QUERY_STRING

user=$(/usr/syno/synoman/webman/modules/authenticate.cgi 2>/dev/null)
[ -n "$user" ] || deny "401 Unauthorized" "not signed in to DSM"
id -G "$user" 2>/dev/null | tr ' ' '\n' | grep -qx 101 || deny "403 Forbidden" "administrators only"

REQUEST_METHOD=$ORIG_METHOD
SECDASH_USER=$user
export REQUEST_METHOD SECDASH_USER
PY=$(command -v python3 || echo /usr/bin/python3)
exec "$PY" "$PKG/lib/cgi_main.py"
