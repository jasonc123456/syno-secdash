#!/bin/sh
# SecDash API. DSM runs this with the viewer's session cookie; only members of
# the DSM "administrators" group (gid 101) get data.
PKG=/var/packages/SecDash/target
AUTH=/usr/syno/synoman/webman/modules/authenticate.cgi
LOGIN=/usr/syno/synoman/webman/login.cgi

ORIG_METHOD=$REQUEST_METHOD
TOKEN_SRC=none
AUTH_RC=-1

deny() {
    printf 'Status: %s\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\r\n' "$1"
    cookie=false; [ -n "$HTTP_COOKIE" ] && cookie=true
    printf '{"error":"%s","diag":{"uid":%s,"cookie":%s,"token":"%s","auth_rc":%s}}\n' \
        "$2" "$(id -u)" "$cookie" "$TOKEN_SRC" "$AUTH_RC"
    exit 0
}

# DSM's CSRF protection needs the SynoToken alongside the session cookie. The
# page sends it (from the DSM desktop) as ?SynoToken= or X-SYNO-TOKEN.
case "&$QUERY_STRING&" in
    *"&SynoToken="*) TOKEN_SRC=query ;;
esac
if [ "$TOKEN_SRC" = none ] && [ -n "$HTTP_X_SYNO_TOKEN" ]; then
    tok=$(printf '%s' "$HTTP_X_SYNO_TOKEN" | tr -cd 'A-Za-z0-9._-')
    QUERY_STRING="${QUERY_STRING:+$QUERY_STRING&}SynoToken=$tok"
    TOKEN_SRC=header
fi
# Changes (POST) must carry the token the page got from DSM: fetching one here
# would let another site's form post through with just the session cookie.
if [ "$TOKEN_SRC" = none ] && [ "$ORIG_METHOD" = POST ]; then
    deny "403 Forbidden" "missing SynoToken"
fi
if [ "$TOKEN_SRC" = none ] && [ -x "$LOGIN" ]; then
    tok=$(QUERY_STRING="enable_syno_token=yes" REQUEST_METHOD=GET "$LOGIN" 2>/dev/null |
          sed -n 's/.*"SynoToken" *: *"\([^"]*\)".*/\1/p' | head -n 1)
    if [ -n "$tok" ]; then
        QUERY_STRING="${QUERY_STRING:+$QUERY_STRING&}SynoToken=$tok"
        TOKEN_SRC=login
    fi
fi
export QUERY_STRING

# authenticate.cgi only evaluates GET requests; it prints the user name or nothing.
REQUEST_METHOD=GET
export REQUEST_METHOD
user=$("$AUTH" 2>/dev/null)
AUTH_RC=$?
[ -n "$user" ] || deny "401 Unauthorized" "not signed in to DSM"
id -G "$user" 2>/dev/null | tr ' ' '\n' | grep -qx 101 || deny "403 Forbidden" "administrators only"

REQUEST_METHOD=$ORIG_METHOD
SECDASH_USER=$user
export REQUEST_METHOD SECDASH_USER
PY=$(command -v python3 || echo /usr/bin/python3)
exec "$PY" "$PKG/lib/cgi_main.py"
