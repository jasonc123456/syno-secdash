#!/bin/sh
# Build dist/SecDash-<version>-noarch.spk
#
#   ./build.sh                 # version from the latest v* git tag (or 0.1.0)
#   SPK_VERSION=1.2.3 ./build.sh
set -eu

cd "$(dirname "$0")"
ROOT=$(pwd)
BUILD="$ROOT/build/spk"
DIST="$ROOT/dist"

VER=${SPK_VERSION:-$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null | sed 's/^v//' || true)}
VER=${VER:-0.1.0}
NUM=$(git rev-list --count HEAD 2>/dev/null || echo 0)
VERSION="$VER-$(printf '%04d' "$NUM")"

# Bundled GeoIP (DB-IP Country Lite, CC BY 4.0) so maps work before the first monthly download.
if [ ! -f package/geo/dbip-country-lite.mmdb ]; then
    echo "fetching DB-IP Country Lite"
    mkdir -p package/geo
    python3 - <<'PY'
import gzip, shutil, time, urllib.request
t = time.gmtime()
months = ["%04d-%02d" % (t.tm_year, t.tm_mon),
          "%04d-%02d" % ((t.tm_year, t.tm_mon - 1) if t.tm_mon > 1 else (t.tm_year - 1, 12))]
for m in months:
    url = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz" % m
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "syno-secdash-build"})
        with urllib.request.urlopen(req, timeout=120) as r, gzip.GzipFile(fileobj=r) as gz, \
                open("package/geo/dbip-country-lite.mmdb", "wb") as out:
            shutil.copyfileobj(gz, out)
        print("  got", m)
        break
    except Exception as e:
        print("  %s: %s" % (m, e))
else:
    raise SystemExit("could not download DB-IP Country Lite")
PY
fi

rm -rf "$BUILD"
mkdir -p "$BUILD" "$DIST"

# package.tgz: everything installed to /var/packages/SecDash/target
tar -czf "$BUILD/package.tgz" --owner=0 --group=0 \
    --exclude='__pycache__' --exclude='*.pyc' -C package .

sed "s/@VERSION@/$VERSION/" INFO.in > "$BUILD/INFO"
echo "checksum=\"$(md5sum "$BUILD/package.tgz" | cut -d' ' -f1)\"" >> "$BUILD/INFO"

cp -r scripts conf WIZARD_UIFILES "$BUILD/"
cp PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG "$BUILD/"
chmod 755 "$BUILD"/scripts/*

OUT="$DIST/SecDash-$VERSION-noarch.spk"
tar -cf "$OUT" --owner=0 --group=0 -C "$BUILD" \
    INFO package.tgz scripts conf WIZARD_UIFILES PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG
echo "built $OUT ($(du -h "$OUT" | cut -f1))"
