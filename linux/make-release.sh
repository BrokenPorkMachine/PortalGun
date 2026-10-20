#!/usr/bin/env bash
# make-release.sh — build a versioned PortalGun release bundle.
#
# Produces a source tarball + zip containing exactly the tracked files (no
# .git, no __pycache__, no results.jsonl) plus a SHA256SUMS manifest.
#
# Usage:
#   ./make-release.sh                 # build for the version in VERSION
#   ./make-release.sh --version 1.2.3 # override
#   ./make-release.sh --out DIR       # output dir (default: dist/)
#
# The version comes from the VERSION file unless overridden. It is embedded
# into portal/server.py's server_version banner so a running instance reports
# the release it came from.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

VERSION=""
OUT="$ROOT/dist"
DO_BANNER=1

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="$2"; shift 2;;
        --out)     OUT="$2"; shift 2;;
        --no-banner) DO_BANNER=0; shift;;
        -h|--help)
            sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
            exit 0;;
        *) echo "unknown option: $1" >&2; exit 1;;
    esac
done

cd "$ROOT"

if [ -z "$VERSION" ]; then
    [ -f VERSION ] || { echo "no VERSION file and no --version given" >&2; exit 1; }
    VERSION="$(tr -d '[:space:]' < VERSION)"
fi
echo "==> building PortalGun $VERSION"

# ---------------------------------------------------------------- preflight
echo "==> preflight checks"
fail=0
for f in portal/server.py portal/site/core.js portal/catalog.json \
         mac/start.sh linux/setup-gateway.sh linux/setup-enforcement.sh; do
    [ -f "$f" ] || { echo "  MISSING: $f" >&2; fail=1; }
done
[ "$fail" = 0 ] || exit 1

python3 -m py_compile portal/server.py || fail=1
for j in portal/site/core.js portal/tools/checkmodules.js portal/tools/testrun.js; do
    node --check "$j" || fail=1
done
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -s sh mac/start.sh || fail=1
    shellcheck -s bash linux/setup-gateway.sh || fail=1
    shellcheck -s bash linux/setup-enforcement.sh || fail=1
    shellcheck -s bash "$0" || fail=1
else
    echo "  (shellcheck not installed — skipping)"
fi
bash -n mac/start.sh || fail=1
bash -n linux/setup-gateway.sh || fail=1
bash -n linux/setup-enforcement.sh || fail=1

# catalog must match disk, or the release ships a lying index
( cd portal && python3 tools/mkcatalog.py --check ) || fail=1
[ "$fail" = 0 ] || { echo "preflight failed" >&2; exit 1; }
echo "  all checks passed"

# ---------------------------------------------------------------- banner
if [ "$DO_BANNER" = 1 ] && [ -f portal/server.py ]; then
    if grep -q 'server_version = "PortalGun/' portal/server.py; then
        python3 - "$VERSION" <<'PY'
import re, sys
v = sys.argv[1]
p = "portal/server.py"
s = open(p, encoding="utf-8").read()
new = re.sub(r'server_version = "PortalGun/[^"]*"',
             'server_version = "PortalGun/%s"' % v, s)
if new != s:
    open(p, "w", encoding="utf-8").write(new)
    print("  banner -> PortalGun/%s" % v)
else:
    print("  banner already correct")
PY
    fi
fi

# ---------------------------------------------------------------- stage
echo "==> staging"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
NAME="PortalGun-$VERSION"
STAGE="$WORK/$NAME"
mkdir -p "$STAGE"

# only tracked files — keeps .git, __pycache__, results.jsonl and editor
# droppings out of the bundle
git archive --format=tar HEAD | tar -x -C "$STAGE" 2>/dev/null || {
    echo "  git archive failed; falling back to file copy" >&2
    git ls-files -z | while IFS= read -r -d '' f; do
        mkdir -p "$STAGE/$(dirname "$f")"
        cp "$f" "$STAGE/$f"
    done
}
# include the working-tree changes that are not committed yet
if ! git diff --quiet HEAD -- 2>/dev/null; then
    git ls-files -z --modified --others --exclude-standard | \
    while IFS= read -r -d '' f; do
        [ -f "$f" ] || continue
        mkdir -p "$STAGE/$(dirname "$f")"
        cp "$f" "$STAGE/$f"
    done
fi

# VERSION file must be in the bundle
printf '%s\n' "$VERSION" > "$STAGE/VERSION"

# strip anything that should never ship
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -name '*.pyc' -delete 2>/dev/null || true
find "$STAGE" -name '.DS_Store' -delete 2>/dev/null || true
find "$STAGE" -name 'results.jsonl' -delete 2>/dev/null || true

# ---------------------------------------------------------------- archive
echo "==> archiving"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
TARBALL="$OUT/$NAME.tar.gz"
ZIP="$OUT/$NAME.zip"

rm -f "$TARBALL" "$ZIP"

# The bundle is rooted at $NAME/ so it unpacks into a single named folder.
tar -czf "$TARBALL" -C "$WORK" "$NAME"

if command -v zip >/dev/null 2>&1; then
    ( cd "$WORK" && zip -qr "$ZIP" "$NAME" -x '*.DS_Store' )
else
    echo "  (zip not installed — creating the zip with python)"
    python3 - "$WORK" "$ZIP" "$NAME" <<'PY'
import os, sys, zipfile
work, dst, name = sys.argv[1], sys.argv[2], sys.argv[3]
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(os.path.join(work, name)):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, work))
PY
fi

# ---------------------------------------------------------------- sums
echo "==> checksums"
if command -v shasum >/dev/null 2>&1; then
    ( cd "$OUT" && shasum -a 256 "$NAME.tar.gz" "$NAME.zip" > "$NAME.SHA256SUMS" )
else
    ( cd "$OUT" && sha256sum "$NAME.tar.gz" "$NAME.zip" > "$NAME.SHA256SUMS" )
fi
cat "$OUT/$NAME.SHA256SUMS"

# ---------------------------------------------------------------- verify
echo "==> verifying"
TMPV="$(mktemp -d)"
tar -xzf "$TARBALL" -C "$TMPV"
R="$TMPV/$NAME"

# the bundle must be self-contained and complete
for f in portal/server.py portal/site/core.js portal/site/index.html \
         portal/catalog.json portal/modules/CVE-2018-4233/index.html \
         mac/start.sh linux/setup-gateway.sh linux/setup-enforcement.sh \
         README.md LICENSE VERSION; do
    [ -f "$R/$f" ] || { echo "  tarball missing $f" >&2; exit 1; }
done

# nothing that should have been stripped
if find "$R" -name '__pycache__' -o -name '*.pyc' -o -name 'results.jsonl' | grep -q .; then
    echo "  tarball contains files that should have been stripped" >&2
    exit 1
fi

# the extracted copy must still parse and still serve
python3 -m py_compile "$R/portal/server.py" || { echo "  bundled server.py does not compile" >&2; exit 1; }
node --check "$R/portal/site/core.js" || { echo "  bundled core.js is invalid" >&2; exit 1; }

# and the module catalog must match the modules actually in the bundle
( cd "$R/portal" && python3 tools/mkcatalog.py --check ) \
    || { echo "  bundled catalog does not match bundled modules" >&2; exit 1; }

# smoke-test the bundled server on a spare port
if command -v python3 >/dev/null 2>&1; then
    ( cd "$R/portal" && PORTAL_TOKEN=reltest python3 server.py --port 8098 >/dev/null 2>&1 & echo $! > "$TMPV/pid" )
    sleep 2
    code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8098/healthz 2>/dev/null || echo 000)"
    kill "$(cat "$TMPV/pid")" 2>/dev/null || true
    [ "$code" = "200" ] || { echo "  bundled server did not answer /healthz (got $code)" >&2; exit 1; }
    echo "  bundled server serves OK (banner: $(grep -o 'PortalGun/[0-9.]*' "$R/portal/server.py" | head -1))"
fi

rm -rf "$TMPV"

echo
echo "release $VERSION built:"
for f in "$TARBALL" "$ZIP" "$OUT/$NAME.SHA256SUMS"; do
    sz="$(wc -c < "$f" | tr -d ' ')"
    printf "  %-10s %s\n" "$(echo "$sz" | awk '{printf "%.1fK", $1/1024}')" "$f"
done
echo
echo "next:"
echo "  git tag -a v$VERSION -m 'PortalGun $VERSION'"
echo "  git push origin v$VERSION"
echo "  gh release create v$VERSION $TARBALL $ZIP --title 'PortalGun $VERSION'"
