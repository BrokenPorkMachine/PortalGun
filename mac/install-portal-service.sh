#!/usr/bin/env bash
# install-portal-service.sh — run the PortalGun portal on the Mac as an
# always-on launchd service (no pf, no DHCP, no NAT, no Internet Sharing).
#
# This is the Mac-side counterpart of the Linux gateway service: same portal
# server, same /report and /dashboard API, but nothing is forced through it.
# Use it when the Mac has to serve the portal on its own - for example when
# the Linux gateway is down, or when the Mac is the only machine that can
# reach the devices under test.
#
# The pf enforcement in setup-captive.sh and the AP bridge in
# setup-ap-bridge.sh are NOT touched here. Those are separate concerns and
# mixing them into one script is how a lab ends up with rules that fight each
# other.
#
# Usage:
#   ./mac/install-portal-service.sh              # install + start
#   ./mac/install-portal-service.sh --status     # is it up?
#   ./mac/install-portal-service.sh --remove     # stop + uninstall
#   ./mac/install-portal-service.sh --port 8080
#   PORTAL_TOKEN=... ./mac/install-portal-service.sh
#
# The service is a per-user LaunchAgent: it starts when you log in and stops
# when you log out. That is deliberate - the portal should not outlive the
# session that set it up.
set -euo pipefail

PROG="$(basename "$0")"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
die() { echo "$PROG: $*" >&2; exit 1; }
usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }

LABEL=com.portalgun.portal
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG_DIR="$HOME/Library/Logs"
LOG="$LOG_DIR/portalgun-portal.log"
PORT=8080
REMOVE=0
STATUS=0

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--port) [ $# -ge 2 ] || die "-p needs a value"; PORT="$2"; shift 2;;
        --remove) REMOVE=1; shift;;
        --status) STATUS=1; shift;;
        -h|--help) usage; exit 0;;
        *) usage >&2; die "unknown option: $1";;
    esac
done

PYTHON_BIN="$(command -v python3 2>/dev/null || echo /usr/bin/python3)"
[ -f "$REPO_DIR/portal/server.py" ] || die "missing $REPO_DIR/portal/server.py"

# ---------------------------------------------------------------- status
if [ "$STATUS" = 1 ]; then
    echo "service : $(launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | sed -n 's/^[[:space:]]*state = //p' | head -1 || echo 'not loaded')"
    echo "plist   : $PLIST"
    if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "listener: :$PORT"
    else
        echo "listener: nothing on :$PORT"
    fi
    echo "log     : $LOG"
    exit 0
fi

# ---------------------------------------------------------------- remove
if [ "$REMOVE" = 1 ]; then
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    rm -f "$PLIST"
    echo "portal service removed (the portal is offline now)"
    exit 0
fi

# ---------------------------------------------------------------- token
# Same token as the operator's other installs, so one code works everywhere.
if [ -n "${PORTAL_TOKEN:-}" ]; then
    TOKEN="$PORTAL_TOKEN"
elif [ -s "$HOME/.portalg_token" ]; then
    TOKEN="$(cat "$HOME/.portalg_token")"
elif [ -s "$HOME/.lancheck_token" ]; then
    TOKEN="$(cat "$HOME/.lancheck_token")"
else
    TOKEN="$(openssl rand -hex 12 2>/dev/null || head -c 24 /dev/urandom | xxd -p | tr -d '\n')"
    printf '%s\n' "$TOKEN" > "$HOME/.portalg_token"
    chmod 600 "$HOME/.portalg_token"
    echo "(created portal token in $HOME/.portalg_token)"
fi

mkdir -p "$HOME/Library/LaunchAgents" "$LOG_DIR"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_BIN</string>
        <string>$REPO_DIR/portal/server.py</string>
        <string>--port</string>
        <string>$PORT</string>
    </array>
    <key>WorkingDirectory</key><string>$REPO_DIR/portal</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PORTAL_TOKEN</key><string>$TOKEN</string>
    </dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>$LOG</string>
    <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
EOF
chmod 600 "$PLIST"

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>/dev/null \
    || launchctl load -w "$PLIST" 2>/dev/null \
    || die "could not load $PLIST"

# The firewall may ask once when a server starts listening.
if ! lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    sleep 2
fi

HOSTNAME_LOCAL="$(scutil --get LocalHostName 2>/dev/null || hostname -s).local"
cat <<EOF

portal service installed (always-on, per-user).

  Portal   : http://$HOSTNAME_LOCAL:$PORT/
  Dashboard: http://$HOSTNAME_LOCAL:$PORT/dashboard
  Token    : $TOKEN
  log      : $LOG

manage it:
  ./mac/install-portal-service.sh --status
  ./mac/install-portal-service.sh --remove
EOF
