#!/bin/sh
# On-demand launcher for PortalGun (macOS).
#
# The portal is OFFLINE unless this script is running. Nothing is installed,
# no DHCP/DNS/NAT is configured - nothing is forced through the Mac.
#
#   ./start.sh [port]            # default port 8080
#   PORT=8080 ./start.sh
#   ./start.sh --gateway [port]  # captive-gateway mode (needs setup-captive.sh)
#   ./start.sh --help            # usage only
#
# Then open the printed URL on each device you want to test.
# Ctrl-C stops everything.
#
# --gateway is the one difference between the two modes: it wires POST
# /login to the captive-auth helper, so a client that signs in at the portal
# page is granted internet access by the pf rules in setup-captive.sh. The
# enforcement itself has to be applied first:
#
#   sudo ./mac/setup-captive.sh
#
set -eu

usage() {
    sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
}

GATEWAY=0
case "${1:-}" in
    -h|--help) usage; exit 0;;
    --gateway) GATEWAY=1; shift;;
esac

cd "$(dirname "$0")/../portal"
PORT="${1:-${PORT:-8080}}"

# --- checks ---------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found. Install the Xcode command line tools: xcode-select --install" >&2
    exit 1
fi

# --- portal token (gates who can fire the test) ---------------------------
# Token file lives in ~/.portalg_token. The legacy ~/.lancheck_token is still
# honoured if present, so an existing setup keeps working after the rename.
if [ -n "${PORTALGUN_TOKEN_FILE:-}" ]; then
    TOKEN_FILE="$PORTALGUN_TOKEN_FILE"
elif [ -n "${LANCHECK_TOKEN_FILE:-}" ]; then
    TOKEN_FILE="$LANCHECK_TOKEN_FILE"
elif [ -s "$HOME/.portalg_token" ]; then
    TOKEN_FILE="$HOME/.portalg_token"
elif [ -s "$HOME/.lancheck_token" ]; then
    TOKEN_FILE="$HOME/.lancheck_token"
else
    # nothing exists yet -> create the new one
    TOKEN_FILE="$HOME/.portalg_token"
fi
if [ -n "${PORTAL_TOKEN:-}" ]; then
    TOKEN="$PORTAL_TOKEN"
elif [ -s "$TOKEN_FILE" ]; then
    TOKEN="$(cat "$TOKEN_FILE")"
else
    TOKEN="$(openssl rand -hex 12 2>/dev/null \
        || head -c 24 /dev/urandom | xxd -p | tr -d '\n')"
    printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    echo "(created portal token in $TOKEN_FILE)"
fi

# --- addresses -------------------------------------------------------------
HOSTNAME_LOCAL="$(scutil --get LocalHostName 2>/dev/null || hostname -s).local"
LAN_IP=""
for IF in en0 en1 en5 en6; do
    LAN_IP="$(ipconfig getifaddr "$IF" 2>/dev/null || true)"
    # a link-local address means "no DHCP" - not something to print
    case "$LAN_IP" in 169.254.*) LAN_IP="";; esac
    [ -n "$LAN_IP" ] && break
done
[ -n "$LAN_IP" ] || LAN_IP="<this-mac-ip>"

# The Internet Sharing bridge: hotspot clients reach the portal here.
# (ipconfig getifaddr knows nothing about bridges - parse ifconfig for them.)
GW_IP=""
for IF in bridge100 $(ifconfig -l 2>/dev/null | grep '^bridge'); do
    GW_IP="$(ipconfig getifaddr "$IF" 2>/dev/null || true)"
    [ -n "$GW_IP" ] || GW_IP="$(ifconfig "$IF" 2>/dev/null | awk '/inet /{print $2; exit}')"
    [ -n "$GW_IP" ] && break
done

# --- module count (for the banner) ------------------------------------------
MODULE_COUNT=0
for d in modules/*/; do
    case "${d#modules/}" in
        _*) continue;;
    esac
    [ -f "modules/${d#modules/}module.json" ] || continue
    MODULE_COUNT=$((MODULE_COUNT + 1))
done

# --- gateway mode: wire the login handler to the pf helper -----------------
if [ "$GATEWAY" = 1 ]; then
    CAPTIVE_AUTH="${CAPTIVE_AUTH:-/usr/local/sbin/captive-auth}"
    if [ ! -x "$CAPTIVE_AUTH" ]; then
        echo "WARN: $CAPTIVE_AUTH is missing - sign-in will be rejected." >&2
        echo "      Run: sudo ./mac/setup-captive.sh" >&2
        CAPTIVE_AUTH=""
    elif [ "$(id -u)" -ne 0 ] \
         && ! (sudo -n true 2>/dev/null); then
        echo "WARN: not root and no passwordless sudo - the helper cannot" >&2
        echo "      run pfctl, so sign-in will fail. Start the portal with" >&2
        echo "      'sudo ./mac/start.sh --gateway' or add a sudoers rule." >&2
    fi
    if [ -z "$CAPTIVE_AUTH" ]; then
        unset CAPTIVE_AUTH
    fi
    export CAPTIVE_AUTH
fi

cat <<EOF

  PortalGun — $MODULE_COUNT exploit-verification modules  (on-demand, macOS)

  Portal   : http://$HOSTNAME_LOCAL:$PORT/
  Dashboard: http://$HOSTNAME_LOCAL:$PORT/dashboard    (operator view, all devices)
  JSON API : http://$LAN_IP:$PORT/api/devices
  Token    : $TOKEN   (page prefills it; reports without it are rejected)
EOF

if [ "$GATEWAY" = 1 ]; then
    cat <<EOF

  -- gateway mode --
  Hotspot  : http://${GW_IP:-<no bridge>}:$PORT/       (what clients see)
  Sign-in  : http://${GW_IP:-<no bridge>}:$PORT/login  (opens the OS sign-in sheet)
  Granting : POST /login -> captive-auth -> pf table portal_auth (lease ${PORTAL_LEASE_SECONDS:-3600}s)
EOF
fi

cat <<EOF

  Per-case workflow: open the Portal URL on a device you own, tick
  authorization, run the check, watch the Dashboard. Repeat per device.
  Ctrl-C shuts it all down — nothing survives this script.

EOF

if [ "$GATEWAY" = 1 ] && [ -n "${CAPTIVE_AUTH:-}" ]; then
    exec env PORTAL_TOKEN="$TOKEN" CAPTIVE_AUTH="$CAPTIVE_AUTH" \
        PORTAL_LEASE_SECONDS="${PORTAL_LEASE_SECONDS:-3600}" \
        python3 server.py --port "$PORT"
fi

PORTAL_TOKEN="$TOKEN" exec python3 server.py --port "$PORT"
