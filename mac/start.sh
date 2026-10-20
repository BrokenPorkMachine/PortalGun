#!/bin/sh
# On-demand launcher for PortalGun (macOS).
#
# The portal is OFFLINE unless this script is running. Nothing is installed,
# no DHCP/DNS/NAT is configured — nothing is forced through the Mac.
#
#   ./start.sh [port]        # default port 8080
#   PORT=8080 ./start.sh
#
# Then open the printed URL on each device you want to test.
# Ctrl-C stops everything.
set -eu

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
    [ -n "$LAN_IP" ] && break
done
[ -n "$LAN_IP" ] || LAN_IP="<this-mac-ip>"

cat <<EOF

  PortalGun — CVE-2025-43529  (on-demand, macOS)

  Portal   : http://$HOSTNAME_LOCAL:$PORT/
  Dashboard: http://$HOSTNAME_LOCAL:$PORT/dashboard    (operator view, all devices)
  JSON API : http://$LAN_IP:$PORT/api/devices
  Token    : $TOKEN   (page prefills it; reports without it are rejected)

  Per-case workflow: open the Portal URL on a device you own, tick
  authorization, run the check, watch the Dashboard. Repeat per device.
  Ctrl-C shuts it all down — nothing survives this script.

EOF

PORTAL_TOKEN="$TOKEN" exec python3 server.py --port "$PORT"
