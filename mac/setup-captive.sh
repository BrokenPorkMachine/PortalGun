#!/usr/bin/env bash
# setup-captive.sh — captive-portal enforcement for the macOS gateway.
#
# On macOS the Mac itself is the access point: Internet Sharing (System
# Settings > General > Sharing > Internet Sharing) creates the hotspot, hands
# out 192.168.2.x by DHCP and NATs the clients out through the shared uplink.
# This script adds the missing half - the enforcement - with pf:
#
#   4a. redirect unauthenticated plain HTTP to the portal
#   4b. drop everything else for unauthenticated clients (443 included: TLS
#       cannot be transparently redirected, and dropping it is what makes the
#       OS fall back to its plain-HTTP detectability probe)
#   5.  outbound NAT is already done by Internet Sharing - do not add a
#       second one (never mix NAT backends; see linux/README.md)
#   6.  install the captive-auth helper (pf table + lease tracking)
#   7.  check that the portal answers the OS probes with a 302, not a 200
#   8.  --status / --monitor to watch it live
#
# Usage:
#   sudo ./mac/setup-captive.sh                # detect + apply + probe check
#   sudo ./mac/setup-captive.sh --dry-run      # print what would change
#   sudo ./mac/setup-captive.sh --status       # rules, grants, counters
#   sudo ./mac/setup-captive.sh --monitor      # apply, then watch counters
#   sudo ./mac/setup-captive.sh --remove       # tear the enforcement down
#
# Options:
#   -b BRIDGE   hotspot bridge interface         (default: auto-detect, else bridge100)
#   -g IP       hotspot gateway IP                (default: auto-detect on the bridge)
#   -p PORT     portal port HTTP is redirected to (default: 8080)
#   -t SECS     authorization lease in seconds    (default: 3600)
#   -u IFACE    shared/uplink interface           (default: from com.apple.nat)
#   -a ANCHOR   pf anchor to load the rules into  (default: com.apple/000.portal)
#   --portal-daemon  also install the portal as a launchd daemon (always-on)
#
# Exit codes: 0 = all good, 1 = setup error, 2 = enforcement live but the
# probe check found problems (the portal would not open the sign-in sheet).
set -euo pipefail

PROG="$(basename "$0")"
die() { echo "$PROG: $*" >&2; exit 1; }

usage() {
    sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------- defaults
BRIDGE=""
GW_IP=""
UP_IFACE=""
PORTAL_PORT=8080
LEASE=3600
ANCHOR="com.apple/000.portal"
DRY=0 STATUS=0 MONITOR=0 REMOVE=0 PORTAL_DAEMON=0

while [ $# -gt 0 ]; do
    case "$1" in
        -b) [ $# -ge 2 ] || die "-b needs a value"; BRIDGE="$2"; shift 2;;
        -g) [ $# -ge 2 ] || die "-g needs a value"; GW_IP="$2"; shift 2;;
        -u) [ $# -ge 2 ] || die "-u needs a value"; UP_IFACE="$2"; shift 2;;
        -p) [ $# -ge 2 ] || die "-p needs a value"; PORTAL_PORT="$2"; shift 2;;
        -t) [ $# -ge 2 ] || die "-t needs a value"; LEASE="$2"; shift 2;;
        -a) [ $# -ge 2 ] || die "-a needs a value"; ANCHOR="$2"; shift 2;;
        --dry-run)  DRY=1; shift;;
        --status)   STATUS=1; shift;;
        --monitor)  MONITOR=1; shift;;
        --remove)   REMOVE=1; shift;;
        --portal-daemon) PORTAL_DAEMON=1; shift;;
        -h|--help)  usage; exit 0;;
        *) usage >&2; die "unknown option: $1";;
    esac
done

[ "$(uname -s)" = "Darwin" ] || die "this script is for macOS (it drives pf + Internet Sharing)"
[ "$(id -u)" -eq 0 ] || [ "$DRY" = 1 ] || die "run as root: sudo $0 $*"

# --------------------------------------------------------------- constants
NAT_PLIST=/Library/Preferences/SystemConfiguration/com.apple.nat.plist
RULES_FILE=/etc/pf.anchors/portal
HELPER=/usr/local/sbin/captive-auth
STATE_DIR=/var/db/portalgun
STATE_FILE="$STATE_DIR/auth.tsv"
REAP_PLIST=/Library/LaunchDaemons/com.portalgun.captive-reap.plist
REAP_LABEL=com.portalgun.captive-reap
PORTAL_LABEL=com.portalgun.portal
PORTAL_PLIST=/Library/LaunchDaemons/com.portalgun.portal.plist
PORTAL_LOG=/var/log/portalgun-portal.log
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="$(command -v python3 2>/dev/null || echo /usr/bin/python3)"

# ---------------------------------------------------------------- helpers
plist_get() {
    # plist_get NAT:Enabled  ->  true|false|<empty>
    /usr/libexec/PlistBuddy -c "Print :$1" "$NAT_PLIST" 2>/dev/null || true
}

detect_bridge() {
    # Internet Sharing puts the hotspot on a bridge (bridge100 by default).
    # Prefer the classic one, then any bridge that holds an IPv4 address.
    local dev ip
    for dev in bridge100 $(ifconfig -l 2>/dev/null | grep '^bridge'); do
        ip="$(iface_ipv4 "$dev")"
        if [ -n "$ip" ]; then echo "$dev"; return 0; fi
    done
    echo "bridge100"
}

iface_ipv4() {
    # `ipconfig getifaddr` knows nothing about bridge interfaces, so fall
    # back to ifconfig for them.
    local ip
    ip="$(ipconfig getifaddr "$1" 2>/dev/null || true)"
    if [ -z "$ip" ]; then
        ip="$(ifconfig "$1" 2>/dev/null | awk '/inet /{print $2; exit}')"
    fi
    printf '%s' "$ip"
}

detect_uplink() {
    # The shared device is the one Internet Sharing NATs *from*.
    local dev
    dev="$(plist_get 'NAT:SharingDevices:0')"
    case "$dev" in
        en*) echo "$dev"; return 0;;
    esac
    # Fall back to the interface holding the default route.
    route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}'
}

ics_state() {
    # internet sharing on/off, hotspot radio on/off.
    # The plist stores these as 1/0 integers (older builds used booleans),
    # so accept both spellings.
    local nat radio
    nat="$(plist_get 'NAT:Enabled')"
    radio="$(plist_get 'NAT:AirPort:Enabled')"
    truthy "$nat" || { echo "off"; return; }
    truthy "$radio" && echo "hotspot" || echo "nat-only"
}

truthy() {
    case "${1:-}" in
        true|1|yes|Yes) return 0;;
        *) return 1;;
    esac
}

# ---------------------------------------------------------------- detection
# Note: detection never dies here. --status and --remove have to keep
# working when the uplink is unplugged or Internet Sharing is off.
[ -n "$BRIDGE" ] || BRIDGE="$(detect_bridge)"
[ -n "$GW_IP" ] || GW_IP="$(iface_ipv4 "$BRIDGE")"
[ -n "$UP_IFACE" ] || UP_IFACE="$(detect_uplink)"

UP_IP="$(iface_ipv4 "$UP_IFACE")"

echo "  hotspot  : $BRIDGE (${GW_IP:-no IPv4})" >&2
echo "  uplink   : ${UP_IFACE:-none} (${UP_IP:-no IPv4})" >&2
echo "  portal   : :$PORTAL_PORT   lease: ${LEASE}s" >&2
echo "  anchor   : $ANCHOR" >&2

ICS="$(ics_state)"

# ------------------------------------------------------------------ status
if [ "$STATUS" = 1 ]; then
    echo "== internet sharing" >&2
    echo "  state    : $ICS" >&2
    echo "  hotspot  : $BRIDGE (${GW_IP:-none})  uplink: ${UP_IFACE:-none} (${UP_IP:-none})" >&2
    echo "== pf anchor $ANCHOR" >&2
    pfctl -a "$ANCHOR" -s rules 2>&1 | sed 's/^/  /' >&2 || true
    echo "== authorized clients" >&2
    "$HELPER" list 2>&1 | sed 's/^/  /' >&2 || echo "  (no helper installed)" >&2
    echo "== counters" >&2
    pfctl -a "$ANCHOR" -v -s rules 2>&1 | grep -E "^\s+[0-9]+" | sed 's/^/  /' >&2 || true
    echo "== ipv6" >&2
    echo "  net.inet6.ip6.forwarding = $(sysctl -n net.inet6.ip6.forwarding 2>/dev/null || echo '?') (must be 0: macOS pf is IPv4-only, a live IPv6 path bypasses the portal)" >&2
    exit 0
fi

# ------------------------------------------------------------------ remove
if [ "$REMOVE" = 1 ]; then
    pfctl -a "$ANCHOR" -F all 2>/dev/null || true
    rm -f "$RULES_FILE"
    launchctl bootout "system/$REAP_LABEL" 2>/dev/null || launchctl unload "$REAP_PLIST" 2>/dev/null || true
    rm -f "$REAP_PLIST"
    launchctl bootout "system/$PORTAL_LABEL" 2>/dev/null || true
    rm -f "$PORTAL_PLIST"
    rm -f "$HELPER"
    rm -rf "$STATE_DIR"
    # restore the macOS default: the stack may forward IPv6 again
    sysctl -w net.inet6.ip6.forwarding=1 >/dev/null 2>&1 || true
    if [ -f /etc/sysctl.conf ]; then
        sed -i '' '/PortalGun captive portal/,+1d' /etc/sysctl.conf 2>/dev/null || true
    fi
    echo "removed: pf anchor $ANCHOR, $HELPER, lease state, launchd agents" >&2
    echo "note: Internet Sharing itself was left alone - turn it off in" >&2
    echo "      System Settings > General > Sharing > Internet Sharing." >&2
    exit 0
fi

# --------------------------------------------------- internet sharing sanity
# Only the apply path needs these; --status and --remove must keep working
# when the network is down.
if [ -z "$GW_IP" ]; then
    die "no IPv4 address on $BRIDGE - is Internet Sharing on? (System Settings > General > Sharing > Internet Sharing)"
fi
case "$ICS" in
    off)
        die "Internet Sharing is off - turn it on (System Settings > General > Sharing > Internet Sharing, share '$UP_IFACE' to Wi-Fi) and re-run" ;;
    nat-only)
        echo "WARN: Internet Sharing is on but the Wi-Fi hotspot radio is off" >&2
        echo "      (NAT.AirPort.Enabled=0) - no client can associate yet." >&2
        echo "      System Settings > General > Sharing > Internet Sharing." >&2
        ;;
esac
if [ -z "$UP_IP" ]; then
    die "the shared interface $UP_IFACE has no IPv4 address - the hotspot would have no internet"
fi
case "$UP_IP" in
    169.254.*)
        die "$UP_IFACE is link-local ($UP_IP): DHCP did not answer. Plug Ethernet into the router (or use a USB adapter) - the Wi-Fi radio cannot share its own connection on Apple Silicon" ;;
esac

# ------------------------------------------------------------ ruleset (pf)
cat > /tmp/portal.rules.$$ <<EOF
# PortalGun - captive portal enforcement (macOS / pf)
# Generated by setup-captive.sh - edits are overwritten on re-run.
#
# Loaded into the pf anchor "$ANCHOR". The anchor name is chosen so that it
# sorts BEFORE the other com.apple/* anchors: pf.conf(5) evaluates wildcard
# anchors in alphabetical order of their name, and Internet Sharing installs
# its own pass rules for the shared interface. The first matching pf rule
# wins, so these have to be reached first.

# Authorized clients. pf tables have no TTL (nftables sets do), so
# captive-auth tracks the lease in $STATE_FILE and reaps expired entries.
table <portal_auth> persist { }

# 4a. unauthenticated plain HTTP -> the portal.
#     The target is the bridge address, not 127.0.0.1: pf.conf(5) warns that
#     redirecting to loopback lets anyone on the segment reach any
#     loopback-bound daemon on the gateway.
rdr pass on $BRIDGE inet proto tcp from !<portal_auth> to any port 80 -> $GW_IP port $PORTAL_PORT

# 4b. forward policy = drop until the client IP lands in <portal_auth>.
#     DNS, DHCP and the portal itself stay reachable before sign-in;
#     everything else is dropped - 443 included, because TLS cannot be
#     redirected and dropping it is what makes the OS fall back to its
#     plain-HTTP probe and open the sign-in sheet.
pass in on $BRIDGE inet proto tcp to $GW_IP port $PORTAL_PORT
pass in on $BRIDGE inet proto udp to port 53
pass in on $BRIDGE inet proto tcp to port 53
pass in on $BRIDGE inet proto udp to port 67
pass in on $BRIDGE inet proto udp to port 68
pass in on $BRIDGE inet proto icmp to any icmp-type echoreq
pass in on $BRIDGE inet from <portal_auth> to any
block in quick on $BRIDGE inet to any
EOF
RULES=$(cat /tmp/portal.rules.$$)
rm -f /tmp/portal.rules.$$

if [ "$DRY" = 1 ]; then
    echo "--- pf rules that would be loaded into $ANCHOR (dry-run; nothing changed):" >&2
    echo "$RULES" >&2
    echo >&2
else
    # ------------------------------------------------------------- apply
    install -m 0644 /dev/stdin "$RULES_FILE" <<EOF
$RULES
EOF
    # syntax-check before touching the live ruleset
    if ! pfctl -n -a "$ANCHOR" -f "$RULES_FILE" >/tmp/portal-pfcheck.$$ 2>&1; then
        cat /tmp/portal-pfcheck.$$ >&2
        rm -f /tmp/portal-pfcheck.$$
        die "pf rejected the ruleset (see above)"
    fi
    rm -f /tmp/portal-pfcheck.$$

    # load into the anchor; the wildcard "com.apple/*" picks it up at runtime
    pfctl -a "$ANCHOR" -f "$RULES_FILE" || die "pfctl refused the ruleset"
    pfctl -e 2>/dev/null || true

    # the anchor must be attached under com.apple, or the rules are dead
    if ! pfctl -a com.apple -s Anchors 2>/dev/null | grep -q "000.portal"; then
        die "anchor $ANCHOR is not attached under com.apple - pf will not evaluate it"
    fi

    # ------------------------------------------------- IPv6 (portal must win)
    # macOS pf is IPv4-only. With IPv6 forwarding on, a client that picked up
    # an IPv6 address routes around the portal entirely. Turn transit IPv6
    # off and persist it; Internet Sharing may turn it back on, so --status
    # reports it.
    if [ "$(sysctl -n net.inet6.ip6.forwarding 2>/dev/null || echo 0)" != "0" ]; then
        sysctl -w net.inet6.ip6.forwarding=0 >/dev/null
        echo "ipv6 forwarding off (the portal is IPv4-only)" >&2
    fi
    if [ -f /etc/sysctl.conf ] && ! grep -q "PortalGun captive portal" /etc/sysctl.conf 2>/dev/null; then
        {
            echo "# PortalGun captive portal"
            echo "net.inet6.ip6.forwarding=0"
        } >> /etc/sysctl.conf
    fi

    # ------------------------------------------------------ step 6: helper
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    [ -f "$STATE_FILE" ] || : > "$STATE_FILE"
    chmod 600 "$STATE_FILE"

    install -m 0755 /dev/stdin "$HELPER" <<'HELPER_EOF'
#!/bin/sh
# captive-auth - grant/revoke internet access through the macOS captive gateway.
#
#   captive-auth add <ip> [secs]   authorize a client (default lease 3600s)
#   captive-auth del <ip>          revoke + kill the client's live flows
#   captive-auth list              show authorized clients and lease expiry
#   captive-auth reap              drop expired leases (run by launchd)
#
# The authorized set is the pf table <portal_auth> inside the enforcement
# anchor. pf tables have no TTL, so the lease is tracked in a state file and
# reaped by a timer - nftables gets this for free with "flags timeout".
set -eu

ANCHOR="${CAPTIVE_ANCHOR:-com.apple/000.portal}"
TABLE="$ANCHOR/portal_auth"
STATE_DIR="${CAPTIVE_STATE_DIR:-/var/db/portalgun}"
STATE="$STATE_DIR/auth.tsv"
DEFAULT_LEASE=3600

die() { echo "captive-auth: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || {
    # The portal may run unprivileged; escalate silently if that is allowed.
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        exec sudo -n "$0" "$@"
    fi
    die "must run as root (pfctl needs it)"
}

command -v pfctl >/dev/null 2>&1 || die "pfctl not found"

mkdir -p "$STATE_DIR" 2>/dev/null || true
[ -d "$STATE_DIR" ] || die "state directory $STATE_DIR missing - run setup-captive.sh"

have_table() {
    pfctl -a "$ANCHOR" -s Tables 2>/dev/null | grep -q "portal_auth"
}

require_table() {
    have_table || die "no table $TABLE - is setup-captive.sh applied?"
}

now() { date +%s; }

state_write() {
    # state_write <ip> <expiry-epoch>
    ip="$1"; exp="$2"
    tmp="$STATE.tmp.$$"
    : > "$tmp"
    if [ -f "$STATE" ]; then
        while read -r old_ip old_exp; do
            [ -n "${old_ip:-}" ] || continue
            [ "$old_ip" = "$ip" ] && continue
            printf '%s %s\n' "$old_ip" "$old_exp" >> "$tmp"
        done < "$STATE"
    fi
    printf '%s %s\n' "$ip" "$exp" >> "$tmp"
    mv "$tmp" "$STATE"
    chmod 600 "$STATE"
}

state_drop() {
    ip="$1"
    [ -f "$STATE" ] || return 0
    tmp="$STATE.tmp.$$"
    : > "$tmp"
    while read -r old_ip old_exp; do
        [ -n "${old_ip:-}" ] || continue
        [ "$old_ip" = "$ip" ] && continue
        printf '%s %s\n' "$old_ip" "$old_exp" >> "$tmp"
    done < "$STATE"
    mv "$tmp" "$STATE"
}

case "${1:-}" in
    add)
        IP="${2:?usage: captive-auth add <ip> [secs]}"
        SECS="${3:-$DEFAULT_LEASE}"
        require_table
        case "$IP" in
            *[!0-9.]*|"") die "not an IPv4 address: $IP";;
        esac
        pfctl -t "$TABLE" -T add "$IP" || die "could not add $IP to $TABLE"
        state_write "$IP" "$(( $(now) + SECS ))"
        echo "authorized $IP (lease ${SECS}s)"
        ;;
    del)
        IP="${2:?usage: captive-auth del <ip>}"
        require_table
        pfctl -t "$TABLE" -T delete "$IP" 2>/dev/null || true
        pfctl -k "$IP" 2>/dev/null || true      # drop the client's live flows
        state_drop "$IP"
        echo "revoked $IP"
        ;;
    list)
        require_table
        echo "authorized (pf table $TABLE):"
        pfctl -t "$TABLE" -T show 2>/dev/null | sed 's/^/  /' || true
        if [ -f "$STATE" ]; then
            echo "leases:"
            t="$(now)"
            while read -r ip exp; do
                [ -n "${ip:-}" ] || continue
                left=$(( exp - t ))
                [ "$left" -lt 0 ] && left=0
                printf '  %-16s expires in %ss\n' "$ip" "$left"
            done < "$STATE"
        fi
        ;;
    reap)
        require_table
        [ -f "$STATE" ] || exit 0
        t="$(now)"
        tmp="$STATE.tmp.$$"
        : > "$tmp"
        while read -r ip exp; do
            [ -n "${ip:-}" ] || continue
            if [ "$exp" -le "$t" ]; then
                pfctl -t "$TABLE" -T delete "$ip" 2>/dev/null || true
                pfctl -k "$ip" 2>/dev/null || true
                echo "reaped $ip (lease expired)"
            else
                printf '%s %s\n' "$ip" "$exp" >> "$tmp"
            fi
        done < "$STATE"
        mv "$tmp" "$STATE"
        ;;
    *)
        echo "usage: captive-auth {add <ip> [secs]|del <ip>|list|reap}" >&2
        exit 1
        ;;
esac
HELPER_EOF

    # ---------------------------------------------- lease reaper (launchd)
    install -m 0644 /dev/stdin "$REAP_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$REAP_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$HELPER</string>
        <string>reap</string>
    </array>
    <key>StartInterval</key><integer>60</integer>
    <key>RunAtLoad</key><true/>
    <key>StandardOutPath</key><string>/var/log/portalgun-captive-reap.log</string>
    <key>StandardErrorPath</key><string>/var/log/portalgun-captive-reap.log</string>
</dict>
</plist>
EOF
    launchctl bootout "system/$REAP_LABEL" 2>/dev/null || true
    launchctl bootstrap system "$REAP_PLIST" 2>/dev/null \
        || launchctl load -w "$REAP_PLIST" 2>/dev/null \
        || echo "WARN: could not load $REAP_PLIST - leases will not be reaped automatically" >&2

    # ------------------------------------- optional: always-on portal daemon
    if [ "$PORTAL_DAEMON" = 1 ]; then
        if [ ! -f "$REPO_DIR/portal/server.py" ]; then
            echo "WARN: $REPO_DIR/portal/server.py not found - skipping the portal daemon" >&2
        elif lsof -nP -iTCP:"$PORTAL_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
            echo "NOTE: something already listens on :$PORTAL_PORT - not installing the portal daemon" >&2
        else
            # token: env > the operator's file > a fresh one, kept with the state
            TOKEN="${PORTAL_TOKEN:-}"
            [ -n "$TOKEN" ] || { [ -s "$HOME/.portalg_token" ] && TOKEN="$(cat "$HOME/.portalg_token")"; }
            if [ -z "$TOKEN" ]; then
                TOKEN="$(openssl rand -hex 12 2>/dev/null || head -c 24 /dev/urandom | xxd -p | tr -d '\n')"
                printf '%s\n' "$TOKEN" > "$STATE_DIR/token"
                chmod 600 "$STATE_DIR/token"
                echo "portal token (generated): $TOKEN" >&2
            fi
            install -m 0644 /dev/stdin "$PORTAL_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$PORTAL_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_BIN</string>
        <string>$REPO_DIR/portal/server.py</string>
        <string>--port</string>
        <string>$PORTAL_PORT</string>
    </array>
    <key>WorkingDirectory</key><string>$REPO_DIR/portal</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PORTAL_TOKEN</key><string>$TOKEN</string>
        <key>CAPTIVE_AUTH</key><string>$HELPER</string>
        <key>PORTAL_LEASE_SECONDS</key><string>$LEASE</string>
        <key>PORTAL_RESULTS</key><string>$STATE_DIR/results.jsonl</string>
    </dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>$PORTAL_LOG</string>
    <key>StandardErrorPath</key><string>$PORTAL_LOG</string>
</dict>
</plist>
EOF
            launchctl bootout "system/$PORTAL_LABEL" 2>/dev/null || true
            launchctl bootstrap system "$PORTAL_PLIST" 2>/dev/null \
                || launchctl load -w "$PORTAL_PLIST" 2>/dev/null \
                || echo "WARN: could not load $PORTAL_PLIST - start the portal by hand" >&2
            echo "portal daemon installed: http://$GW_IP:$PORTAL_PORT/ (logs: $PORTAL_LOG)" >&2
        fi
    fi

    echo "applied: pf anchor $ANCHOR, $HELPER, lease reaper" >&2
fi

# ---------------------------------------------------- step 7: probe checks
PROBE_ISSUES=0
probe() {
    # $1 = base url, $2 = probe path, $3 = critical (1 = no answer is a failure)
    local url="$1" path="$2" critical="$3" code loc body verdict
    body_file="$(mktemp)"; hdr_file="$(mktemp)"
    code="$(curl -sS -m 5 -o "$body_file" -D "$hdr_file" -w '%{http_code}' \
            "$url$path" 2>/dev/null || true)"
    if [ -z "$code" ] || [ "$code" = 000 ]; then
        if [ "$critical" = 1 ]; then
            echo "    $path -> NO ANSWER (portal server not running on :$PORTAL_PORT?)" >&2
            PROBE_ISSUES=$((PROBE_ISSUES + 1))
        else
            echo "    $path -> nothing listening (ok if you are not the gateway)" >&2
        fi
        rm -f "$body_file" "$hdr_file"
        return 0
    fi
    loc="$(tr -d '\r' < "$hdr_file" | awk -F': *' 'tolower($1)=="location"{print $2; exit}')"
    body="$(tr -d '\r' < "$body_file")"
    rm -f "$body_file" "$hdr_file"
    verdict=""
    case "$path" in
        /hotspot-detect.html)
            if [ -n "$loc" ]; then
                verdict="ok  302 -> $loc"
            elif [ "$code" = 200 ] && [ "$body" = '<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>' ]; then
                verdict="BAD returns Apple's exact SUCCESS page - sign-in sheet will NEVER open"
            else
                verdict="BAD $code, but no redirect - sheet opens showing this URL instead of the portal"
            fi
            ;;
        /generate_204)
            if [ -n "$loc" ]; then
                verdict="ok  302 -> $loc"
            elif [ "$code" = 204 ]; then
                verdict="BAD returns 204 - Android's expected success, no sheet"
            else
                verdict="BAD $code, but no redirect - add a 302 to the portal"
            fi
            ;;
        /connecttest.txt|/ncsi.txt)
            if [ -n "$loc" ]; then
                verdict="ok  302 -> $loc"
            elif [ "$body" = "Microsoft Connect Test" ]; then
                verdict="BAD returns Windows' expected success - no sheet"
            else
                verdict="BAD $code, but no redirect - add a 302 to the portal"
            fi
            ;;
    esac
    case "$verdict" in
        ok*)  echo "    $path -> $verdict" >&2;;
        *)    echo "    $path -> $verdict" >&2
             PROBE_ISSUES=$((PROBE_ISSUES + 1));;
    esac
}

if command -v curl >/dev/null 2>&1; then
    echo "probe check (step 7):" >&2
    echo "  portal server :$PORTAL_PORT (what redirected clients hit):" >&2
    for p in /hotspot-detect.html /generate_204 /connecttest.txt /ncsi.txt; do
        probe "http://127.0.0.1:$PORTAL_PORT" "$p" 1
    done
else
    echo "WARN: curl not installed - skipping probe checks" >&2
fi

# ------------------------------------------------------ step 8 + summary
if [ "$DRY" = 1 ]; then
    echo "DRY-RUN complete - nothing was applied. Re-run as root to enforce." >&2
else
    cat <<EOF >&2

enforcement live. Clients on $BRIDGE ($GW_IP) are held at the portal until they sign in.

    sudo $HELPER add <client-ip>      # authorize (lease ${LEASE}s)
    sudo $HELPER list                 # who is authorized
    sudo $HELPER del <client-ip>      # revoke + kill live flows

wiring the portal login handler (step 6): POST /login runs the helper for the
client that submits the portal token (page at http://$GW_IP:$PORTAL_PORT/login).
Start the portal with the helper visible:

    CAPTIVE_AUTH=$HELPER PORTAL_TOKEN=<token> python3 portal/server.py --port $PORTAL_PORT

Without CAPTIVE_AUTH the endpoint stays disabled (503) and no firewall is touched.

verify from a client:
    curl -v http://example.com            # expect 302 -> portal
    curl -m 5 -v https://example.com      # expect timeout (443 dropped)
    open http://captive.apple.com         # -> "Sign in to network" sheet
live watch:
    sudo $PROG --status                   # rules, grants, packet counters
    sudo pfctl -a $ANCHOR -v -s rules     # per-rule counters
EOF
fi

if [ "$MONITOR" = 1 ] && [ "$DRY" != 1 ]; then
    echo >&2
    echo "watching counters (Ctrl-C to stop)..." >&2
    trap 'echo; exit 0' INT
    while :; do
        printf '\033[2J\033[H' >&2
        date >&2
        pfctl -a "$ANCHOR" -v -s rules >&2 2>/dev/null || { echo "(anchor removed)"; break; }
        sleep 2
    done
    exit 0
fi

if [ "$PROBE_ISSUES" -gt 0 ]; then
    echo >&2
    echo "PROBE CHECK: $PROBE_ISSUES issue(s) - the portal would not open the" >&2
    echo "sign-in sheet cleanly. Fix (both live in this repo):" >&2
    echo "  * portal/server.py   - must 302 /hotspot-detect.html, /generate_204," >&2
    echo "    /connecttest.txt, /ncsi.txt to the portal (redeploy server.py)" >&2
    exit 2
fi
