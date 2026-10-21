#!/usr/bin/env bash
# setup-ap-bridge.sh — turn this Mac into a pure layer-2 access point for the
# PortalGun closed-loop lab.
#
# Topology this creates:
#
#     device under test
#          |  Wi-Fi (10.20.0.x, gw/dns 10.20.0.1)
#          v
#     [ Mac mini ]   SoftAP + bridge100 = { Wi-Fi radio, en0 }
#          |  en0 (Ethernet, plain bridge member, 10.20.0.2)
#          v
#     [ Linux gateway 10.20.0.1 ]  DHCP + DNS + portal :8080 + nginx :80 + nftables
#
# The Mac is the RADIO and nothing else. It runs no DHCP server, no NAT and no
# routing: the Linux box is the gateway, and it must see every client's real
# IP address or the captive-portal grants (captive-auth) address the wrong
# host. macOS Internet Sharing cannot do that on its own — it always hands out
# 192.168.2.x leases and NATs the clients out through the Mac, which turns the
# Mac into the gateway and hides every client behind one address.
#
# So this script turns Internet Sharing into what the lab needs:
#
#   1. the hotspot radio stays up (it is the only supported AP on Apple Silicon)
#   2. the wired port is added to the hotspot bridge  -> ONE layer-2 segment,
#      so a client's frames reach the gateway directly instead of being routed
#      and NATed by the Mac
#   3. macOS's own DHCP server (bootpd) is disabled      -> the Linux box is
#      the only DHCP server, so clients get a 10.20.0.x lease with the gateway
#      as router and DNS
#   4. a launchd keepalive re-asserts 2 and 3          -> the sharing daemon
#      re-applies its own configuration after a link flap or a reboot, and a
#      single stray 192.168.2.x lease is enough to break the lab silently
#
# The bridge keeps macOS's own 192.168.2.1 address on purpose: the Internet
# Sharing NAT rule matches 192.168.2.0/24, and the lab traffic is 10.20.0.0/24,
# so nothing on the lab path is ever NATed.
#
# Usage:
#   sudo ./mac/setup-ap-bridge.sh --dry-run      # preview, changes nothing
#   sudo ./mac/setup-ap-bridge.sh                # apply + verify
#   sudo ./mac/setup-ap-bridge.sh --status       # what the AP looks like now
#   sudo ./mac/setup-ap-bridge.sh --remove       # undo (leaves Internet Sharing on)
#
# Options:
#   -e IFACE      wired port to the gateway        (default: en0)
#   -b BRIDGE     hotspot bridge                   (default: bridge100)
#   -g IP         gateway address to check against (default: 10.20.0.1)
#   -a IP         this Mac's address on the lab segment (default: 10.20.0.2)
#   --ssid NAME        hotspot SSID                (default: PortalGun-LAB)
#   --passphrase PASS  hotspot passphrase          (default: generated)
#   --router IP        give the wired port a default route (default: none,
#                      so the Mac keeps its own internet path over Wi-Fi)
#   --no-keepalive     do not install the launchd keepalive
#
# Exit codes: 0 = up, 1 = setup error.
set -euo pipefail

PROG="$(basename "$0")"
die() { echo "$PROG: $*" >&2; exit 1; }
usage() { sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'; }

# ---------------------------------------------------------------- defaults
LAN_IFACE=""
BRIDGE=""
GW_IP=10.20.0.1
AP_IP=10.20.0.2
AP_NETMASK=255.255.255.0
SSID="PortalGun-LAB"
PASSPHRASE=""
ROUTER=""
ROUTER_GIVEN=0
DNS=""
DRY=0 STATUS=0 REMOVE=0 KEEPALIVE=1

while [ $# -gt 0 ]; do
    case "$1" in
        -e) [ $# -ge 2 ] || die "-e needs a value"; LAN_IFACE="$2"; shift 2;;
        -b) [ $# -ge 2 ] || die "-b needs a value"; BRIDGE="$2"; shift 2;;
        -g) [ $# -ge 2 ] || die "-g needs a value"; GW_IP="$2"; shift 2;;
        -a) [ $# -ge 2 ] || die "-a needs a value"; AP_IP="$2"; shift 2;;
        --ssid) [ $# -ge 2 ] || die "--ssid needs a value"; SSID="$2"; shift 2;;
        --passphrase) [ $# -ge 2 ] || die "--passphrase needs a value"; PASSPHRASE="$2"; shift 2;;
        --router) [ $# -ge 2 ] || die "--router needs a value"; ROUTER="$2"; ROUTER_GIVEN=1; shift 2;;
        --no-keepalive) KEEPALIVE=0; shift;;
        --dry-run)  DRY=1; shift;;
        --status)   STATUS=1; shift;;
        --remove)   REMOVE=1; shift;;
        -h|--help)  usage; exit 0;;
        *) usage >&2; die "unknown option: $1";;
    esac
done

[ "$(uname -s)" = "Darwin" ] || die "this script is for macOS"
# --status only reads; everything else writes system state.
if [ "$STATUS" != 1 ] && [ "$DRY" != 1 ] && [ "$(id -u)" -ne 0 ]; then
    die "run as root: sudo $0 $*"
fi

# ---------------------------------------------------------------- constants
NAT_PLIST=/Library/Preferences/SystemConfiguration/com.apple.nat.plist
# The Internet Sharing daemon is com.apple.NetworkSharing (/usr/libexec/
# InternetSharing); the DHCP server it uses is com.apple.bootpd, and launchd
# starts it on demand through a bootps socket listener - so it has to be
# DISABLED, not merely stopped, or it comes back on the next request.
SHARING_LABEL=com.apple.NetworkSharing
SHARING_PLIST=/System/Library/LaunchDaemons/com.apple.NetworkSharing.plist
BOOTPD_LABEL=com.apple.bootpd
KEEPALIVE_BIN=/usr/local/sbin/portalgun-ap-keepalive
KEEPALIVE_PLIST=/Library/LaunchDaemons/com.portalgun.ap-keepalive.plist
KEEPALIVE_LABEL=com.portalgun.ap-keepalive
KEEPALIVE_LOG=/var/log/portalgun-ap-keepalive.log

# ---------------------------------------------------------------- helpers
iface_ipv4() {
    local ip
    ip="$(ipconfig getifaddr "$1" 2>/dev/null || true)"
    [ -n "$ip" ] || ip="$(ifconfig "$1" 2>/dev/null | awk '/inet /{print $2; exit}')"
    printf '%s' "$ip"
}

has_carrier() {
    case "$(ifconfig "$1" 2>/dev/null | awk '/status:/{print $2; exit}')" in
        active) return 0;;
        *) return 1;;
    esac
}

bridge_has_member() {
    ifconfig "$1" 2>/dev/null | grep -q "member: $2 "
}

plist_get() {
    /usr/libexec/PlistBuddy -c "Print :$1" "$NAT_PLIST" 2>/dev/null || true
}

sharing_state() {
    # Internet Sharing on/off and hotspot radio on/off.
    local nat radio
    nat="$(plist_get 'NAT:Enabled')"
    radio="$(plist_get 'NAT:AirPort:Enabled')"
    case "$nat" in
        1|true|yes|Yes) ;;
        *) echo off; return;;
    esac
    case "$radio" in
        1|true|yes|Yes) echo hotspot;;
        *) echo nat-only;;
    esac
}

detect_wifi_iface() {
    networksetup -listallhardwareports 2>/dev/null | awk '
        /^Hardware Port: Wi-Fi/ { want=1; next }
        /^Hardware Port:/        { want=0 }
        want && /^Device:/        { print $2; exit }'
}

detect_lan_iface() {
    # The wired port: a physical Ethernet port that is not the Wi-Fi radio.
    # Prefer one with a carrier (the cable is plugged), then one that looks
    # like a real NIC, and never a port that reports "media: none" (those are
    # Thunderbolt/USB slots with nothing in them).
    local wifi="$1" dev fallback=""
    for dev in en0 en1 en2 en3 en4 en5 en6 en7 en8; do
        [ "$dev" = "$wifi" ] && continue
        ifconfig "$dev" 2>/dev/null | grep -q "ether " || continue
        if ifconfig "$dev" 2>/dev/null | grep -q "media: none"; then continue; fi
        if has_carrier "$dev"; then echo "$dev"; return 0; fi
        [ -n "$fallback" ] || fallback="$dev"
    done
    [ -n "$fallback" ] || fallback=en0
    echo "$fallback"
}

detect_bridge() {
    # The hotspot bridge: bridge100 by convention. Fall back to any bridge
    # that holds an IPv4 address.
    local dev ip
    for dev in bridge100 $(ifconfig -l 2>/dev/null | grep '^bridge'); do
        [ -e "/sys/class/net/$dev" ] || continue
        ip="$(iface_ipv4 "$dev")"
        [ -n "$ip" ] || continue
        echo "$dev"; return 0
    done
    echo bridge100
}

detect_service() {
    # The network service that owns the wired port (for networksetup).
    local wifi="$1" svc devs
    devs="$(networksetup -listallhardwareports 2>/dev/null | awk -v w="$wifi" '
        /^Hardware Port:/ { port=$3 }
        /^Device:/        { if ($2 != w) print port "|" $2 }')"
    while IFS='|' read -r port dev; do
        [ -n "$dev" ] || continue
        svc="$(networksetup -listallnetworkservices 2>/dev/null | grep -i "^$port$" | head -1)"
        [ -n "$svc" ] || continue
        echo "$svc"; return 0
    done <<< "$devs"
    echo "Ethernet"
}

# The wired port's current router and DNS. Both are the operator's business:
# the script only changes them when it is told to, because the lab gateway
# resolves the OS probe names and nothing else (no upstream - closed loop),
# so pointing this Mac's DNS at it would break every other lookup here.
current_router() {
    networksetup -getinfo "$1" 2>/dev/null \
        | awk -F': ' '/^Router:/ { print $2 }' \
        | sed 's/^There isn.t a router set.*$//'
}

current_dns() {
    local out
    out="$(networksetup -getdnsservers "$1" 2>/dev/null | head -1 || true)"
    case "$out" in
        ""|There*) echo "";;
        *) echo "$out";;
    esac
}

# ---------------------------------------------------------------- detection
WIFI_IFACE="$(detect_wifi_iface || true)"
[ -n "$WIFI_IFACE" ] || WIFI_IFACE=en1
[ -n "$LAN_IFACE" ] || LAN_IFACE="$(detect_lan_iface "$WIFI_IFACE")"
[ -n "$BRIDGE" ] || BRIDGE="$(detect_bridge)"
[ -n "$PASSPHRASE" ] || PASSPHRASE="$(openssl rand -hex 8 2>/dev/null || head -c 16 /dev/urandom | xxd -p | tr -d '\n')"
SVC="$(detect_service "$WIFI_IFACE")"
# Router and DNS of the wired port: keep whatever the operator has unless
# told otherwise.
[ "$ROUTER_GIVEN" = 1 ] || ROUTER="$(current_router "$SVC")"
[ -n "$DNS" ] || DNS="$(current_dns "$SVC")"

# ---------------------------------------------------------------- status
if [ "$STATUS" = 1 ]; then
    echo "== access point (closed-loop lab)" >&2
    echo "  radio        : $WIFI_IFACE (SSID: $(plist_get 'NAT:AirPort:NetworkName'))" >&2
    echo "  sharing      : $(sharing_state)" >&2
    if [ -e "/sys/class/net/$BRIDGE" ]; then
        echo "  bridge       : $BRIDGE ($(iface_ipv4 "$BRIDGE" || echo 'no IPv4'))" >&2
        for m in $(ifconfig "$BRIDGE" 2>/dev/null | awk '/member:/{print $2}'); do
            echo "    member     : $m" >&2
        done
    else
        echo "  bridge       : $BRIDGE (not created - Internet Sharing is off)" >&2
    fi
    echo "  wired port   : $LAN_IFACE ($(iface_ipv4 "$LAN_IFACE" || echo 'no IPv4'))" >&2
    echo "  bootpd       : $(launchctl print-disabled system 2>/dev/null | grep -q "$BOOTPD_LABEL.*disabled" && echo 'disabled (good)' || echo 'may be enabled')" >&2
    echo "  gateway      : $GW_IP (ping: $(ping -c1 -W1000 "$GW_IP" >/dev/null 2>&1 && echo reachable || echo UNREACHABLE))" >&2
    echo "  keepalive    : $([ -x "$KEEPALIVE_BIN" ] && echo installed || echo 'not installed')" >&2
    echo >&2
    echo "  healthy when: '$BRIDGE' holds '$LAN_IFACE', bootpd is disabled, and" >&2
    echo "  a client gets a 10.20.0.x lease from the gateway." >&2
    exit 0
fi

# ---------------------------------------------------------------- remove
if [ "$REMOVE" = 1 ]; then
    echo "removing the lab AP wiring"
    if [ "$DRY" != 1 ]; then
        launchctl bootout "system/$KEEPALIVE_LABEL" 2>/dev/null || true
        rm -f "$KEEPALIVE_PLIST" "$KEEPALIVE_BIN"
        launchctl enable "system/$BOOTPD_LABEL" 2>/dev/null || true
        if [ -e "/sys/class/net/$BRIDGE" ]; then
            ifconfig "$BRIDGE" remove "$LAN_IFACE" 2>/dev/null || true
        fi
    fi
    echo "done. Internet Sharing itself is left alone - turn it off in" >&2
    echo "System Settings > General > Sharing > Internet Sharing." >&2
    exit 0
fi

# ---------------------------------------------------------------- preflight
echo "== preflight" >&2
echo "  radio      : $WIFI_IFACE" >&2
echo "  wired port : $LAN_IFACE (service: $SVC)" >&2
echo "  bridge     : $BRIDGE" >&2
echo "  gateway    : $GW_IP" >&2
echo "  this Mac   : $AP_IP/$AP_NETMASK" >&2
echo "  SSID       : $SSID   passphrase: $PASSPHRASE" >&2

if ! has_carrier "$LAN_IFACE"; then
    die "$LAN_IFACE has no cable. Plug it into the Linux gateway first."
fi
if ! ping -c1 -W1000 "$GW_IP" >/dev/null 2>&1; then
    echo "WARN: $GW_IP does not answer yet. If the wired port has no address" >&2
    echo "      yet this is expected; the script will assign $AP_IP." >&2
fi

# ------------------------------------------------- internet sharing (the radio)
ICS="$(sharing_state)"
if [ "$ICS" != "hotspot" ]; then
    echo >&2
    echo "Internet Sharing is not running with the hotspot radio on." >&2
    echo "The SoftAP is the only access point macOS exposes on Apple Silicon," >&2
    echo "so it has to be on before this script can convert it into a bridge." >&2
    echo >&2
    if [ "$DRY" = 1 ]; then
        echo "[dry-run] would write the sharing preferences and start the daemon." >&2
    else
        # Best effort: write the preferences the sharing daemon reads, then
        # start it. If macOS refuses, fall back to the UI.
        python3 - "$NAT_PLIST" "$LAN_IFACE" "$WIFI_IFACE" "$SSID" "$PASSPHRASE" <<'PYEOF'
import plistlib, sys
path, lan, wifi, ssid, passwd = sys.argv[1:6]
try:
    with open(path, "rb") as fh:
        plist = plistlib.load(fh)
except Exception:
    plist = {}
nat = plist.setdefault("NAT", {})
nat["Enabled"] = 1
nat["PrimaryInterface"] = {"Device": lan, "Enabled": 0,
                           "HardwareKey": "", "PrimaryUserReadable": "Ethernet"}
nat["SharingDevices"] = [wifi]
airport = nat.setdefault("AirPort", {})
airport["Enabled"] = 1
airport["NetworkName"] = ssid
# The password is stored as <data> (raw bytes), not as a hex string.
airport["NetworkPassword"] = {"length": len(passwd), "bytes": passwd.encode()}
airport["40BitEncrypt"] = 1
airport["Channel"] = 0
with open(path, "wb") as fh:
    plistlib.dump(plist, fh)
print("wrote", path)
PYEOF
        launchctl bootstrap system "$SHARING_PLIST" 2>/dev/null \
            || launchctl load -w "$SHARING_PLIST" 2>/dev/null \
            || true
        sleep 3
        ICS="$(sharing_state)"
        if [ "$ICS" != "hotspot" ]; then
            die "could not start Internet Sharing from the command line.
  Turn it on by hand once, and re-run this script:
    System Settings > General > Sharing > Internet Sharing
      Share your connection from: $LAN_IFACE ($SVC)
      To computers using: $WIFI_IFACE (Wi-Fi)
    Password for the hotspot: the passphrase this script printed above."
        fi
    fi
fi
echo "  sharing    : $ICS" >&2

# ------------------------------------------------- 1. the wired port joins the bridge
echo "== bridge" >&2
if bridge_has_member "$BRIDGE" "$LAN_IFACE"; then
    echo "  $BRIDGE already holds $LAN_IFACE" >&2
elif [ "$DRY" = 1 ]; then
    echo "  [dry-run] would add $LAN_IFACE to $BRIDGE" >&2
else
    ifconfig "$BRIDGE" add "$LAN_IFACE" up \
        || die "could not add $LAN_IFACE to $BRIDGE.
  Without this the two ports are separate layer-2 segments and the clients
  reach the gateway through the Mac's routing (and its NAT) instead of
  directly, which hides every client behind the Mac's address."
    echo "  added $LAN_IFACE to $BRIDGE" >&2
fi

# ------------------------------------------------- 2. macOS's DHCP server must be off
# This is the step that actually makes the Linux box the gateway: with bootpd
# running, devices take a 192.168.2.x lease from the Mac and route through
# it. launchd starts bootpd on demand through a bootps socket listener, so
# stopping it is not enough - it has to be disabled in launchd, or the very
# first DHCP request brings it back.
echo "== DHCP" >&2
if [ "$DRY" = 1 ]; then
    echo "  [dry-run] would disable $BOOTPD_LABEL and unload it" >&2
else
    launchctl bootout "system/$BOOTPD_LABEL" 2>/dev/null || true
    launchctl disable "system/$BOOTPD_LABEL" 2>/dev/null || true
    if launchctl print-disabled system 2>/dev/null | grep -q "$BOOTPD_LABEL.*disabled"; then
        echo "  $BOOTPD_LABEL disabled (the gateway is the only DHCP server)" >&2
    else
        die "could not disable $BOOTPD_LABEL - devices would keep taking leases from macOS"
    fi
fi

# ------------------------------------------------- 3. this Mac's address on the segment
# The management address lives on the wired port, not on the bridge: the
# bridge keeps macOS's own 192.168.2.1 (which is what makes the sharing NAT
# rule inert for lab traffic), and the wired port is what the Linux box sees.
#
# Only the address is set here. The router and the DNS of this Mac are left
# as the operator has them: the lab gateway resolves the OS probe names and
# nothing else (no upstream - it is a closed loop), so pointing the Mac's DNS
# at it would break every other lookup on this machine.
echo "== address" >&2
CURRENT_IP="$(iface_ipv4 "$LAN_IFACE")"
if [ "$CURRENT_IP" = "$AP_IP" ]; then
    echo "  $LAN_IFACE already holds $AP_IP" >&2
elif [ "$DRY" = 1 ]; then
    echo "  [dry-run] would set $SVC to $AP_IP/$AP_NETMASK" >&2
else
    if ! networksetup -setmanual "$SVC" "$AP_IP" "$AP_NETMASK" "$ROUTER" "$DNS" 2>/dev/null; then
        if ! networksetup -setmanual "$SVC" "$AP_IP" "$AP_NETMASK" "$ROUTER" "$GW_IP" 2>/dev/null; then
            die "networksetup could not set $SVC to $AP_IP/$AP_NETMASK"
        fi
        echo "  $SVC = $AP_IP/$AP_NETMASK (DNS: $GW_IP)" >&2
    else
        echo "  $SVC = $AP_IP/$AP_NETMASK" >&2
    fi
fi

# ------------------------------------------------- 4. keepalive
if [ "$KEEPALIVE" = 1 ]; then
    echo "== keepalive" >&2
    if [ "$DRY" = 1 ]; then
        echo "  [dry-run] would install $KEEPALIVE_BIN and $KEEPALIVE_PLIST" >&2
    else
        install -m 0755 /dev/stdin "$KEEPALIVE_BIN" <<EOF
#!/bin/sh
# portalgun-ap-keepalive - re-assert the closed-loop AP bridge state.
#
# The macOS sharing daemon re-applies its own configuration after a link
# flap, a reboot or a restart of the sharing service: it puts bootpd back
# and re-addresses the bridge. Either change is enough to break the lab
# silently (devices take 192.168.2.x leases and the portal vanishes), so
# this re-asserts both every minute.
#
# Generated by setup-ap-bridge.sh - edits are overwritten on re-run.
BRIDGE=$BRIDGE
LAN=$LAN_IFACE
AP_IP=$AP_IP
AP_NETMASK=$AP_NETMASK
SVC="$SVC"
GW_IP=$GW_IP
ROUTER="$ROUTER"
DNS="$DNS"
BOOTPD_LABEL=$BOOTPD_LABEL
LOG=$KEEPALIVE_LOG

say() { printf '%s %s\n' "\$(date '+%Y-%m-%d %H:%M:%S')" "\$*" >> "\$LOG"; }

# 1. bootpd must stay off: the gateway is the only DHCP server.
if launchctl print-disabled system 2>/dev/null | grep -q "\$BOOTPD_LABEL.*disabled"; then
    :
else
    launchctl disable "system/\$BOOTPD_LABEL" 2>/dev/null || true
    say "re-disabled \$BOOTPD_LABEL"
fi
launchctl bootout "system/\$BOOTPD_LABEL" 2>/dev/null || true

# 2. the wired port must still be a member of the hotspot bridge.
if ! ifconfig "\$BRIDGE" 2>/dev/null | grep -q "member: \$LAN "; then
    if ifconfig "\$BRIDGE" add "\$LAN" up 2>/dev/null; then
        say "re-added \$LAN to \$BRIDGE"
    else
        say "could not re-add \$LAN to \$BRIDGE"
    fi
fi

# 3. the wired port must still carry the lab address.
cur=\$(ipconfig getifaddr "\$LAN" 2>/dev/null || true)
if [ "\$cur" != "\$AP_IP" ]; then
    networksetup -setmanual "\$SVC" "\$AP_IP" "\$AP_NETMASK" "\$ROUTER" "\$DNS" >/dev/null 2>&1 \
        && say "restored \$LAN address \$AP_IP" \
        || say "could not restore \$LAN address (\$cur)"
fi
EOF
        install -m 0644 /dev/stdin "$KEEPALIVE_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$KEEPALIVE_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$KEEPALIVE_BIN</string>
    </array>
    <key>StartInterval</key><integer>60</integer>
    <key>RunAtLoad</key><true/>
    <key>StandardOutPath</key><string>$KEEPALIVE_LOG</string>
    <key>StandardErrorPath</key><string>$KEEPALIVE_LOG</string>
</dict>
</plist>
EOF
        launchctl bootout "system/$KEEPALIVE_LABEL" 2>/dev/null || true
        launchctl bootstrap system "$KEEPALIVE_PLIST" 2>/dev/null \
            || launchctl load -w "$KEEPALIVE_PLIST" 2>/dev/null \
            || echo "WARN: could not load $KEEPALIVE_PLIST - re-run this script after a reboot" >&2
        echo "  keepalive installed ($KEEPALIVE_LABEL, every 60s)" >&2
    fi
else
    echo "== keepalive: skipped (--no-keepalive)" >&2
fi

# ------------------------------------------------- verify
echo "== verify" >&2
RC=0
if [ "$DRY" = 1 ]; then
    echo "  [dry-run] nothing was changed." >&2
    exit 0
fi
if bridge_has_member "$BRIDGE" "$LAN_IFACE"; then
    echo "  bridge holds $LAN_IFACE" >&2
else
    echo "  BRIDGE DOES NOT HOLD $LAN_IFACE" >&2; RC=1
fi
if launchctl print-disabled system 2>/dev/null | grep -q "$BOOTPD_LABEL.*disabled"; then
    echo "  bootpd disabled" >&2
else
    echo "  BOOTPD STILL ENABLED" >&2; RC=1
fi
if [ "$(iface_ipv4 "$LAN_IFACE")" = "$AP_IP" ]; then
    echo "  $LAN_IFACE = $AP_IP" >&2
else
    echo "  $LAN_IFACE has $(iface_ipv4 "$LAN_IFACE" || echo 'no address') (expected $AP_IP)" >&2; RC=1
fi
if ping -c1 -W1000 "$GW_IP" >/dev/null 2>&1; then
    echo "  gateway $GW_IP reachable" >&2
else
    echo "  gateway $GW_IP NOT reachable - check the cable and the gateway" >&2; RC=1
fi

cat >&2 <<EOF

AP up. The Mac is the radio only: no DHCP, no NAT, no routing.

    SSID        : $SSID
    passphrase  : $PASSPHRASE
    clients get : 10.20.0.50-150 from the gateway, router/DNS $GW_IP
    this Mac   : $AP_IP on $LAN_IFACE

A device that associates must get a 10.20.0.x address:

    ipconfig getifaddr en0        # on the device (or check the DHCP lease)

If it shows 192.168.2.x, macOS's DHCP server is still answering:
    sudo ./mac/setup-ap-bridge.sh --status
    sudo launchctl print-disabled system | grep bootpd

The portal (on the Linux gateway):  http://$GW_IP/
EOF

[ "$RC" = 0 ] || exit 1
exit 0
