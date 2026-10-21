#!/usr/bin/env bash
# setup-enforcement.sh — captive-portal enforcement for the Linux gateway box.
#
# Automates steps 4-8 of the gateway path:
#   4. apply the nftables rules  (HTTP -> portal redirect, forward policy drop)
#   5. outbound NAT              (masquerade in nft — never mixed with iptables)
#   6. auth helper               (installs /usr/local/sbin/captive-auth)
#   7. probe check               (portal must NOT answer OS probes with success)
#   8. live watch                (--monitor / --status)
#
# Usage:
#   ./setup-enforcement.sh --dry-run [-i wlan0 -u eth0 -g 10.20.0.1 -p 8080]
#   sudo ./setup-enforcement.sh                 # detect + apply + probe check
#   sudo ./setup-enforcement.sh --persist       # also save rules for boot
#   sudo ./setup-enforcement.sh --status        # table, auth set, counters
#   sudo ./setup-enforcement.sh --monitor       # apply, then watch counters live
#   sudo ./setup-enforcement.sh --remove        # tear down the captive table
#
# IPv6 is disabled on the hotspot interface by default, because this enforcement
# is IPv4-only and a client with an IPv6 default route would bypass the portal.
# Pass --no-ipv6 to skip that (only if you are deliberately dual-stacking).
#
# Options:
#   -i IFACE   hotspot interface                  (default: wlan0)
#   -u IFACE   upstream/internet interface        (default: default-route iface)
#   -g IP      hotspot gateway IP                 (default: auto-detect on -i)
#   -p PORT    portal port HTTP is redirected to  (default: 8080)
#   -t SECS    authorization lease in seconds     (default: 3600)
#   --closed-loop  no upstream behind the gateway: the lab network IS the
#                  whole network, so no masquerade rule is installed. Chosen
#                  automatically when there is no default route, or the only
#                  one is on the hotspot interface itself.
#   --no-ipv6  leave IPv6 enabled on the hotspot interface
#
# Exit codes: 0 = all good, 1 = setup error, 2 = enforcement live but probe
# check found problems (portal would not open the sign-in sheet).
#
# NOTE: re-running replaces the table — every existing grant is cleared.
set -euo pipefail

PROG="$(basename "$0")"
die() { echo "$PROG: $*" >&2; exit 1; }

usage() {
    sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------- defaults
IFACE=wlan0
UP_IFACE=""
GW_IP=""
PORTAL_PORT=8080
LEASE=3600
NO_IPV6=0
CLOSED_LOOP=0
DRY=0 PERSIST=0 MONITOR=0 STATUS=0 REMOVE=0

while [ $# -gt 0 ]; do
    case "$1" in
        -i) [ $# -ge 2 ] || die "-i needs a value"; IFACE="$2"; shift 2;;
        -u) [ $# -ge 2 ] || die "-u needs a value"; UP_IFACE="$2"; shift 2;;
        -g) [ $# -ge 2 ] || die "-g needs a value"; GW_IP="$2"; shift 2;;
        -p) [ $# -ge 2 ] || die "-p needs a value"; PORTAL_PORT="$2"; shift 2;;
        -t) [ $# -ge 2 ] || die "-t needs a value"; LEASE="$2"; shift 2;;
        --closed-loop) CLOSED_LOOP=1; shift;;
        --dry-run)  DRY=1; shift;;
        --persist)  PERSIST=1; shift;;
        --monitor)  MONITOR=1; shift;;
        --status)   STATUS=1; shift;;
        --remove)   REMOVE=1; shift;;
        --no-ipv6)  NO_IPV6=1; shift;;
        -h|--help)  usage; exit 0;;
        *) usage >&2; die "unknown option: $1";;
    esac
done

TMP_RULES="$(mktemp)"
TMP_BODY="$(mktemp)"
TMP_HDR="$(mktemp)"
trap 'rm -f "$TMP_RULES" "$TMP_BODY" "$TMP_HDR"' EXIT

[ "$(id -u)" -eq 0 ] || [ "$DRY" = 1 ] || die "run as root: sudo $0 $*"

if [ "$DRY" != 1 ]; then
    command -v nft >/dev/null 2>&1 \
        || die "nft not found — install nftables (apt/dnf/pacman install nftables)"
fi

# ------------------------------------------------- status / remove shortcuts
if [ "$STATUS" = 1 ]; then
    nft list table ip captive 2>/dev/null \
        || die "no 'ip captive' table — has setup-enforcement.sh been applied?"
    if [ -d "/proc/sys/net/ipv6/conf/$IFACE" ]; then
        printf 'ipv6 on %s: disable_ipv6=%s accept_ra=%s\n' "$IFACE" \
            "$(cat "/proc/sys/net/ipv6/conf/$IFACE/disable_ipv6" 2>/dev/null)" \
            "$(cat "/proc/sys/net/ipv6/conf/$IFACE/accept_ra" 2>/dev/null)"
    fi
    exit 0
fi
if [ "$REMOVE" = 1 ]; then
    nft delete table ip captive 2>/dev/null || true
    echo "removed table ip captive (auth helper left at /usr/local/sbin/captive-auth;"
    echo "delete it manually if you want it gone)"
    exit 0
fi

# ----------------------------------------------------------- detection
if [ -z "$GW_IP" ]; then
    command -v ip >/dev/null 2>&1 || die "-g <gateway-ip> required (no 'ip' command)"
    GW_IP="$(ip -4 -o addr show dev "$IFACE" 2>/dev/null \
             | awk '{print $4}' | cut -d/ -f1 | head -n1)"
    [ -n "$GW_IP" ] || die "interface $IFACE has no IPv4 address — is the AP (hostapd / NM-shared) up?"
fi
if [ -z "$UP_IFACE" ]; then
    UP_IFACE="$(ip -4 route show default 2>/dev/null \
                | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
    # No default route at all, or the only one is on the hotspot interface:
    # there is nothing behind the gateway to NAT to. That is the closed-loop
    # lab (gateway + access point + devices under test are the whole
    # network), so drop the masquerade rule instead of inventing an upstream.
    if [ -z "$UP_IFACE" ] || [ "$UP_IFACE" = "$IFACE" ]; then
        UP_IFACE=""
        CLOSED_LOOP=1
    fi
elif [ "$CLOSED_LOOP" = 1 ]; then
    echo "  note: --closed-loop given, ignoring -u $UP_IFACE (no upstream, no NAT)" >&2
    UP_IFACE=""
fi

echo "  hotspot  : $IFACE ($GW_IP)" >&2
if [ "$CLOSED_LOOP" = 1 ]; then
    echo "  upstream : none (closed loop - no NAT, nothing behind the gateway)" >&2
else
    echo "  upstream : $UP_IFACE" >&2
fi
echo "  portal   : :$PORTAL_PORT   lease: ${LEASE}s" >&2

# ----------------------------------------------------------- ruleset (steps 4+5)
# The postrouting (NAT) chain only exists when there is an upstream. In the
# closed loop there is none, and a masquerade rule with nowhere to masquerade
# to is just noise that hides what the table actually does.
if [ "$CLOSED_LOOP" = 1 ]; then
    NAT_CHAIN=""
else
    NAT_CHAIN="
    # step 5: outbound NAT (only traffic the forward chain lets through reaches it)
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        oifname \"$UP_IFACE\" counter masquerade
    }
"
fi

cat > "$TMP_RULES" <<EOF
# generated by setup-enforcement.sh — captive portal enforcement
table ip captive {
    set auth {
        type ipv4_addr
        flags timeout
    }

    # step 4a: unauthenticated HTTP -> portal; authed clients pass through
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
        iifname "$IFACE" ip daddr $GW_IP return
        iifname "$IFACE" ip saddr @auth return
        iifname "$IFACE" tcp dport 80 counter redirect to :$PORTAL_PORT
    }

$NAT_CHAIN
    # portal traffic is local (INPUT, not FORWARD): keep DHCP/DNS/portal alive
    # even if a host firewall sets a stricter INPUT policy elsewhere
    chain input {
        type filter hook input priority 0; policy accept;
        iifname "$IFACE" udp dport { 53, 67 } accept
        iifname "$IFACE" tcp dport 53 accept
        iifname "$IFACE" tcp dport $PORTAL_PORT accept
    }

    # step 4b: unauthenticated clients get DNS + portal only; HTTPS and
    # everything else drop until their IP lands in @auth
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related counter accept
        iifname "$IFACE" udp dport 53 counter accept
        iifname "$IFACE" tcp dport 53 counter accept
        ip saddr @auth counter accept
        iifname "$IFACE" ip daddr $GW_IP counter accept
    }
}
EOF

if [ "$DRY" = 1 ]; then
    echo "--- ruleset that would be applied (dry-run; nothing changed):" >&2
    cat "$TMP_RULES"     # stdout only, so this can be piped to `nft -c -f -`
    echo >&2
else
    # ------------------------------------------------------- apply (atomic)
    nft delete table ip captive 2>/dev/null || true
    nft -c -f "$TMP_RULES"   # syntax-check against the kernel before touching it
    nft -f "$TMP_RULES"
    echo "applied: table ip captive"

    # firewall must forward at all
    if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" != 1 ]; then
        sysctl -w net.ipv4.ip_forward=1 >/dev/null
    fi
    mkdir -p /etc/sysctl.d
    grep -qs 'net.ipv4.ip_forward' /etc/sysctl.d/99-captive-portal.conf 2>/dev/null \
        || echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-captive-portal.conf

    # --- IPv6 suppression on the hotspot ---------------------------------
    # This enforcement is IPv4-only. If a client picks up an IPv6 address and a
    # default route (from kernel RAs or a stray DHCPv6/radvd), it bypasses the
    # portal entirely over IPv6. Turning IPv6 off on the hotspot interface is
    # what makes the portal actually authoritative, so we apply it, not just
    # document it. (--no-ipv6 skips this if you are deliberately dual-stacking.)
    if [ "$NO_IPV6" != 1 ]; then
        if [ -d "/proc/sys/net/ipv6/conf/$IFACE" ]; then
            sysctl -w "net.ipv6.conf.$IFACE.disable_ipv6=1" >/dev/null || true
            sysctl -w "net.ipv6.conf.$IFACE.accept_ra=0" >/dev/null || true
            sysctl -w "net.ipv6.conf.$IFACE.accept_ra_defrtr=0" >/dev/null || true
            sysctl -w "net.ipv6.conf.$IFACE.autoconf=0" >/dev/null || true
            SYSCTL_FILE=/etc/sysctl.d/99-captive-portal.conf
            {
                echo "net.ipv6.conf.$IFACE.disable_ipv6=1"
                echo "net.ipv6.conf.$IFACE.accept_ra=0"
                echo "net.ipv6.conf.$IFACE.accept_ra_defrtr=0"
                echo "net.ipv6.conf.$IFACE.autoconf=0"
            } >> "$SYSCTL_FILE"
            # keep the file free of duplicate lines across re-runs
            awk '!seen[$0]++' "$SYSCTL_FILE" > "$SYSCTL_FILE.tmp" && mv "$SYSCTL_FILE.tmp" "$SYSCTL_FILE"
            echo "ipv6 off on $IFACE (portal is IPv4-only)"
        else
            echo "NOTE: no IPv6 sysctls for $IFACE — skipping IPv6 suppression"
        fi
    else
        echo "NOTE: --no-ipv6 given — leaving IPv6 enabled; add matching ip6 rules"
    fi

    # --- ufw: the host firewall on top of ours -------------------------------
    # ufw installs its own base chain on the input hook. With its default
    # "deny incoming" policy it drops the front door and the DNS/DHCP the
    # clients need BEFORE they can reach the portal at all — and because it
    # runs at the same hook priority as our table, our accept rules never
    # get a say. Open the lab subnet explicitly for the portal path.
    #
    # Only the lab subnet is opened. Everything else stays as ufw had it.
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -q "Status: active"; then
        LAB_NET="${GW_IP%.*}.0/24"
        echo "ufw active — opening the portal path for $LAB_NET"
        # The stale rules from the old 192.168.2.0/24 hotspot are dead weight
        # and actively confusing (the lab moved to 10.20.0.0/24): drop them.
        # Rule numbers shift as rules are deleted, so go from the bottom up.
        # (ufw prints "[ 7] 8080/tcp ...", so the number has to be pulled out
        # of the bracket - it is not awk's $1, the bracket is.)
        for old in $(ufw status numbered 2>/dev/null \
                        | sed -n 's/^\[[ ]*\([0-9]\{1,\}\)\].*192\.168\.2\.0\/24.*/\1/p' \
                        | sort -rn); do
            ufw --force delete "$old" >/dev/null 2>&1 || true
        done
        ufw allow from "$LAB_NET" to any port 80 proto tcp \
            comment 'PortalGun: captive front door' >/dev/null
        ufw allow from "$LAB_NET" to any port "$PORTAL_PORT" proto tcp \
            comment 'PortalGun: portal server' >/dev/null
        ufw allow from "$LAB_NET" to any port 53 proto tcp \
            comment 'PortalGun: DNS' >/dev/null
        ufw allow from "$LAB_NET" to any port 53 proto udp \
            comment 'PortalGun: DNS' >/dev/null
        ufw allow from "$LAB_NET" to any port 67 proto udp \
            comment 'PortalGun: DHCP' >/dev/null
        echo "ufw: opened 80, $PORTAL_PORT, 53 and 67 for $LAB_NET"
    elif command -v ufw >/dev/null 2>&1; then
        echo "NOTE: ufw is installed but inactive — nothing to open"
    fi
fi

# step 5 note: NAT lives in nft above; deliberately NOT adding the iptables
# MASQUERADE line — mixing backends makes the NAT path impossible to reason about.

# ----------------------------------------------------------- conflicts (warn only)
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "WARN: firewalld is active — it manages NAT/forward too; make sure its" >&2
    echo "      zones do not ACCEPT past this policy (nft list ruleset | less)" >&2
fi
if command -v nmcli >/dev/null 2>&1 \
   && nmcli -g ipv4.method con show --active 2>/dev/null | grep -qx shared; then
    echo "WARN: NetworkManager 'shared' connection is active — it auto-inserts" >&2
    echo "      NAT/DNS/forward rules. Review them: nft list ruleset" >&2
fi
IPT_FWD="$(iptables -S FORWARD 2>/dev/null | grep -F -- "-i $IFACE" || true)"
if [ -n "$IPT_FWD" ]; then
    echo "WARN: pre-existing iptables FORWARD rules for $IFACE (bypass risk):" >&2
    printf '%s\n' "$IPT_FWD" >&2
fi

# ----------------------------------------------------------- step 6: auth helper
if [ "$DRY" = 1 ]; then
    echo "(dry-run) would install: /usr/local/sbin/captive-auth" >&2
else
mkdir -p /usr/local/sbin
TMP_HELPER="$(mktemp)"
cat > "$TMP_HELPER" <<'EOF'
#!/bin/sh
# captive-auth — grant/revoke internet access through the captive gateway.
#
#   captive-auth add <ip> [secs]   authorize a client   (default lease 3600s)
#   captive-auth del <ip>          revoke + drop the client's live flows
#   captive-auth list              show authorized clients
#
# Called from the portal's login handler, or by hand:
#   sudo captive-auth add 10.20.0.50
set -eu
TABLE=captive
case "${1:-}" in
    add)
        IP="${2:?usage: captive-auth add <ip> [secs]}"
        SECS="${3:-3600}"
        nft get table ip "$TABLE" >/dev/null 2>&1 || {
            echo "captive-auth: no 'ip captive' table — run setup-enforcement.sh first" >&2
            exit 1; }
        nft delete element ip "$TABLE" auth { "$IP" } 2>/dev/null || true
        nft add element ip "$TABLE" auth { "$IP" timeout "${SECS}s" }
        echo "authorized $IP (lease ${SECS}s)"
        ;;
    del)
        IP="${2:?usage: captive-auth del <ip>}"
        nft delete element ip "$TABLE" auth { "$IP" } 2>/dev/null || true
        conntrack -D -s "$IP" 2>/dev/null || true
        echo "revoked $IP"
        ;;
    list)
        nft list set ip "$TABLE" auth
        ;;
    *)
        echo "usage: captive-auth {add <ip> [secs]|del <ip>|list}" >&2
        exit 1
        ;;
esac
EOF
install -m 0755 "$TMP_HELPER" /usr/local/sbin/captive-auth
rm -f "$TMP_HELPER"
echo "installed: /usr/local/sbin/captive-auth"
fi  # end non-dry-run

# ----------------------------------------------------------- step 7: probe checks
PROBE_ISSUES=0
probe() {
    # $1 = base url, $2 = probe path, $3 = critical (1 = no-answer is a failure)
    local url="$1" path="$2" critical="$3" code loc body verdict
    code="$(curl -sS -m 5 -o "$TMP_BODY" -D "$TMP_HDR" -w '%{http_code}' \
            "$url$path" 2>/dev/null || true)"
    if [ -z "$code" ] || [ "$code" = 000 ]; then
        if [ "$critical" = 1 ]; then
            echo "    $path -> NO ANSWER (portal server not running on :$PORTAL_PORT?)" >&2
            PROBE_ISSUES=$((PROBE_ISSUES + 1))
        else
            echo "    $path -> nothing listening (ok if you are not using the sinkhole dnsmasq)" >&2
        fi
        return 0
    fi
    loc="$(tr -d '\r' < "$TMP_HDR" | awk -F': *' 'tolower($1)=="location"{print $2; exit}')"
    body="$(tr -d '\r' < "$TMP_BODY")"
    verdict=""
    case "$path" in
        /hotspot-detect.html)
            if [ -n "$loc" ]; then
                verdict="ok  302 -> $loc"
            elif [ "$code" = 200 ] && [ "$body" = '<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>' ]; then
                verdict="BAD returns Apple's exact SUCCESS page — sign-in sheet will NEVER open"
            else
                verdict="BAD $code, but no redirect — sheet opens showing this URL instead of the portal"
            fi
            ;;
        /generate_204)
            if [ -n "$loc" ]; then
                verdict="ok  302 -> $loc"
            elif [ "$code" = 204 ]; then
                verdict="BAD returns 204 — Android's expected success, no sheet"
            else
                verdict="BAD $code, but no redirect — add a 302 to the portal"
            fi
            ;;
        /connecttest.txt|/ncsi.txt)
            if [ -n "$loc" ]; then
                verdict="ok  302 -> $loc"
            elif [ "$body" = "Microsoft Connect Test" ]; then
                verdict="BAD returns Windows' expected success — no sheet"
            else
                verdict="BAD $code, but no redirect — add a 302 to the portal"
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
    echo "  portal server :$PORTAL_PORT (what DNATed clients hit):" >&2
    for p in /hotspot-detect.html /generate_204 /connecttest.txt /ncsi.txt; do
        probe "http://127.0.0.1:$PORTAL_PORT" "$p" 1
    done
    echo "  gateway :80 (what sinkhole-dns clients hit):" >&2
    for p in /hotspot-detect.html /generate_204 /connecttest.txt /ncsi.txt; do
        probe "http://$GW_IP" "$p" 0
    done
else
    echo "WARN: curl not installed — skipping probe checks" >&2
fi

# ----------------------------------------------------------- step 8 + summary
EX_IP="${GW_IP%.*}.50"
if [ "$DRY" = 1 ]; then
    STATUS_LINE="DRY-RUN complete — nothing was applied. Re-run as root to enforce."
else
    STATUS_LINE="enforcement live. grant a client internet access with:"
fi
cat <<EOF >&2

$STATUS_LINE

    sudo captive-auth add $EX_IP          # (its IP from: ip -br addr / dhcp lease)
    sudo captive-auth list
    sudo captive-auth del $EX_IP          # revoke + kill live flows

wiring the portal login handler (step 6): DONE on the server side —
server.py exposes POST /login, which runs \`captive-auth add <client-ip>\` for the
client that submits the portal token (page at http://<gateway>:$PORTAL_PORT/login).
Just start the server with the helper path visible:

    CAPTIVE_AUTH=/usr/local/sbin/captive-auth PORTAL_TOKEN=<token> python3 server.py --port $PORTAL_PORT

Without CAPTIVE_AUTH the endpoint stays disabled (503) and no firewall is touched.
Lease defaults to ${LEASE}s; override with PORTAL_LEASE_SECONDS.

notes:
  * sinkhole dnsmasq must be OFF — linux/dnsmasq.conf no longer wildcards DNS
    (address=/#/) because that would keep authenticated clients from resolving
    real names; this path uses real DNS + the HTTP redirect above.
  * IPv4 only: keep RA/DHCPv6 off the hotspot, or add matching ip6 rules.
  * re-running this script clears all grants.
EOF

if [ "$CLOSED_LOOP" = 1 ]; then
    cat >&2 <<EOF
  * closed loop: there is no upstream behind $IFACE, so no masquerade rule was
    installed. Nothing can reach the internet from this network by design —
    the gateway, the access point and the devices under test ARE the network.
EOF
fi

cat >&2 <<EOF

verify from the Mac (step 7/8 of the client path):
    curl -v http://example.com            # expect 302 -> portal
    curl -m 5 -v https://example.com      # expect timeout (443 dropped)
    open http://captive.apple.com         # -> "Sign in to network" sheet
live watch:
    sudo $PROG --status                   # rules, grants, packet counters
    sudo nft monitor                      # grant/revoke events as they happen
EOF

if [ "$PERSIST" = 1 ] && [ "$DRY" != 1 ]; then
    mkdir -p /etc/nftables.d
    cp "$TMP_RULES" /etc/nftables.d/captive.nft
    if [ -f /etc/nftables.conf ] && ! grep -qs 'nftables.d' /etc/nftables.conf; then
        echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable nftables >/dev/null 2>&1 || true
    fi
    echo "persisted: /etc/nftables.d/captive.nft (loaded by nftables.service at boot)" >&2
fi

if [ "$MONITOR" = 1 ] && [ "$DRY" != 1 ]; then
    echo >&2
    echo "watching counters (Ctrl-C to stop)..." >&2
    trap 'echo; exit 0' INT
    while :; do
        printf '\033[2J\033[H' >&2
        date >&2
        nft list table ip captive >&2 2>/dev/null || { echo "(table removed)"; break; }
        sleep 2
    done
    exit 0
fi

if [ "$PROBE_ISSUES" -gt 0 ]; then
    echo >&2
    echo "PROBE CHECK: $PROBE_ISSUES issue(s) — the portal would not open the" >&2
    echo "sign-in sheet cleanly. Fix (both live in this repo):" >&2
    echo "  * portal/server.py       — must 302 /hotspot-detect.html, /generate_204," >&2
    echo "    /connecttest.txt, /ncsi.txt to / (redeploy server.py to the box)" >&2
    echo "  * linux/nginx.conf       — probe locations must 'return 302 http://\$host/;'" >&2
    echo "    (reload: nginx -s reload)" >&2
    exit 2
fi
