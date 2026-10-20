#!/usr/bin/env bash
# setup-gateway.sh — one-shot bring-up of the full Linux captive-portal gateway.
#
# Ties the three configs in this folder together, then hands off to
# setup-enforcement.sh for the firewall/sign-in half:
#
#   hostapd.conf          the hotspot (wlan0)          -> hostapd.service
#   dnsmasq.conf          DHCP + real DNS (no sinkhole) -> dnsmasq.service
#   nginx.conf            port-80 front door            -> nginx
#   setup-enforcement.sh  redirect + forward drop + NAT + /login grant
#
# It also deploys the portal server itself to /opt/lan-check so nginx can serve
# it, and starts it with enforcement enabled.
#
# Usage:
#   ./setup-gateway.sh --dry-run            # show what would change (no root)
#   sudo ./setup-gateway.sh                 # deploy + start everything
#   sudo ./setup-gateway.sh --persist       # also survive reboot
#   sudo ./setup-gateway.sh --status        # what is up right now
#   sudo ./setup-gateway.sh --stop          # stop portal + AP + DHCP + firewall rules
#
# Options (same meanings as setup-enforcement.sh):
#   -i IFACE   hotspot interface      (default: wlan0)
#   -u IFACE   upstream interface     (default: default-route iface, else eth0)
#   -g IP      hotspot gateway IP     (default: 10.20.0.1)
#   -p PORT    portal port            (default: 8080)
#   -t SECS    authorization lease    (default: 3600)
#   --no-ipv6  leave IPv6 enabled on the hotspot (default: IPv6 is turned off,
#              because the enforcement is IPv4-only and IPv6 would bypass it)
#
# Scope: only ever run this on a dedicated test box with a closed SSID. It
# forces every client on the hotspot through the portal.
set -euo pipefail

PROG="$(basename "$0")"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
die() { echo "$PROG: $*" >&2; exit 1; }

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; }

# ---------------------------------------------------------------- defaults
IFACE=wlan0
UP_IFACE=""
GW_IP=10.20.0.1
PORTAL_PORT=8080
LEASE=3600
DRY=0 PERSIST=0 STATUS=0 STOP=0 NO_IPV6=0

DEPLOY_DIR=/opt/lan-check
TOKEN_FILE=/etc/lan-check-token

# ---------------------------------------------------------------- distro detect
# The three config files land in different places depending on the package
# layout. Arch/CachyOS is the important divergence: dnsmasq does NOT read a
# drop-in directory unless it is explicitly told to, so a config written to
# /etc/dnsmasq.d/ is silently ignored there.
DISTRO=unknown
PKG_HINT=""
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case " ${ID:-} ${ID_LIKE:-} " in
        *arch*|*cachyos*) DISTRO=arch;;
        *debian*|*ubuntu*) DISTRO=debian;;
        *fedora*|*rhel*|*centos*) DISTRO=rhel;;
        *) DISTRO="${ID:-unknown}";;
    esac
fi
case "$DISTRO" in
    arch)   PKG_HINT="sudo pacman -S hostapd dnsmasq nginx nftables python curl";;
    debian) PKG_HINT="sudo apt install hostapd dnsmasq nginx nftables python3 curl";;
    rhel)   PKG_HINT="sudo dnf install hostapd dnsmasq nginx nftables python3 curl";;
    *)      PKG_HINT="install: hostapd dnsmasq nginx nftables python3 curl";;
esac
# Where dnsmasq/nginx/hostapd config gets read from. These paths are the same
# on Debian, RHEL and Arch; the real Arch divergence is that dnsmasq does not
# read the drop-in dir unless conf-dir= is present (handled below).
DNSMASQ_DEST=/etc/dnsmasq.d/lan-check.conf
DNSMASQ_INCLUDE=/etc/dnsmasq.conf
HOSTAPD_DEST=/etc/hostapd/hostapd.conf
NGINX_DEST=/etc/nginx/conf.d/lan-check.conf
# Arch calls the interpreter `python`; everywhere else it is `python3`.
PYTHON_BIN=python3
[ "$DISTRO" = arch ] && PYTHON_BIN=python

while [ $# -gt 0 ]; do
    case "$1" in
        -i) [ $# -ge 2 ] || die "-i needs a value"; IFACE="$2"; shift 2;;
        -u) [ $# -ge 2 ] || die "-u needs a value"; UP_IFACE="$2"; shift 2;;
        -g) [ $# -ge 2 ] || die "-g needs a value"; GW_IP="$2"; shift 2;;
        -p) [ $# -ge 2 ] || die "-p needs a value"; PORTAL_PORT="$2"; shift 2;;
        -t) [ $# -ge 2 ] || die "-t needs a value"; LEASE="$2"; shift 2;;
        --dry-run) DRY=1; shift;;
        --persist) PERSIST=1; shift;;
        --status)  STATUS=1; shift;;
        --stop)    STOP=1; shift;;
        --no-ipv6) NO_IPV6=1; shift;;
        -h|--help) usage; exit 0;;
        *) usage >&2; die "unknown option: $1";;
    esac
done

run() {  # echo + execute (respects dry-run)
    if [ "$DRY" = 1 ]; then echo "    [dry-run] $*"; else echo "    + $*"; "$@"; fi
}

# status is read-only and works unprivileged; everything else needs root.
if [ "$STATUS" != 1 ] && [ "$DRY" != 1 ] && [ "$(id -u)" -ne 0 ]; then
    die "run as root: sudo $0 $*   (or $0 --dry-run to preview)"
fi

# ---------------------------------------------------------------- status / stop
if [ "$STATUS" = 1 ]; then
    echo "distro   : $DISTRO (python: $PYTHON_BIN)"
    echo "portal   : $(pgrep -f 'server.py --port' >/dev/null && echo running || echo stopped)"
    echo "hostapd  : $(systemctl is-active hostapd 2>/dev/null || echo n/a)"
    echo "dnsmasq  : $(systemctl is-active dnsmasq 2>/dev/null || echo n/a)"
    echo "nginx    : $(systemctl is-active nginx 2>/dev/null || echo n/a)"
    echo "ip_forward: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '?')"
    if nft list table ip captive >/dev/null 2>&1; then
        echo "enforcement: active"
        nft list set ip captive auth 2>/dev/null | sed 's/^/    /'
    else
        echo "enforcement: not applied"
    fi
    exit 0
fi

if [ "$STOP" = 1 ]; then
    echo "stopping portal + AP + DHCP and removing firewall rules"
    if [ "$DRY" != 1 ]; then
        pkill -f "server.py --port $PORTAL_PORT" 2>/dev/null || true
        "$HERE/setup-enforcement.sh" --remove || true
        for svc in hostapd dnsmasq nginx; do
            systemctl stop "$svc" 2>/dev/null || true
        done
    fi
    echo "stopped. (--persist artifacts under /etc/nftables.d left in place)"
    exit 0
fi

# ---------------------------------------------------------------- preflight
echo "== preflight"
[ -f "$HERE/hostapd.conf" ] || die "missing $HERE/hostapd.conf"
[ -f "$HERE/dnsmasq.conf" ] || die "missing $HERE/dnsmasq.conf"
[ -f "$HERE/nginx.conf" ]   || die "missing $HERE/nginx.conf"
[ -x "$HERE/setup-enforcement.sh" ] || die "missing/executable: $HERE/setup-enforcement.sh"
[ -f "$REPO/portal/server.py" ] || die "missing $REPO/portal/server.py"

if [ "$DRY" != 1 ]; then
    missing=""
    for bin in hostapd dnsmasq nginx nft curl; do
        command -v "$bin" >/dev/null 2>&1 || missing="$missing $bin"
    done
    command -v "$PYTHON_BIN" >/dev/null 2>&1 \
        || command -v python3 >/dev/null 2>&1 \
        || missing="$missing python3"
    [ -z "$missing" ] || die "install missing packages first:$missing
  $PKG_HINT
  ($DISTRO detected; python as '$PYTHON_BIN')"
fi

# ---------------------------------------------------------------- deploy portal
echo "== deploy portal -> $DEPLOY_DIR"
run mkdir -p "$DEPLOY_DIR"
for d in server.py site modules catalog.json; do
    [ -e "$REPO/portal/$d" ] || continue
    run cp -R "$REPO/portal/$d" "$DEPLOY_DIR/"
done

# portal token (reused across runs so reports stay valid)
if [ -f "$TOKEN_FILE" ] && [ -s "$TOKEN_FILE" ]; then
    TOKEN="$(cat "$TOKEN_FILE")"
    echo "    reusing token in $TOKEN_FILE"
else
    TOKEN="${PORTAL_TOKEN:-$(openssl rand -hex 12 2>/dev/null || head -c 24 /dev/urandom | xxd -p | tr -d '\n')}"
    if [ "$DRY" = 1 ]; then
        echo "    [dry-run] would write token to $TOKEN_FILE"
    else
        printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE"
        echo "    wrote portal token to $TOKEN_FILE"
    fi
fi

# ---------------------------------------------------------------- configs
echo "== install service configs (distro: $DISTRO)"
run install -m 0644 "$HERE/hostapd.conf" "$HOSTAPD_DEST"
# Debian/Ubuntu point hostapd at the config via /etc/default/hostapd; Arch and
# RHEL read /etc/hostapd/hostapd.conf directly. Only touch the Debian knob.
if [ "$DRY" != 1 ] && [ -f /etc/default/hostapd ]; then
    grep -q '^DAEMON_CONF=' /etc/default/hostapd \
        && sed -i 's|^DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd \
        || echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' >> /etc/default/hostapd
fi

run install -m 0644 "$HERE/dnsmasq.conf" "$DNSMASQ_DEST"
# Arch ships conf-dir commented out. Without it our drop-in is never read, and
# the portal silently gets no DHCP/DNS. Add the include idempotently.
if [ "$DRY" != 1 ]; then
    if ! grep -qsE '^\s*conf-dir=/etc/dnsmasq\.d' "$DNSMASQ_INCLUDE"; then
        if [ "$DISTRO" = arch ]; then
            echo "    enabling conf-dir=/etc/dnsmasq.d/ in $DNSMASQ_INCLUDE"
            echo 'conf-dir=/etc/dnsmasq.d/,*.conf' >> "$DNSMASQ_INCLUDE"
        else
            echo "    NOTE: $DNSMASQ_INCLUDE does not include /etc/dnsmasq.d/ — verify"
            echo "          with: dnsmasq --test && systemctl cat dnsmasq"
        fi
    fi
    # If the host's resolv.conf points at a local stub (systemd-resolved on
    # 127.0.0.53, or dnsmasq itself), clients cannot use it as a forwarder.
    # linux/dnsmasq.conf leaves upstreams unset so dnsmasq follows resolv.conf;
    # that only works if resolv.conf lists real upstream IPs.
    if [ -r /etc/resolv.conf ] && grep -qsE '^\s*nameserver\s+127\.' /etc/resolv.conf; then
        echo "    WARN: /etc/resolv.conf points at a local stub resolver — clients"
        echo "          will get no usable upstream DNS. Add real servers to"
        echo "          /etc/dnsmasq.d/lan-check.conf, e.g.:"
        echo "              server=1.1.1.1"
        echo "              server=9.9.9.9"
    fi
    if command -v dnsmasq >/dev/null 2>&1; then
        dnsmasq --test 2>&1 | sed 's/^/    dnsmasq: /' || true
    fi
fi

# Arch's nginx has no default site, but Debian's does — a second default_server
# on :80 makes nginx refuse to start. Detect and warn.
if [ "$DRY" != 1 ] && [ "$DISTRO" != arch ] && [ -f /etc/nginx/sites-enabled/default ]; then
    echo "    WARN: /etc/nginx/sites-enabled/default exists and also declares"
    echo "          default_server on :80 — nginx will refuse to start. Disable it:"
    echo "          rm /etc/nginx/sites-enabled/default"
fi
run install -m 0644 "$HERE/nginx.conf" "$NGINX_DEST"
if [ "$DRY" != 1 ] && command -v nginx >/dev/null 2>&1; then
    nginx -t 2>&1 | sed 's/^/    nginx: /' || true
fi

# ---------------------------------------------------------------- NM must not manage wlan0
# NetworkManager will try to manage the hotspot interface and fight hostapd.
# The ArchWiki documents this as the top cause of "hostapd won't start".
NM_CONF=/etc/NetworkManager/conf.d/99-lan-check-unmanaged.conf
if command -v nmcli >/dev/null 2>&1 && nmcli -t -f RUNNING general 2>/dev/null | grep -q running; then
    echo "== NetworkManager: marking $IFACE unmanaged"
    if [ "$DRY" = 1 ]; then
        echo "    [dry-run] would write $NM_CONF (unmanaged-devices=interface-name:$IFACE)"
    else
        mkdir -p /etc/NetworkManager/conf.d
        cat > "$NM_CONF" <<EOF
# Added by lan-check setup-gateway.sh: $IFACE is the captive-portal AP.
# NetworkManager must leave it alone or hostapd cannot start.
[keyfile]
unmanaged-devices=interface-name:$IFACE
EOF
        systemctl reload NetworkManager 2>/dev/null || systemctl restart NetworkManager
        echo "    wrote $NM_CONF and reloaded NetworkManager"
    fi
fi

# CachyOS/Arch commonly install iptables-nft, whose FORWARD policy is DROP by
# default in some presets. Confirm our nft table is what actually governs.
if [ "$DRY" != 1 ] && command -v iptables >/dev/null 2>&1; then
    fwd_policy="$(iptables -S FORWARD 2>/dev/null | head -1 || true)"
    case "$fwd_policy" in
        *DROP*) echo "    NOTE: iptables FORWARD default policy is DROP; the nft"
                echo "          captive table's forward chain governs this path.";;
    esac
fi

# ---------------------------------------------------------------- portal service
echo "== portal service"
UNIT=/etc/systemd/system/lan-check-portal.service
if [ "$DRY" = 1 ]; then
    echo "    [dry-run] would write $UNIT and enable it"
else
    cat > "$UNIT" <<EOF
[Unit]
Description=PortalGun (captive gateway)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DEPLOY_DIR
Environment=PORTAL_TOKEN=$TOKEN
Environment=CAPTIVE_AUTH=/usr/local/sbin/captive-auth
Environment=PORTAL_LEASE_SECONDS=$LEASE
ExecStart=/usr/bin/env $PYTHON_BIN $DEPLOY_DIR/server.py --port $PORTAL_PORT
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now lan-check-portal
fi

# ---------------------------------------------------------------- start services
echo "== start AP + DHCP + front door"
run systemctl enable --now hostapd
run systemctl enable --now dnsmasq
run systemctl restart nginx

# ---------------------------------------------------------------- enforcement
echo "== enforcement (handoff to setup-enforcement.sh)"
ENF_ARGS=(-i "$IFACE" -g "$GW_IP" -p "$PORTAL_PORT" -t "$LEASE")
[ -n "$UP_IFACE" ] && ENF_ARGS+=(-u "$UP_IFACE")
[ "$PERSIST" = 1 ] && ENF_ARGS+=(--persist)
[ "$NO_IPV6" = 1 ] && ENF_ARGS+=(--no-ipv6)
if [ "$DRY" = 1 ]; then
    "$HERE/setup-enforcement.sh" --dry-run "${ENF_ARGS[@]}"
    echo
    echo "DRY-RUN complete — nothing was changed."
    exit 0
fi
"$HERE/setup-enforcement.sh" "${ENF_ARGS[@]}"

# ---------------------------------------------------------------- summary
cat <<EOF >&2

gateway up.
  SSID      : $(grep -m1 '^ssid=' "$HERE/hostapd.conf" | cut -d= -f2-)
  gateway   : http://$GW_IP/
  dashboard : http://$GW_IP/dashboard
  sign-in   : http://$GW_IP/login
  token     : $TOKEN   (stored in $TOKEN_FILE)
  lease     : ${LEASE}s
  ipv6      : $(if [ -d "/proc/sys/net/ipv6/conf/$IFACE" ] && [ "$(cat "/proc/sys/net/ipv6/conf/$IFACE/disable_ipv6" 2>/dev/null)" = 1 ]; then echo "disabled on $IFACE (portal is IPv4-only)"; elif [ "$NO_IPV6" = 1 ]; then echo "ENABLED — you passed --no-ipv6; add matching ip6 rules or clients bypass the portal"; else echo "check with: $PROG --status"; fi)

clients that connect get HTTP-redirected to the portal and must sign in at
/login (token above) before anything but DNS + the portal passes.

next:
  $PROG --status      # confirm everything is running
  $PROG --stop        # tear it all down when finished
EOF
