# PortalGun — Linux gateway (captive portal)

Everything Linux-side lives in this folder. This is the **persistent, always-on**
deployment: a dedicated box becomes a Wi-Fi hotspot where every client is forced
through the portal before it can reach the internet.

If you only want to test a device by browsing to a page yourself, you don't need
any of this — use the on-demand launcher in `../mac/`.

## What's in here

| File | Role |
|------|------|
| `setup-gateway.sh` | One-shot bring-up: deploys the portal, installs configs, starts the AP/DHCP/nginx, then calls the enforcement script |
| `setup-enforcement.sh` | The firewall half: HTTP redirect to the portal, forward-drop for unauthenticated clients, NAT, and the `captive-auth` grant helper |
| `hostapd.conf` | The hotspot (interface, SSID, WPA2, IPv6-off note) |
| `dnsmasq.conf` | DHCP + **real** DNS for the hotspot clients |
| `nginx.conf` | Port-80 front door: answers OS probes with a redirect, proxies the rest to the portal |

## Quick start

```bash
# preview first (no root, changes nothing):
./setup-gateway.sh --dry-run

# on the Linux box:
sudo ./setup-gateway.sh            # bring it up
sudo ./setup-gateway.sh --status   # confirm
sudo ./setup-gateway.sh --stop     # tear down
```

### CachyOS / Arch

```bash
sudo pacman -S hostapd dnsmasq nginx nftables python curl
sudo ./setup-gateway.sh
```

Two Arch-specific things the script handles for you, both worth understanding:

- **dnsmasq does not read `/etc/dnsmasq.d/` by default on Arch.** The stock
  `/etc/dnsmasq.conf` ships with `conf-dir=` commented out, so a drop-in config
  is silently ignored. The script appends
  `conf-dir=/etc/dnsmasq.d/,*.conf` if it's missing.
- **NetworkManager will fight hostapd for `wlan0`.** The script writes
  `/etc/NetworkManager/conf.d/99-lan-check-unmanaged.conf` marking the hotspot
  interface unmanaged, and reloads NM. This is the ArchWiki's documented top
  cause of "hostapd won't start".

If `/etc/resolv.conf` on your box points at a local stub (`127.0.0.53` from
systemd-resolved), clients get no usable upstream DNS. The script warns about
this; the fix is to name real resolvers explicitly in
`/etc/dnsmasq.d/lan-check.conf`:

```
server=1.1.1.1
server=9.9.9.9
```

Debian/Ubuntu and Fedora/RHEL are also supported; only the config paths and
python binary differ, and the script detects the distro from `/etc/os-release`.

## How the captive portal actually works

There are three jobs, and it matters which component does which:

1. **Redirect plain HTTP** from unauthenticated clients to the portal.
   → `setup-enforcement.sh` DNATs port 80 to the portal (nftables `prerouting`).
2. **Block everything else** for unauthenticated clients.
   → the `forward` chain has `policy drop`; only DNS (53), the gateway itself,
   and authenticated IPs are allowed. HTTPS is *dropped, not redirected* — you
   cannot transparently redirect TLS, and blocking it is what makes the OS fall
   back to its plain-HTTP probe.
3. **Answer the OS probe correctly.**
   → `nginx.conf` and `server.py` both `302` the probe paths to the portal.
   Returning the OS's *expected success content* (Apple's "Success" page, a
   `204`, "Microsoft Connect Test") tells the device the network is open and
   **hides** the portal. This was the original bug in this folder.

Once a client signs in at `/login`, its IP is added to the nftables `auth` set
with a lease, and job 2 stops applying to it.

## Sign-in flow

```
client --HTTP--> :80  --(nft redirect)--> portal :8080 /login
                                              |
                                    POST /login {token}
                                              |
                                   captive-auth add <client-ip> <lease>
                                              |
                                   nft add element ip captive auth {...}
                                              |
                                       client now forwards freely
```

The token is the same `PORTAL_TOKEN` that gates `/report`, so a passerby cannot
self-authorize. The server only runs the helper when `CAPTIVE_AUTH` points at an
executable, so on a non-gateway host `/login` is simply disabled (503).

## Important design notes

- **DNS is *not* wildcarded.** `dnsmasq.conf` resolves real names. An earlier
  revision used `address=/#/` (sinkhole everything to the portal); that breaks
  authenticated clients, who would still resolve every name to the portal and
  never reach the internet.
- **IPv4 only — and the script enforces that.** If a client picked up an IPv6
  address and a default route, it would bypass the portal entirely over IPv6.
  `setup-enforcement.sh` therefore **disables IPv6 on the hotspot interface** by
  default (`disable_ipv6`, `accept_ra`, `accept_ra_defrtr`, `autoconf`), and
  persists it to `/etc/sysctl.d/99-captive-portal.conf`. Pass `--no-ipv6` to
  skip that — but then you must add matching `ip6` nft rules yourself, or the
  portal is not actually authoritative. Check the live state with
  `setup-enforcement.sh --status`.
- **NAT lives in nftables only.** Do not also add an iptables `MASQUERADE`;
  mixing backends makes the NAT path impossible to reason about.
- **Watch out for bypass rules.** NetworkManager "shared" mode and firewalld
  auto-insert their own forward-accept/NAT rules. `setup-enforcement.sh` warns
  when it sees them.
- **Re-running `setup-enforcement.sh` clears all grants** (the table is rebuilt).

## Verify from a client

```bash
curl -v http://example.com        # 302 -> portal
curl -m 5 -v https://example.com  # times out (443 dropped) until signed in
open http://captive.apple.com      # macOS "Sign in to network" sheet
```

On the gateway:

```bash
sudo ./setup-enforcement.sh --status    # rules, active grants, counters
sudo nft monitor                        # grant/revoke as they happen
sudo /usr/local/sbin/captive-auth list
```

## Scope

Only run this on a dedicated box with a closed SSID and clients you own or are
authorized to test. It forces traffic; that is the point. Never put it on a
shared network.
