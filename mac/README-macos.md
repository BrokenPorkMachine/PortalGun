# PortalGun — macOS

Three ways to run the portal on the Mac:

| Mode | What it is | What it forces through the portal |
|------|-----------|----------------------------------|
| **On-demand** (`./mac/start.sh`) | A plain HTTP server you start when you want to test | Nothing — you browse to the page yourself |
| **Gateway** (`./mac/setup-captive.sh`) | The Mac *is* the access point: clients must sign in before they get internet | Everything, until the client IP is authorized |
| **AP bridge** (`./mac/setup-ap-bridge.sh`) | The Mac is the *radio only* for a closed-loop lab; the Linux box is the gateway | Nothing — there is no internet behind it, by design |

Pick the on-demand mode unless you specifically need the captive-portal
behaviour (an OS sign-in sheet appearing on a phone, enforced access, a
sign-in-gated test network).

---

## Mode A — on-demand (default)

Run the portal **only when you choose to test**, from the Mac mini, with
nothing forced through it. No DHCP server, no DNS wildcard, no NAT, no
startup items. When the launcher isn't running, your network is untouched.

### Start (one command)

```sh
chmod +x mac/start.sh
./mac/start.sh              # default port 8080
```

Output looks like:

```
Portal   : http://Mac-mini.local:8080/
Dashboard: http://Mac-mini.local:8080/dashboard
Token    : a1b2…   (page prefills it; reports without it are rejected)
```

The portal is live only while that command runs. **Ctrl-C = fully offline.**

### Testing a device (per case)

1. Start the portal on the mini.
2. On the device you own, open `http://Mac-mini.local:8080/` in Safari.
3. Tick authorization (token prefills), pick a preset: **light** for phones/
   tablets in the browser sheet, **standard/deep** for desktop Safari.
4. Watch `http://Mac-mini.local:8080/dashboard` on the mini — one row per
   device with its verdict (`vulnerable` + leaked pointer, `no-uaf`,
   `patched`).
5. Ctrl-C the launcher when done.

Notes:

- `Mac-mini.local` requires the device to be on the same LAN; fall back to
  the mini's IP (the launcher prints it via `/api/devices` line) if mDNS is
  blocked by client isolation on your router.
- First run creates `~/.portalg_token` (mode 600). Override anytime with
  `PORTAL_TOKEN=... ./mac/start.sh` — reports without the current
  token get `403`. (The legacy `~/.lancheck_token` is still read if it
  exists, so an older install keeps its token.)
- macOS firewall may prompt once on first server start; allow it.
- Results append to `portal/results.jsonl`; delete it between engagements.

---

## Mode B — gateway (the Mac as the AP)

macOS gives you the access point for free — **Internet Sharing** creates the
hotspot, hands out `192.168.2.x` by DHCP and NATs the clients out. It gives
you **no enforcement**: clients are online the moment they associate, and
nothing opens a sign-in sheet.

`setup-captive.sh` adds the missing half with `pf`:

```
client --HTTP:80--> bridge100 --rdr--> portal :8080  (sign-in sheet opens)
                     |
                     +-- everything else dropped until the client IP is in
                         the pf table <portal_auth> (3600s lease by default)
```

### Before you start: the uplink rule

On Apple Silicon the Wi-Fi radio **cannot share its own connection over
itself** — `PrimaryInterface=en1, Enabled=0` in
`/Library/Preferences/SystemConfiguration/com.apple.nat.plist` is macOS
refusing exactly that. So the hotspot needs a **non-Wi-Fi uplink**:

1. Plug Ethernet into the router (the shared device becomes `en0`), or
2. use a USB adapter (Ethernet or a Wi-Fi adapter in client mode) as the
   shared device.

Then in **System Settings → General → Sharing → Internet Sharing**:

- *Share your connection from:* **Ethernet (en0)** — not Wi-Fi
- *Share with:* **Wi-Fi**
- turn it **on**

The hotspot is then `failbr34k's Mac mini` on `192.168.2.1`.

Check the result:

```sh
ipconfig getifaddr en0        # must be a real 192.168.x.x, not 169.254.x.x
ipconfig getifaddr bridge100  # 192.168.2.1
```

### Apply the enforcement

```sh
sudo ./mac/setup-captive.sh --dry-run    # preview, changes nothing
sudo ./mac/setup-captive.sh              # apply + probe check
sudo ./mac/setup-captive.sh --status     # rules, grants, counters
sudo ./mac/setup-captive.sh --remove     # tear it down
```

What it does:

| Step | Where |
|------|-------|
| AP + DHCP + NAT | macOS Internet Sharing (not touched by the script) |
| HTTP → portal | pf `rdr` on the bridge, for clients not in `<portal_auth>` |
| forward policy | pf `block in quick` — everything but DNS/DHCP/the portal is dropped |
| 443 | dropped, not redirected: TLS cannot be transparently redirected, and dropping it is what makes the OS fall back to its plain-HTTP probe |
| authorized set | pf table `<portal_auth>` — **pf tables have no TTL**, so `captive-auth` tracks the lease in `/var/db/portalgun/auth.tsv` and a launchd timer reaps expired entries every 60s |
| sign-in wiring | `POST /login` → `captive-auth add <client-ip>` |
| IPv6 | `net.inet6.ip6.forwarding=0` — macOS `pf` is IPv4-only, so a live IPv6 path would route straight around the portal |

The rules live in the pf anchor **`com.apple/000.portal`**. The name is not
decorative: `/etc/pf.conf` references `anchor "com.apple/*"`, and
`pf.conf(5)` says wildcard anchors are evaluated *in alphabetical order of
their anchor name* — so `000.portal` is reached before the `200.AirDrop` /
`250.ApplicationFirewall` anchors and before the rules Internet Sharing
installs for the shared interface. The first matching pf rule wins, so this
is what makes the block effective. Nothing in `/etc/pf.conf` is modified and
the main ruleset is never flushed, so Internet Sharing keeps working.

### Run the portal

```sh
sudo ./mac/start.sh --gateway            # sign-in wired to the pf helper
# or, always-on:
sudo ./mac/setup-captive.sh --portal-daemon   # launchd service, survives logout
```

`--gateway` is the only difference from the plain launcher: it exports
`CAPTIVE_AUTH=/usr/local/sbin/captive-auth`, which is what turns `POST
/login` from "disabled (503)" into "grant this client".

### Verify from a client (phone on the hotspot)

```sh
curl -v http://example.com            # 302 -> portal
curl -m 5 -v https://example.com      # times out (443 dropped) until signed in
open http://captive.apple.com         # -> "Sign in to network" sheet
```

The sheet must open on the **sign-in page**, not the module catalog: the
probe handlers in `portal/server.py` answer with `302 Location: /login` when
enforcement is enabled. Answering a probe with the OS' *expected* success
content (Apple's "Success" page, a `204`, "Microsoft Connect Test") tells the
device the network is open and **hides** the portal — that was the original
bug in this repo.

On the Mac:

```sh
sudo ./mac/setup-captive.sh --status            # rules, grants, counters
sudo pfctl -a com.apple/000.portal -v -s rules  # per-rule hit counters
sudo /usr/local/sbin/captive-auth list          # who is authorized, until when
sudo /usr/local/sbin/captive-auth add 192.168.2.50
sudo /usr/local/sbin/captive-auth del 192.168.2.50
```

### Not needed here: dnsmasq

The Linux gateway needs dnsmasq for DHCP and DNS. On macOS, Internet Sharing
already does both, and DNS must stay **real**: the OS probes are intercepted
by the `rdr` rule on port 80, not by a DNS sinkhole. A wildcard
`address=/#/` would break every authenticated client that tries to resolve a
real name. If you installed dnsmasq for the old attempt, remove the
sinkhole line (`/opt/homebrew/etc/dnsmasq.conf`) and leave the service
stopped.

### Cleanup

```sh
sudo ./mac/setup-captive.sh --remove
```

removes the pf anchor, the helper, the lease state, the launchd agents and
restores IPv6 forwarding. Internet Sharing itself is left alone — turn it off
in System Settings when the session ends.

### Caveats worth knowing

- **The sign-in page hands out the token.** `/login` embeds `PORTAL_TOKEN` in
  the page so the operator can just press *Connect*, which means any device
  on the hotspot can read it and authorize itself. Fine for a closed lab
  SSID; if that matters, drop the token from the page and have the operator
  type the access code.
- **The application firewall** may prompt for incoming connections the first
  time the portal binds. Allow it, or pre-approve the interpreter:
  `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add "$(command -v python3)"`.
- **Stale anchors from earlier attempts.** A previous tool left
  `/etc/pf.anchors/captivator.6987` and `captivator.71192` behind. They were
  never referenced from `/etc/pf.conf`, so pf never evaluated them; delete
  them (`sudo rm -f /etc/pf.anchors/captivator.*`) to keep things readable.
- **Scope.** This forces traffic. Use a closed SSID and only devices you own
  or are authorized to test — see `../README.md`.

---

## Mode C — AP bridge (closed-loop lab)

The lab is **closed**: the gateway, the access point and the devices under test
are the entire network. Nothing reaches the internet, by design — the devices
are tested against the portal, not against the web.

```
   device under test
        |  Wi-Fi  10.20.0.50-150, gw/dns 10.20.0.1
        v
   [ Mac mini ]  AP + L2 bridge (no DHCP, no NAT, no routing)
        |  en0  10.20.0.2/24
        v
   [ Linux gateway ]  10.20.0.1/24 — DHCP, DNS, portal :8080, nginx :80, nftables
```

### Why the Mac cannot be the gateway here

macOS Internet Sharing is a router: it hands out `192.168.2.x` leases, makes
itself the gateway and NATs the clients out through the wired port. Then the
Linux box sees every client as one address, and the per-client sign-in grants
(`captive-auth add <ip>`) address the wrong host. The clients have to be on
the *same layer-2 segment* as the gateway, so the Mac has to be a dumb bridge.

### What the script does

```sh
sudo ./mac/setup-ap-bridge.sh --dry-run    # preview, changes nothing
sudo ./mac/setup-ap-bridge.sh              # apply + verify
sudo ./mac/setup-ap-bridge.sh --status     # what the AP looks like now
sudo ./mac/setup-ap-bridge.sh --remove     # undo (leaves Internet Sharing on)
```

1. **The hotspot stays on.** The SoftAP is the only access point macOS exposes
   on Apple Silicon — the Wi-Fi radio cannot share its own link. If Internet
   Sharing is not running, the script writes the sharing preferences and
   starts the daemon; if macOS refuses, it tells you to flip the switch in
   *System Settings → General → Sharing → Internet Sharing* (share from the
   wired port to Wi-Fi) and re-run.
2. **The wired port joins the hotspot bridge** (`ifconfig bridge100 add en0 up`).
   The radio and the wired port become ONE layer-2 segment, so a client's
   frames reach the gateway directly instead of being routed and NATed by the
   Mac.
3. **macOS's DHCP server (`bootpd`) is disabled**, not just stopped — in
   launchd, so the sharing daemon cannot bring it back. This is the step that
   actually makes the Linux box the gateway: with `bootpd` running, devices
   take a `192.168.2.x` lease from the Mac and route through it.
4. **The Mac's lab address** (`10.20.0.2/24` by default) goes on the wired
   port. The *bridge* keeps macOS's own `192.168.2.1` on purpose: the sharing
   NAT rule matches `192.168.2.0/24` while the lab traffic is `10.20.0.0/24`,
   so nothing on the lab path is ever NATed.
5. **A launchd keepalive** (`com.portalgun.ap-keepalive`, every 60s)
   re-asserts steps 2-4. The sharing daemon re-applies its own configuration
   after a link flap, a reboot or a restart of the sharing service, and a
   single stray `192.168.2.x` lease is enough to break the lab silently.

The Mac's router and DNS are left exactly as they are: the lab gateway
resolves the OS probe names and nothing else (no upstream — it is a closed
loop), so pointing this Mac's DNS at it would break every other lookup here.

### Verify

```sh
sudo ./mac/setup-ap-bridge.sh --status
#   bridge holds en0, bootpd disabled, gateway reachable

# on the device under test:
ipconfig getifaddr en0        # must be 10.20.0.x, NOT 192.168.2.x
```

If the device shows `192.168.2.x`, macOS's DHCP server is still answering:

```sh
sudo launchctl print-disabled system | grep bootpd
```

### The gateway side

On the Linux box:

```bash
sudo ./linux/setup-gateway.sh --no-hostapd --closed-loop -i eth0 -g 10.20.0.1
```

`--no-hostapd` — this box is the gateway only, the radio is on the Mac.
`--closed-loop` — nothing lives behind it, so no NAT is installed and DNS
resolves only the OS probe names (which have to resolve, or the device never
issues the probe and the sign-in sheet never opens).

The portal lives on the gateway: `http://10.20.0.1/` (nginx) or
`http://10.20.0.1:8080/` (the portal server directly).

### Cleanup

```sh
sudo ./mac/setup-ap-bridge.sh --remove
```

removes the bridge membership, re-enables `bootpd` and removes the keepalive.
Internet Sharing itself is left alone — turn it off in System Settings.

---

## Adding more checks

The portal is modular now: drop a folder into `portal/modules/` (copy
`portal/modules/_template/`), fill in `module.json` + `index.html`, refresh the
catalog page — no restart, no server changes. Module pages get the shared
consent/token/preset/log plumbing from `/core.js` for free. See
`../README.md` for the module API.

## Per-case vs always-on

The on-demand setup is intentionally manual: the strongest scope guarantee is
that the exploit page is only ever reachable while you're sitting there
running it. If you later want always-on anywhere on your LAN, use the
gateway mode above — or re-enable the `../linux/` stack on a dedicated Linux
box instead — never on a shared SSID.
