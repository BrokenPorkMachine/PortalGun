# PortalGun — macOS on-demand mode (Mac mini M2)

Run the portal **only when you choose to test**, from the Mac mini, with
nothing forced through it. No DHCP server, no DNS wildcard, no NAT, no
startup items. When the launcher isn't running, your network is untouched.

## Why not the full captive-portal gateway on macOS

- `hostapd`/`dnsmasq` from `../linux/` need Linux; macOS's IO80211 does not
  expose AP mode to userland, and most USB Wi-Fi adapters don't do AP on macOS
  either.
- Full portal interception = forcing traffic. You explicitly don't want that,
  and for per-case testing it buys nothing: you browse to the page yourself.

## Start (one command)

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

## Testing a device (per case)

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

## Optional: the auto-popup captive sheet

Only if you ever want the iOS/Android captive-network-assistant auto-popup
during a test session, turn on **System Settings → General → Sharing →
Internet Sharing** (share from your uplink, to the built-in Wi-Fi) *for the
duration of the test*, and point the shared clients at a local dnsmasq so the
OS probes hit the Mac:

```sh
brew install dnsmasq
# wildcard A record to the mini; see ../linux/dnsmasq.conf for the comment block
echo "address=/#/$(ipconfig getifaddr en0)" >> $(brew --prefix)/etc/dnsmasq.conf
sudo brew services start dnsmasq
```

Caveats: Internet Sharing NATs clients through the mini (turn it off right
after the session), a bridged/AP-mode USB adapter is *not* required for this
path, and guests on the SSID will also see the sheet — re-read the scope
rules in `../README.md` before doing this.

## Adding more checks

The portal is modular now: drop a folder into `portal/modules/` (copy
`portal/modules/_template/`), fill in `module.json` + `index.html`, refresh the
catalog page — no restart, no server changes. Module pages get the shared
consent/token/preset/log plumbing from `/core.js` for free. See
`../README.md` for the module API.

## Per-case vs always-on

This setup is intentionally manual: the strongest scope guarantee is that
the exploit page is only ever reachable while you're sitting there running it.
If you later want always-on anywhere on your LAN, re-enable the `../linux/`
gateway stack on a dedicated Linux box instead — never on a shared SSID.
