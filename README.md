# PortalGun

A modular, tiered exploit verification portal for WebKit/JavaScriptCore vulnerabilities. Designed for security researchers to safely test vulnerability primitives on their own devices.

## Features

- **Modular Architecture**: Drop-in CVE modules in `portal/modules/` with auto-discovery (no server restart)
- **Three-Tier System**:
  - Tier 1: Full public PoC (5 modules)
  - Tier 2: Reconstructed probes from public root cause analysis (108 modules)
  - Tier 3: Advisory-only engine fingerprint pages (2 modules)
- **Crash Oracle**: localStorage marker + 1Hz heartbeat detects renderer crashes
- **Token-Gated Reporting**: `PORTAL_TOKEN` environment variable protects report endpoint
- **Consent Gate**: Users must explicitly consent before running tests
- **Per-CVE Presets**: Configurable test parameters per module
- **macOS On-Demand Launcher**: `./mac/start.sh` for ephemeral testing
- **macOS Gateway Mode**: `./mac/setup-captive.sh` — the Mac as the AP, pf-enforced sign-in
- **Linux Gateway Configs**: `./linux/` for persistent deployments
- **Operator Dashboard**: Real-time device/module telemetry at `/dashboard`

## Quick Start

### macOS (On-Demand)
```bash
export PORTAL_TOKEN="your-secure-token"
./mac/start.sh
# Opens http://localhost:8080 in Safari
# Ctrl-C to stop and go offline
```

### macOS (Gateway — the Mac is the AP)
```bash
# 1. plug Ethernet into the router and turn on
#    System Settings > General > Sharing > Internet Sharing
#    (share Ethernet -> Wi-Fi; the Wi-Fi radio cannot share its own link)
# 2. enforce the portal with pf
sudo ./mac/setup-captive.sh --dry-run
sudo ./mac/setup-captive.sh
# 3. run the portal with the sign-in handler wired to the pf helper
sudo ./mac/start.sh --gateway
# Clients get a "Sign in to network" sheet; the OS probes must get a 302.
```
See `mac/README-macos.md` for the design (rdr + forward-drop + pf-table
leases) and the verification steps.

### Linux (Persistent Gateway)
```bash
# Preview first (no root, no changes):
./linux/setup-gateway.sh --dry-run

# On the gateway box — deploys the portal, starts AP/DHCP/nginx, applies enforcement:
sudo ./linux/setup-gateway.sh
sudo ./linux/setup-gateway.sh --status
sudo ./linux/setup-gateway.sh --stop
```
See `linux/README.md` for the captive-portal design (redirect + forward-drop +
sign-in lease) and `linux/setup-enforcement.sh` to apply only the firewall half.

### Manual Server
```bash
export PORTAL_TOKEN="your-secure-token"
cd portal
python3 server.py
# Serves on :8080
```

## Architecture

```
portal/
├── server.py              # Main HTTP server with module discovery
├── site/
│   ├── core.js           # PortalGun runtime (consent, crash oracle, reporting)
│   ├── core.css          # Shared dark theme
│   └── index.html        # Landing page (module catalog)
├── modules/              # Drop-in CVE modules (auto-discovered)
│   ├── CVE-YYYY-NNNNN/
│   │   ├── module.json   # Metadata: tier, title, CVE, presets, source
│   │   └── index.html    # Probe logic using PortalGun.start()
│   └── _template/        # Template for new modules
├── results.jsonl         # Append-only test results
└── tools/
    └── mkadvisory-modules.py  # Generates tier-3 modules from advisory data
```

Platform-specific files live at the top level:

```
linux/                    # everything Linux (persistent captive gateway)
├── setup-gateway.sh      # one-shot bring-up (deploy portal + AP + DHCP + nginx + enforcement)
├── setup-enforcement.sh  # firewall half: redirect, forward-drop, NAT, captive-auth helper
├── hostapd.conf          # WiFi AP config
├── dnsmasq.conf          # DHCP + real DNS (never wildcarded)
├── nginx.conf            # port-80 front door / probe redirect
└── README.md             # gateway design + verification

mac/                      # everything macOS
├── start.sh              # ephemeral launcher (Ctrl-C = offline)
├── setup-captive.sh      # gateway mode: pf enforcement for the hotspot
└── README-macos.md       # macOS usage guide (on-demand + gateway)
```

## Module Development

### Creating a New Module

```bash
cp -r portal/modules/_template portal/modules/CVE-YYYY-NNNNN
# Edit module.json and index.html
```

### Module Metadata (module.json)
```json
{
  "id": "CVE-YYYY-NNNNN",
  "title": "Vulnerability Name — tier X probe",
  "cve": "CVE-YYYY-NNNNN",
  "engine": "JavaScriptCore (WebKit)",
  "platform": "Safari / iOS / WebKitGTK",
  "category": "use-after-free | memory corruption | info disclosure | etc",
  "severity": "high | medium | low (description)",
  "summary": "Description of vulnerability and probe approach",
  "affected": "Affected versions",
  "fixed": "Fixed versions",
  "proof": "Expected proof artifact (crash oracle / pointer leak / etc)",
  "presets": ["probe"],
  "source": "Apple security advisory (CVE-YYYY-NNNNN)",
  "tier": 2
}
```

### Probe Logic (index.html)
```html
<script src="/core.js"></script>
<script>
PortalGun.start({
  module: "CVE-YYYY-NNNNN",
  crashOracle: true,  // Enable crash detection
  intro: '<div class="card">What this checks...</div>',
  presets: {
    probe: { label: "Probe", blurb: "description", desc: "details", capMin: 3 }
  },
  run: async function(ctx) {
    // ctx.log(), ctx.report(), ctx.tick(), ctx.aborted(), ctx.expired()
    return { outcome: "vulnerable|patched|unknown", detail: {}, html: "..." };
  }
});
</script>
```

## Tier Taxonomy

| Tier | Description | Count |
|------|-------------|-------|
| 1 | Full public PoC with working exploit | 5 |
| 2 | Reconstructed probe from public root cause analysis | 108 |
| 3 | Advisory-only (engine fingerprint) | 2 |

## Security & Scope

- **Own devices only**: Only test devices you own or are explicitly authorized to test
- **Proof-level only**: Modules demonstrate pointer leaks (addrof/fakeobj) or crash primitives — never escalate to code execution
- **Ephemeral by default**: macOS launcher stops server on Ctrl-C
- **Token-gated reports**: `PORTAL_TOKEN` required for `/report` endpoint
- **Consent required**: Users must click "I consent" before any test runs

## Dashboard

Access `/dashboard` for real-time operator view:
- All devices and modules seen
- Latest verdict per module/device
- Crash oracle staleness detection (>45s heartbeat = crash)
- Export via `portal/results.jsonl`

## Vulnerability Coverage

### Tier 1 (Full PoCs)
- CVE-2018-4441: JSArray::unshiftCountWithArrayStorage OOB clear
- CVE-2020-9802: DFG INT_MIN bounds-check-elimination OOB write
- CVE-2022-22620: Safari PopStateEvent use-after-free
- CVE-2025-14174: ANGLE Metal staging buffer OOB write
- CVE-2025-43529: WebKit DFG JIT use-after-free (StoreBarrierInsertionPhase)

### Tier 2 Categories (108 modules)
- **Memory corruption / crash**: 78 probes (crash oracle)
- **Use-after-free / GC**: 18 probes
- **JIT / compiler bugs**: 15 probes
- **Out-of-bounds access / write**: 7 probes
- **History sniffing / privacy**: 7 probes
- **Type confusion**: 6 probes
- **Info disclosure / leak**: 6 probes
- **Race condition / TOCTOU**: 5 probes
- **CSP bypass**: 4 probes
- **Sandbox escape / bypass**: 4 probes
- **Logic errors**: 2 probes
- **DoS / resource exhaustion**: 2 probes
- **Universal XSS**: 2 probes
- **SOP bypass**: 2 probes
- **UI spoofing / phishing**: 1 probe

## Requirements

- Python 3.8+
- Modern browser (Safari, Chrome, Firefox)
- Network access for device testing

## License

MIT License - See LICENSE file

## Disclaimer

This tool is for authorized security testing on devices you own. Unauthorized testing is illegal. The authors assume no liability for misuse.
