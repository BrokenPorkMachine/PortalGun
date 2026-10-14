# CVE Exploit Verification Portal

A modular, tiered exploit verification portal for WebKit/JavaScriptCore vulnerabilities. Designed for security researchers to safely test vulnerability primitives on their own devices.

## Features

- **Modular Architecture**: Drop-in CVE modules in `portal/modules/` with auto-discovery (no server restart)
- **Three-Tier System**:
  - Tier 1: Full public PoC (5 modules)
  - Tier 2: Reconstructed probes from public root cause analysis (126+ modules)
  - Tier 3: Advisory-only engine fingerprint pages (0 remaining - all upgraded)
- **Crash Oracle**: localStorage marker + 1Hz heartbeat detects renderer crashes
- **Token-Gated Reporting**: `PORTAL_TOKEN` environment variable protects report endpoint
- **Consent Gate**: Users must explicitly consent before running tests
- **Per-CVE Presets**: Configurable test parameters per module
- **macOS On-Demand Launcher**: `./mac/start.sh` for ephemeral testing
- **Linux Gateway Configs**: `portal/lab/` for persistent deployments
- **Operator Dashboard**: Real-time device/module telemetry at `/dashboard`

## Quick Start

### macOS (On-Demand)
```bash
export PORTAL_TOKEN="your-secure-token"
./mac/start.sh
# Opens http://localhost:8080 in Safari
# Ctrl-C to stop and go offline
```

### Linux (Persistent Gateway)
```bash
export PORTAL_TOKEN="your-secure-token"
cd portal/lab
# Configure hostapd/dnsmasq/nginx per lab/README.md
sudo ./setup-gateway.sh
```

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
│   ├── core.js           # LanCheck runtime (consent, crash oracle, reporting)
│   ├── core.css          # Shared dark theme
│   └── index.html        # Landing page (module catalog)
├── modules/              # Drop-in CVE modules (auto-discovered)
│   ├── CVE-YYYY-NNNNN/
│   │   ├── module.json   # Metadata: tier, title, CVE, presets, source
│   │   └── index.html    # Probe logic using LanCheck.start()
│   └── _template/        # Template for new modules
├── mac/
│   ├── start.sh          # macOS on-demand launcher
│   └── README-macos.md   # macOS usage guide
├── lab/                  # Linux gateway configs
│   ├── hostapd.conf      # WiFi AP config
│   ├── dnsmasq.conf      # DHCP/DNS config
│   ├── nginx.conf        # Reverse proxy config
│   └── README.md         # Lab setup guide
├── results.jsonl         # Append-only test results
└── tools/
    └── mkadvisory-modules.py  # Generates tier-3 modules from advisory data
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
LanCheck.start({
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
| 2 | Reconstructed probe from public root cause analysis | 126+ |
| 3 | Advisory-only (engine fingerprint) | 0 (all upgraded) |

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

### Tier 2 Categories (126+ modules)
- **Use-after-free**: 20+ probes (crash oracle)
- **Memory corruption crashes**: 30+ probes (crash oracle)
- **Out-of-bounds access**: 10+ probes (crash oracle)
- **Type confusion**: 8+ probes
- **CSP bypass**: 5+ probes
- **Sandbox escape**: 5+ probes
- **Info disclosure**: 10+ probes
- **Race conditions**: 5+ probes
- **UI spoofing**: 3+ probes
- **History sniffing**: 2+ probes
- **Logic errors**: 3+ probes
- **DoS/resource exhaustion**: 3+ probes
- **Universal XSS**: 2+ probes

## Requirements

- Python 3.8+
- Modern browser (Safari, Chrome, Firefox)
- Network access for device testing

## License

MIT License - See LICENSE file

## Disclaimer

This tool is for authorized security testing on devices you own. Unauthorized testing is illegal. The authors assume no liability for misuse.
