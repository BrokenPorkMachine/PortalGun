/*
 * LanCheck core — shared runtime for all check modules.
 *
 * A module page only needs:
 *   <html><head>…<link rel=stylesheet href="/core.css">
 *     <meta name="portal-token" content="__PORTAL_TOKEN__">…</head>
 *   <body><div id="lc-app"></div>
 *   <script src="/core.js"></script>
 *   <script>LanCheck.start({ module: "CVE-…", presets: {...}, run: async (ctx) => ({…}) })</script>
 *   </body></html>
 *
 * The core renders the consent gate, token field, preset picker, run/abort
 * buttons, progress bar, log and result panel, and takes care of reporting
 * every event to the portal server. The module only implements the check.
 */
window.LanCheck = (function () {
  "use strict";

  var TOKEN = (document.querySelector('meta[name="portal-token"]') || { content: "" }).content || "";

  function el(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }
  function onReady(fn) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", fn);
    else fn();
  }
  function report(event, detail) {
    try {
      fetch("/report", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token: el("lc-token") ? el("lc-token").value.trim() || null : null,
          consent: window.__lcConsent === true,
          ua: navigator.userAgent,
          event: event,
          detail: detail || null,
          ts: Date.now(),
        }),
      }).catch(function () {});
    } catch (e) { /* reporting is best-effort */ }
  }

  /* Render the whole control surface into #lc-app. */
  function render(opts, state) {
    var presetNames = Object.keys(opts.presets);
    var presetHtml = presetNames.map(function (name, i) {
      var p = opts.presets[name];
      return '<label class="preset' + (p === state.cfg ? " sel" : "") + '" data-preset="' + esc(name) + '">' +
        '<input type="radio" name="lc-preset" ' + (i === 0 ? "checked" : "") + ">" +
        "<span><b>" + esc(p.label || name) + "</b> — " + esc(p.blurb || "") +
        "<small>" + esc(p.desc || "") + "</small></span></label>";
    }).join("");

    el("lc-app").innerHTML =
      (opts.intro || "") +
      '<div class="card warn"><b>Authorization &amp; scope.</b> ' +
      (opts.scopeText ||
        "Only run this on devices you own or are explicitly authorized to test. " +
        "This harness is proof-level only and never escalates to code execution. " +
        "Dismiss the page or hit Abort to stop at any time.") + "</div>" +
      '<div class="card"><label><input type="checkbox" id="lc-consent"> ' +
      "I own this device, or I am authorized to test it on this network.</label></div>" +
      '<div class="card"><h2>Preset</h2><div class="presets" id="lc-presets">' + presetHtml + "</div>" +
      '<div class="row" style="margin-top:.7rem">' +
      '<button id="lc-run" class="primary" disabled>Run check</button>' +
      '<button id="lc-abort" class="danger" disabled>Abort</button></div>' +
      '<p style="margin:.6rem 0"><progress id="lc-bar" value="0" max="100"></progress></p>' +
      '<div id="lc-log"></div></div>' +
      '<div class="card" id="lc-result">—</div>' +
      (opts.notes || "") +
      '<p class="foot">module <code>' + esc(opts.module) + "</code> · operator dashboard: " +
      '<a href="/dashboard">/dashboard</a></p>';
  }

  function outcomeClass(outcome) {
    if (outcome === "vulnerable" || outcome === "vulnerable-class") return "bad";
    if (outcome === "no-uaf" || outcome === "patched" || outcome === "aborted") return "ok";
    return "dim";
  }

  /* Crash oracle: reproduces many WebKit bugs = the renderer dies. We detect
   * that two ways: a localStorage marker left as "running" across loads, and
   * a heartbeat the server can see stop. Opt in with opts.crashOracle. */
  function crashKey(opts) {
    return "lc-crash-" + (opts.module || "default");
  }

  function start(opts) {
    onReady(function () {
      if (!el("lc-app")) return;
      var state = { cfg: opts.presets[Object.keys(opts.presets)[0]], aborted: false, running: false };
      render(opts, state);

      // token field is injected below from the server-provided meta tag
      var tokenInput = document.createElement("input");
      tokenInput.type = "text";
      tokenInput.id = "lc-token";
      tokenInput.value = TOKEN;
      tokenInput.placeholder = "Portal token (prefilled from gateway)";
      el("lc-consent").closest(".card").appendChild(tokenInput);
      el("lc-consent").closest(".card").style.marginTop = ".5rem";

      // previous-run crash detection
      var prevCrash = false;
      if (opts.crashOracle) {
        try {
          prevCrash = localStorage.getItem(crashKey(opts)) === "running";
          localStorage.setItem(crashKey(opts), "idle");
        } catch (e) { /* private mode etc. */ }
        if (prevCrash) {
          report("crash", { module: opts.module, note: "previous run of this module ended without finishing" });
        }
      }


      var logEl = el("lc-log");
      function log(msg, cls) {
        var line = document.createElement("div");
        if (cls) line.className = cls;
        var t = new Date().toTimeString().slice(0, 8);
        line.textContent = "[" + t + "] " + msg;
        logEl.appendChild(line);
        logEl.scrollTop = logEl.scrollHeight;
      }

      el("lc-consent").addEventListener("change", function () {
        window.__lcConsent = el("lc-consent").checked;
        el("lc-run").disabled = !window.__lcConsent || state.running;
        report("consent", { consent: window.__lcConsent === true });
      });

      document.querySelectorAll(".preset").forEach(function (pEl) {
        pEl.addEventListener("click", function () {
          document.querySelectorAll(".preset").forEach(function (x) { x.classList.remove("sel"); });
          pEl.classList.add("sel");
          state.cfg = opts.presets[pEl.dataset.preset];
          log("preset: " + (state.cfg.label || pEl.dataset.preset), "dim");
        });
      });

      el("lc-abort").addEventListener("click", function () {
        state.aborted = true;
        log("abort requested by user", "pass");
        report("abort");
      });

      function setRunning(on) {
        state.running = on;
        el("lc-run").disabled = on || window.__lcConsent !== true;
        el("lc-abort").disabled = !on;
      }

      el("lc-run").addEventListener("click", async function () {
        if (state.running) return;
        if (window.__lcConsent !== true) { alert("Confirm authorization first."); return; }
        setRunning(true);
        logEl.innerHTML = "";
        var deadline = Date.now() + (state.cfg.capMin || 5) * 60000;
        el("lc-bar").value = 0;
        el("lc-bar").max = state.cfg.attempts || 100;

        var ctx = {
          cfg: state.cfg,
          aborted: function () { return state.aborted; },
          expired: function () { return Date.now() > deadline; },
          tick: function () { return new Promise(function (r) { setTimeout(r, 0); }); },
          sleep: function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); },
          log: log,
          progress: function (n) { el("lc-bar").value = n; },
          report: report,
        };

        // crash-oracle: mark running + heartbeat so a dead renderer is visible
        var hb = null, seq = 0;
        if (opts.crashOracle) {
          try { localStorage.setItem(crashKey(opts), "running"); } catch (e) {}
          hb = setInterval(function () {
            ctx.report("alive", { seq: ++seq });
          }, 1000);
        }

        report("start", { preset: Object.keys(opts.presets).find(function (k) { return opts.presets[k] === state.cfg; }) || null, module: opts.module });
        try {
          var res = await opts.run(ctx);
          var outcome = (res && res.outcome) || "unknown";
          var detail = (res && res.detail) || null;
          log("outcome: " + outcome, outcomeClass(outcome));
          el("lc-result").innerHTML = res && res.html
            ? res.html
            : '<span class="' + outcomeClass(outcome) + '"><b>' + esc(outcome).toUpperCase() +
              "</b></span>" + (detail ? " — " + esc(JSON.stringify(detail)) : "");
          report("result", { outcome: outcome, detail: detail, module: opts.module });
        } catch (e) {
          log("[!] error: " + e, "bad");
          el("lc-result").innerHTML = '<span class="bad"><b>ERROR</b></span> — ' + esc(String(e));
          report("error", { message: String(e), module: opts.module });
        } finally {
          if (hb) clearInterval(hb);
          if (opts.crashOracle) {
            try { localStorage.setItem(crashKey(opts), "finished"); } catch (e) {}
          }
          setRunning(false);
        }
      });

      report("pageview", { module: opts.module });
      if (opts.crashOracle && prevCrash) {
        log("[!] previous run of this module died without finishing — renderer crash " +
            "recorded (vulnerable-class signal)", "bad");
      } else {
        log("module loaded: " + opts.module + " — confirm authorization, then Run check", "dim");
      }
    });
  }

  return { start: start, report: report, esc: esc };
})();
