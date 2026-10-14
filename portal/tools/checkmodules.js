// Syntax-check every generated module page: extract the inline <script> blocks,
// stub the DOM bits they touch, and make sure the whole thing parses AND that
// LanCheck.start() is called with the expected shape.
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const modsRoot = path.resolve(__dirname, "..", "modules");
const ids = process.argv.slice(2);
if (!ids.length) {
  console.error("usage: node checkmodules.js <module-id>...");
  process.exit(2);
}

function stubs(id) {
  const mk = () => ({
    style: {}, dataset: {}, classList: { add() {}, remove() {} }, children: [],
    appendChild() {}, addEventListener() {}, removeEventListener() {},
    setAttribute() {}, getAttribute() { return null; }, closest() { return mk(); },
    querySelector() { return mk(); }, querySelectorAll() { return []; },
    contains() { return false; }, focus() {}, blur() {}, remove() {},
    set innerHTML(v) {}, get innerHTML() { return ""; },
    set textContent(v) {}, get textContent() { return ""; },
    set value(v) {}, get value() { return ""; },
  });
  return {
    window: null, document: {
      readyState: "loading",
      querySelector: () => ({ content: "" }),
      querySelectorAll: () => [],
      getElementById: () => null,
      createElement: mk,
      addEventListener() {}, body: mk(),
    },
    localStorage: { _d: new Map(), getItem(k) { return this._d.has(k) ? this._d.get(k) : null; },
                    setItem(k, v) { this._d.set(k, String(v)); } },
    navigator: { userAgent: "checker", platform: "MacIntel", maxTouchPoints: 0 },
    fetch: () => Promise.resolve({ json: () => Promise.resolve([]) }),
    performance: { now: () => 0 },
    setTimeout, clearTimeout, setInterval: () => 0, clearInterval,
    Worker: function () {
      this.postMessage = () => {}; this.terminate = () => {};
      Object.defineProperty(this, "onmessage", { set(f) {}, get() { return null; } });
      Object.defineProperty(this, "onerror", { set(f) {}, get() { return null; } });
    },
    Blob: function () {}, URL: { createObjectURL: () => "blob:stub" },
    alert: (m) => { (globalThis.__alerts = globalThis.__alerts || []).push(m); },
    console,
  };
}

let failures = 0;
for (const id of ids) {
  const file = path.join(modsRoot, id, "index.html");
  if (!fs.existsSync(file)) { console.log(`${id}: MISSING index.html`); failures++; continue; }
  const html = fs.readFileSync(file, "utf8");

  // inline script blocks only (src= blocks are separate files we check above)
  const blocks = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  if (!blocks.length) { console.log(`${id}: no inline script`); failures++; continue; }
  const src = blocks.join("\n;\n");

  const seen = [];
  const sandbox = stubs(id);
  sandbox.window = sandbox;
  sandbox.LanCheck = { start: (opts) => seen.push(opts) };
  sandbox.globalThis = sandbox;

  let ok = true, note = "";
  try {
    vm.createContext(sandbox);
    vm.runInContext(src, sandbox, { filename: id + "/index.html" });
  } catch (e) { ok = false; note = "RUN ERROR: " + e.message; }
  if (ok && seen.length !== 1) { ok = false; note = "LanCheck.start called " + seen.length + " times"; }
  if (ok) {
    const o = seen[0];
    const problems = [];
    if (o.module !== id) problems.push("module id mismatch: " + o.module);
    if (typeof o.run !== "function") problems.push("run is not a function");
    if (!o.presets || !Object.keys(o.presets).length) problems.push("no presets");
    for (const k of Object.keys(o.presets)) {
      const p = o.presets[k];
      if (!p.label || !p.blurb || !p.desc) problems.push(`preset ${k} missing label/blurb/desc`);
      if (!Number.isFinite(p.attempts) || !Number.isFinite(p.capMin))
        problems.push(`preset ${k} missing attempts/capMin`);
    }
    if (problems.length) { ok = false; note = problems.join("; "); }
  }
  console.log(`${ok ? "OK  " : "FAIL"} ${id}${note ? "  -- " + note : ""}` + (
    ok ? `  (crashOracle=${seen[0].crashOracle === true}, presets=${Object.keys(seen[0].presets).join("/")})` : ""));
  if (!ok) failures++;
}

// also verify the manifest
console.log("--- manifests ---");
for (const id of ids) {
  try {
    const m = JSON.parse(fs.readFileSync(path.join(modsRoot, id, "module.json"), "utf8"));
    const need = ["id","title","cve","engine","platform","category","severity","summary",
                  "affected","fixed","proof","presets","source","tier"];
    const missing = need.filter(k => !(k in m));
    const extra = Object.keys(m).filter(k => !need.includes(k));
    console.log(`${m.id} tier=${m.tier} presets=${JSON.stringify(m.presets)}` +
      (missing.length ? ` MISSING=${missing}` : "") + (extra.length ? ` extra=${extra}` : ""));
  } catch (e) { console.log(`${id}: BAD JSON ${e.message}`); failures++; }
}
process.exit(failures ? 1 : 0);
