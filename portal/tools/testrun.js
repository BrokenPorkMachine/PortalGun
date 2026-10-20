// Execute each module's run(ctx) against a stubbed DOM and report the outcome.
// This catches runtime errors, infinite loops and nonsense verdicts.
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const modsRoot = path.resolve(__dirname, "..", "modules");
const id = process.argv[2];
if (!id) { console.error("usage: node testrun.js <module-id>"); process.exit(2); }

const file = path.join(modsRoot, id, "index.html");
const html = fs.readFileSync(file, "utf8");

function mk(tag) {
  const self = {
    tagName: String(tag || "DIV").toUpperCase(),
    href: "", rel: "", style: {}, dataset: {}, id: "",
    classList: { add() {}, remove() {} }, children: [],
    appendChild(c) { self.children.push(c); return c; },
    addEventListener() {}, removeEventListener() {},
    setAttribute() {}, getAttribute() { return null; }, closest() { return mk(); },
    querySelector() { return mk(); }, querySelectorAll() { return []; },
    contains() { return false; }, focus() {}, blur() {},
    remove() { self.children.length = 0; },
    click() { self.clicked = (self.clicked || 0) + 1; },
    width: 1, height: 1,
    set innerHTML(v) {}, get innerHTML() { return ""; },
    set textContent(v) {}, get textContent() { return ""; },
    set value(v) {}, get value() { return ""; },
    getContext() { return null; },
  };
  return self;
}

const sandbox = {
  console,
  setTimeout, clearTimeout, setInterval: () => 0, clearInterval,
  Promise, Error, TypeError, JSON, Math, Date, Object, Array, String, Number,
  isNaN, parseInt, parseFloat, encodeURIComponent, decodeURIComponent,
  Uint8Array, Uint32Array, Float64Array, ArrayBuffer, Uint8ClampedArray,
  Map, Set, WeakMap, RegExp, Blob: function () {}, ImageData: function () {},
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
sandbox.window._listeners = Object.create(null);
sandbox.window.addEventListener = (type, fn) => {
  (sandbox.window._listeners[type] ||= []).push(fn);
};
sandbox.window.removeEventListener = (type, fn) => {
  sandbox.window._listeners[type] = (sandbox.window._listeners[type] || []).filter((x) => x !== fn);
};
sandbox.document = {
  readyState: "loading",
  querySelector: () => ({ content: "" }),
  querySelectorAll: () => [],
  getElementById: () => null,
  createElement: (tag) => mk(tag),
  addEventListener() {},
  body: mk(),
};
sandbox.navigator = { userAgent: "NodeRunner/1.0", platform: "MacIntel", maxTouchPoints: 0 };
sandbox.performance = { now: () => Date.now() };
sandbox.fetch = () => Promise.resolve({ json: () => Promise.resolve([]) });
sandbox.alert = () => {};
sandbox.localStorage = {
  _d: new Map(),
  getItem(k) { return this._d.has(k) ? this._d.get(k) : null; },
  setItem(k, v) { this._d.set(k, String(v)); },
};
// Worker stub: never produces a message, so the run() falls through its timeout path
sandbox.Worker = function () {
  this.postMessage = () => {};
  this.terminate = () => {};
  Object.defineProperty(this, "onmessage", { set(f) {}, get() { return null; } });
  Object.defineProperty(this, "onerror", { set(f) {}, get() { return null; } });
};
sandbox.URL = URL;
sandbox.URLSearchParams = URLSearchParams;
sandbox.URL.createObjectURL = () => "blob:stub";
sandbox.URL.revokeObjectURL = () => {};
sandbox.location = { href: "http://portal/module/", toString: () => "http://portal/module/" };
sandbox.history = {
  _state: "",
  pushState(s, t, u) { sandbox.location.href = u; },
  replaceState(s, t, u) { sandbox.location.href = u; },
  back() {}, forward() {}, go() {},
};
sandbox.ImageData = function (w, h) { this.width = w; this.height = h; };
// Navigation API stub: dispatch a synthetic `navigate` event so the SOP-gate
// probe can be exercised. Flip DEFAULT_CAN_INTERCEPT to model each build.
const DEFAULT_CAN_INTERCEPT = process.env.CAN_INTERCEPT === "1";
sandbox.window.navigation = {
  _ls: [],
  addEventListener(t, f) { if (t === "navigate") this._ls.push(f); },
  removeEventListener(t, f) { this._ls = this._ls.filter(x => x !== f); },
};
sandbox.__fireNavigate = function (url, canIntercept) {
  const ev = {
    destination: { url },
    canIntercept,
    intercept(o) { this._intercepted = true; },
    preventDefault() { this._prevented = true; },
  };
  for (const f of sandbox.window.navigation._ls.splice(0)) f(ev);
  return ev;
};

// Load vendored sibling scripts in the SAME ORDER the page references them,
// not alphabetical — int64.js builds Int64.Zero at parse time and needs
// unhexlify() from utils.js, so order is load-bearing.
vm.createContext(sandbox);
const dir = path.dirname(file);
const srcOrder = [...html.matchAll(/<script\s+src="([^"]+)"><\/script>/g)].map(m => m[1]);
for (const src of srcOrder) {
  // /core.js and /core.css are portal-provided, not module siblings
  if (src.startsWith("/")) continue;
  const sib = path.basename(src);
  const p = path.join(dir, sib);
  if (!fs.existsSync(p)) { console.log(`[missing ${src}]`); continue; }
  vm.runInContext(fs.readFileSync(p, "utf8"), sandbox, { filename: id + "/" + sib });
  console.log(`[loaded ${src} in page order]`);
}

const opts = [];
sandbox.PortalGun = { start: (o) => opts.push(o) };
vm.createContext(sandbox);
const blocks = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
vm.runInContext(blocks.join("\n;\n"), sandbox, { filename: id + "/index.html" });

const o = opts[0];
const log = [];
const cap = (o.presets[Object.keys(o.presets)[0]].capMin || 1) * 60000;
const ctx = {
  cfg: o.presets[Object.keys(o.presets)[0]],
  aborted: () => false,
  expired: () => Date.now() - t0 > cap,
  tick: () => Promise.resolve(),
  sleep: (ms) => new Promise((r) => setTimeout(r, 0)),
  log: (m, c) => log.push(c ? `[${c}] ${m}` : m),
  progress: () => {},
  report: () => {},
};

const t0 = Date.now();
const timer = setTimeout(() => {
  console.log(`\n!! TIMEOUT after 20s — likely an infinite loop (or a preset cap over 20s)`);
  process.exit(3);
}, 20000);

// The module synthesises an <a> click to fire the navigation. In a real browser
// that dispatches `navigate`; here we hook the click and fire it ourselves, so
// the module's listener path is genuinely exercised.
sandbox.__armNavigate = function () {
  const origAppend = sandbox.document.body.appendChild.bind(sandbox.document.body);
  sandbox.document.body.appendChild = function (c) {
    const r = origAppend(c);
    if (c && c.tagName === "A" && c.href && c.href !== sandbox.location.href) {
      // the module appended the cross-origin link: dispatch `navigate` for it
      setTimeout(() => {
        const ev = sandbox.__fireNavigate(c.href, DEFAULT_CAN_INTERCEPT);
        sandbox.__lastNav = { url: c.href, canIntercept: ev.canIntercept,
                              intercepted: ev._intercepted === true,
                              prevented: ev._prevented === true };
      }, 0);
    }
    return r;
  };
};
if (sandbox.window.navigation) sandbox.__armNavigate();

Promise.resolve(o.run(ctx)).then((res) => {
  clearTimeout(timer);
  console.log(`\n--- ${id} finished in ${Date.now() - t0}ms ---`);
  console.log("outcome:", res && res.outcome);
  console.log("detail :", JSON.stringify(res && res.detail));
  console.log("html   :", String(res && res.html).slice(0, 240));
  if (sandbox.__lastNav) {
    console.log("nav    :", JSON.stringify(sandbox.__lastNav),
                "(navigation stayed on-page:",
                !!(sandbox.__lastNav.intercepted || sandbox.__lastNav.prevented), ")");
  }
  console.log("log    :");
  for (const l of log.slice(-12)) console.log("   " + l);
  if (!res || !res.outcome) { console.log("!! run() returned no outcome"); process.exit(4); }
  process.exit(0);
}).catch((e) => {
  clearTimeout(timer);
  console.log(`\n!! run() threw: ${e && e.stack ? e.stack.split("\n").slice(0, 4).join("\n") : e}`);
  process.exit(5);
});
