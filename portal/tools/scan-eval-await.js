// Scan every module for .eval(`...`/('...')) argument strings that contain
// top-level `await` (invalid outside async functions/modules) — the bug class
// found in CVE-2026-64753's cross-origin test.
"use strict";
const fs = require("fs");
const path = require("path");
const modsRoot = path.resolve(__dirname, "..", "modules");

function extractCallArg(src, idx) {
  // idx points at '(' of the eval call. Return the raw argument text.
  let depth = 0, inStr = null, esc = false;
  for (let i = idx; i < src.length; i++) {
    const c = src[i];
    if (inStr) {
      if (esc) { esc = false; continue; }
      if (c === "\\") { esc = true; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") { inStr = c; continue; }
    if (c === "(") depth++;
    else if (c === ")") { depth--; if (depth === 0) return src.slice(idx + 1, i); }
  }
  return null;
}

const problems = [];
for (const id of fs.readdirSync(modsRoot)) {
  const file = path.join(modsRoot, id, "index.html");
  if (!fs.existsSync(file)) continue;
  const src = fs.readFileSync(file, "utf8");
  let at = 0, found = false;
  while (true) {
    const m = src.indexOf(".eval(", at);
    if (m < 0) break;
    at = m + 6;
    const arg = extractCallArg(src, src.indexOf("(", m));
    if (arg == null) continue;
    // strip template-literal wrappers for analysis
    let code = arg;
    if (/^`[\s\S]*`$/.test(code) || /^["']/.test(code)) {
      try { code = JSON.parse('"' + code.slice(1, -1).replace(/\\.|"/g, c => c === '"' ? '\\"' : c) + '"'); } catch (e) {}
    }
    if (/\bawait\b/.test(code) && !/\basync\b/.test(code)) {
      problems.push(id);
      found = true;
      const line = src.slice(0, m).split("\n").length;
      console.log(`${id}:${line}  top-level await in eval() string`);
      break;
    }
  }
}
console.log(problems.length ? `\n${problems.length} module(s) with broken eval+await` : "clean");
