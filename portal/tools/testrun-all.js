// Run every installed module through the same bounded harness used for
// individual checks. Unknown is a valid probe result; only runner failures
// and timeouts fail this command.
"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const root = path.resolve(__dirname, "..");
const modules = fs.readdirSync(path.join(root, "modules")).filter((id) => {
  return !id.startsWith("_") && fs.existsSync(path.join(root, "modules", id, "index.html"));
}).sort();

const counts = Object.create(null);
const failures = [];
for (const id of modules) {
  const run = spawnSync(process.execPath, [path.join(__dirname, "testrun.js"), id], {
    cwd: root,
    encoding: "utf8",
    timeout: 25000,
    maxBuffer: 1024 * 1024,
  });
  const output = (run.stdout || "") + (run.stderr || "");
  const match = output.match(/^outcome:\s*(\S+)/m);
  const outcome = match && match[1];
  const timedOut = run.error && run.error.code === "ETIMEDOUT";
  if (timedOut || run.status !== 0 || !outcome) {
    failures.push({ id, reason: timedOut ? "timeout" : (run.error && run.error.message) || "runner failure" });
    console.log(`FAIL ${id} — ${failures[failures.length - 1].reason}`);
    continue;
  }
  counts[outcome] = (counts[outcome] || 0) + 1;
  console.log(`${outcome === "unknown" ? "INFO" : " OK "} ${id} — ${outcome}`);
}

console.log("\nSummary:", JSON.stringify(counts));
console.log("Modules:", modules.length, "Runner failures:", failures.length);
process.exitCode = failures.length ? 1 : 0;
