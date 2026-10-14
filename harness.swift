// harness.swift — fallback runner that executes poc.js inside the *system*
// JavaScriptCore via JavaScriptCore.framework. Useful as a smoke test on
// machines without a custom jsc build. NOTE: macOS >= 26.2 ships the fix
// (commit b21a503), so there the PoC should exit cleanly with "race not won".
//
//   swiftc -O harness.swift -o harness && ./harness poc.js
import JavaScriptCore

let args = CommandLine.arguments
let path = args.count > 1 ? args[1] : "poc.js"

let src = try String(contentsOfFile: path, encoding: .utf8)

let vm = JSVirtualMachine()
let ctx = JSContext(virtualMachine: vm)!

// jsc-shell-style `print` so the PoC's log() helper works.
let printBlock: @convention(block) (String) -> Void = { print($0) }
ctx.setObject(printBlock, forKeyedSubscript: "print" as NSString)

ctx.exceptionHandler = { _, exception in
    if let e = exception { print("[!] JS exception: \(e)") }
}

_ = ctx.evaluateScript(src)
