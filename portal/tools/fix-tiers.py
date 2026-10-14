#!/usr/bin/env python3
"""Fix tier assignments: only verified PoCs get tier 1/2, rest tier 3."""
import json
import os
import sys

MODULES = "/Users/failbr34k/CVE-2025-43529/portal/modules"

# Tier 1: verified public PoC with working trigger in our portal
TIER1 = {
    "CVE-2018-4441",   # verbatim P0 splice (crash oracle)
    "CVE-2020-9802",   # verbatim browser-exploit PoC (addrof/fakeobj)
    "CVE-2022-22620",  # GPZ infoleak UAF
    "CVE-2022-22620",  # duplicate
    "CVE-2025-14174",  # ANGLE OOB write trigger + backend gate
    "CVE-2025-43529",  # original DFG StoreBarrier
}

# Tier 2: reconstructed probes from public root cause
TIER2 = {
    "CVE-2023-28205",  # Map/Date GC race (reconstructed probe)
    "CVE-2023-32439",  # for..in constant-folding (mismatch oracle)
    "CVE-2024-23222",  # tryGetConstantProperty TOCTOU (divergence oracle)
}

# Tier 3: everything else (advisory only, no PoC)
def main():
    fixed = 0
    for d in os.listdir(MODULES):
        if d.startswith("_"):
            continue
        mf = os.path.join(MODULES, d, "module.json")
        if not os.path.isfile(mf):
            continue
        with open(mf) as fh:
            m = json.load(fh)
        cid = m.get("id", d)
        old = m.get("tier")
        if cid in TIER1:
            m["tier"] = 1
        elif cid in TIER2:
            m["tier"] = 2
        else:
            m["tier"] = 3
        if old != m["tier"]:
            with open(mf, "w") as fh:
                json.dump(m, fh, indent=2)
            fixed += 1
            print(f"  {cid}: tier {old} -> {m['tier']}")
    print(f"Fixed {fixed} modules")

if __name__ == "__main__":
    main()
