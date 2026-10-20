#!/usr/bin/env python3
"""
Build the machine-readable tier index for the module repo.

portal/catalog.json is the single place an operator (or a script) can read to
answer "what do I have, in which tier, and where did it come from?" without
walking portal/modules/. It is generated, never hand-edited.

    python3 tools/mkcatalog.py            # write portal/catalog.json
    python3 tools/mkcatalog.py --check    # verify the catalog matches reality

The check is the useful mode for CI: it fails if a manifest's count, tier or
source disagrees with what is on disk, or if a module directory has drifted
from its generator's output.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PORTAL = os.path.normpath(os.path.join(HERE, ".."))
MODULES = os.path.join(PORTAL, "modules")
CATALOG = os.path.join(PORTAL, "catalog.json")

TIER_NAMES = {
    1: "public PoC exists — detection stage only",
    2: "root cause public — reconstructed probe",
    3: "advisory only — engine report, no exploit code",
}

# Which generator owns a module id. Used by --check to catch drift between what
# is on disk and what the generators would produce.
POC_GENERATOR = os.path.join(PORTAL, "tools", "mkpoc-modules.py")
ADV_GENERATOR = os.path.join(PORTAL, "tools", "mkadvisory-modules.py")


def load():
    mods = []
    for name in sorted(os.listdir(MODULES)):
        if name.startswith("_"):
            continue
        mf = os.path.join(MODULES, name, "module.json")
        ix = os.path.join(MODULES, name, "index.html")
        if not os.path.isfile(mf):
            continue
        with open(mf, encoding="utf-8") as fh:
            m = json.load(fh)
        m["_dir"] = name
        m["_has_page"] = os.path.isfile(ix)
        mods.append(m)
    return mods


def build(mods):
    tiers = {}
    for t in sorted({m.get("tier", 3) for m in mods}):
        group = [m for m in mods if m.get("tier", 3) == t]
        tiers[str(t)] = {
            "name": TIER_NAMES.get(t, "unknown"),
            "count": len(group),
            "modules": [
                {
                    "id": m["id"],
                    "title": m.get("title", ""),
                    "engine": m.get("engine", ""),
                    "category": m.get("category", ""),
                    "severity": m.get("severity", ""),
                    "oracle": m.get("proof", ""),
                    "affected": m.get("affected", ""),
                    "fixed": m.get("fixed", ""),
                    "presets": m.get("presets", []),
                    "source": m.get("source", ""),
                    "crashOracle": "crashOracle: true" in open(
                        os.path.join(MODULES, m["_dir"], "index.html"),
                        encoding="utf-8").read(20000),
                }
                for m in sorted(group, key=lambda x: x["id"])
            ],
        }
    return {
        "generated_by": "portal/tools/mkcatalog.py",
        "module_root": "portal/modules",
        "totals": {
            "modules": len(mods),
            "by_tier": {str(t): tiers[str(t)]["count"] for t in tiers},
        },
        "tiers": tiers,
    }


def committed():
    """Load the catalog.json that is actually on disk, or None if absent."""
    if not os.path.isfile(CATALOG):
        return None
    with open(CATALOG, encoding="utf-8") as fh:
        return json.load(fh)


def drift(built, have):
    """Compare the freshly built catalog against the committed one."""
    if have is None:
        return ["catalog.json is missing — run: python3 tools/mkcatalog.py"]
    bad = []
    if have.get("totals") != built["totals"]:
        bad.append("catalog totals %s != disk %s"
                   % (have.get("totals"), built["totals"]))
    ht = {t: {x["id"] for x in v.get("modules", [])}
          for t, v in have.get("tiers", {}).items()}
    bt = {t: {x["id"] for x in v.get("modules", [])}
          for t, v in built["tiers"].items()}
    for t in sorted(set(ht) | set(bt)):
        missing = sorted(bt.get(t, set()) - ht.get(t, set()))
        extra = sorted(ht.get(t, set()) - bt.get(t, set()))
        if missing:
            bad.append("tier %s: on disk but not in catalog: %s"
                       % (t, ", ".join(missing)))
        if extra:
            bad.append("tier %s: in catalog but not on disk: %s"
                       % (t, ", ".join(extra)))
    return bad


def problems(mods, cat):
    bad = []
    # 1. catalog totals must match disk
    if cat["totals"]["modules"] != len(mods):
        bad.append("catalog count %d != %d on disk"
                   % (cat["totals"]["modules"], len(mods)))
    # 2. every module needs a page and a source
    for m in mods:
        if not m["_has_page"]:
            bad.append("%s: no index.html" % m["id"])
        if not m.get("source"):
            bad.append("%s: no source in manifest" % m["id"])
        if m.get("id") != m["_dir"]:
            bad.append("%s: manifest id != directory name" % m["id"])
        for f in ("title", "engine", "platform", "category", "severity",
                  "summary", "affected", "fixed", "proof", "presets"):
            if not m.get(f):
                bad.append("%s: missing manifest field %s" % (m["id"], f))
    # 3. every module in the catalog must be listed in exactly one tier
    listed = [x["id"] for t in cat["tiers"].values() for x in t["modules"]]
    if len(listed) != len(set(listed)):
        bad.append("catalog lists a module in more than one tier")
    if set(listed) != {m["id"] for m in mods}:
        bad.append("catalog ids != module dirs")
    # 4. a module that appears in both generators would be silently duplicated
    poc_ids = ids_from(POC_GENERATOR)
    adv_ids = ids_from(ADV_GENERATOR)
    both = sorted(poc_ids & adv_ids)
    if both:
        bad.append("generated by BOTH generators: %s" % ", ".join(both))
    return bad


def ids_from(path):
    """Rough id extraction from a generator: the cve="..." literals it writes."""
    if not os.path.isfile(path):
        return set()
    out = set()
    txt = open(path, encoding="utf-8").read()
    i = 0
    while True:
        i = txt.find('cve="CVE-', i)
        if i < 0:
            break
        j = txt.find('"', i + 5)
        out.add(txt[i + 5:j])
        i = j
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="verify the catalog matches disk; exit 1 on drift")
    args = ap.parse_args()

    mods = load()
    cat = build(mods)

    if args.check:
        bad = problems(mods, cat)
        bad += drift(cat, committed())
        for b in bad:
            print("  DRIFT:", b)
        print("%s: %d modules, tiers %s"
              % ("FAIL" if bad else "OK", len(mods),
                 ", ".join("%s=%d" % (k, v["count"])
                           for k, v in sorted(cat["tiers"].items()))))
        if bad:
            print("  fix: python3 tools/mkcatalog.py")
        return 1 if bad else 0

    with open(CATALOG, "w", encoding="utf-8") as fh:
        json.dump(cat, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("wrote", CATALOG)
    for k, v in sorted(cat["tiers"].items()):
        print("  tier %-2s %-52s %3d modules" % (k, v["name"], v["count"]))
    print("  total: %d" % cat["totals"]["modules"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
