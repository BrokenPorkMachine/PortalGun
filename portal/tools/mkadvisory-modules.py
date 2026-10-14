#!/usr/bin/env python3
"""
Generate tier-3 (advisory) modules for the LAN self-check portal.

Tier 3 = CVE is publicly disclosed with advisory metadata, but there is no
public client-side PoC. The module is therefore an honest information page
with engine/version reporting — no exploit code, no crash oracle.

    python3 tools/mkadvisory-modules.py                  # generate into portal/modules/
    python3 tools/mkadvisory-modules.py --dry-run        # list what would be written
    python3 tools/mkadvisory-modules.py --only WSA-2026-0006   # just one advisory

Sources (metadata transcribed verbatim from the advisories):
  * WebKitGTK/WPE advisories WSA-2026-0001 (2026-03-18) through
    WSA-2026-0006 (2026-09-29)
  * Ubuntu USN-7957-1 (2026-01-13)

Scope note on WSA-2026-0006: that advisory lists roughly 200 Chromium-bundled
Skia/ANGLE CVE IDs ("… in Google Chrome prior to …") next to 21 WebKit-native
entries. Only the WebKit-native ones (the entries carrying "Credit to …" and a
"WebKit Bugzilla" reference) are transcribed here. A WebKit engine fingerprint
taken from a device on your LAN says nothing about a Skia bug that ships inside
Google Chrome, so those modules would look thorough while reporting nothing.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODULES = os.path.normpath(os.path.join(HERE, "..", "modules"))

WSA = "https://www.webkitgtk.org/security/WSA-2026-0001.html"

# (cve, bug, short title, affected, fixed, impact, credit)
WSA_2026_0001 = [
    ("CVE-2023-43010", 260913, "Memory corruption (Coruna exploit chain fix)",
     "WebKitGTK/WPE before 2.44.0; iOS before 17.2", "WebKitGTK 2.44.0 / iOS 17.2",
     "memory corruption", "Apple"),
    ("CVE-2025-31223", 289387, "Memory corruption (insufficient checks)",
     "WebKitGTK/WPE before 2.50.0", "WebKitGTK 2.50.0",
     "memory corruption", "Andreas Jaegersberger & Ro Achterberg (Nosebeard Labs)"),
    ("CVE-2025-31277", 291745, "Memory corruption (improved memory handling)",
     "WebKitGTK/WPE before 2.50.0", "WebKitGTK 2.50.0",
     "memory corruption", "Yuhao Hu, Yan Kang, Chenggang Wu, Xiaojie Wei"),
    ("CVE-2025-43213", 292621, "Unexpected Safari crash",
     "WebKitGTK/WPE before 2.50.5", "WebKitGTK 2.50.5",
     "crash", "Google V8 Security Team"),
    ("CVE-2025-43214", 292599, "Unexpected Safari crash",
     "WebKitGTK/WPE before 2.50.5", "WebKitGTK 2.50.5",
     "crash", "shandikri (Trend Micro ZDI), Google V8 Security Team"),
    ("CVE-2025-43433", 298093, "Memory corruption (Big Sleep)",
     "WebKitGTK/WPE before 2.50.2", "WebKitGTK 2.50.2",
     "memory corruption", "Google Big Sleep"),
    ("CVE-2025-43438", 297662, "Use-after-free",
     "WebKitGTK/WPE before 2.50.2", "WebKitGTK 2.50.2",
     "use-after-free", "rheza (@ginggilBesel), shandikri (Trend Micro ZDI)"),
    ("CVE-2025-43441", 298496, "Unexpected process crash",
     "WebKitGTK/WPE before 2.50.2", "WebKitGTK 2.50.2",
     "crash", "rheza (@ginggilBesel)"),
    ("CVE-2025-43457", 298606, "Use-after-free",
     "WebKitGTK/WPE before 2.50.6", "WebKitGTK 2.50.6",
     "use-after-free", "Gary Kwong, Hossein Lotfi (@hosselot, Trend Micro ZDI)"),
    ("CVE-2025-43511", 300926, "Use-after-free",
     "WebKitGTK/WPE before 2.50.5", "WebKitGTK 2.50.5",
     "use-after-free", "이동하 (Lee Dong Ha, BoB 14th)"),
    ("CVE-2025-46299", 299518, "Internal state disclosure (memory initialization)",
     "WebKitGTK/WPE before 2.52.0", "WebKitGTK 2.52.0",
     "info disclosure", "Google Big Sleep"),
    ("CVE-2026-20608", 303357, "Unexpected process crash (state management)",
     "WebKitGTK/WPE before 2.50.6", "WebKitGTK 2.50.6",
     "crash", "HanQing (TSDubhe), Nan Wang (@eternalsakura13)"),
    ("CVE-2026-20635", 304661, "Unexpected process crash",
     "WebKitGTK/WPE before 2.50.6", "WebKitGTK 2.50.6",
     "crash", "EntryHi"),
    ("CVE-2026-20636", 304657, "Unexpected process crash",
     "WebKitGTK/WPE before 2.50.6", "WebKitGTK 2.50.6",
     "crash", "EntryHi"),
    ("CVE-2026-20644", 303444, "Unexpected process crash",
     "WebKitGTK/WPE before 2.50.6", "WebKitGTK 2.50.6",
     "crash", "HanQing (TSDubhe), Nan Wang (@eternalsakura13)"),
    ("CVE-2026-20652", 303959, "Denial of service",
     "WebKitGTK/WPE before 2.50.6", "WebKitGTK 2.50.6",
     "DoS", "Nathaniel Oh (@calysteon)"),
    ("CVE-2026-20676", 305020, "Cross-site user tracking via Safari web extensions",
     "WebKitGTK/WPE before 2.50.6", "WebKitGTK 2.50.6",
     "tracking", "Tom Van Goethem"),
]

# WSA-2026-0002 — 2026-03-28, all fixed in WebKitGTK 2.52.1.
#
# CVE-2026-20643 is deliberately absent: a public PoC exists for it
# (0xjohnnydev/WebKit-NavigationAPI-SOP-Bypass), so tools/mkpoc-modules.py
# generates it as tier 1 instead. Generating it here as well would leave two
# modules with the same id, and load_modules() picks whichever it scans first.
WSA_2026_0002 = [
    ("CVE-2026-20664", 306136, "Unexpected process crash",
     "WebKitGTK/WPE before 2.52.1", "WebKitGTK 2.52.1",
     "crash", "Daniel Rhea, Söhnke Benedikt Fischedick (Tripton), Emrovsky & Switch, Yevhen Pervushyn"),
    ("CVE-2026-20665", 304951, "Content Security Policy not enforced",
     "WebKitGTK/WPE before 2.52.1", "WebKitGTK 2.52.1",
     "CSP bypass", "webb"),
    ("CVE-2026-20691", 306827, "User fingerprinting (authorization issue)",
     "WebKitGTK/WPE before 2.52.1", "WebKitGTK 2.52.1",
     "fingerprinting", "Gongyu Ma (@Mezone0)"),
    ("CVE-2026-28857", 307723, "Unexpected process crash",
     "WebKitGTK/WPE before 2.52.1", "WebKitGTK 2.52.1",
     "crash", "Narcis Oliveras Fontàs, Söhnke Benedikt Fischedick (Tripton), Daniel Rhea, "
     "Nathaniel Oh (@calysteon)"),
    ("CVE-2026-28859", 308248, "Sandbox escape (restricted web content outside the sandbox)",
     "WebKitGTK/WPE before 2.52.1", "WebKitGTK 2.52.1",
     "sandbox escape", "greenbynox, Arni Hardarson"),
    ("CVE-2026-28861", 307014, "Cross-origin script message handler access",
     "WebKitGTK/WPE before 2.52.1", "WebKitGTK 2.52.1",
     "cross-origin handler access",
     "Hongze Wu and Shuaike Dong from Ant Group Infrastructure Security Team"),
    ("CVE-2026-28871", 305859, "Cross-site scripting (logic issue)",
     "WebKitGTK/WPE before 2.52.1", "WebKitGTK 2.52.1",
     "cross-site scripting", "@hamayanhamayan"),
]

# WSA-2026-0003 — 2026-06-02, all fixed in WebKitGTK 2.52.4.
WSA_2026_0003 = [
    ("CVE-2026-28847", 308707, "Unexpected process crash",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "crash", "DARKNAVY (@DarkNavyOrg), Anonymous working with TrendAI Zero Day Initiative, "
     "Daniel Rhea"),
    ("CVE-2026-28883", 313939, "Use-after-free (unexpected process crash)",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "use-after-free", "kwak kiyong / kakaogames"),
    ("CVE-2026-28901", 310207, "Unexpected process crash",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "crash", "Aisle offensive security research team (Joshua Rogers, Luigino Camastra, "
     "Igor Morgenstern, and Guido Vranken), Maher Azzouzi, Ngan Nguyen of Calif.io"),
    ("CVE-2026-28902", 309861, "Unexpected process crash",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "crash", "Tristan Madani (@TristanInSec) from Talence Security, Nathaniel Oh (@calysteon)"),
    ("CVE-2026-28903", 310303, "Unexpected process crash",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "crash", "Mateusz Krzywicki (iVerify.io)"),
    ("CVE-2026-28904", 309601, "Unexpected process crash",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "crash", "Luka Rački"),
    ("CVE-2026-28905", 308545, "Unexpected process crash",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "crash", "Yuhao Hu, Yuanming Lai, Chenggang Wu, and Zhe Wang"),
    ("CVE-2026-28907", 308675, "Content Security Policy not enforced",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "CSP bypass", "Cantina"),
    ("CVE-2026-28942", 312180, "Use-after-free (unexpected Safari crash)",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "use-after-free", "Milad Nasr and Nicholas Carlini with Claude, Anthropic"),
    ("CVE-2026-28946", 310544, "Use-after-free (unexpected Safari crash)",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "use-after-free", "Gia Bui (@yabeow) from Calif.io, dr3dd, w0wbox"),
    ("CVE-2026-28947", 310234, "Use-after-free (unexpected Safari crash)",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "use-after-free", "dr3dd"),
    ("CVE-2026-28953", 309628, "Unexpected process crash",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "crash", "Maher Azzouzi"),
    ("CVE-2026-28955", 310880, "Unexpected process crash",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "crash", "wac and Kookhwan Lee working with TrendAI Zero Day Initiative"),
    ("CVE-2026-28958", 311228, "Sensitive user data access (data protection)",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "info disclosure", "Cantina"),
    ("CVE-2026-43658", 307669, "Unexpected Safari crash",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "crash", "Do Young Park"),
    ("CVE-2026-43660", 308906, "Content Security Policy not enforced",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "CSP bypass", "Cantina"),
]

# WSA-2026-0004 — 2026-07-10, all fixed in WebKitGTK 2.52.5.
WSA_2026_0004 = [
    ("CVE-2024-4367", None, "PDF.js font handling type check missing",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "arbitrary JavaScript execution (PDF.js context)", "Thomas Rinsma of Codean Labs"),
    ("CVE-2026-39872", 313528, "Unexpected process crash",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "crash", "Utkarsh Pal, Ignacio Sanmillan (@ulexec)"),
    ("CVE-2026-43663", 312781, "Unexpected process crash",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "crash", "Soyeon Park, Amy Burnett, Khai Tran, sherkito, Kota Toda, HexRabbit (@h3xr4bb1t) "
     "and NiNi (@terrynini38514) of DEVCORE Research Team, Using GLM From Z.AI, "
     "Tristan Madani (@TristanInSec) from Talence Security, Brian Carpenter"),
    ("CVE-2026-43676", 317231, "Out-of-bounds access (unexpected Safari crash)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "out-of-bounds access", "Mateusz Krzywicki (iVerify.io), dr3dd, "
     "Tommy DeVoss from Braze Security Team (@thedawgyg)"),
    ("CVE-2026-43699", 317227, "Use-after-free (unexpected process crash)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "use-after-free", "Tommy DeVoss from Braze Security Team (@thedawgyg)"),
    ("CVE-2026-43701", 315004, "Sandbox escape (restricted web content outside the sandbox)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "sandbox escape", "Aaron Grattafiori - NVIDIA AI Red Team"),
    ("CVE-2026-43705", 314528, "Type confusion — memory corruption",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "memory corruption", "dr3dd"),
    ("CVE-2026-43707", 315951, "Memory corruption (unexpected process crash)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "memory corruption", "OpenAI Codex Security - Amy Burnett"),
    ("CVE-2026-43712", 314235, "Unexpected process crash",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "crash", "Kwak Kiyong, Song Nuri, Tristan Madani (@TristanInSec) from Talence Security"),
    ("CVE-2026-43713", 314806, "Sensitive data leak (permissions issue)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "info disclosure", "Jody Ritonga"),
    ("CVE-2026-43715", 313577, "Use-after-free — memory corruption",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "use-after-free", "Milad Nasr and Nicholas Carlini with Claude, Anthropic"),
    ("CVE-2026-43716", 313473, "Unexpected Safari crash",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "crash", "Tuan and Duc from Calif.io, OpenAI Codex Security - Amy Burnett, Evan Lambert"),
    ("CVE-2026-43720", 313175, "Use-after-free (unexpected Safari crash)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "use-after-free", "Gia Bui (@yabeow) from Calif.io, Josef Korbel"),
    ("CVE-2026-43721", 313478, "Silent clipboard data hijack",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "clipboard hijack", "Idan Masas"),
    ("CVE-2026-43725", 312832, "Sandbox escape (restricted web content outside the sandbox)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "sandbox escape", "Luke Francis"),
    ("CVE-2026-43726", 313857, "Use-after-free (unexpected process crash)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "use-after-free", "Josef Korbel (Citadelo), Tristan Madani (@TristanInSec) from "
     "Talence Security, Gia Bui (@yabeow) from Calif.io, Narendra Singh (@_3P1C)"),
    ("CVE-2026-43727", 313691, "Use-after-free (unexpected Safari crash)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "use-after-free", "Tommy DeVoss from Braze Security Team (@thedawgyg), "
     "Gia Bui (@yabeow) from Calif.io, Gurpreet Shergill"),
    ("CVE-2026-43731", 314115, "Use-after-free — memory corruption",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "use-after-free", "dr3dd"),
    ("CVE-2026-43732", 313085, "Sensitive user information disclosure (path handling)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "info disclosure", "Nan Wang (@eternalsakura13)"),
    ("CVE-2026-43734", 313693, "Use-after-free (unexpected process crash)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "use-after-free", "Jonathan Alush-Aben"),
    ("CVE-2026-43740", 308046, "Process memory disclosure",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "info disclosure", "Nathaniel Oh (@calysteon), Arni Hardarson"),
    ("CVE-2026-43742", 315161, "Use-after-free (unexpected process crash)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "use-after-free", "Юлия Мерцалова"),
    ("CVE-2026-43745", 315365, "Out-of-bounds write (unexpected Safari crash)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "out-of-bounds write", "OpenAI Codex Security - Amy Burnett, Khai Tran"),
]

# WSA-2026-0005 — 2026-08-20.
WSA_2026_0005 = [
    ("CVE-2026-28984", 311883, "Unexpected Safari crash",
     "WebKitGTK/WPE before 2.52.4", "WebKitGTK 2.52.4",
     "crash", "Artem Dinaburg of Trail of Bits via Anthropic CVD"),
    ("CVE-2026-43804", 316816, "App denial-of-service",
     "WebKitGTK/WPE before 2.52.6", "WebKitGTK 2.52.6",
     "DoS", "Heiko Kiesel of SEEMOO, TU Darmstadt"),
    ("CVE-2026-64713", 316827, "Visited-link fingerprinting",
     "WebKitGTK/WPE before 2.52.6", "WebKitGTK 2.52.6",
     "tracking", "Kwak Kiyong, Song Nuri"),
    ("CVE-2026-64719", 319404, "Out-of-bounds access (unexpected Safari crash)",
     "WebKitGTK/WPE before 2.52.6", "WebKitGTK 2.52.6",
     "out-of-bounds access", "Shaheen Fazim"),
    ("CVE-2026-64728", 313220, "iframe sandboxing policy violation",
     "WebKitGTK/WPE before 2.52.6", "WebKitGTK 2.52.6",
     "sandbox bypass", "an anonymous researcher"),
    ("CVE-2026-64730", 311660, "UI spoofing",
     "WebKitGTK/WPE before 2.52.6", "WebKitGTK 2.52.6",
     "UI spoofing", "Kagami Rosylight of Mozilla"),
    ("CVE-2026-64757", 315082, "Memory corruption (unexpected Safari crash)",
     "WebKitGTK/WPE before 2.52.6", "WebKitGTK 2.52.6",
     "memory corruption", "Milad Nasr and Nicholas Carlini with Claude, Anthropic"),
    ("CVE-2026-64783", 313521, "Use-after-free (unexpected Safari crash)",
     "WebKitGTK/WPE before 2.52.6", "WebKitGTK 2.52.6",
     "use-after-free", "杉山 壮太, lattice, Behzad Najjarpour Jabbari (@G4ru), Junyeong Lee, "
     "Mooth.ai, OGINOME Tomohito, Using GLM From Z.AI, Gia Bui (@yabeow) from Calif.io"),
    ("CVE-2026-64787", 313703, "Use-after-free (unexpected process termination)",
     "WebKitGTK/WPE before 2.52.5", "WebKitGTK 2.52.5",
     "use-after-free", "杉山 壮太, Shubham Chaskar"),
]

# WSA-2026-0006 — 2026-09-29, WebKit-native entries only (see module docstring).
WSA_2026_0006 = [
    ("CVE-2026-43670", 309004, "Content Security Policy bypass (AudioWorklet)",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "CSP bypass", "lebr0nli of National Yang Ming Chiao Tung University, Security and Systems Lab"),
    ("CVE-2026-64715", 316347, "Use-after-free (unexpected process crash)",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "use-after-free", "Hossein Lotfi (@hosselot) of TrendAI Zero Day Initiative"),
    ("CVE-2026-64753", 315121, "Sensitive user information disclosure (permissions)",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "info disclosure", "Viggo Lekdorf"),
    ("CVE-2026-64778", 322124, "Sensitive data leak",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "info disclosure", "Mohit Negi"),
    ("CVE-2026-64779", 321485, "Memory corruption (improved locking)",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "memory corruption", "Shubham Chaskar, Tommy DeVoss from Braze Security Team (@thedawgyg)"),
    ("CVE-2026-64780", 316918, "Unexpected crash",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "crash", "OpenAI Codex Security - Amy Burnett"),
    ("CVE-2026-64781", 321484, "Unexpected crash",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "crash", "Thomas Guillem"),
    ("CVE-2026-64782", 321480, "Memory corruption (improved locking)",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "memory corruption", "Charles Kern, Shubham Chaskar, Seonwook Kim, lattice, Josef Korbel"),
    ("CVE-2026-64784", 317632, "Out-of-bounds access",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "out-of-bounds access", "Janggoon Lee of Out of Bounds, OpenAI Codex Security - Amy Burnett"),
    ("CVE-2026-65331", 317611, "Unexpected crash",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "crash", "OpenAI Codex Security - Amy Burnett"),
    ("CVE-2026-65332", 317450, "Unexpected crash",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "crash", "Kun Peeks (@SwayZGl1tZyyy), OpenAI Codex Security - Amy Burnett"),
    ("CVE-2026-65333", 317603, "Unexpected crash",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "crash", "OpenAI Codex Security - Amy Burnett"),
    ("CVE-2026-65334", 316791, "Memory corruption (state management)",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "memory corruption", "OpenAI Codex Security - Amy Burnett"),
    ("CVE-2026-65336", 317349, "Unexpected crash",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "crash", "Josef Korbel"),
    ("CVE-2026-65337", 317142, "Unexpected crash",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "crash", "OpenAI Codex Security - Amy Burnett"),
    ("CVE-2026-65338", 318348, "Unexpected crash",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "crash", "OpenAI Codex Security - Amy Burnett"),
    ("CVE-2026-65340", 316996, "Unexpected crash",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "crash", "Claudio Bozzato and Francesco Benvenuto of Cisco Talos, Josef Korbel (Citadelo)"),
    ("CVE-2026-65341", 318405, "Memory corruption",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "memory corruption", "Henock Habte"),
    ("CVE-2026-65351", 321517, "Unexpected crash",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "crash", "Niels Hofmans"),
    ("CVE-2026-84635", 310457, "Unexpected process termination (logic issue)",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "crash", "Souta Sugiyama"),
    ("CVE-2026-86898", 318271, "Universal cross-site scripting via webarchive",
     "WebKitGTK/WPE before 2.54.0", "WebKitGTK 2.54.0",
     "cross-site scripting", "Tomi Garcia (archyxsec)"),
]

# Apple-side Dec-2025 batch listed in USN-7957-1 references (fixed in the
# WebKitGTK 2.50.4 packages). Per-CVE impact text is not in the USN; kept
# deliberately generic — no invented details.
USN_7957_1 = [
    ("CVE-2025-43501", None),
    ("CVE-2025-43531", None),
    ("CVE-2025-43536", None),
    ("CVE-2025-43541", None),
]

# Advisory label -> landing page for the "References" line of each module.
WSA_URLS = {
    "WSA-2026-0001": "https://www.webkitgtk.org/security/WSA-2026-0001.html",
    "WSA-2026-0002": "https://www.webkitgtk.org/security/WSA-2026-0002.html",
    "WSA-2026-0003": "https://www.webkitgtk.org/security/WSA-2026-0003.html",
    "WSA-2026-0004": "https://www.webkitgtk.org/security/WSA-2026-0004.html",
    "WSA-2026-0005": "https://www.webkitgtk.org/security/WSA-2026-0005.html",
    "WSA-2026-0006": "https://www.webkitgtk.org/security/WSA-2026-0006.html",
}

# advisory label -> entry list, in catalog order.
WSA_LISTS = [
    ("WSA-2026-0001", WSA_2026_0001),
    ("WSA-2026-0002", WSA_2026_0002),
    ("WSA-2026-0003", WSA_2026_0003),
    ("WSA-2026-0004", WSA_2026_0004),
    ("WSA-2026-0005", WSA_2026_0005),
    ("WSA-2026-0006", WSA_2026_0006),
]

MANIFEST = """{
  "id": "__ID__",
  "title": "__TITLE__",
  "cve": "__CVE__",
  "engine": "WebKit (JavaScriptCore)",
  "platform": "__PLATFORM__",
  "category": "__CATEGORY__",
  "severity": "__SEVERITY__",
  "summary": "__SUMMARY__",
  "affected": "__AFFECTED__",
  "fixed": "__FIXED__",
  "proof": "none — tier 3: advisory + engine report, no public client-side PoC",
  "presets": ["report"],
  "source": "__SOURCE__",
  "tier": 3
}
"""

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="portal-token" content="__PORTAL_TOKEN__">
<title>__CVE__ — advisory module</title>
<link rel="stylesheet" href="/core.css">
</head>
<body>
<h1>__CVE__</h1>
<p class="sub">__TITLE__</p>
<div id="lc-app"></div>

<script src="/core.js"></script>
<script>
"use strict";
/*
 * TIER 3 — ADVISORY MODULE.
 * No public client-side PoC exists for this CVE. This page records engine
 * metadata for the fleet dashboard and links the public references; it runs
 * no exploit code.
 */
LanCheck.start({
  module: "__ID__",
  intro:
    '<div class="card"><b>__CVE__</b> — __TITLE__<br>' +
    '<b>Impact:</b> __IMPACT__<br>' +
    '<b>Affected:</b> __AFFECTED__<br>' +
    '<b>Fixed:</b> __FIXED__<br>' +
    '<b>Credit:</b> __CREDIT__<br>' +
    '<b>References:</b> <a href="__BUGURL__">__BUGLABEL__</a> · ' +
    '<a href="__CVEURL__">CVE record</a> · <a href="__REFURL__">__REF__</a></div>',
  presets: {
    report: {
      label: "Report", blurb: "engine fingerprint only",
      desc: "no exploit code — logs engine metadata, ~1min cap",
      attempts: 1, capMin: 1,
    },
  },

  run: async function (ctx) {
    const ua = navigator.userAgent;
    let version = "", wbtag = "";
    const mv = ua.match(/Version\\/(\\d+(?:\\.\\d+)+)/);
    const ms = ua.match(/Safari\\/(\\d+(?:\\.\\d+)+)/);
    if (mv) version = mv[1];
    if (ms) wbtag = ms[1];

    const isIOS = /iPhone|iPad|iPod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
    const os = isIOS ? "iOS/iPadOS" : /Mac OS X/.test(ua) ? "macOS" : "other";

    const facts = {
      sdk_version: version || "n/a (in-app web view / captive sheet)",
      webkit_build: wbtag || "n/a",
      os_class: os,
      jit_expected: true,
      ua: ua,
    };

    ctx.log("[*] engine: " + (version || "unknown") +
            " · webkit build: " + (wbtag || "unknown") + " · " + os);
    ctx.report("fingerprint", facts);

    // JIT presence sanity check (timing side channel only; not an exploit):
    // a hot loop in the same tier should run materially faster after tier-up.
    function spin(n) { let s = 0; for (let i = 0; i < n; ++i) s = (s + i) | 0; return s; }
    const t0 = performance.now(); spin(2e6); const t1 = performance.now();
    spin(2e6); const t2 = performance.now();
    const speedup = t1 - t0 > 0 ? (t1 - t0) / Math.max(t2 - t1, 1e-3) : 1;
    ctx.log("[*] jit speedup proxy: " + speedup.toFixed(2) + "x (>1 suggests JIT active)");
    ctx.report("jit_proxy", { speedup: Number(speedup.toFixed(2)) });

    return {
      outcome: "advisory",
      detail: Object.assign(facts, { jit_proxy: Number(speedup.toFixed(2)) }),
      html: '<span class="dim"><b>ADVISORY</b></span> — no public PoC for __CVE__. ' +
            "Engine recorded: " + (version || "unknown") + " / webkit " + (wbtag || "unknown") +
            " (" + os + "). Compare against “__FIXED__” on your fleet dashboard.",
    };
  },
});
</script>
</body>
</html>
"""


def modules_to_generate(only=None):
    out = []
    for ref, entries in WSA_LISTS:
        if only and ref != only:
            continue
        url = WSA_URLS[ref]
        for cve, bug, title, affected, fixed, impact, credit in entries:
            out.append({
                "cve": cve,
                "bug": str(bug) if bug else "n/a",
                "title": title,
                "affected": affected,
                "fixed": fixed,
                "impact": impact,
                "credit": credit,
                "platform": "WebKitGTK/WPE; Apple browsers per Apple advisory",
                "category": impact,
                "severity": "see CPE / advisory",
                "source": url,
                "ref": ref,
                "refurl": url,
                # No upstream bug number in the advisory (CVE-2024-4367 is a
                # PDF.js entry) — point at the advisory itself instead of a
                # fabricated webkit.org/b/ link.
                "bugurl": f"https://webkit.org/b/{bug}" if bug else url,
                "buglabel": f"WebKit bug {bug}" if bug else "advisory entry (no WebKit bug listed)",
            })
    # The USN entry has no advisory id of its own, so --only cannot target it;
    # it is only generated on a full run.
    if only:
        return out
    usn = "https://ubuntu.com/security/notices/USN-7957-1"
    for cve, bug in USN_7957_1:
        out.append({
            "cve": cve,
            "bug": "n/a",
            "title": "WebKit security issue (Apple Dec-2025 batch)",
            "affected": "WebKit before the Apple Dec-2025 updates; WebKitGTK before 2.50.4",
            "fixed": "WebKitGTK 2.50.4 (USN-7957-1); Apple Safari/iOS/macOS 26.2 batch",
            "impact": "unspecified in USN (XSS/DoS/RCE family)",
            "credit": "see Apple advisory",
            "platform": "WebKitGTK; Apple browsers per USN-7957-1",
            "category": "advisory",
            "severity": "see CVE record",
            "source": usn,
            "ref": "USN-7957-1",
            "refurl": usn,
            "bugurl": f"https://ubuntu.com/security/{cve}",
            "buglabel": "Ubuntu CVE page",
        })
    return out


def esc(s):
    return (s or "").replace('"', "'")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only", metavar="ADVISORY",
                    help="generate only one advisory, e.g. WSA-2026-0006")
    args = ap.parse_args()

    mods = modules_to_generate(args.only)
    print(f"{len(mods)} tier-3 modules")
    for m in mods:
        mid = m["cve"]
        d = os.path.join(MODULES, mid)
        manifest = (MANIFEST
                    .replace("__ID__", mid)
                    .replace("__TITLE__", esc(m["title"]))
                    .replace("__CVE__", mid)
                    .replace("__PLATFORM__", esc(m["platform"]))
                    .replace("__CATEGORY__", m["category"])
                    .replace("__SEVERITY__", m["severity"])
                    .replace("__SUMMARY__", esc(f'{m["title"]} — impact: {m["impact"]}. '
                                               f'Affected: {m["affected"]}. Fixed: {m["fixed"]}.'))
                    .replace("__AFFECTED__", esc(m["affected"]))
                    .replace("__FIXED__", esc(m["fixed"]))
                    .replace("__SOURCE__", m["source"]))
        page = (PAGE
                .replace("__PORTAL_TOKEN__", "__PORTAL_TOKEN__")
                .replace("__ID__", mid)
                .replace("__CVE__", mid)
                .replace("__TITLE__", esc(m["title"]))
                .replace("__IMPACT__", esc(m["impact"]))
                .replace("__AFFECTED__", esc(m["affected"]))
                .replace("__FIXED__", esc(m["fixed"]))
                .replace("__CREDIT__", esc(m["credit"]))
                .replace("__BUGLABEL__", esc(m["buglabel"]))
                .replace("__BUGURL__", m["bugurl"])
                .replace("__CVEURL__", f"https://www.cve.org/CVERecord?id={mid}")
                .replace("__REFURL__", m["refurl"])
                .replace("__REF__", m["ref"]))
        if args.dry_run:
            print("  would write", os.path.join(d, "module.json"), "+ index.html")
            continue
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "module.json"), "w", encoding="utf-8") as fh:
            fh.write(manifest)
        with open(os.path.join(d, "index.html"), "w", encoding="utf-8") as fh:
            fh.write(page)
        # sanity: manifest must parse
        with open(os.path.join(d, "module.json"), encoding="utf-8") as fh:
            json.load(fh)
        print("  wrote", mid)


if __name__ == "__main__":
    sys.exit(main())
