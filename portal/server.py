#!/usr/bin/env python3
"""
CVE LAN self-check portal — modular edition.

Generic harness: a landing catalog plus drop-in check modules in
portal/modules/<id>/module.json + index.html. The module list is re-scanned on
every /api/modules request, so adding a module needs no restart.

Scope: devices you own or are explicitly authorized to test. Modules are
proof-level only; the harness never escalates to code execution. Reports are
rejected unless they carry the portal token, which is what stops a passerby
from firing a check.

    PORTAL_TOKEN=lab-secret python3 server.py [--port 8080]
"""
import argparse
import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
SITE = os.path.join(HERE, "site")
MODULES = os.path.join(HERE, "modules")
RESULTS_FILE = os.path.join(HERE, "results.jsonl")

TOKEN = os.environ.get("PORTAL_TOKEN", "")
INJECT_TOKEN = b"__PORTAL_TOKEN__"
LOCK = threading.Lock()
EVENTS = deque(maxlen=20000)  # in-memory tail for the dashboard
SEQ = [0]                     # monotonic: fmt_ts truncates to whole seconds,
                              # so ts alone cannot order same-second events


def fmt_ts(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).astimezone().isoformat(timespec="seconds")


def note(event):
    with LOCK:
        SEQ[0] += 1
        event["seq"] = SEQ[0]
        EVENTS.append(event)
        with open(RESULTS_FILE, "a") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")


# ---------------------------------------------------------------- modules --
def load_modules():
    """Scan modules/ fresh every call — drop-in without a restart.
    Directories starting with '_' (like _template) are ignored."""
    mods = []
    if not os.path.isdir(MODULES):
        return mods
    for name in sorted(os.listdir(MODULES)):
        if name.startswith("_"):
            continue
        mf = os.path.join(MODULES, name, "module.json")
        if not os.path.isfile(mf):
            continue
        try:
            with open(mf) as fh:
                m = json.load(fh)
        except Exception as exc:
            print("bad module manifest (%s): %s" % (name, exc))
            continue
        m.setdefault("id", name)
        mods.append(m)
    return mods


def safe_file(base, *parts):
    """Resolve base/parts, refusing anything that escapes base."""
    target = os.path.realpath(os.path.join(base, *parts))
    if target != base and not target.startswith(base + os.sep):
        return None
    if not os.path.isfile(target):
        return None
    return target


def inject_token(payload: bytes) -> bytes:
    return payload.replace(INJECT_TOKEN, TOKEN.encode())


CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".txt": "text/plain; charset=utf-8",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "LANCheck/2.0"
    protocol_version = "HTTP/1.1"

    def _send(self, code, payload, ctype="text/html; charset=utf-8", inject=False):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        if inject:
            payload = inject_token(payload)
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(payload)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _send_file(self, path, ctype=None, inject=False):
        ext = os.path.splitext(path)[1].lower()
        ctype = ctype or CONTENT_TYPES.get(ext, "application/octet-stream")
        try:
            with open(path, "rb") as fh:
                content = fh.read()
                if inject and ext in (".html", ".htm"):
                    # Inject module script for HTML files
                    # Extract module ID from path
                    rel_path = os.path.relpath(path, MODULES)
                    module_id = rel_path.split(os.sep)[0]
                    script = self._get_module_script(module_id)
                    if script:
                        # Inject the script before </head> or at the beginning of body
                        content_str = content.decode("utf-8")
                        if "</head>" in content_str:
                            content_str = content_str.replace("</head>", '<script src="/core.js"></script>\n<script>\n' + script + '\n</script>\n</head>')
                        elif "<body>" in content_str:
                            content_str = content_str.replace("<body>", "<body>\n<script src=\"/core.js\"></script>\n<script>\n" + script + "\n</script>")
                        else:
                            content_str = '<script src="/core.js"></script>\n<script>\n' + script + '\n</script>\n' + content_str
                        content = content_str.encode("utf-8")
                self._send(200, content, ctype, inject=False)
        except OSError:
            self._send(404, "not found", "text/plain")

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("", "/"):
            self._send_file(os.path.join(SITE, "index.html"), inject=True)
        elif path in ("/core.js", "/core.css"):
            self._send_file(os.path.join(SITE, path.lstrip("/")), inject=True)
        elif path == "/api/modules":
            self._send(200, json.dumps(load_modules()), "application/json")
        elif path == "/healthz":
            self._send(200, "ok", "text/plain")
        elif path == "/dashboard":
            self._send(200, dashboard())
        elif path == "/api/devices":
            self._send(200, json.dumps(devices()), "application/json")
        elif path == "/report" or path == "/reload":
            self._send(405, "POST only", "text/plain")
        elif path.startswith("/modules/"):
            self._serve_module(path[len("/modules/"):])
        else:
            self._send(404, "not found", "text/plain")

    def _get_module_script(self, module_id):
        """Extract inline script content from module's index.html, skipping external scripts."""
        index_path = os.path.join(MODULES, module_id, "index.html")
        if not os.path.isfile(index_path):
            return None
        with open(index_path, "r") as f:
            html = f.read()
        # Find all script tags, skip external ones (with src=)
        import re
        for m in re.finditer(r'<script([^>]*)>([\s\S]*?)</script>', html):
            attrs = m.group(1)
            content = m.group(2)
            if 'src=' not in attrs:
                return content
        return None

    def _serve_module(self, rest):
        parts = [p for p in rest.split("/") if p not in ("", ".")]
        if not parts:
            self._send(404, "no module id", "text/plain")
            return
        mid = parts[0]
        known = {m["id"] for m in load_modules()}  # "_"-prefixed dirs are excluded
        if mid not in known:
            # Check if it's a subdirectory of a known module
            parent_dir = os.path.join(MODULES, mid)
            if not os.path.isdir(parent_dir):
                self._send(404, "unknown module: %s" % mid, "text/plain")
                return
            # Check if parent directory (without suffix) is a known module
            # e.g., CVE-2026-28984-dom -> parent is CVE-2026-28984
            parent_mid = mid
            for known_mid in known:
                if mid.startswith(known_mid + "-") or mid == known_mid:
                    parent_mid = known_mid
                    break
            if parent_mid not in known:
                self._send(404, "unknown module: %s" % mid, "text/plain")
                return
            mid = parent_mid
        rel = parts[1:] if len(parts) > 1 else ["index.html"]
        target = safe_file(os.path.join(MODULES, mid), *rel)
        if target is None:
            self._send(403, "forbidden", "text/plain")
            return
        inject = os.path.splitext(target)[1].lower() in (".html", ".js")
        self._send_file(target, inject=inject)

    # ----------------------------------------------------------------- POST
    def do_POST(self):
        if urlparse(self.path).path != "/report":
            self._send(404, "not found", "text/plain")
            return
        try:
            length = int(self.headers.get("content-length", "0"))
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception as exc:
            self._send(400, "bad json", "text/plain")
            print("bad report:", exc)
            return

        ip = self.client_address[0]
        token = data.get("token")
        token_ok = bool(TOKEN) and token == TOKEN
        detail = data.get("detail")
        if not isinstance(detail, dict):
            detail = {"raw": detail} if detail is not None else {}
        event = {
            "ts": fmt_ts(data.get("ts", int(time.time() * 1000))),
            "epoch": data.get("ts", int(time.time() * 1000)),
            "ip": ip,
            "module": data.get("module") or detail.get("module") or "-",
            "event": data.get("event"),
            "consent": bool(data.get("consent")),
            "token_ok": bool(token_ok),
            "token_rejected": bool(TOKEN) and not token_ok,
            "detail": detail,
            "ua": (data.get("ua") or "")[:300],
        }
        note(event)
        if event["token_rejected"]:
            print("REJECTED report (bad token) from %s for module %s" % (ip, event["module"]))
        self._send(200 if token_ok else 403, "ok" if token_ok else "bad token", "text/plain")

    def log_message(self, fmt, *args):
        msg = fmt % args
        if any(code in msg for code in (" 404 ", " 403 ", " 400 ", " 500 ")):
            print(msg)


# -------------------------------------------------------------- dashboard --
FINAL_EVENTS = {"result", "error", "abort", "crash"}


def verdict_of(ev):
    d = ev.get("detail") or {}
    if not isinstance(d, dict):
        d = {}
    if ev.get("event") == "crash":
        return "crashed (previous run died)"
    return d.get("verdict") or d.get("outcome") or ev.get("event") or "?"


def staleness_verdict(ev):
    """A non-final heartbeat/start/progress event that went stale means the
    renderer died mid-run — the crash oracle's server-side half."""
    if ev.get("event") not in ("alive", "start", "progress"):
        return None
    epoch = ev.get("epoch")
    if not epoch:
        return None
    age = (time.time() * 1000 - epoch) / 1000.0
    if age > 45:
        return "crashed (renderer died)"
    return "running…"


def addrof_of(ev):
    d = ev.get("detail") or {}
    return d.get("addrof", "") if isinstance(d, dict) else ""


def latest_per_device_module():
    """Newest report per (module, ip, ua) — the operator view."""
    seen = {}
    with LOCK:
        for ev in EVENTS:
            key = (ev.get("module") or "-", ev["ip"], ev.get("ua") or "")
            rank = (ev["ts"], ev.get("seq", 0))
            if key not in seen or rank > (seen[key]["ts"], seen[key].get("seq", 0)):
                seen[key] = ev
    return list(seen.values())


def devices():
    out = []
    for ev in latest_per_device_module():
        out.append({
            "module": ev.get("module") or "-",
            "ip": ev["ip"],
            "last_seen": ev["ts"],
            "verdict": staleness_verdict(ev) or verdict_of(ev),
            "addrof": addrof_of(ev),
            "consent": ev["consent"],
            "token_ok": ev["token_ok"],
            "ua": ev.get("ua") or "",
        })
    return sorted(out, key=lambda d: (d["last_seen"], d["ip"]), reverse=True)


def esc(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def dashboard():
    rows = []
    for d in devices():
        v = str(d["verdict"])
        cls = "bad" if (v in ("vulnerable", "vulnerable-class") or v.startswith("crashed")) else \
              "ok" if v in ("no-uaf", "patched", "aborted") else "dim"
        rows.append(
            f"<tr><td>{esc(d['module'])}</td><td>{esc(d['ip'])}</td>"
            f"<td class='{cls}'>{esc(v)}</td><td>{esc(d['addrof'])}</td>"
            f"<td>{'yes' if d['consent'] else 'NO'}</td>"
            f"<td>{esc(d['last_seen'])}</td><td>{esc(d['ua'])}</td></tr>"
        )
    modules = " · ".join(f"{m['id']} ({m.get('title','')})" for m in load_modules()) or "none"
    return f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>LAN check dashboard</title>
<link rel=stylesheet href="/core.css">
</head><body>
<h1>LAN device security self-check — devices seen</h1>
<p class=sub>Scoped to devices owned/authorized on this network.
Modules loaded: {esc(modules)}</p>
<table><tr><th>Module</th><th>IP</th><th>Latest verdict</th><th>addrof</th>
<th>consent</th><th>Last seen</th><th>UA</th></tr>
{''.join(rows) if rows else '<tr><td colspan=7 class=dim>no devices yet</td></tr>'}
</table>
<p><a href="/">back to the catalog</a></p>
</body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    if not TOKEN:
        print("WARNING: PORTAL_TOKEN not set — reports are still recorded, but the "
              "token gate cannot reject unauthenticated runs. Set PORTAL_TOKEN.")
    print("modules: " + ", ".join(m["id"] for m in load_modules()))
    print(f"portal serving on :{args.port}  (catalog: http://<host>:{args.port}/  "
          f"dashboard: http://<host>:{args.port}/dashboard)")
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
