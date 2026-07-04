"""
sidecar.py — Tiny HTTP sidecar server: PAC file, live status dashboard,
             /hosts, /health, and management endpoints.

Endpoints
---------
GET  /                  Live HTML dashboard (auto-refreshes every 5 s)
GET  /status            Alias for /
GET  /proxy.pac         PAC file for browser auto-config
GET  /hosts             Plain-text /etc/hosts block
GET  /stats.json        Machine-readable stats JSON (includes top-level totals)
GET  /logs.json?limit=N Recent requests ring buffer (newest first, default 100, max 200)
GET  /config.json       Currently running config (strips _comments)
GET  /health            JSON health check (for Docker / uptime monitors)
GET  /reset/<fake>      Reset one alias's stats + redirect to dashboard

POST /reload            Hot-reload config.json
POST /stats/save        Persist stats to disk immediately
POST /reset             Reset all stats counters
POST /reset/<fake>      Reset one alias's stats
POST /alias             Add/update alias  {"fake": "...", "real": "..."}
DELETE /alias/<fake>    Remove an alias at runtime

Authentication
--------------
Mutating endpoints (POST /reload, POST /alias, DELETE /alias, POST /reset,
POST /stats/save) require the ``X-Proxyevil-Token`` request header to match
the ``sidecar_token`` value in config.json.  If ``sidecar_token`` is not set
(or is an empty string) the check is skipped — preserving backwards-compat
for local dev setups that don't need it.

To enable, add to config.json::

    "sidecar_token": "your-secret-token"

Then pass the header::

    curl -X POST -H "X-Proxyevil-Token: your-secret-token" \\
         http://127.0.0.1:8081/reload
"""

import json
import logging
import time
import threading
from html import escape as _html_escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

from alias_map import AliasMap
from config    import load_config, save_config
from stats     import Stats
from hosts_manager import update_hosts_file
from logfilter import install_log_filters

if TYPE_CHECKING:
    from addon import DomainAliasAddon

log = logging.getLogger("proxyevil.sidecar")

from _version import __version__


# ── HTML dashboard ─────────────────────────────────────────────────────────────

_DASHBOARD_CSS = """
body{font-family:monospace;padding:1.5em;background:#111;color:#eee;margin:0}
a{color:#7af}
table{border-collapse:collapse;width:100%;margin-top:.5em}
th,td{border:1px solid #444;padding:.4em .8em;text-align:left;white-space:nowrap}
th{background:#222;color:#ccc;font-size:.85em;text-transform:uppercase;letter-spacing:.05em}
tr:hover td{background:#1a1a1a}
button{background:#2a2a2a;color:#ddd;border:1px solid #555;padding:.3em .8em;
       cursor:pointer;border-radius:3px;font-family:monospace}
button:hover{background:#383838;color:#fff}
button.danger{border-color:#844}
button.danger:hover{background:#522;color:#fcc}
.n-err span{color:#e57}
#topbar{display:flex;align-items:baseline;gap:1.2em;flex-wrap:wrap;margin-bottom:.6em}
#status{font-size:.8em;color:#888}
.type-bar{display:flex;gap:.3em;font-size:.75em}
.type-pill{background:#2a2a2a;border:1px solid #444;padding:.1em .45em;border-radius:10px}
"""

_DASHBOARD_JS = """
const START = Date.now() - {uptime_ms};
function fmtUptime(ms) {{
  const s = Math.floor(ms/1000), m = Math.floor(s/60), h = Math.floor(m/60);
  return h+'h '+(m%60)+'m '+(s%60)+'s';
}}
function fmtKB(b) {{ return b >= 1048576 ? (b/1048576).toFixed(1)+' MB' : Math.floor(b/1024)+' KB'; }}
function typePills(rbt) {{
  return Object.entries(rbt||{{}})
    .filter(([,v])=>v>0)
    .map(([k,v])=>`<span class="type-pill">${{k}}: ${{v}}</span>`)
    .join('');
}}
async function refresh() {{
  try {{
    const r = await fetch('/stats.json');
    if (!r.ok) return;
    const d = await r.json();
    if (d.gen === _lastGen) {{
      document.getElementById('uptime').textContent = fmtUptime(Date.now()-START);
      document.getElementById('status').textContent = ' • no change';
      return;
    }}
    _lastGen = d.gen;
    document.getElementById('uptime').textContent = fmtUptime(Date.now()-START);
    for (const [alias, st] of Object.entries(d.aliases)) {{
      const row = document.querySelector(`tr[data-alias="${{alias}}"]`);
      if (!row) continue;
      row.querySelector('.n-req').textContent  = st.requests   ?? 0;
      row.querySelector('.n-rw').textContent   = fmtKB(st.bytes_rewritten ?? 0);
      const errs = st.errors ?? 0;
      row.querySelector('.n-err').innerHTML    = errs ? `<span>${{errs}}</span>` : '0';
      row.querySelector('.n-last').textContent = st.last_seen  ?? '—';
      const tp = row.querySelector('.n-types');
      if (tp) tp.innerHTML = typePills(st.rewrite_by_type);
    }}
    document.getElementById('status').textContent =
      ' • updated '+(new Date().toLocaleTimeString());
  }} catch(e) {{
    document.getElementById('status').textContent = ' • update failed';
  }}
}}
setInterval(refresh, 5000);
let _lastGen = -1;
const _TOKEN = {token_json};
function _authHeaders() {{
  return _TOKEN ? {{'X-Proxyevil-Token': _TOKEN}} : {{}};
}}
async function doPost(url, label) {{
  if (label && !confirm(label)) return;
  const r = await fetch(url, {{method:'POST', headers: _authHeaders()}});
  const t = await r.text();
  document.getElementById('status').textContent = ' • ' + t;
  await refresh();
}}
async function resetOne(fake) {{ await doPost('/reset/'+fake, 'Reset '+fake+'?'); }}
async function resetAll()     {{ await doPost('/reset', 'Reset all stats?'); }}
async function reloadCfg()    {{ await doPost('/reload', null); }}
"""


def _build_dashboard(snap, aliases, uptime, uptime_str, since_str,
                     proxy_host, proxy_port, sidecar_port, token=""):
    rows = ""
    for fake, real in sorted(aliases.items()):
        st       = snap.get(fake, {})
        last     = st.get("last_seen", "—")
        rw_bytes = st.get("bytes_rewritten", 0)
        errs     = st.get("errors", 0)
        rbt      = st.get("rewrite_by_type", {})
        rbt_pills = "".join(
            f'<span class="type-pill">{k}: {v}</span>'
            for k, v in sorted(rbt.items()) if v > 0
        )
        rw_label = (
            f"{rw_bytes / 1048576:.1f} MB" if rw_bytes >= 1048576
            else f"{rw_bytes // 1024} KB"
        )
        err_cell  = f'<span>{errs}</span>' if errs else "0"
        safe_fake = _html_escape(fake, quote=True)
        safe_real = _html_escape(real, quote=True)
        safe_last = _html_escape(last)
        rows += (
            f'<tr data-alias="{safe_fake}">'
            f'<td>{safe_fake}</td>'
            f'<td>{safe_real}</td>'
            f'<td class="n-req">{st.get("requests", 0)}</td>'
            f'<td class="n-rw">{rw_label}</td>'
            f'<td class="n-err">{err_cell}</td>'
            f'<td class="n-types type-bar">{rbt_pills}</td>'
            f'<td class="n-last">{safe_last}</td>'
            f'<td><button class="danger" onclick="resetOne(\'{safe_fake}\')">reset</button></td>'
            f'</tr>'
        )

    js = _DASHBOARD_JS.format(
        uptime_ms=uptime * 1000,
        token_json=json.dumps(token or ""),
    )

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>proxyevil v{__version__}</title>
<style>{_DASHBOARD_CSS}</style></head><body>
<div id="topbar">
  <h2 style="margin:0">&#x1F9B9; proxyevil <small style="color:#888">v{__version__}</small></h2>
  <span>Proxy: <code>{proxy_host}:{proxy_port}</code></span>
  <a href="/proxy.pac">proxy.pac</a>
  <a href="/hosts">hosts</a>
  <a href="/aliases">aliases</a>
  <a href="/stats.json">stats.json</a>
  <a href="/config.json">config.json</a>
  <a href="/health">health</a>
  <span>Uptime: <span id="uptime">{uptime_str}</span></span>
  <span id="status"></span>
</div>
<p style="margin:.2em 0 .8em;font-size:.8em;color:#666">Stats since: {since_str}</p>
<table>
<tr><th>Fake domain</th><th>Real upstream</th><th>Requests</th>
<th>Bytes rewritten</th><th>Errors</th><th>By type</th><th>Last seen</th><th></th></tr>
{rows}
</table>
<div style="margin-top:1em;display:flex;gap:.6em;flex-wrap:wrap;align-items:center">
  <button onclick="reloadCfg()">&#x21BA; Reload config</button>
  <button class="danger" onclick="resetAll()">&#x2297; Reset all stats</button>
  <small style="color:#555">or: <code>curl -X POST http://127.0.0.1:{sidecar_port}/reload</code></small>
</div>
<script>{js}</script>
</body></html>"""


# ── request handler ────────────────────────────────────────────────────────────

class _SidecarHandler(BaseHTTPRequestHandler):
    """Base handler; per-server subclass is created by start_sidecar()."""

    alias_map:   AliasMap
    stats:       Stats
    stats_path:  object
    proxy_host:  str
    proxy_port:  int
    cfg:         dict
    config_path: str
    addon:       object
    _start_time: float
    _since_str:  str

    def log_message(self, *_):
        pass  # silence default access log

    # Fix #4: use try/finally so _head_only is always cleared even if do_GET raises
    def do_HEAD(self):
        self._head_only = True
        try:
            self.do_GET()
        finally:
            self._head_only = False

    def do_GET(self):
        self._head_only = getattr(self, "_head_only", False)
        p = self.path.split("?")[0]
        if p in ("/proxy.pac",):
            self._serve_pac()
        elif p in ("/", "/status"):
            self._serve_status()
        elif p == "/hosts":
            self._serve_hosts()
        elif p == "/aliases":
            self._serve_aliases_json()
        elif p == "/stats.json":
            self._serve_stats_json()
        elif p == "/logs.json":
            self._serve_logs_json()
        elif p == "/config.json":
            self._serve_config_json()
        elif p == "/health":
            self._serve_health()
        elif p.startswith("/reset/"):
            if not self._check_token():
                return
            if not self._check_origin():
                return
            fake = p[len("/reset/"):]
            self.stats.reset(fake)
            log.info(f"[RESET] stats reset for {fake} (via GET)")
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
        else:
            self.send_error(404)

    def do_POST(self):
        if not self._check_token():
            return
        if not self._check_origin():
            return
        p = self.path.split("?")[0]
        if p == "/reload":
            self._handle_reload()
        elif p == "/stats/save":
            self._handle_stats_save()
        elif p == "/reset":
            self._handle_reset_all()
        elif p.startswith("/reset/"):
            self._handle_reset_one(p[len("/reset/"):])
        elif p == "/alias":
            self._handle_add_alias()
        else:
            self.send_error(405)

    def do_DELETE(self):
        if not self._check_token():
            return
        if not self._check_origin():
            return
        p = self.path.split("?")[0]
        if p.startswith("/alias/"):
            self._handle_remove_alias(p[len("/alias/"):])
        else:
            self.send_error(405)

    # ── auth helpers ──────────────────────────────────────────────────────────

    def _check_token(self) -> bool:
        expected = self.cfg.get("sidecar_token", "")
        if not expected:
            return True
        provided = self.headers.get("X-Proxyevil-Token", "")
        if provided == expected:
            return True
        self._respond(403, "text/plain", b"forbidden: missing or wrong X-Proxyevil-Token")
        return False

    def _check_origin(self) -> bool:
        origin = self.headers.get("Origin", "")
        if not origin:
            return True
        sidecar_port = self.server.server_address[1]
        allowed = {
            "null",
            f"http://127.0.0.1:{sidecar_port}",
            f"http://localhost:{sidecar_port}",
        }
        if origin in allowed:
            return True
        self._respond(403, "text/plain", b"forbidden: cross-origin request rejected")
        return False

    # ── GET endpoints ─────────────────────────────────────────────────────────

    def _serve_pac(self):
        aliases = self.cfg.get("aliases", {})
        # Fix #13: use canonical SPOOF_ALL_DOMAINS key only (config.py normalises
        # SPOOF_ALL_UNMAPPED_DOMAINS → SPOOF_ALL_DOMAINS on load).
        spoof_all = self.cfg.get("SPOOF_ALL_DOMAINS", False) or any(
            isinstance(val, dict) and val.get("SPOOF_ALL_DOMAINS", False)
            for val in aliases.values()
        )
        content = _pac_file(
            self.alias_map.mapping, self.proxy_host, self.proxy_port, spoof_all
        ).encode()
        self._respond(200, "application/x-ns-proxy-autoconfig", content)

    def _serve_hosts(self):
        self._respond(200, "text/plain", _hosts_block(self.alias_map.mapping).encode())

    def _serve_stats_json(self):
        # Fix #16: include aggregated totals at top level so consumers don't have to sum
        snap = self.stats.snapshot()
        gen  = snap.pop("_gen", 0)   # pull out meta-key before summing alias entries
        total_requests = sum(v.get("requests", 0) for v in snap.values())
        total_bytes    = sum(v.get("bytes_rewritten", 0) for v in snap.values())
        total_errors   = sum(v.get("errors", 0) for v in snap.values())
        payload = json.dumps({
            "uptime_seconds":        int(time.time() - self._start_time),
            "since":                 self._since_str,
            "gen":                   gen,
            "total_requests":        total_requests,
            "total_bytes_rewritten": total_bytes,
            "total_errors":          total_errors,
            "aliases":               snap,
        }, indent=2).encode()
        self._respond(200, "application/json", payload)

    def _serve_logs_json(self):
        qs = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
        try:
            limit = int(qs.get("limit", ["100"])[0])
        except (ValueError, IndexError):
            limit = 100
        limit = max(1, min(limit, 200))
        payload = json.dumps(self.stats.recent(limit), indent=2).encode()
        self._respond(200, "application/json", payload)

    def _serve_aliases_json(self):
        payload = json.dumps(self.alias_map.full_mapping, indent=2).encode()
        self._respond(200, "application/json", payload)

    def _serve_config_json(self):
        live = {k: v for k, v in self.cfg.items() if k != "_comments"}
        self._respond(200, "application/json", json.dumps(live, indent=2).encode())

    def _serve_health(self):
        payload = json.dumps({
            "status":         "ok",
            "version":        __version__,
            "uptime_seconds": int(time.time() - self._start_time),
            "alias_count":    len(self.alias_map.mapping),
        }).encode()
        self._respond(200, "application/json", payload)

    def _serve_status(self):
        snap    = self.stats.snapshot()
        snap.pop("_gen", None)   # Fix #2: strip meta-key before passing to _build_dashboard
        aliases = self.alias_map.mapping
        uptime  = int(time.time() - self._start_time)
        h, rem  = divmod(uptime, 3600)
        m, s    = divmod(rem, 60)
        uptime_str   = f"{h}h {m}m {s}s"
        sidecar_port = self.server.server_address[1]
        token        = self.cfg.get("sidecar_token", "")
        html = _build_dashboard(
            snap, aliases, uptime, uptime_str, self._since_str,
            self.proxy_host, self.proxy_port, sidecar_port, token=token,
        )
        self._respond(200, "text/html", html.encode())

    # ── POST endpoints ────────────────────────────────────────────────────────

    def _handle_reload(self):
        try:
            new_cfg     = load_config(self.config_path)
            new_aliases = new_cfg.get("aliases", {})
            self.alias_map.reload(new_aliases)
            _atomic_cfg_update(self.cfg, new_cfg)
            # Fix A: init stats before notify_reload so addon sees fresh counters
            # (mirrors the order in watcher.py)
            self.stats.init(self.alias_map.stats_keys)
            addon = getattr(self, "addon", None)
            if addon is not None and hasattr(addon, "notify_reload"):
                addon.notify_reload()
            root_aliases = {
                k: v if isinstance(v, str) else v.get("real", "")
                for k, v in new_aliases.items()
            }
            update_hosts_file(root_aliases)
            # Fix D: refresh log filters so new aliases suppress TLS noise immediately
            install_log_filters(self.alias_map, verbose=self.cfg.get("verbose", False))
            msg = f"reloaded — {len(new_aliases)} aliases"
            log.info(f"[RELOAD] {msg}")
            self._respond(200, "text/plain", msg.encode())
        except SystemExit:
            msg = "reload failed: config has errors — previous config kept"
            log.warning(f"[RELOAD] {msg}")
            self._respond(400, "text/plain", msg.encode())
        except Exception as exc:
            log.warning(f"[RELOAD] failed: {exc}")
            self._respond(500, "text/plain", str(exc).encode())

    def _handle_stats_save(self):
        try:
            self.stats.dump(self.stats_path)
            self._respond(200, "text/plain", f"stats saved to {self.stats_path}".encode())
        except Exception as exc:
            log.warning(f"[STATS] save failed: {exc}")
            self._respond(500, "text/plain", str(exc).encode())

    def _handle_reset_all(self):
        self.stats.reset()
        log.info("[RESET] all stats reset")
        self._respond(200, "text/plain", b"all stats reset")

    def _handle_reset_one(self, fake: str):
        self.stats.reset(fake)
        log.info(f"[RESET] stats reset for {fake}")
        self._respond(200, "text/plain", f"reset {fake}".encode())

    @staticmethod
    def _has_save(path: str) -> bool:
        qs = path.split("?", 1)[1] if "?" in path else ""
        return any(p.strip() == "save=1" for p in qs.split("&"))

    def _handle_add_alias(self):
        """POST /alias  body: {"fake": "...", "real": "..."}

        Fix #11: cfg_aliases may include enabled:false entries; alias_map.reload()
        correctly filters them via _load(), so passing the full dict is safe.
        """
        try:
            length = min(int(self.headers.get("Content-Length", 0)), 65536)
            if length <= 0:
                self._respond(400, "text/plain", b"Content-Length required")
                return
            body   = self.rfile.read(length)
            data   = json.loads(body)
            fake   = data.get("fake", "").strip().lower()
            real   = data.get("real", "").strip().lower()
            if not fake or not real:
                self._respond(400, "text/plain", b"'fake' and 'real' are required")
                return
            cfg_aliases = self.cfg.setdefault("aliases", {})
            cfg_aliases[fake] = real
            # reload() filters disabled entries internally via _load()
            self.alias_map.reload(cfg_aliases)
            self.stats.init([fake])
            root_aliases = {
                k: v if isinstance(v, str) else v.get("real", "")
                for k, v in cfg_aliases.items()
            }
            update_hosts_file(root_aliases)
            # Fix K: refresh log filters so the new alias suppresses TLS noise
            install_log_filters(self.alias_map, verbose=self.cfg.get("verbose", False))
            save = self._has_save(self.path)
            if save and self.config_path:
                save_config(self.cfg, self.config_path)
                msg = f"alias added: {fake} → {real} (persisted)"
            else:
                msg = f"alias added: {fake} → {real} (runtime only)"
            log.info(f"[ALIAS] {msg}")
            self._respond(200, "text/plain", msg.encode())
        except (json.JSONDecodeError, ValueError) as exc:
            self._respond(400, "text/plain", f"bad JSON: {exc}".encode())
        except Exception as exc:
            log.warning(f"[ALIAS] add failed: {exc}")
            self._respond(500, "text/plain", str(exc).encode())

    # ── DELETE endpoints ──────────────────────────────────────────────────────

    def _handle_remove_alias(self, fake: str):
        fake = fake.strip().lower()
        cfg_aliases = self.cfg.get("aliases", {})
        if fake not in self.alias_map.mapping and fake not in cfg_aliases:
            self._respond(404, "text/plain", f"alias '{fake}' not found".encode())
            return
        cfg_aliases.pop(fake, None)
        self.alias_map.reload(cfg_aliases)
        root_aliases = {
            k: v if isinstance(v, str) else v.get("real", "")
            for k, v in cfg_aliases.items()
        }
        update_hosts_file(root_aliases)
        # Fix K: refresh log filters so removed alias no longer suppresses TLS noise
        install_log_filters(self.alias_map, verbose=self.cfg.get("verbose", False))
        save = self._has_save(self.path)
        if save and self.config_path:
            save_config(self.cfg, self.config_path)
            msg = f"alias removed: {fake} (persisted)"
        else:
            msg = f"alias removed: {fake} (runtime only)"
        log.info(f"[ALIAS] {msg}")
        self._respond(200, "text/plain", msg.encode())

    # ── shared ────────────────────────────────────────────────────────────────

    def _respond(self, code: int, ct: str, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(body)


# ── factory ───────────────────────────────────────────────────────────────────

def _atomic_cfg_update(live: dict, new: dict):
    """Replace live cfg contents with *new* atomically (under GIL)."""
    merged = dict(new)
    live.clear()
    live.update(merged)


def start_sidecar(
    alias_map:    AliasMap,
    stats:        Stats,
    stats_path:   str,
    proxy_host:   str,
    proxy_port:   int,
    sidecar_port: int,
    cfg:          dict,
    config_path:  str   = "",
    addon:        object = None,
) -> HTTPServer:
    """Start the sidecar HTTP server in a daemon thread and return it."""
    since_str   = time.strftime("%Y-%m-%d %H:%M:%S")
    handler_cls = type("_Handler", (_SidecarHandler,), {
        "alias_map":   alias_map,
        "stats":       stats,
        "stats_path":  stats_path,
        "proxy_host":  proxy_host,
        "proxy_port":  proxy_port,
        "cfg":         cfg,
        "config_path": config_path,
        "addon":       addon,
        "_start_time": time.time(),
        "_since_str":  since_str,
    })
    server = HTTPServer((proxy_host, sidecar_port), handler_cls)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    log.info(f"[SIDECAR] status   → http://127.0.0.1:{sidecar_port}/")
    log.info(f"[SIDECAR] PAC      → http://127.0.0.1:{sidecar_port}/proxy.pac")
    log.info(f"[SIDECAR] stats    → http://127.0.0.1:{sidecar_port}/stats.json")
    log.info(f"[SIDECAR] health   → http://127.0.0.1:{sidecar_port}/health")
    log.info(f"[SIDECAR] aliases  → http://127.0.0.1:{sidecar_port}/aliases")
    log.info(f"[SIDECAR] reload   → POST http://127.0.0.1:{sidecar_port}/reload")
    log.info(f"[SIDECAR] add alias→ POST http://127.0.0.1:{sidecar_port}/alias")
    return server


# ── PAC / hosts helpers ───────────────────────────────────────────────────────

def _hosts_block(aliases: dict) -> str:
    lines = [
        "# proxyevil — add to /etc/hosts",
        "# Windows: C:\\Windows\\System32\\drivers\\etc\\hosts  (as Administrator)",
    ]
    for fake in sorted(aliases.keys()):
        lines.append(f"127.0.0.1  {fake}")
    return "\n".join(lines)


def _pac_file(aliases: dict, host: str, port: int, spoof_all: bool = False) -> str:
    conds = [
        f'shExpMatch(host, "*.{fake}") || shExpMatch(host, "{fake}")'
        for fake in sorted(aliases.keys())
    ]
    if spoof_all:
        conds.append('shExpMatch(host, "*.local")')
    conditions = " ||\n        ".join(conds)
    return f"""// proxyevil PAC — auto-generated
function FindProxyForURL(url, host) {{
    if (
        {conditions}
    ) {{
        return "PROXY {host}:{port}";
    }}
    return "DIRECT";
}}
"""
