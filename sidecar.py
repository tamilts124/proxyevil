"""
sidecar.py — Tiny HTTP sidecar server: PAC file, live status dashboard,
             /hosts endpoint, and POST /reload for hot-config-reload.
"""

import logging
import json
import time
import threading
from html import escape as _html_escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

from alias_map import AliasMap
from config   import load_config
from stats    import Stats

if TYPE_CHECKING:
    from addon import DomainAliasAddon

log = logging.getLogger("proxyevil.sidecar")

from _version import __version__


class _SidecarHandler(BaseHTTPRequestHandler):
    """Base handler; per-server subclass is created by start_sidecar()."""

    # Overridden per-subclass by start_sidecar()
    alias_map:   AliasMap
    stats:       Stats
    proxy_host:  str
    proxy_port:  int
    cfg:         dict        # live reference — mutated on hot-reload
    config_path: str         # path passed at startup, used by /reload
    addon:       object      # DomainAliasAddon — notified on hot-reload (Optional)
    _start_time: float
    _since_str:  str

    def log_message(self, *_):
        pass  # silence default access log

    def do_HEAD(self):
        self._head_only = True
        self.do_GET()
        self._head_only = False

    def do_POST(self):
        if self.path == "/reload":
            self._handle_reload()
        elif self.path == "/reset":
            self._handle_reset_all()
        elif self.path.startswith("/reset/"):
            fake = self.path[len("/reset/"):]
            self._handle_reset_one(fake)
        else:
            self.send_error(405)

    def do_GET(self):
        self._head_only = getattr(self, "_head_only", False)
        if self.path in ("/proxy.pac", "/proxy.pac?"):
            self._serve_pac()
        elif self.path in ("/", "/status"):
            self._serve_status()
        elif self.path == "/hosts":
            self._serve_hosts()
        elif self.path == "/stats.json":
            self._serve_stats_json()
        else:
            self.send_error(404)

    # ── endpoints ─────────────────────────────────────────────────────────────

    def _handle_reload(self):
        """POST /reload — re-read config.json and hot-reload aliases + rewrite opts."""
        try:
            new_cfg     = load_config(self.config_path)   # use startup path, not cwd
            new_aliases = new_cfg.get("aliases", {})
            self.alias_map.reload(new_aliases)
            # Update live cfg in-place so DomainAliasAddon properties pick up changes
            _atomic_cfg_update(self.cfg, new_cfg)
            # Notify addon so it invalidates any cached derived values (e.g. strip_hdrs).
            addon = getattr(self, "addon", None)
            if addon is not None and hasattr(addon, "notify_reload"):
                addon.notify_reload()
            self.stats.init(self.alias_map.stats_keys)
            msg = f"reloaded — {len(new_aliases)} aliases"
            log.info(f"[RELOAD] {msg}")
            self._respond(200, "text/plain", msg.encode())
        except Exception as exc:
            log.warning(f"[RELOAD] failed: {exc}")
            self._respond(500, "text/plain", str(exc).encode())

    def _handle_reset_all(self):
        """POST /reset — reset stats for all aliases."""
        self.stats.reset()
        log.info("[RESET] all stats reset")
        self._respond(200, "text/plain", b"stats reset")

    def _handle_reset_one(self, fake: str):
        """POST /reset/<fake> — reset stats for a single alias."""
        self.stats.reset(fake)
        log.info(f"[RESET] stats reset for {fake}")
        self._respond(200, "text/plain", f"reset {fake}".encode())

    def _serve_pac(self):
        content = _pac_file(
            self.alias_map.mapping, self.proxy_host, self.proxy_port
        ).encode()
        self._respond(200, "application/x-ns-proxy-autoconfig", content)

    def _serve_hosts(self):
        content = _hosts_block(self.alias_map.mapping).encode()
        self._respond(200, "text/plain", content)

    def _serve_stats_json(self):
        """Machine-readable stats endpoint for external monitoring."""
        payload = json.dumps({
            "uptime_seconds": int(time.time() - self._start_time),
            "since":          self._since_str,
            "aliases":        self.stats.snapshot(),
        }, indent=2).encode()
        self._respond(200, "application/json", payload)

    def _serve_status(self):
        snap    = self.stats.snapshot()
        aliases = self.alias_map.mapping
        uptime  = int(time.time() - self._start_time)
        h, rem  = divmod(uptime, 3600)
        m, s    = divmod(rem, 60)
        uptime_str = f"{h}h {m}m {s}s"
        rows = ""
        for fake, real in sorted(aliases.items()):
            st       = snap.get(fake, {})
            last     = st.get("last_seen", "\u2014")
            rw_kb    = st.get("bytes_rewritten", 0) // 1024
            errs     = st.get("errors", 0)
            err_cell = f'<span style="color:#e57">{errs}</span>' if errs else "0"
            safe_fake = _html_escape(fake, quote=True)
            safe_real = _html_escape(real, quote=True)
            safe_last = _html_escape(last)
            rows += (
                f'<tr data-alias="{safe_fake}">'
                f'<td>{safe_fake}</td><td>{safe_real}</td>'
                f'<td class="n-req">{st.get("requests", 0)}</td>'
                f'<td class="n-rw">{rw_kb} KB</td>'
                f'<td class="n-err">{err_cell}</td>'
                f'<td class="n-last">{safe_last}</td>'
                f'<td><button onclick="resetOne(\'{safe_fake}\')">reset</button></td></tr>'
            )
        sidecar_port = self.server.server_address[1]
        html = f"""<!doctype html><html><head><title>proxyevil</title>
<style>
body{{font-family:monospace;padding:2em;background:#111;color:#eee}}
a{{color:#7af}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #444;padding:.4em .8em;text-align:left}}
th{{background:#222;color:#fff}}
tr:hover{{background:#1a1a1a}}
button{{background:#333;color:#eee;border:1px solid #555;padding:.3em .8em;cursor:pointer}}
button:hover{{background:#444}}
#status{{font-size:.8em;color:#888;margin-left:1em}}
</style></head><body>
<h2>&#x1F9B9; proxyevil v{__version__}</h2>
<p>Proxy: <code>{self.proxy_host}:{self.proxy_port}</code> &nbsp;|&nbsp;
<a href="/proxy.pac">proxy.pac</a> &nbsp;|&nbsp;
<a href="/hosts">hosts</a> &nbsp;|&nbsp;
<a href="/stats.json">stats.json</a> &nbsp;|&nbsp;
Uptime: <span id="uptime">{uptime_str}</span><span id="status"></span></p>
<p><small>Stats since: {self._since_str}</small></p>
<table><tr><th>Fake domain</th><th>Real upstream</th>
<th>Requests</th><th>Bytes rewritten</th><th>Errors</th><th>Last seen</th><th></th></tr>{rows}</table>
<hr>
<form method="POST" action="/reload" style="display:inline">
<button>&#x21BA; Reload config</button></form>
&nbsp;
<button onclick="resetAll()">&#x2297; Reset all stats</button>
<small> &nbsp;or: <code>curl -X POST http://127.0.0.1:{sidecar_port}/reload</code></small>
<script>
const START = Date.now() - {uptime * 1000};
function fmtUptime(ms) {{
  const s = Math.floor(ms/1000), m = Math.floor(s/60), h = Math.floor(m/60);
  return h+'h '+( m%60)+'m '+(s%60)+'s';
}}
function fmtKB(b) {{ return Math.floor(b/1024)+' KB'; }}
async function refresh() {{
  try {{
    const r = await fetch('/stats.json');
    if (!r.ok) return;
    const d = await r.json();
    document.getElementById('uptime').textContent = fmtUptime(Date.now()-START);
    for (const [alias, st] of Object.entries(d.aliases)) {{
      const row = document.querySelector(`tr[data-alias="${{alias}}"]`);
      if (!row) continue;
      row.querySelector('.n-req').textContent  = st.requests   ?? 0;
      row.querySelector('.n-rw').textContent   = fmtKB(st.bytes_rewritten ?? 0);
      const errs = st.errors ?? 0;
      row.querySelector('.n-err').innerHTML    = errs ? `<span style="color:#e57">${{errs}}</span>` : '0';
      row.querySelector('.n-last').textContent = st.last_seen  ?? '\u2014';
    }}
    document.getElementById('status').textContent = ' \u2022 updated '+(new Date().toLocaleTimeString());
  }} catch(e) {{ document.getElementById('status').textContent = ' \u2022 update failed'; }}
}}
setInterval(refresh, 5000);
async function resetOne(fake) {{
  if (!confirm('Reset '+fake+'?')) return;
  await fetch('/reset/'+fake, {{method:'POST'}});
  refresh();
}}
async function resetAll() {{
  if (!confirm('Reset all stats?')) return;
  await fetch('/reset', {{method:'POST'}});
  refresh();
}}
</script>
</body></html>"""
        self._respond(200, "text/html", html.encode())

    def _respond(self, code: int, ct: str, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(body)


# ── factory ───────────────────────────────────────────────────────────────────

def _atomic_cfg_update(live: dict, new: dict):
    """Replace live cfg contents with *new*.

    Builds the replacement dict outside *live* first, then does a single
    clear() + update() to keep the window of partial-visibility as small as
    possible.  Under the GIL, dict.update() with a pre-built dict is
    effectively one operation for readers that only call .get().
    """
    merged = dict(new)
    live.clear()
    live.update(merged)


def start_sidecar(
    alias_map:    AliasMap,
    stats:        Stats,
    proxy_host:   str,
    proxy_port:   int,
    sidecar_port: int,
    cfg:          dict,
    config_path:  str = "",
    addon:        object = None,
) -> HTTPServer:
    """Start the sidecar HTTP server in a daemon thread and return it."""
    since_str   = time.strftime("%Y-%m-%d %H:%M:%S")
    handler_cls = type("_Handler", (_SidecarHandler,), {
        "alias_map":   alias_map,
        "stats":       stats,
        "proxy_host":  proxy_host,
        "proxy_port":  proxy_port,
        "cfg":         cfg,
        "config_path": config_path,
        "addon":       addon,
        "_start_time": time.time(),
        "_since_str":  since_str,
    })
    server = HTTPServer(("127.0.0.1", sidecar_port), handler_cls)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    log.info(f"[SIDECAR] status   → http://127.0.0.1:{sidecar_port}/")
    log.info(f"[SIDECAR] PAC      → http://127.0.0.1:{sidecar_port}/proxy.pac")
    log.info(f"[SIDECAR] stats    → http://127.0.0.1:{sidecar_port}/stats.json")
    log.info(f"[SIDECAR] reload   → POST http://127.0.0.1:{sidecar_port}/reload")
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


def _pac_file(aliases: dict, host: str, port: int) -> str:
    conditions = " ||\n        ".join(
        f'shExpMatch(host, "*.{fake}") || shExpMatch(host, "{fake}")'
        for fake in sorted(aliases.keys())
    )
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
