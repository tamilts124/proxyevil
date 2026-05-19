"""
addon.py — mitmproxy addon: bidirectional domain rewriter.

Wires together AliasMap, codec, and Stats to rewrite every HTTP/HTTPS
flow that involves a known fake domain.
"""

import logging
import os
import re
import time
from pathlib import Path
from typing import Optional

from mitmproxy import http as mhttp  # type: ignore

from alias_map import AliasMap
from codec     import decompress, recompress
from stats     import Stats

log = logging.getLogger("proxyevil.addon")

_BINARY_TYPES = {
    "image/", "video/", "audio/", "font/",
    "application/octet-stream", "application/pdf",
    "application/zip", "application/wasm",
}
_DEFAULT_BODY_SIZE_LIMIT = 10 * 1024 * 1024   # 10 MB
_SRI_RE = re.compile(r"""\s+integrity=(?:"[^"]*"|'[^']*')""")

# Metadata keys stamped in request() and consumed in response()
_META_FAKE = "proxyevil.fake"
_META_REAL = "proxyevil.real"

# Map content-type substrings to stats bucket names
_CT_BUCKETS: list[tuple[str, str]] = [
    ("text/html",    "html"),
    ("javascript",   "js"),
    ("ecmascript",   "js"),
    ("text/css",     "css"),
    ("json",         "json"),
]


def _ct_bucket(ct: str) -> str:
    """Return the stats bucket name for a content-type string."""
    for substr, bucket in _CT_BUCKETS:
        if substr in ct:
            return bucket
    return "other"


class DomainAliasAddon:
    """Bidirectional domain rewriter registered as a mitmproxy addon."""

    def __init__(self, alias_map: AliasMap, cfg: dict, stats: Stats):
        self.aliases  = alias_map
        self.cfg      = cfg        # kept by reference so hot-reload is instant
        self.stats    = stats
        self._log_fh: Optional[object] = None
        self._log_path: Optional[Path] = None
        self._cfg_gen = 0          # bumped on hot-reload to invalidate caches
        self._init_access_log()

    # ── access log ───────────────────────────────────────────────────────────

    def _init_access_log(self):
        """Open or re-open the access log file. Safe to call on hot-reload."""
        if self._log_fh is not None:
            try:
                self._log_fh.close()
            except OSError:
                pass
            self._log_fh  = None
            self._log_path = None

        if not self.cfg.get("access_log", False):
            return
        data_dir = Path(self.cfg.get("data_dir", "evil_data"))
        data_dir.mkdir(parents=True, exist_ok=True)
        path = data_dir / "access.log"
        try:
            self._log_fh   = open(path, "a", encoding="utf-8", buffering=1)
            self._log_path = path
            log.info(f"[ACCESS] logging to {path}")
        except OSError as exc:
            log.warning(f"[ACCESS] could not open log file {path}: {exc}")

    def _write_access(self, method: str, fake: str, path: str,
                      status: int, size: int, ct: str = ""):
        """Append one TSV access-log line if the log is open.

        Format: timestamp  method  fake  path  status  size  content_type
        """
        if self._log_fh is None:
            return
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            self._log_fh.write(f"{ts}\t{method}\t{fake}\t{path}\t{status}\t{size}\t{ct}\n")
        except OSError as exc:
            log.debug(f"[ACCESS] write failed: {exc}")

    # ── live config properties ────────────────────────────────────────────────

    @property
    def rw(self) -> dict:
        return self.cfg.get("rewrite", {})

    def _refresh_strip_hdrs(self):
        self._strip_hdrs_cache: set = {h.lower() for h in self.cfg.get("strip_headers", [])}
        self._strip_hdrs_gen = self._cfg_gen

    @property
    def strip_hdrs(self) -> set:
        if not hasattr(self, "_strip_hdrs_cache") or getattr(self, "_strip_hdrs_gen", -1) != self._cfg_gen:
            self._refresh_strip_hdrs()
        return self._strip_hdrs_cache

    def notify_reload(self):
        """Call after a hot-reload so cached derived values are invalidated."""
        self._cfg_gen += 1
        self._init_access_log()

    @property
    def body_size_limit(self) -> int:
        return int(self.cfg.get("max_body_bytes", _DEFAULT_BODY_SIZE_LIMIT))

    # ── outgoing: fake → real ─────────────────────────────────────────────────

    def server_connect(self, data):
        if not data.server.address:
            return
        host, port = data.server.address
        if isinstance(host, str):
            real = self.aliases.real_for(host)
            if real:
                old_sni = getattr(data.server, "sni", None)
                data.server.address = (real, port)
                
                # Cloudfront/API Gateway strictly requires SNI to match the upstream domain.
                # Always set it regardless of what the client sent.
                data.server.sni = real
                
                log.debug(f"[SERVER_CONNECT] mapped {host}:{port} -> {real}:{port}, SNI {old_sni} -> {data.server.sni}")

    def request(self, flow: mhttp.HTTPFlow):
        print(f"DEBUG REQUEST HOOK: flow.request.host={flow.request.host}, flow.request.pretty_host={flow.request.pretty_host}")
        if hasattr(flow.request, "authority"):
            print(f"DEBUG REQUEST HOOK: authority={flow.request.authority}")
        
        # Get the fake host from the client's original request headers or SNI, NOT the upstream connection
        host = flow.request.pretty_host
        real = self.aliases.real_for(host)
        if real is None:
            return

        flow.metadata[_META_FAKE] = host
        flow.metadata[_META_REAL] = real

        log.info(f"[REQ]  {flow.request.method} {host}{flow.request.path}  →  {real}")
        flow.request.host            = real
        flow.request.host_header     = real
        if hasattr(flow.request, "authority") and flow.request.authority:
            flow.request.authority = real
        if "Host" in flow.request.headers:
            flow.request.headers["Host"] = real

        print("DEBUG HEADERS TO UPSTREAM:")
        for k, v in flow.request.headers.items():
            print(f"  {k}: {v}")
        if hasattr(flow.request, "authority"):
            print(f"  :authority: {flow.request.authority}")

        rw = self.rw

        if rw.get("headers", True):
            for hdr in ("referer", "origin"):
                val = flow.request.headers.get(hdr, "")
                if val:
                    flow.request.headers[hdr] = self.aliases.rewrite_fake_to_real(val)

        if rw.get("cookies", True):
            raw_cookie = flow.request.headers.get("cookie", "")
            if raw_cookie:
                flow.request.headers["cookie"] = self.aliases.rewrite_fake_to_real(raw_cookie)

        if flow.request.content:
            ct  = flow.request.headers.get("content-type",     "").lower()
            enc = flow.request.headers.get("content-encoding", "").lower()
            if any(t in ct for t in ("json", "form", "text", "xml")):
                try:
                    raw = flow.request.content
                    if enc and enc != "identity":
                        decompressed, did_decompress, actual_enc = decompress(raw, enc)
                    else:
                        decompressed, did_decompress, actual_enc = raw, False, enc

                    if any(n in decompressed.lower() for n in self.aliases._fake_needles):
                        body_text = decompressed.decode("utf-8", errors="replace")
                        new_text  = self.aliases.rewrite_fake_to_real(body_text)
                        if new_text != body_text:
                            new_bytes = new_text.encode("utf-8")
                            if did_decompress and actual_enc:
                                new_bytes = recompress(new_bytes, actual_enc)
                            elif did_decompress:
                                del flow.request.headers["content-encoding"]
                            flow.request.content                   = new_bytes
                            flow.request.headers["content-length"] = str(len(new_bytes))
                except Exception as exc:
                    log.debug(f"[REQ body] {exc}")
                    self.stats.error(flow.metadata.get(_META_FAKE, host))

        if self.cfg.get("capture_requests", False):
            self._capture_body("req", host, flow.request.method,
                               flow.request.path, flow.request.content)

    # ── incoming: real → fake ─────────────────────────────────────────────────

    def response(self, flow: mhttp.HTTPFlow):
        fake = flow.metadata.get(_META_FAKE)
        if fake is None:
            return

        rw         = self.rw
        strip_hdrs = self.strip_hdrs

        for hdr in list(flow.response.headers.keys()):
            if hdr.lower() in strip_hdrs:
                del flow.response.headers[hdr]

        if rw.get("headers", True):
            self._rewrite_response_headers(flow)

        if rw.get("cookies", True):
            self._rewrite_cookies(flow, fake)

        ct = flow.response.headers.get("content-type", "").lower()
        try:
            bytes_rw = self._rewrite_body(flow, rw)
        except Exception as exc:
            log.warning(f"[BODY] unexpected error for {fake}: {exc}")
            self.stats.error(fake)
            bytes_rw = 0

        self.stats.hit(fake, bytes_rw, content_type=_ct_bucket(ct))
        self._write_access(
            flow.request.method,
            fake,
            flow.request.path,
            flow.response.status_code,
            len(flow.response.content or b""),
            ct.split(";")[0].strip(),
        )

        if self.cfg.get("capture_responses", False):
            self._capture_body("resp", fake, flow.request.method,
                               flow.request.path, flow.response.content)

        self._inject(flow, fake)

    def error(self, flow: mhttp.HTTPFlow):
        fake = flow.metadata.get(_META_FAKE)
        if fake is None:
            return

        err_msg = flow.error.msg if flow.error else "unknown error"
        log.warning(f"[ERR]  {flow.request.method} {fake}{flow.request.path}  →  {err_msg}")
        self.stats.error(fake)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _capture_body(self, direction: str, fake: str, method: str,
                       path: str, body: Optional[bytes]):
        """Dump request or response body to evil_data/captures/<fake>/."""
        if not body:
            return
        data_dir = Path(self.cfg.get("data_dir", "evil_data"))
        cap_dir  = data_dir / "captures" / fake
        try:
            cap_dir.mkdir(parents=True, exist_ok=True)
            ts    = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            slug  = re.sub(r"[^\w\-]", "_", path[:40].lstrip("/")) or "root"
            fname = f"{ts}_{direction}_{method}_{slug}.bin"
            (cap_dir / fname).write_bytes(body)
            log.debug(f"[CAPTURE] {direction} {fake} → {cap_dir / fname}")
        except OSError as exc:
            log.debug(f"[CAPTURE] write failed: {exc}")

    def _inject(self, flow: mhttp.HTTPFlow, fake: str):
        """Inject snippet HTML/JS into HTML responses if configured.

        Config example::

            "inject": {
                "mybook.local": "<script>console.log('injected')</script>",
                "*": "<!-- proxyevil -->"
            }
        """
        inject_map = self.cfg.get("inject", {})
        snippet    = inject_map.get(fake) or inject_map.get("*")
        if not snippet:
            return
        ct = flow.response.headers.get("content-type", "").lower()
        if "text/html" not in ct:
            return
        body = flow.response.content
        if not body:
            return
        try:
            charset = "utf-8"
            if "charset=" in ct:
                charset = ct.split("charset=")[-1].split(";")[0].strip() or "utf-8"
            text = body.decode(charset, errors="replace")
            if "</body>" in text:
                text = text.replace("</body>", snippet + "\n</body>", 1)
            elif "</html>" in text:
                text = text.replace("</html>", snippet + "\n</html>", 1)
            else:
                text = text + snippet
            new_bytes = text.encode(charset, errors="replace")
            flow.response.content                   = new_bytes
            flow.response.headers["content-length"] = str(len(new_bytes))
            log.debug(f"[INJECT] injected {len(snippet)} chars into {fake}")
        except Exception as exc:
            log.debug(f"[INJECT] failed for {fake}: {exc}")

    def _rewrite_response_headers(self, flow: mhttp.HTTPFlow):
        for hdr in ("location", "refresh", "link", "content-location",
                    "access-control-allow-origin"):
            val = flow.response.headers.get(hdr, "")
            if val:
                new_val = self.aliases.rewrite_real_to_fake(val)
                if new_val != val:
                    flow.response.headers[hdr] = new_val
                    log.debug(f"[HDR] {hdr}: {val!r} → {new_val!r}")

    def _rewrite_cookies(self, flow: mhttp.HTTPFlow, fake_base: str):
        raw_cookies = flow.response.headers.get_all("set-cookie")
        if not raw_cookies:
            return

        fake_is_http = flow.request.scheme == "http"
        new_cookies  = []

        for raw in raw_cookies:
            first_semi = raw.find(";")
            if first_semi == -1:
                new_cookies.append(self.aliases.rewrite_real_to_fake(raw))
                continue
            name_val     = raw[:first_semi]
            attrs        = raw[first_semi:]
            new_name_val = self.aliases.rewrite_real_to_fake(name_val)
            new_attrs    = re.sub(
                r'(?i)(;\s*domain=)[^;]*',
                f'; Domain={fake_base}',
                attrs,
            )
            if fake_is_http:
                new_attrs = re.sub(r'(?i);\s*Secure\b', '', new_attrs)
            elif not re.search(r'(?i);\s*Secure\b', new_attrs):
                new_attrs += "; Secure"
            if not re.search(r'(?i);\s*SameSite\s*=', new_attrs):
                new_attrs += "; SameSite=Lax"
            new_cookies.append(new_name_val + new_attrs)

        while "set-cookie" in flow.response.headers:
            del flow.response.headers["set-cookie"]
        for c in new_cookies:
            flow.response.headers.add("set-cookie", c)

    def _rewrite_body(self, flow: mhttp.HTTPFlow, rw: dict) -> int:
        """Decompress → rewrite domain refs → recompress. Returns delta bytes rewritten."""
        if not flow.response.content:
            return 0

        ct  = flow.response.headers.get("content-type",     "").lower()
        enc = flow.response.headers.get("content-encoding", "").lower()

        if any(ct.startswith(bt) for bt in _BINARY_TYPES):
            return 0

        is_html = "text/html"  in ct
        is_js   = "javascript" in ct or "ecmascript" in ct
        is_css  = "text/css"   in ct
        is_json = "json"       in ct
        is_text = "text/"      in ct or "xml" in ct

        should_rewrite = (
            (is_html and rw.get("html",  True)) or
            (is_js   and rw.get("js",    True)) or
            (is_css  and rw.get("css",   True)) or
            (is_json and rw.get("json",  True)) or
            is_text
        )
        if not should_rewrite:
            return 0

        raw = flow.response.content
        if len(raw) > self.body_size_limit:
            log.debug(f"[BODY] skipping {len(raw) // 1024}KB body (over limit)")
            return 0

        if enc and enc != "identity":
            decompressed, did_decompress, actual_enc = decompress(raw, enc)
        else:
            decompressed, did_decompress, actual_enc = raw, False, enc

        active_enc = actual_enc if (did_decompress and actual_enc and actual_enc != "identity") else ""

        dec_lower = decompressed.lower()
        if not any(n in dec_lower for n in self.aliases._real_needles):
            return 0

        charset = "utf-8"
        if "charset=" in ct:
            charset = ct.split("charset=")[-1].split(";")[0].strip() or "utf-8"

        try:
            text = decompressed.decode(charset, errors="replace")
        except Exception:
            text = decompressed.decode("utf-8", errors="replace")

        if is_html and rw.get("html", True):
            text = _SRI_RE.sub("", text)

        new_text = self.aliases.rewrite_real_to_fake(text)
        if new_text == text:
            return 0

        try:
            new_bytes = new_text.encode(charset, errors="replace")
        except Exception:
            new_bytes = new_text.encode("utf-8", errors="replace")

        if active_enc:
            new_bytes = recompress(new_bytes, active_enc)
        elif did_decompress:
            if "content-encoding" in flow.response.headers:
                del flow.response.headers["content-encoding"]

        flow.response.content                   = new_bytes
        flow.response.headers["content-length"] = str(len(new_bytes))

        delta = len(new_text) - len(text)
        log.debug(f"[BODY] {ct[:30]}  {len(raw)}B → {len(new_bytes)}B  Δ{delta:+d} chars")
        return max(0, delta)
