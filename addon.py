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
_PRECHECK_LIMIT = 512 * 1024                  # 512 KB — threshold for cheap .lower() copy in needle pre-check
_SRI_RE = re.compile(r"""\s+integrity=(?:"[^"]*"|'[^']*')""")

_URL_HOST_RE = re.compile(r'https?://([a-zA-Z0-9.\-_]+)', re.IGNORECASE)
_PROTO_RELATIVE_RE = re.compile(r'//([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)+\.[a-zA-Z]{2,12})(?=[/\s\'">:,;\]\)]|$)', re.IGNORECASE)
_QUOTED_DOMAIN_RE = re.compile(
    r'''(?:["'])([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,12})(?:["'])''',
    re.IGNORECASE
)

# Fix #19: cap on dynamic alias registration to prevent unbounded memory growth
# in SPOOF_ALL_DOMAINS mode. Override via config: "max_dynamic_aliases": N
_DEFAULT_MAX_DYNAMIC_ALIASES = 500


def _is_ip_or_localhost(host: str) -> bool:
    host = host.lower().strip()
    if host == "localhost":
        return True
    if host.endswith(".local"):
        return True
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
        return True
    if ":" in host:
        return True
    return False


_META_FAKE = "proxyevil.fake"
_META_REAL = "proxyevil.real"

_CT_BUCKETS: list[tuple[str, str]] = [
    ("text/html",    "html"),
    ("javascript",   "js"),
    ("ecmascript",   "js"),
    ("text/css",     "css"),
    ("json",         "json"),
]


def _ct_bucket(ct: str) -> str:
    for substr, bucket in _CT_BUCKETS:
        if substr in ct:
            return bucket
    return "other"


class DomainAliasAddon:
    """Bidirectional domain rewriter registered as a mitmproxy addon."""

    def __init__(self, alias_map: AliasMap, cfg: dict, stats: Stats):
        self.aliases  = alias_map
        self.cfg      = cfg
        self.stats    = stats
        self._log_fh: Optional[object] = None
        self._log_path: Optional[Path] = None
        self._cfg_gen = 0
        # Fix #19: track count of dynamically registered aliases
        self._dynamic_alias_count = 0
        self._init_access_log()

    # ── access log ───────────────────────────────────────────────────────────

    def _init_access_log(self):
        if self._log_fh is not None:
            try:
                self._log_fh.close()
            except OSError:
                pass
            self._log_fh   = None
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
        self._cfg_gen += 1
        # Reset cap counter: alias_map.reload() already cleared dynamic aliases,
        # so the count must go back to zero to avoid allowing max_dynamic*N_reloads
        # total registrations across successive hot-reloads.
        self._dynamic_alias_count = 0
        self._init_access_log()

    @property
    def body_size_limit(self) -> int:
        return int(self.cfg.get("max_body_bytes", _DEFAULT_BODY_SIZE_LIMIT))

    @property
    def _global_spoof(self) -> bool:
        """True when global SPOOF_ALL_DOMAINS is enabled.
        config.py normalises SPOOF_ALL_UNMAPPED_DOMAINS → SPOOF_ALL_DOMAINS on
        load, so we only need to read the canonical key here.
        """
        return bool(self.cfg.get("SPOOF_ALL_DOMAINS", False))

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
                data.server.sni = real
                log.debug(f"[SERVER_CONNECT] mapped {host}:{port} -> {real}:{port}, SNI {old_sni} -> {data.server.sni}")

    def request(self, flow: mhttp.HTTPFlow):
        host = flow.request.pretty_host
        real = self.aliases.real_for(host)
        if real is None:
            return

        flow.metadata[_META_FAKE] = host
        flow.metadata[_META_REAL] = real

        log.info(f"[REQ]  {flow.request.method} {host}{flow.request.path}  →  {real}")
        flow.request.host        = real
        flow.request.host_header = real
        if hasattr(flow.request, "authority") and flow.request.authority:
            flow.request.authority = real
        if "Host" in flow.request.headers:
            flow.request.headers["Host"] = real

        rw           = self.rw
        global_spoof = self._global_spoof
        exclude_list = self.cfg.get("SPOOFING_EXCLUDE_LIST", []) + self.aliases.get_exclusions_for(host)

        if rw.get("headers", True):
            for hdr in ("referer", "origin"):
                val = flow.request.headers.get(hdr, "")
                if val:
                    flow.request.headers[hdr] = self.aliases.rewrite_fake_to_real(
                        val, context_fake=host, global_spoof=global_spoof, exclude_list=exclude_list
                    )

        if rw.get("cookies", True):
            raw_cookie = flow.request.headers.get("cookie", "")
            if raw_cookie:
                flow.request.headers["cookie"] = self.aliases.rewrite_fake_to_real(
                    raw_cookie, context_fake=host, global_spoof=global_spoof, exclude_list=exclude_list
                )

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

                    body_text = decompressed.decode("utf-8", errors="replace")
                    new_text  = self.aliases.rewrite_fake_to_real(
                        body_text, context_fake=host, global_spoof=global_spoof, exclude_list=exclude_list
                    )
                    if new_text != body_text:
                        new_bytes = new_text.encode("utf-8")
                        if did_decompress and actual_enc:
                            recompressed, ok = recompress(new_bytes, actual_enc)
                            if ok:
                                new_bytes = recompressed
                            else:
                                del flow.request.headers["content-encoding"]
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
        fake         = flow.metadata.get(_META_FAKE)
        global_spoof = self._global_spoof
        if fake is None and not global_spoof:
            return

        ctx_fake     = fake if fake else flow.request.pretty_host
        rw           = self.rw
        strip_hdrs   = self.strip_hdrs
        # Compute exclude_list once; passed to all sub-methods to avoid 3× rebuild.
        exclude_list = self.cfg.get("SPOOFING_EXCLUDE_LIST", []) + self.aliases.get_exclusions_for(ctx_fake)

        for hdr in list(flow.response.headers.keys()):
            if hdr.lower() in strip_hdrs:
                del flow.response.headers[hdr]

        if rw.get("headers", True):
            self._rewrite_response_headers(flow, ctx_fake, global_spoof, exclude_list)

        if rw.get("cookies", True):
            self._rewrite_cookies(flow, ctx_fake, global_spoof, exclude_list)

        ct = flow.response.headers.get("content-type", "").lower()
        try:
            bytes_rw = self._rewrite_body(flow, rw, global_spoof, exclude_list)
        except Exception as exc:
            log.warning(f"[BODY] unexpected error for {ctx_fake}: {exc}")
            self.stats.error(ctx_fake)
            bytes_rw = 0

        if getattr(flow, "_proxyevil_aliases_modified", False):
            from hosts_manager import update_hosts_file
            update_hosts_file(self.aliases.mapping)
            self._cfg_gen += 1   # invalidate strip_hdrs cache without reopening log
            flow._proxyevil_aliases_modified = False

        self._inject(flow, ctx_fake)

        self.stats.hit(ctx_fake, bytes_rw, content_type=_ct_bucket(ct))
        self._write_access(
            flow.request.method,
            ctx_fake,
            flow.request.path,
            flow.response.status_code,
            len(flow.response.content or b""),
            ct.split(";")[0].strip(),
        )

        if self.cfg.get("capture_responses", False):
            self._capture_body("resp", ctx_fake, flow.request.method,
                               flow.request.path, flow.response.content)

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

    def _rewrite_response_headers(self, flow: mhttp.HTTPFlow, ctx_fake: str,
                                   global_spoof: bool, exclude_list: list):
        for hdr in ("location", "refresh", "link", "content-location",
                    "access-control-allow-origin"):
            val = flow.response.headers.get(hdr, "")
            if val:
                new_val = self.aliases.rewrite_real_to_fake(
                    val, context_fake=ctx_fake, global_spoof=global_spoof, exclude_list=exclude_list
                )
                if new_val != val:
                    flow.response.headers[hdr] = new_val
                    log.debug(f"[HDR] {hdr}: {val!r} → {new_val!r}")

    def _rewrite_cookies(self, flow: mhttp.HTTPFlow, fake_base: str,
                          global_spoof: bool, exclude_list: list):
        raw_cookies = flow.response.headers.get_all("set-cookie")
        if not raw_cookies:
            return

        fake_is_http = flow.request.scheme == "http"
        new_cookies  = []

        for raw in raw_cookies:
            first_semi = raw.find(";")
            if first_semi == -1:
                new_cookies.append(self.aliases.rewrite_real_to_fake(
                    raw, context_fake=fake_base, global_spoof=global_spoof, exclude_list=exclude_list
                ))
                continue
            name_val     = raw[:first_semi]
            attrs        = raw[first_semi:]
            new_name_val = self.aliases.rewrite_real_to_fake(
                name_val, context_fake=fake_base, global_spoof=global_spoof, exclude_list=exclude_list
            )
            new_attrs = re.sub(r'(?i)(;\s*domain=)[^;]*', f'; Domain={fake_base}', attrs)
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

    def _rewrite_body(self, flow: mhttp.HTTPFlow, rw: dict,
                       global_spoof: bool, exclude_list: list) -> int:
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
        # Pre-filter on compressed size; real limit is enforced on decompressed bytes below.
        if len(raw) > self.body_size_limit:
            log.debug(f"[BODY] skipping {len(raw) // 1024}KB compressed body (over limit)")
            return 0

        if enc and enc != "identity":
            decompressed, did_decompress, actual_enc = decompress(raw, enc)
        else:
            decompressed, did_decompress, actual_enc = raw, False, enc

        if len(decompressed) > self.body_size_limit:
            log.debug(f"[BODY] skipping {len(decompressed) // 1024}KB decompressed body (over limit)")
            return 0

        active_enc = actual_enc if (did_decompress and actual_enc and actual_enc != "identity") else ""

        fake          = flow.metadata.get(_META_FAKE, "")
        spoof_enabled = global_spoof or self.aliases.is_spoof_all_enabled(fake)

        # Pre-check: skip bodies that contain none of the real-side domain needles.
        # Fix C: needles are pre-lowercased bytes. Search a lowercased view only when
        # the body is small enough that the copy is cheap; for large bodies fall through
        # to the full rewrite which handles case via the regex (re.IGNORECASE).
        # This avoids both the original wasteful full-copy AND the fix-#5 regression
        # where mixed-case domains (e.g. FACEBOOK.COM in JSON) were silently skipped.
        # Fix: SRI integrity= attrs must be stripped even when the body has no
        # real-domain reference to rewrite (e.g. third-party CDN <script> tags
        # on an otherwise-unrelated page) — bypass the domain-needle precheck
        # in that case so _SRI_RE.sub() below still runs.
        has_sri = is_html and rw.get("html", True) and b"integrity=" in decompressed.lower()

        if not spoof_enabled and not has_sri:
            if did_decompress or not enc or enc == "identity":
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

        if spoof_enabled:
            scan_text    = text.replace("\\/", "/")
            url_hosts    = _URL_HOST_RE.findall(scan_text)
            proto_hosts  = _PROTO_RELATIVE_RE.findall(scan_text)
            quoted_hosts = _QUOTED_DOMAIN_RE.findall(scan_text)
            all_found    = set()
            for h in url_hosts + proto_hosts + quoted_hosts:
                h = h.lower().strip().rstrip(".")
                if h and "." in h:
                    all_found.add(h)

            # Fix #19: enforce cap on total dynamic alias count
            max_dynamic = int(self.cfg.get("max_dynamic_aliases", _DEFAULT_MAX_DYNAMIC_ALIASES))

            # Snapshot both maps once — avoids 2*N lock acquisitions inside the loop.
            existing_f2r = self.aliases.mapping
            existing_r2f = {v: k for k, v in existing_f2r.items()}
            to_register: list[tuple[str, str, str | None]] = []
            for host in all_found:
                if _is_ip_or_localhost(host):
                    continue
                if host in existing_r2f or host in existing_f2r:
                    continue

                is_excluded = False
                for exc in exclude_list:
                    exc = exc.lower().strip()
                    if host == exc or host.endswith("." + exc):
                        is_excluded = True
                        break
                if is_excluded:
                    continue

                if self._dynamic_alias_count + len(to_register) >= max_dynamic:
                    log.warning(
                        f"[DYNAMIC SPOOF] cap reached ({max_dynamic}) — "
                        f"skipping {host}. Raise 'max_dynamic_aliases' in config to increase."
                    )
                    break

                to_register.append((f"{host}.local", host, fake if fake else None))

            if to_register:
                added = self.aliases.register_dynamic_aliases_bulk(to_register)
                if added:
                    self._dynamic_alias_count += added
                    log.info(f"[DYNAMIC SPOOF] registered {added} dynamic alias(es) ({self._dynamic_alias_count}/{max_dynamic})")
                    flow._proxyevil_aliases_modified = True

        original_text = text  # Fix: baseline for the "anything changed?" check below,
                              # captured BEFORE SRI stripping so an SRI-only change
                              # (no domain rewrite) is still detected and written back.
        if is_html and rw.get("html", True):
            text = _SRI_RE.sub("", text)

        new_text = self.aliases.rewrite_real_to_fake(
            text, context_fake=fake if fake else None, global_spoof=global_spoof, exclude_list=exclude_list
        )
        if new_text == original_text:
            return 0

        try:
            new_bytes = new_text.encode(charset, errors="replace")
        except Exception:
            new_bytes = new_text.encode("utf-8", errors="replace")

        if active_enc:
            recompressed, ok = recompress(new_bytes, active_enc)
            if ok:
                new_bytes = recompressed
            else:
                log.debug(f"[BODY] recompress({active_enc}) failed — serving uncompressed")
                if "content-encoding" in flow.response.headers:
                    del flow.response.headers["content-encoding"]
        elif did_decompress:
            if "content-encoding" in flow.response.headers:
                del flow.response.headers["content-encoding"]

        flow.response.content                   = new_bytes
        flow.response.headers["content-length"] = str(len(new_bytes))

        delta = len(new_bytes) - len(raw)
        log.debug(f"[BODY] {ct[:30]}  {len(raw)}B → {len(new_bytes)}B  Δ{delta:+d} bytes")
        return max(0, delta)
