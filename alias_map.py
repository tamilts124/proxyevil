"""
alias_map.py — Bidirectional fake ↔ real domain map with subdomain support.

Config aliases support two forms:
    "mybook.local": "www.facebook.com"                   (simple)
    "mybook.local": {                                     (extended)
        "real": "www.facebook.com",
        "extra_real": ["fbcdn.net", "fbsbx.com"]
    }

extra_real domains are additional real-side domains (CDNs, APIs) that will
be rewritten to the same fake domain.
"""

import logging
import re
import threading
from collections import OrderedDict
from typing import Optional

log = logging.getLogger("proxyevil.alias_map")


# ── lock-free lookup helpers used inside rewrite closures ───────────────────────

def _lookup_fake(host: str, real_to_fake: dict) -> Optional[str]:
    """Return the fake domain for *host* using a pre-snapshotted dict (no lock)."""
    if host in real_to_fake:
        return real_to_fake[host]
    for r, f in real_to_fake.items():
        if host.endswith("." + r):
            sub = host[: -(len(r) + 1)]
            base_fake = re.sub(r"^www\.", "", f) if f.startswith("www.") else f
            return f"{sub}.{base_fake}"
    return None


def _lookup_real(host: str, fake_to_real: dict) -> Optional[str]:
    """Return the real domain for *host* using a pre-snapshotted dict (no lock)."""
    if host in fake_to_real:
        return fake_to_real[host]
    for f, r in fake_to_real.items():
        if host.endswith("." + f):
            sub = host[: -(len(f) + 1)]
            base_real = re.sub(r"^www\.", "", r) if r.startswith("www.") else r
            return f"{sub}.{base_real}"
    return None

_CACHE_MAX  = 2_000   # max entries per lookup cache
_CACHE_EVICT = 200    # how many to drop when full (oldest-first LRU)


class AliasMap:
    def __init__(self, aliases: dict):
        self._fake_to_real: dict[str, str] = {}
        self._real_to_fake: dict[str, str] = {}
        self._lock = threading.RLock()
        self._load(aliases)

    # ── internal ──────────────────────────────────────────────────────────────

    def _load(self, aliases: dict):
        """Rebuild all internal state. Must be called with self._lock held (or during __init__)."""
        self._fake_to_real.clear()
        self._real_to_fake.clear()
        skipped = 0
        for fake, val in aliases.items():
            fake = fake.lower().rstrip(".")
            if isinstance(val, str):
                real   = val.lower().rstrip(".")
                extras = []
            else:
                # Skip disabled aliases without removing them from config
                if not val.get("enabled", True):
                    skipped += 1
                    log.debug(f"[ALIAS] skipping disabled alias: {fake}")
                    continue
                real    = val["real"].lower().rstrip(".")
                extras  = [e.lower().rstrip(".") for e in val.get("extra_real", [])]

            self._fake_to_real[fake] = real
            self._real_to_fake[real] = fake
            for extra in extras:
                # Generate a unique fake domain for this extra_real to maintain 1-to-1 reverse mapping
                # e.g., extra="fbcdn.net", fake="mybook.local" -> "fbcdn-net.mybook.local"
                extra_fake = f"{extra.replace('.', '-')}.{fake}"
                self._fake_to_real[extra_fake] = extra
                self._real_to_fake[extra] = extra_fake

        if skipped:
            log.info(f"[ALIAS] {skipped} disabled alias(es) skipped")

        # Sort dictionaries by key length descending so that longest domains match first.
        # This prevents 'fbcdn-net.mybook.local' from being caught by the shorter 'mybook.local' match.
        self._fake_to_real = dict(sorted(self._fake_to_real.items(), key=lambda x: len(x[0]), reverse=True))
        self._real_to_fake = dict(sorted(self._real_to_fake.items(), key=lambda x: len(x[0]), reverse=True))

        self._rebuild_patterns()

    def _rebuild_patterns(self):
        """Recompile regex patterns and reset caches. Must be called with self._lock held."""
        real_sorted = sorted(self._real_to_fake.keys(), key=len, reverse=True)
        fake_sorted = sorted(self._fake_to_real.keys(), key=len, reverse=True)

        def _pat(domains: list[str]) -> Optional[re.Pattern]:
            if not domains:
                return None
            escaped     = [re.escape(d) for d in domains]
            domain_alts = "|".join(escaped)
            return re.compile(
                r"(?:https?://(?:[a-zA-Z0-9\-]+\.)*(?:" + domain_alts + r"))"
                r"|(?:(?<![a-zA-Z0-9\-])(?:[a-zA-Z0-9\-]+\.)*(?:" + domain_alts + r"))",
                re.IGNORECASE,
            )

        self._real_pattern = _pat(real_sorted)
        self._fake_pattern = _pat(fake_sorted)
        # Pre-encoded needle bytes for fast body pre-check.
        # Encode as IDNA so non-ASCII (IDN) domains produce the wire-form
        # bytes that actually appear in HTML bodies.
        needles = []
        for r in self._real_to_fake:
            try:
                needles.append(r.encode("idna"))
            except (UnicodeError, UnicodeDecodeError):
                needles.append(r.encode("utf-8"))
        self._real_needles: list[bytes] = needles
        # Fake-side needles for the request-body pre-check (rewrite_fake_to_real).
        fake_needles = []
        for f in self._fake_to_real:
            try:
                fake_needles.append(f.encode("idna"))
            except (UnicodeError, UnicodeDecodeError):
                fake_needles.append(f.encode("utf-8"))
        self._fake_needles: list[bytes] = fake_needles
        # LRU caches — OrderedDict with move-to-end on hit, evict oldest on full
        self._real_cache: OrderedDict[str, Optional[str]] = OrderedDict()
        self._fake_cache: OrderedDict[str, Optional[str]] = OrderedDict()

    # ── lookup (LRU-cached, lock-protected) ───────────────────────────────────

    def _real_for_cached(self, fake: str) -> Optional[str]:
        with self._lock:
            if fake in self._real_cache:
                self._real_cache.move_to_end(fake)
                return self._real_cache[fake]

            result = None
            if fake in self._fake_to_real:
                result = self._fake_to_real[fake]
            else:
                for f, r in self._fake_to_real.items():
                    if fake.endswith("." + f):
                        sub       = fake[: -(len(f) + 1)]
                        # Only strip a leading 'www.' if the fake root itself
                        # starts with 'www.' — otherwise bare subdomains like
                        # 'app.example.com' are wrongly truncated.
                        base_real = re.sub(r"^www\.", "", r) if r.startswith("www.") else r
                        result    = f"{sub}.{base_real}"
                        break

            self._real_cache[fake] = result
            if len(self._real_cache) > _CACHE_MAX:
                for _ in range(_CACHE_EVICT):
                    self._real_cache.popitem(last=False)
            return result

    def _fake_for_cached(self, real: str) -> Optional[str]:
        with self._lock:
            if real in self._fake_cache:
                self._fake_cache.move_to_end(real)
                return self._fake_cache[real]

            result = None
            if real in self._real_to_fake:
                result = self._real_to_fake[real]
            else:
                for r, f in self._real_to_fake.items():
                    if real.endswith("." + r):
                        sub       = real[: -(len(r) + 1)]
                        base_fake = re.sub(r"^www\.", "", f) if f.startswith("www.") else f
                        result    = f"{sub}.{base_fake}"
                        break

            self._fake_cache[real] = result
            if len(self._fake_cache) > _CACHE_MAX:
                for _ in range(_CACHE_EVICT):
                    self._fake_cache.popitem(last=False)
            return result

    # ── public API ────────────────────────────────────────────────────────────

    def real_for(self, fake: str) -> Optional[str]:
        """Return the real upstream domain for a fake domain (or None)."""
        return self._real_for_cached(fake.lower())

    def fake_for(self, real: str) -> Optional[str]:
        """Return the fake domain for a real upstream domain (or None)."""
        return self._fake_for_cached(real.lower())

    def rewrite_real_to_fake(self, text: str) -> str:
        with self._lock:
            pattern = self._real_pattern
            # Snapshot the lookup dicts so the inner _replace closure doesn't
            # need to re-acquire the lock for every match (avoids lock contention
            # hotspot under concurrent traffic + reload).
            real_to_fake = dict(self._real_to_fake)
            fake_to_real_keys = list(self._fake_to_real.keys())
        if not pattern:
            return text

        def _replace(m: re.Match) -> str:
            full = m.group(0)
            if "://" in full:
                proto, rest = full.split("://", 1)
                host_and_port = rest.split("/")[0]
                host_part     = host_and_port.split(":")[0]
                fake          = _lookup_fake(host_part.lower(), real_to_fake)
                if not fake:
                    return full
                # Drop the port from the remainder so it isn't blindly carried
                # into the fake URL (fake.local:443 would look broken to browsers).
                remainder = rest[len(host_and_port):]
                return proto + "://" + fake + remainder
            fake = _lookup_fake(full.lower(), real_to_fake)
            return fake if fake else full

        return pattern.sub(_replace, text)

    def rewrite_fake_to_real(self, text: str) -> str:
        with self._lock:
            pattern = self._fake_pattern
            # Same snapshot pattern as rewrite_real_to_fake.
            fake_to_real = dict(self._fake_to_real)
        if not pattern:
            return text

        def _replace(m: re.Match) -> str:
            full = m.group(0)
            if "://" in full:
                proto, rest = full.split("://", 1)
                host_and_port = rest.split("/")[0]
                host_part     = host_and_port.split(":")[0]
                real          = _lookup_real(host_part.lower(), fake_to_real)
                if not real:
                    return full
                # Drop the port from the remainder (same reasoning as real→fake).
                remainder = rest[len(host_and_port):]
                return proto + "://" + real + remainder
            real = _lookup_real(full.lower(), fake_to_real)
            return real if real else full

        return pattern.sub(_replace, text)

    def reload(self, aliases: dict):
        """Hot-reload aliases without restarting the proxy.
        Holds the lock for the entire rebuild so no reader sees partial state."""
        with self._lock:
            self._load(aliases)
        log.info(f"[ALIAS] reloaded — {len(self._fake_to_real)} aliases")

    @property
    def mapping(self) -> dict[str, str]:
        """Return fake → primary-real dict (for PAC file, hosts block, banner)."""
        with self._lock:
            return dict(self._fake_to_real)

    @property
    def full_mapping(self) -> dict[str, dict]:
        """Return fake → {real, extra_real} dict including CDN/extra_real entries.

        Used by the dashboard so all configured real-side domains are visible.
        """
        with self._lock:
            # Invert _real_to_fake to collect extra_real entries per fake.
            extras: dict[str, list[str]] = {}
            for real, fake in self._real_to_fake.items():
                if real != self._fake_to_real.get(fake):
                    extras.setdefault(fake, []).append(real)
            result = {}
            for fake, primary_real in self._fake_to_real.items():
                result[fake] = {"real": primary_real, "extra_real": extras.get(fake, [])}
            return result

    @property
    def stats_keys(self) -> list[str]:
        with self._lock:
            return list(self._fake_to_real.keys())
