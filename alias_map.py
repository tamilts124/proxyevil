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

_MAX_PARENT_DEPTH = 50   # Fix #6: guard against circular parent chains


def _combined_byte_pattern(needles: list) -> Optional[re.Pattern]:
    """Compile a single alternation regex over pre-lowercased byte needles.

    Used for the "does this body contain any real/fake domain at all"
    pre-check. A single combined pattern lets the regex engine scan the
    haystack once regardless of alias count, instead of the naive
    O(len(needles) * len(haystack)) cost of testing each needle with `in`.
    Falls back to None (caller treats as "no needles, nothing to match")
    when the alias set is empty.
    """
    if not needles:
        return None
    return re.compile(b"|".join(re.escape(n) for n in needles))

# Fix #21: single module-level _pat() used everywhere (was copy-pasted in two methods)
def _pat(domains: list) -> Optional[re.Pattern]:
    """Compile a domain-matching regex from a list of domain strings."""
    if not domains:
        return None
    escaped     = [re.escape(d) for d in domains]
    domain_alts = "|".join(escaped)
    return re.compile(
        r"(?:https?://(?:[a-zA-Z0-9\-]+\.)*(?:" + domain_alts + r"))"
        r"|(?:(?<![a-zA-Z0-9\-])(?:[a-zA-Z0-9\-]+\.)*(?:" + domain_alts + r"))",
        re.IGNORECASE,
    )


# ── lock-free lookup helpers used inside rewrite closures ───────────────────────

def _lookup_fake(host: str, real_to_fake: dict) -> Optional[str]:
    """Return the fake domain for *host* using a pre-snapshotted dict (no lock)."""
    if host in real_to_fake:
        return real_to_fake[host]
    for r, f in real_to_fake.items():
        if host.endswith("." + r):
            sub = host[: -(len(r) + 1)]
            # Note (Fix #3): www. is stripped from the base fake only when it already
            # starts with www., giving e.g. sub.mybook.local instead of sub.www.mybook.local.
            # This is intentionally asymmetric: if the base real is facebook.com (no www)
            # the same host matching still works, but no www. strip happens on the fake side.
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


# Fix #21: shared rewrite engine — eliminates ~80% duplication between
# rewrite_real_to_fake and rewrite_fake_to_real.
def _rewrite(text: str, pattern: Optional[re.Pattern],
             lookup_fn, exclude_list: Optional[list]) -> str:
    """Apply *pattern* to *text*, replacing each match via *lookup_fn*.

    *lookup_fn(host: str) -> Optional[str]* — returns the replacement host
    or None to leave the match unchanged.  *exclude_list* is checked against
    the resolved real-side host for real→fake direction; callers handle which
    side to exclude.
    """
    if not text or not pattern:
        return text

    def _replace(m: re.Match) -> str:
        full = m.group(0)
        if "://" in full:
            proto, rest   = full.split("://", 1)
            host_and_port = rest.split("/")[0]
            host_part     = host_and_port.split(":")[0]
            if exclude_list:
                hl = host_part.lower()
                for exc in exclude_list:
                    exc = exc.lower().strip()
                    if hl == exc or hl.endswith("." + exc):
                        return full
            replacement = lookup_fn(host_part.lower())
            if not replacement:
                return full
            return proto + "://" + replacement + rest[len(host_and_port):]

        # Bare domain — strip trailing punctuation before lookup
        clean  = full.rstrip(".,;:'\"\'><)]").lower()
        suffix = full[len(clean):]
        if exclude_list:
            for exc in exclude_list:
                exc = exc.lower().strip()
                if clean == exc or clean.endswith("." + exc):
                    return full
        replacement = lookup_fn(clean)
        return (replacement + suffix) if replacement else full

    return pattern.sub(_replace, text)


_CACHE_MAX  = 2_000
_CACHE_EVICT = 200


class AliasMap:
    def __init__(self, aliases: dict):
        self._lock = threading.RLock()
        self._fake_to_real: dict[str, str] = {}
        self._real_to_fake: dict[str, str] = {}
        self._parents: dict[str, str] = {}
        self._spoof_all_enabled: set[str] = set()

        self._family_real_patterns: dict[str, Optional[re.Pattern]] = {}
        self._family_fake_patterns: dict[str, Optional[re.Pattern]] = {}
        self._family_real_to_fake: dict[str, dict[str, str]] = {}
        self._family_fake_to_real: dict[str, dict[str, str]] = {}
        self._family_exclude_lists: dict[str, list[str]] = {}

        self._load(aliases)

    # ── internal ──────────────────────────────────────────────────────────────

    def _load(self, aliases: dict):
        """Rebuild all internal state. Must be called with self._lock held (or during __init__)."""
        self._fake_to_real.clear()
        self._real_to_fake.clear()
        self._parents.clear()
        self._spoof_all_enabled.clear()
        self._family_real_patterns.clear()
        self._family_fake_patterns.clear()
        self._family_real_to_fake.clear()
        self._family_fake_to_real.clear()
        self._family_exclude_lists.clear()
        skipped = 0
        for fake, val in aliases.items():
            fake = fake.lower().rstrip(".")
            if isinstance(val, str):
                real     = val.lower().rstrip(".")
                extras   = []
                excludes = []
            else:
                if not val.get("enabled", True):
                    skipped += 1
                    log.debug(f"[ALIAS] skipping disabled alias: {fake}")
                    continue
                real     = val["real"].lower().rstrip(".")
                extra_list = val.get("EXTRA_REAL_DOMAINS_TO_SPOOF") or val.get("extra_real") or []
                extras   = [e.lower().rstrip(".") for e in extra_list]
                excludes = [x.lower().strip() for x in val.get("SPOOFING_EXCLUDE_LIST", [])]
                # Fix B: config.py normalises SPOOF_ALL_UNMAPPED_DOMAINS → SPOOF_ALL_DOMAINS
                # on load, so only the canonical key needs to be checked here.
                if val.get("SPOOF_ALL_DOMAINS", False):
                    self._spoof_all_enabled.add(fake)

            self._fake_to_real[fake] = real
            if real in self._real_to_fake and self._real_to_fake[real] != fake:
                log.warning(
                    f"[ALIAS] real domain '{real}' is mapped by both "
                    f"'{self._real_to_fake[real]}' and '{fake}' — "
                    f"'{self._real_to_fake[real]}' reverse-lookup will be broken"
                )
            self._real_to_fake[real] = fake
            self._family_exclude_lists[fake] = excludes
            for extra in extras:
                extra_fake = f"{extra.replace('.', '-')}.{fake}"
                self._fake_to_real[extra_fake] = extra
                self._real_to_fake[extra] = extra_fake
                self._parents[extra_fake] = fake

        if skipped:
            log.info(f"[ALIAS] {skipped} disabled alias(es) skipped")

        self._fake_to_real = dict(sorted(self._fake_to_real.items(), key=lambda x: len(x[0]), reverse=True))
        self._real_to_fake = dict(sorted(self._real_to_fake.items(), key=lambda x: len(x[0]), reverse=True))
        self._rebuild_patterns()

    def _rebuild_patterns(self):
        """Recompile regex patterns and reset caches. Must be called with self._lock held."""
        self._family_real_patterns.clear()
        self._family_fake_patterns.clear()
        self._family_real_to_fake.clear()
        self._family_fake_to_real.clear()

        real_sorted = sorted(self._real_to_fake.keys(), key=len, reverse=True)
        fake_sorted = sorted(self._fake_to_real.keys(), key=len, reverse=True)

        # Fix #21: use module-level _pat() instead of duplicated inner function
        self._real_pattern = _pat(real_sorted)
        self._fake_pattern = _pat(fake_sorted)

        # Stable snapshots for lock-free rewrite calls (replaced atomically here)
        self._real_to_fake_snap = dict(self._real_to_fake)
        self._fake_to_real_snap = dict(self._fake_to_real)

        needles = []
        for r in self._real_to_fake:
            try:
                needles.append(r.encode("idna"))
            except (UnicodeError, UnicodeDecodeError):
                needles.append(r.encode("utf-8"))
        self._real_needles: list[bytes] = needles
        self._real_needle_pattern: Optional[re.Pattern] = _combined_byte_pattern(needles)

        fake_needles = []
        for f in self._fake_to_real:
            try:
                fake_needles.append(f.encode("idna"))
            except (UnicodeError, UnicodeDecodeError):
                fake_needles.append(f.encode("utf-8"))
        self._fake_needles: list[bytes] = fake_needles
        self._fake_needle_pattern: Optional[re.Pattern] = _combined_byte_pattern(fake_needles)

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
        return self._real_for_cached(fake.lower())

    def fake_for(self, real: str) -> Optional[str]:
        return self._fake_for_cached(real.lower())

    def _get_root_fake(self, fake: str) -> str:
        """Find the root fake alias domain by traversing parents recursively.
        Fix #6: bounded by _MAX_PARENT_DEPTH to prevent infinite loops.
        Must be called with self._lock held.
        """
        curr    = fake.lower().rstrip(".")
        visited = {curr}
        while curr in self._parents:
            parent = self._parents[curr].lower().rstrip(".")
            if parent in visited or len(visited) >= _MAX_PARENT_DEPTH:
                break
            curr = parent
            visited.add(curr)
        return curr

    def _build_family_patterns(self, root: str):
        """Build and cache family-specific patterns. Must hold self._lock.
        Fix #10: single loop over _fake_to_real builds both maps simultaneously
        (was two separate loops over the same key space).
        """
        family_r2f = {}
        family_f2r = {}
        for fake, real in self._fake_to_real.items():
            if self._get_root_fake(fake) == root:
                family_f2r[fake] = real
                family_r2f[real] = fake

        self._family_real_patterns[root] = _pat(sorted(family_r2f.keys(), key=len, reverse=True))
        self._family_real_to_fake[root]  = family_r2f
        self._family_fake_patterns[root] = _pat(sorted(family_f2r.keys(), key=len, reverse=True))
        self._family_fake_to_real[root]  = family_f2r

    def rewrite_real_to_fake(self, text: str, context_fake: Optional[str] = None,
                              global_spoof: bool = False,
                              exclude_list: Optional[list] = None) -> str:
        # Fix #21: delegates to shared _rewrite() helper.
        # Perf: grab pattern + snapshot inside lock, then do the (potentially large)
        # regex substitution outside the lock so we don't block other threads.
        if not text:
            return text
        with self._lock:
            if not context_fake or global_spoof:
                pattern      = self._real_pattern
                real_to_fake = self._real_to_fake_snap   # pre-built, no copy needed
            else:
                root = self._get_root_fake(context_fake)
                if root not in self._family_real_patterns:
                    self._build_family_patterns(root)
                pattern      = self._family_real_patterns[root]
                # Take a snapshot so a concurrent hot-reload that clears
                # _family_real_to_fake cannot cause _lookup_fake to iterate
                # an empty dict after we release the lock.
                real_to_fake = dict(self._family_real_to_fake[root])

        return _rewrite(text, pattern,
                        lambda h: _lookup_fake(h, real_to_fake),
                        exclude_list)

    def rewrite_fake_to_real(self, text: str, context_fake: Optional[str] = None,
                              global_spoof: bool = False,
                              exclude_list: Optional[list] = None) -> str:
        # Perf: same lock-minimisation strategy as rewrite_real_to_fake.
        if not text:
            return text
        with self._lock:
            if not context_fake or global_spoof:
                pattern      = self._fake_pattern
                fake_to_real = self._fake_to_real_snap   # pre-built, no copy needed
            else:
                root = self._get_root_fake(context_fake)
                if root not in self._family_fake_patterns:
                    self._build_family_patterns(root)
                pattern      = self._family_fake_patterns[root]
                # Take a snapshot so a concurrent hot-reload that clears
                # _family_fake_to_real cannot cause _lookup_real to iterate
                # an empty dict after we release the lock.
                fake_to_real = dict(self._family_fake_to_real[root])

        return _rewrite(text, pattern,
                        lambda h: _lookup_real(h, fake_to_real),
                        exclude_list)

    def register_dynamic_alias(self, fake: str, real: str,
                               parent_fake: Optional[str] = None) -> bool:
        """Dynamically add a new mapping at runtime.
        Returns True if added, False if already exists.
        For bulk registration use register_dynamic_aliases_bulk().
        """
        with self._lock:
            fake = fake.lower().rstrip(".")
            real = real.lower().rstrip(".")
            if fake in self._fake_to_real or real in self._real_to_fake:
                return False
            self._fake_to_real[fake] = real
            self._real_to_fake[real] = fake

            if parent_fake:
                parent_fake = parent_fake.lower().rstrip(".")
                self._parents[fake] = parent_fake
                if parent_fake in self._spoof_all_enabled:
                    self._spoof_all_enabled.add(fake)

            self._fake_to_real = dict(sorted(self._fake_to_real.items(), key=lambda x: len(x[0]), reverse=True))
            self._real_to_fake = dict(sorted(self._real_to_fake.items(), key=lambda x: len(x[0]), reverse=True))
            self._rebuild_patterns()
            return True

    def register_dynamic_aliases_bulk(
        self, pairs: list[tuple[str, str, Optional[str]]]
    ) -> int:
        """Register multiple (fake, real, parent_fake) aliases in one lock acquisition.
        Fix G: replaces per-alias register_dynamic_alias calls so sort + pattern
        rebuild happens once for the entire batch instead of once per alias.
        Returns the number of aliases actually added.
        """
        if not pairs:
            return 0
        added = 0
        with self._lock:
            for fake, real, parent_fake in pairs:
                fake = fake.lower().rstrip(".")
                real = real.lower().rstrip(".")
                if fake in self._fake_to_real or real in self._real_to_fake:
                    continue
                self._fake_to_real[fake] = real
                self._real_to_fake[real] = fake
                if parent_fake:
                    parent_fake = parent_fake.lower().rstrip(".")
                    self._parents[fake] = parent_fake
                    if parent_fake in self._spoof_all_enabled:
                        self._spoof_all_enabled.add(fake)
                added += 1

            if added:
                self._fake_to_real = dict(sorted(self._fake_to_real.items(), key=lambda x: len(x[0]), reverse=True))
                self._real_to_fake = dict(sorted(self._real_to_fake.items(), key=lambda x: len(x[0]), reverse=True))
                self._rebuild_patterns()
        return added

    def is_spoof_all_enabled(self, fake: str) -> bool:
        with self._lock:
            return fake.lower().rstrip(".") in self._spoof_all_enabled

    def contains_real_needle(self, haystack_lower: bytes) -> bool:
        """Fast pre-check: does *haystack_lower* (already lowercased bytes)
        contain any real-side domain? Uses the combined single-pass pattern
        built in _rebuild_patterns(); returns False (nothing to do) when
        there are no aliases configured."""
        pat = self._real_needle_pattern
        return pat is not None and pat.search(haystack_lower) is not None

    def get_exclusions_for(self, context_fake: Optional[str] = None) -> list:
        if not context_fake:
            return []
        with self._lock:
            root = self._get_root_fake(context_fake)
            return self._family_exclude_lists.get(root, [])

    def reload(self, aliases: dict):
        """Hot-reload aliases without restarting the proxy."""
        with self._lock:
            self._load(aliases)
        log.info(f"[ALIAS] reloaded — {len(self._fake_to_real)} aliases")

    @property
    def mapping(self) -> dict[str, str]:
        with self._lock:
            return dict(self._fake_to_real)

    @property
    def full_mapping(self) -> dict[str, dict]:
        with self._lock:
            extras: dict[str, list[str]] = {}
            for real, fake in self._real_to_fake.items():
                if fake in self._parents:
                    root = self._get_root_fake(fake)
                    extras.setdefault(root, []).append(real)
            result = {}
            for fake, primary_real in self._fake_to_real.items():
                extra_domains = extras.get(fake, [])
                result[fake] = {
                    "real": primary_real,
                    "EXTRA_REAL_DOMAINS_TO_SPOOF": extra_domains,
                    "extra_real": extra_domains,
                }
            return result

    @property
    def stats_keys(self) -> list[str]:
        with self._lock:
            return list(self._fake_to_real.keys())
