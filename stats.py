"""
stats.py — Thread-safe per-alias traffic counters with optional persistence.

Tracks per-alias: request count, bytes rewritten, error count, last-seen
timestamp, and per-content-type rewrite counts (html/js/css/json/other).
"""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger("proxyevil.stats")

_LAST_SEEN_DEFAULT = "—"

# Content-type buckets tracked in rewrite_by_type
_REWRITE_TYPES = ("html", "js", "css", "json", "other")


def _blank_entry() -> dict:
    return {
        "requests":        0,
        "bytes_rewritten": 0,
        "errors":          0,
        "last_seen":       _LAST_SEEN_DEFAULT,
        "rewrite_by_type": {t: 0 for t in _REWRITE_TYPES},
    }

_BLANK = _blank_entry


class Stats:
    """Thread-safe per-alias hit, bytes-rewritten, error, and type counters."""

    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}

    def init(self, fake_domains: list[str]):
        """Pre-seed counters so all known aliases appear in the dashboard."""
        with self._lock:
            for d in fake_domains:
                self._data.setdefault(d, _blank_entry())

    def hit(self, fake: str, bytes_delta: int = 0, content_type: str = "other"):
        """Record one successful request with optional rewritten-byte delta.

        *content_type* should be one of the _REWRITE_TYPES buckets, or 'other'.
        If *bytes_delta* > 0, the rewrite_by_type counter for *content_type* is
        incremented as well, giving a per-type breakdown in /stats.json.
        """
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        bucket = content_type if content_type in _REWRITE_TYPES else "other"
        with self._lock:
            entry = self._data.setdefault(fake, _blank_entry())
            entry["requests"]        += 1
            entry["bytes_rewritten"] += bytes_delta
            entry["last_seen"]        = ts
            if bytes_delta > 0:
                entry["rewrite_by_type"][bucket] += 1

    def error(self, fake: str):
        """Record a processing error for *fake* (shown in dashboard)."""
        with self._lock:
            entry = self._data.setdefault(fake, _blank_entry())
            entry["errors"] += 1

    def snapshot(self) -> dict:
        """Return a deep copy of all counters safe to read outside the lock."""
        with self._lock:
            return {
                k: {**v, "rewrite_by_type": dict(v["rewrite_by_type"])}
                for k, v in self._data.items()
            }

    def reset(self, fake: Optional[str] = None):
        """Reset counters for one alias (or all if *fake* is None)."""
        with self._lock:
            if fake:
                if fake in self._data:
                    self._data[fake] = _blank_entry()
            else:
                for k in self._data:
                    self._data[k] = _blank_entry()

    # ── persistence ───────────────────────────────────────────────────────────

    def dump(self, path: "str | Path"):
        """Write current stats to *path* as JSON (called on /stats/save or shutdown)."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            payload = {
                "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "aliases":  {
                    k: {**v, "rewrite_by_type": dict(v["rewrite_by_type"])}
                    for k, v in self._data.items()
                },
            }
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info(f"[STATS] saved → {p}")

    def load(self, path: "str | Path"):
        """Restore stats from a previously dumped JSON file (best-effort)."""
        p = Path(path)
        if not p.exists():
            return
        try:
            raw   = json.loads(p.read_text(encoding="utf-8"))
            saved = raw.get("aliases", {})
            with self._lock:
                for fake, entry in saved.items():
                    existing = self._data.setdefault(fake, _blank_entry())
                    for key in ("requests", "bytes_rewritten", "errors"):
                        existing[key] = entry.get(key, 0)
                    existing["last_seen"] = entry.get("last_seen", "—")
                    # Restore per-type counts if present (new in v1.6)
                    saved_rbt = entry.get("rewrite_by_type", {})
                    for t in _REWRITE_TYPES:
                        existing["rewrite_by_type"][t] = saved_rbt.get(t, 0)
            log.info(f"[STATS] loaded from {p}  (saved {raw.get('saved_at', '?')})")
        except Exception as exc:
            log.warning(f"[STATS] could not load {p}: {exc}")
