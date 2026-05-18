"""
stats.py — Thread-safe per-alias traffic counters with optional persistence.
"""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger("proxyevil.stats")

_BLANK = lambda: {"requests": 0, "bytes_rewritten": 0, "errors": 0, "last_seen": "—"}  # noqa: E731


class Stats:
    """Thread-safe per-alias hit, bytes-rewritten, and error counters."""

    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}

    def init(self, fake_domains: list[str]):
        """Pre-seed counters so all known aliases appear in the dashboard."""
        with self._lock:
            for d in fake_domains:
                self._data.setdefault(d, _BLANK())

    def hit(self, fake: str, bytes_delta: int = 0):
        """Record one successful request and optional rewritten-byte delta."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())  # UTC, ISO-8601
        with self._lock:
            entry = self._data.setdefault(fake, _BLANK())
            entry["requests"]        += 1
            entry["bytes_rewritten"] += bytes_delta
            entry["last_seen"]        = ts

    def error(self, fake: str):
        """Record a processing error for *fake* (shown in dashboard)."""
        with self._lock:
            entry = self._data.setdefault(fake, _BLANK())
            entry["errors"] += 1

    def snapshot(self) -> dict:
        """Return a deep copy of all counters safe to read outside the lock."""
        with self._lock:
            return {k: dict(v) for k, v in self._data.items()}

    def reset(self, fake: Optional[str] = None):
        """Reset counters for one alias (or all if *fake* is None)."""
        with self._lock:
            if fake:
                if fake in self._data:
                    self._data[fake] = _BLANK()
            else:
                for k in self._data:
                    self._data[k] = _BLANK()

    # ── persistence ───────────────────────────────────────────────────────────

    def dump(self, path: str | Path):
        """Write current stats to *path* as JSON (called on /stats/save or shutdown)."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            payload = {"saved_at": time.strftime("%Y-%m-%d %H:%M:%S"), "aliases": dict(self._data)}
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info(f"[STATS] saved → {p}")

    def load(self, path: str | Path):
        """Restore stats from a previously dumped JSON file (best-effort)."""
        p = Path(path)
        if not p.exists():
            return
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            saved = raw.get("aliases", {})
            with self._lock:
                for fake, entry in saved.items():
                    # Merge into existing (init() may have already pre-seeded)
                    existing = self._data.setdefault(fake, _BLANK())
                    for key in ("requests", "bytes_rewritten", "errors"):
                        existing[key] = entry.get(key, 0)
                    existing["last_seen"] = entry.get("last_seen", "—")
            log.info(f"[STATS] loaded from {p}  (saved {raw.get('saved_at', '?')})")
        except Exception as exc:
            log.warning(f"[STATS] could not load {p}: {exc}")
