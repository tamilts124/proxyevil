"""
stats.py — Thread-safe per-alias traffic counters with optional persistence.

Tracks per-alias:
  requests        — total HTTP requests processed
  bytes_rewritten — cumulative net byte delta from domain rewriting (may be
                    zero for requests where no rewrite was needed; use
                    rewrites to count flows where content was actually changed)
  rewrites        — count of flows where at least one byte was rewritten
  errors          — count of processing errors
  last_seen       — ISO-8601 timestamp of the most recent request
  rewrite_by_type — per-content-type rewrite counts (html/js/css/json/other)
"""

import json
import logging
import threading
import time
from collections import deque
from pathlib import Path
from typing import Optional

_MAX_LOG_ENTRIES = 200

log = logging.getLogger("proxyevil.stats")

_LAST_SEEN_DEFAULT = "—"

# Content-type buckets tracked in rewrite_by_type
_REWRITE_TYPES = ("html", "js", "css", "json", "other")


def _blank_entry() -> dict:
    return {
        "requests":        0,
        "bytes_rewritten": 0,
        # rewrites counts flows where content was actually changed (bytes_delta > 0).
        # bytes_rewritten is the cumulative net size delta across all those flows.
        "rewrites":        0,
        "errors":          0,
        "last_seen":       _LAST_SEEN_DEFAULT,
        "rewrite_by_type": {t: 0 for t in _REWRITE_TYPES},
    }

class Stats:
    """Thread-safe per-alias hit, bytes-rewritten, error, and type counters."""

    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}
        self._gen: int = 0   # incremented on every mutation; exposed in snapshot
        self._recent: deque = deque(maxlen=_MAX_LOG_ENTRIES)  # ring buffer of recent requests

    def init(self, fake_domains: list[str]):
        """Pre-seed counters so all known aliases appear in the dashboard.
        Fix #15: only bumps _gen when at least one new key is actually added,
        so dashboard polls during hot-reload don’t trigger a full DOM refresh
        when no traffic data changed.
        """
        with self._lock:
            added = False
            for d in fake_domains:
                if d not in self._data:
                    self._data[d] = _blank_entry()
                    added = True
            if added:
                self._gen += 1

    def hit(self, fake: str, bytes_delta: int = 0, content_type: str = "other"):
        """Record one successful request with optional rewritten-byte delta.

        *bytes_delta* > 0 means content was actually rewritten for this flow.
        Both ``rewrites`` and ``rewrite_by_type[content_type]`` are incremented
        only when bytes_delta > 0, giving a meaningful count of "flows where
        domain substitution actually changed the body" as opposed to flows that
        were processed but required no changes.

        *content_type* should be one of the _REWRITE_TYPES buckets, or 'other'.
        """
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        bucket = content_type if content_type in _REWRITE_TYPES else "other"
        with self._lock:
            entry = self._data.setdefault(fake, _blank_entry())
            entry["requests"]        += 1
            entry["bytes_rewritten"] += bytes_delta
            entry["last_seen"]        = ts
            if bytes_delta > 0:
                entry["rewrites"]             += 1
                entry["rewrite_by_type"][bucket] += 1
            self._gen += 1

    def log_request(self, fake: str, method: str, path: str, status: int,
                     size: int, content_type: str = ""):
        """Append one entry to the in-memory recent-requests ring buffer.

        Independent of the on-disk access_log (which is opt-in); this buffer
        is always maintained (bounded to _MAX_LOG_ENTRIES) so the sidecar
        dashboard can offer a live requests viewer with zero file I/O.
        """
        entry = {
            "ts":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "fake":     fake,
            "method":   method,
            "path":     path,
            "status":   status,
            "size":     size,
            "content_type": content_type,
        }
        with self._lock:
            self._recent.append(entry)

    def recent(self, limit: int = _MAX_LOG_ENTRIES) -> list:
        """Return up to *limit* most recent request entries, newest first."""
        with self._lock:
            items = list(self._recent)
        items.reverse()
        return items[:max(0, limit)]

    def error(self, fake: str):
        """Record a processing error for *fake* (shown in dashboard)."""
        with self._lock:
            entry = self._data.setdefault(fake, _blank_entry())
            entry["errors"] += 1
            self._gen += 1

    def snapshot(self) -> dict:
        """Return a deep copy of all counters safe to read outside the lock.
        Also includes ``_gen`` so callers can skip processing when nothing changed.
        """
        with self._lock:
            return {
                "_gen": self._gen,
                **{
                    k: {**v, "rewrite_by_type": dict(v["rewrite_by_type"])}
                    for k, v in self._data.items()
                }
            }

    def reset(self, fake: Optional[str] = None):
        """Reset counters for one alias (or all if *fake* is None)."""
        with self._lock:
            if fake:
                # Fix F: only bump _gen when the alias actually exists —
                # resetting a non-existent key caused a spurious dashboard refresh.
                if fake in self._data:
                    self._data[fake] = _blank_entry()
                    self._gen += 1
            else:
                for k in self._data:
                    self._data[k] = _blank_entry()
                self._gen += 1

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
                    for key in ("requests", "bytes_rewritten", "errors", "rewrites"):
                        existing[key] = entry.get(key, 0)
                    existing["last_seen"] = entry.get("last_seen", "—")
                    # Restore per-type counts if present (new in v1.6)
                    saved_rbt = entry.get("rewrite_by_type", {})
                    for t in _REWRITE_TYPES:
                        existing["rewrite_by_type"][t] = saved_rbt.get(t, 0)
            log.info(f"[STATS] loaded from {p}  (saved {raw.get('saved_at', '?')})")
        except Exception as exc:
            log.warning(f"[STATS] could not load {p}: {exc}")
