"""
watcher.py — inotify-backed config hot-reload (requires watchfiles).

Falls back gracefully if watchfiles is not installed.
"""

import logging
import threading
from typing import Optional

from alias_map import AliasMap
from config    import load_config
from stats     import Stats

log = logging.getLogger("proxyevil.watcher")


def start_config_watcher(
    config_path: str,
    alias_map:   AliasMap,
    live_cfg:    dict,
    stats:       Optional[Stats] = None,
) -> Optional[threading.Thread]:
    """Watch *config_path* and hot-reload aliases + rewrite config on change.

    Updates *live_cfg* in-place so that ``DomainAliasAddon.rw`` and
    ``.strip_hdrs`` (properties reading from the live dict) pick up new values
    without restarting the addon.

    If *stats* is provided, ``stats.init()`` is called after each reload so
    newly-added aliases appear in the dashboard immediately.

    Returns the watcher thread (daemon) or None if watchfiles is not installed.
    """
    try:
        from watchfiles import watch  # type: ignore
    except ImportError:
        log.info("[WATCH] watchfiles not installed — install with 'pip install watchfiles' for hot-reload")
        return None

    def _watch():
        # debounce_ms=500 collapses rapid double-fire events (Windows/some editors)
        # and avoids reading a partially-written file on the first event.
        for _ in watch(config_path, debounce=500):
            try:
                new_cfg     = load_config(config_path)
                new_aliases = new_cfg.get("aliases", {})
                alias_map.reload(new_aliases)
                # Replace live cfg atomically: build replacement first, then swap.
                merged = dict(new_cfg)
                live_cfg.clear()
                live_cfg.update(merged)
                if stats is not None:
                    stats.init(alias_map.stats_keys)
                log.info(f"[WATCH] config reloaded — {len(new_aliases)} aliases")
            except SystemExit:
                # load_config / _validate calls sys.exit(1) on bad config.
                # Catch it here so a bad edit doesn't kill the entire proxy.
                log.warning("[WATCH] bad config after edit — keeping previous config")
            except Exception as exc:
                log.warning(f"[WATCH] reload failed: {exc}")

    t = threading.Thread(target=_watch, daemon=True, name="config-watcher")
    t.start()
    log.info(f"[WATCH] watching {config_path}")
    return t
