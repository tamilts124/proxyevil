"""
watcher.py — inotify-backed config hot-reload (requires watchfiles).

Falls back gracefully if watchfiles is not installed.
"""

import logging
import threading
import time
from typing import Optional

from alias_map import AliasMap
from certs     import check_and_renew
from config    import load_config
from hosts_manager import update_hosts_file
from logfilter import install_log_filters
from stats     import Stats

log = logging.getLogger("proxyevil.watcher")

_READ_RETRIES    = 3
_READ_RETRY_WAIT = 0.15


def _load_with_retry(config_path: str) -> dict:
    """Load config, retrying a few times if the file is empty or aliases are missing."""
    last_exc: Exception | None = None
    for attempt in range(_READ_RETRIES):
        try:
            cfg = load_config(config_path)
            if cfg.get("aliases") or attempt == _READ_RETRIES - 1:
                return cfg
            log.debug(f"[WATCH] config has no aliases on attempt {attempt + 1} — retrying")
        except SystemExit:
            raise
        except Exception as exc:
            last_exc = exc
            log.debug(f"[WATCH] config read failed on attempt {attempt + 1}: {exc}")
        time.sleep(_READ_RETRY_WAIT)
    if last_exc is not None:
        raise last_exc
    return load_config(config_path)


def start_config_watcher(
    config_path: str,
    alias_map:   AliasMap,
    live_cfg:    dict,
    stats:       Optional[Stats] = None,
    addon:       object          = None,
    verbose:     bool            = False,
    cert_dir:    Optional[str]   = None,
    renew_interval_s: float      = 86400.0,
    renew_days_threshold: int    = 14,
) -> Optional[threading.Thread]:
    """Watch *config_path* and hot-reload aliases + rewrite config on change.

    If *cert_dir* is given, also starts a background thread that periodically
    (every *renew_interval_s* seconds) checks alias certs for upcoming expiry
    and renews them via mkcert (see certs.check_and_renew).
    """
    try:
        from watchfiles import watch  # type: ignore
    except ImportError:
        log.info("[WATCH] watchfiles not installed — install with 'pip install watchfiles' for hot-reload")
        return None

    def _watch():
        for _ in watch(config_path, debounce=500):
            try:
                new_cfg     = _load_with_retry(config_path)
                new_aliases = new_cfg.get("aliases", {})
                alias_map.reload(new_aliases)

                # Atomically replace live_cfg: clear first, then repopulate.
                # Under CPython's GIL both operations are individually atomic;
                # doing clear+update back-to-back means no concurrent reader
                # ever sees a partially-merged dict (the window where both old
                # and new keys coexist that the previous update()+del-loop had).
                merged = dict(new_cfg)
                live_cfg.clear()
                live_cfg.update(merged)

                if stats is not None:
                    stats.init(alias_map.stats_keys)

                root_aliases = {
                    k: v if isinstance(v, str) else v.get("real", "")
                    for k, v in new_aliases.items()
                }
                update_hosts_file(root_aliases)

                # Fix #7/#16: both stats and addon are optional, guarded independently.
                # Fix #16: refresh log filters so new/removed aliases are reflected immediately.
                install_log_filters(alias_map, verbose=verbose)

                # notify_reload called AFTER stats.init so addon sees fresh counters.
                if addon is not None and hasattr(addon, "notify_reload"):
                    addon.notify_reload()
                log.info(f"[WATCH] config reloaded — {len(new_aliases)} aliases")
            except SystemExit:
                log.warning("[WATCH] bad config edit — validation failed, keeping previous config")
            except Exception as exc:
                log.warning(f"[WATCH] reload failed: {exc}")

    t = threading.Thread(target=_watch, daemon=True, name="config-watcher")
    t.start()
    log.info(f"[WATCH] watching {config_path}")

    if cert_dir:
        def _renew_loop():
            while True:
                time.sleep(renew_interval_s)
                try:
                    aliases = live_cfg.get("aliases", {})
                    root_aliases = {
                        k: v if isinstance(v, str) else v.get("real", "")
                        for k, v in aliases.items()
                    }
                    renewed = check_and_renew(root_aliases, cert_dir, renew_days_threshold)
                    if renewed:
                        log.info(f"[WATCH] auto-renewed certs: {', '.join(renewed)}")
                except Exception as exc:
                    log.warning(f"[WATCH] cert renewal check failed: {exc}")

        rt = threading.Thread(target=_renew_loop, daemon=True, name="cert-renewer")
        rt.start()

    return t
