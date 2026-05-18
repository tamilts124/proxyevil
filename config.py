"""
config.py — Configuration loading, saving, and validation for proxyevil.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger("proxyevil.config")

_REWRITE_KEYS = {"html", "js", "css", "json", "headers", "cookies"}

DEFAULTS: dict = {
    "host":         "127.0.0.1",
    "port":         8080,
    "sidecar_port": 8081,
    "data_dir":     "evil_data",
    "cert_dir":     "certs",
    "verbose":      False,
    "aliases":      {},
    "rewrite": {
        "html":    True,
        "js":      True,
        "css":     True,
        "json":    True,
        "headers": True,
        "cookies": True,
    },
    "strip_headers": [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "X-XSS-Protection",
        "Report-To",
        "NEL",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Resource-Policy",
    ],
}


def load_config(path: Optional[str] = None) -> dict:
    """Load and validate config.json.  Merges defaults so callers always get
    a fully-populated dict even for missing/partial files."""
    p = Path(path) if path else Path(__file__).parent / "config.json"
    if not p.exists():
        log.debug(f"[CFG] {p} not found — using defaults")
        return dict(DEFAULTS)

    raw = p.read_text(encoding="utf-8")
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"[ERROR] config.json has a JSON syntax error: {exc}")
        print(f"        at line {exc.lineno}, column {exc.colno}: {exc.msg}")
        sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] failed to read {p}: {exc}")
        sys.exit(1)

    log.info(f"[CFG] loaded → {p}")
    _validate(cfg)

    # Merge top-level defaults so every key is present
    merged = dict(DEFAULTS)
    merged.update(cfg)
    # Deep-merge the rewrite sub-dict
    merged["rewrite"] = {**DEFAULTS["rewrite"], **cfg.get("rewrite", {})}
    return merged


def save_config(cfg: dict, path: Optional[str] = None):
    """Write cfg back to disk as pretty-printed JSON."""
    p = Path(path) if path else Path(__file__).parent / "config.json"
    p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    log.info(f"[CFG] saved → {p}")


def _validate(cfg: dict):
    unknown_rw = set(cfg.get("rewrite", {}).keys()) - _REWRITE_KEYS
    if unknown_rw:
        log.warning(f"[CFG] unknown rewrite keys (typo?): {unknown_rw}")

    errors: list[str] = []
    aliases = cfg.get("aliases", {})
    for fake, val in aliases.items():
        if not isinstance(val, (str, dict)):
            errors.append(
                f"  alias '{fake}' has unexpected value type {type(val).__name__!r} "
                f"(expected a string or a dict with a 'real' key)"
            )
        elif isinstance(val, dict) and "real" not in val and val.get("enabled", True):
            # Only require 'real' when the alias is not explicitly disabled
            errors.append(
                f"  alias '{fake}' is a dict but is missing the required 'real' key"
            )

    if errors:
        print("[ERROR] config.json has structural errors that would crash at runtime:")
        for e in errors:
            print(e)
        print("        Fix the above aliases in config.json and try again.")
        sys.exit(1)

    port = cfg.get("port")
    sidecar = cfg.get("sidecar_port")
    if port is not None and sidecar is not None and port == sidecar:
        log.warning(f"[CFG] 'port' and 'sidecar_port' are the same ({port}) — this will cause a bind error")
