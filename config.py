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

# Current config schema version — bumped when breaking changes are made.
SCHEMA_VERSION = 1

DEFAULTS: dict = {
    "schema_version": SCHEMA_VERSION,
    "host":           "127.0.0.1",
    "port":           8080,
    "sidecar_port":   8081,
    "data_dir":       "evil_data",
    "cert_dir":       "certs",
    "verbose":        False,
    "access_log":     False,
    "aliases":        {},
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
    _warn_schema_version(cfg)

    # Merge top-level defaults so every key is present
    merged = dict(DEFAULTS)
    merged.update(cfg)
    # Deep-merge the rewrite sub-dict
    merged["rewrite"] = {**DEFAULTS["rewrite"], **cfg.get("rewrite", {})}
    return merged


def save_config(cfg: dict, path: Optional[str] = None):
    """Write cfg back to disk as pretty-printed JSON."""
    p = Path(path) if path else Path(__file__).parent / "config.json"
    # Always stamp the schema version on save.
    cfg.setdefault("schema_version", SCHEMA_VERSION)
    p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    log.info(f"[CFG] saved → {p}")


def _warn_schema_version(cfg: dict):
    """Warn if the config was written by a newer version of proxyevil."""
    file_ver = cfg.get("schema_version")
    if file_ver is None:
        return  # old config without version — silently accept
    if isinstance(file_ver, int) and file_ver > SCHEMA_VERSION:
        log.warning(
            f"[CFG] config schema_version={file_ver} is newer than this build "
            f"(schema_version={SCHEMA_VERSION}). Some options may be ignored."
        )


def _validate(cfg: dict):
    unknown_rw = set(cfg.get("rewrite", {}).keys()) - _REWRITE_KEYS
    if unknown_rw:
        log.warning(f"[CFG] unknown rewrite keys (typo?): {unknown_rw}")

    errors: list[str] = []

    # Port range validation
    for key in ("port", "sidecar_port"):
        val = cfg.get(key)
        if val is not None:
            if not isinstance(val, int) or not (1 <= val <= 65535):
                errors.append(f"  '{key}' must be an integer between 1 and 65535, got {val!r}")

    # max_body_bytes sanity check
    mbb = cfg.get("max_body_bytes")
    if mbb is not None:
        if not isinstance(mbb, int) or mbb < 1024:
            errors.append(f"  'max_body_bytes' must be an integer >= 1024, got {mbb!r}")

    aliases = cfg.get("aliases", {})
    for fake, val in aliases.items():
        if not isinstance(val, (str, dict)):
            errors.append(
                f"  alias '{fake}' has unexpected value type {type(val).__name__!r} "
                f"(expected a string or a dict with a 'real' key)"
            )
        elif isinstance(val, dict) and "real" not in val and val.get("enabled", True):
            errors.append(
                f"  alias '{fake}' is a dict but is missing the required 'real' key"
            )

    if errors:
        print("[ERROR] config.json has structural errors that would crash at runtime:")
        for e in errors:
            print(e)
        print("        Fix the above in config.json and try again.")
        sys.exit(1)

    port = cfg.get("port")
    sidecar = cfg.get("sidecar_port")
    if port is not None and sidecar is not None and port == sidecar:
        log.warning(
            f"[CFG] 'port' and 'sidecar_port' are the same ({port}) — this will cause a bind error"
        )
