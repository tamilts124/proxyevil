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
    # Token required on mutating sidecar endpoints (POST /reload, POST /alias,
    # DELETE /alias, POST /reset, POST /stats/save).  Empty string disables
    # the check — safe for local-only setups that bind to 127.0.0.1.
    # Set to a random string to protect against cross-process exploitation.
    "sidecar_token":  "",
    # Auto-install mitmproxy CA into the Windows Trusted Root Store on first
    # run.  Disabled by default — installing a root CA is a significant
    # security action that should be an explicit opt-in.  Run --setup and
    # `mkcert -install` instead, or set this to true for fully automated
    # environments where you understand the implications.
    "auto_install_ca": False,
    "SPOOF_ALL_DOMAINS": False,
    "SPOOFING_EXCLUDE_LIST": [],
    # Hostnames to block outright (403) instead of proxying. Supports exact
    # matches ("ads.example.com") or "*.example.com" wildcard subdomain matches.
    "blacklist": [],
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


def _migrate_v0_to_v1(cfg: dict) -> dict:
    """Legacy (unversioned) configs → v1: just stamp the version. All v0
    field renames (SPOOF_ALL_UNMAPPED_DOMAINS, extra_real, etc.) are already
    handled generically as back-compat aliases in load_config(), so there is
    nothing else to transform here — this exists as the template for future
    migrations and to make the version bump explicit/logged.
    """
    cfg["schema_version"] = 1
    return cfg


# Registry of migration functions keyed by the *source* version they migrate
# FROM. Add a new entry here (and bump SCHEMA_VERSION) whenever a breaking
# config change ships, e.g. `2: _migrate_v1_to_v2`.
_MIGRATIONS = {
    0: _migrate_v0_to_v1,
}


def _migrate_config(cfg: dict) -> dict:
    """Apply migrations in sequence until cfg reaches SCHEMA_VERSION.

    Configs with no 'schema_version' key are treated as version 0 (pre-dates
    versioning). If no migration is registered for the current version, the
    config is left as-is with a warning rather than crashing — the newer
    fields it's missing will just fall back to DEFAULTS.
    """
    ver = cfg.get("schema_version", 0)
    if not isinstance(ver, int):
        ver = 0
    seen = set()
    while ver < SCHEMA_VERSION:
        if ver in seen:  # pragma: no cover - defensive, prevents infinite loop
            log.warning(f"[CFG] migration cycle detected at schema_version={ver} — aborting migration")
            break
        seen.add(ver)
        migrate_fn = _MIGRATIONS.get(ver)
        if migrate_fn is None:
            log.warning(
                f"[CFG] no migration path from schema_version={ver} to {SCHEMA_VERSION} — leaving config as-is"
            )
            break
        log.info(f"[CFG] migrating config schema_version {ver} → {ver + 1}")
        cfg = migrate_fn(cfg)
        new_ver = cfg.get("schema_version", ver + 1)
        ver = new_ver if isinstance(new_ver, int) else ver + 1
    return cfg


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
    cfg = _migrate_config(cfg)
    _warn_schema_version(cfg)

    # Merge top-level defaults so every key is present
    merged = dict(DEFAULTS)
    merged.update(cfg)
    # Deep-merge the rewrite sub-dict
    merged["rewrite"] = {**DEFAULTS["rewrite"], **cfg.get("rewrite", {})}

    # Fix #14 / #22: normalize SCREAMING_SNAKE keys BEFORE validation so
    # _validate always sees canonical key names.
    # Accepts legacy "SPOOF_ALL_UNMAPPED_DOMAINS" as alias for "SPOOF_ALL_DOMAINS".
    if merged.get("SPOOF_ALL_UNMAPPED_DOMAINS") and not merged.get("SPOOF_ALL_DOMAINS"):
        merged["SPOOF_ALL_DOMAINS"] = bool(merged["SPOOF_ALL_UNMAPPED_DOMAINS"])
    # Normalize per-alias keys too
    for fake, val in merged.get("aliases", {}).items():
        if isinstance(val, dict):
            if "SPOOF_ALL_UNMAPPED_DOMAINS" in val and "SPOOF_ALL_DOMAINS" not in val:
                val["SPOOF_ALL_DOMAINS"] = bool(val["SPOOF_ALL_UNMAPPED_DOMAINS"])
            if "extra_real" in val and "EXTRA_REAL_DOMAINS_TO_SPOOF" not in val:
                val["EXTRA_REAL_DOMAINS_TO_SPOOF"] = val["extra_real"]

    _validate(merged)
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

    # sidecar_token validation
    token = cfg.get("sidecar_token")
    if token is not None and not isinstance(token, str):
        errors.append(f"  'sidecar_token' must be a string (or omitted), got {token!r}")

    # auto_install_ca validation
    aic = cfg.get("auto_install_ca")
    if aic is not None and not isinstance(aic, bool):
        errors.append(f"  'auto_install_ca' must be a boolean, got {aic!r}")

    # SPOOF_ALL_DOMAINS validation (global)
    sad = cfg.get("SPOOF_ALL_DOMAINS")
    if sad is not None and not isinstance(sad, bool):
        errors.append(f"  'SPOOF_ALL_DOMAINS' must be a boolean, got {sad!r}")

    # SPOOFING_EXCLUDE_LIST validation
    sel = cfg.get("SPOOFING_EXCLUDE_LIST")
    if sel is not None:
        if not isinstance(sel, list):
            errors.append(f"  'SPOOFING_EXCLUDE_LIST' must be a list of strings, got {sel!r}")
        elif not all(isinstance(x, str) for x in sel):
            errors.append(f"  'SPOOFING_EXCLUDE_LIST' must only contain strings, got {sel!r}")

    # blacklist validation
    bl = cfg.get("blacklist")
    if bl is not None:
        if not isinstance(bl, list):
            errors.append(f"  'blacklist' must be a list of strings, got {bl!r}")
        elif not all(isinstance(x, str) for x in bl):
            errors.append(f"  'blacklist' must only contain strings, got {bl!r}")

    aliases = cfg.get("aliases", {})
    for fake, val in aliases.items():
        if not isinstance(val, (str, dict)):
            errors.append(
                f"  alias '{fake}' has unexpected value type {type(val).__name__!r} "
                f"(expected a string or a dict with a 'real' key)"
            )
        elif isinstance(val, dict):
            if "real" not in val and val.get("enabled", True):
                errors.append(
                    f"  alias '{fake}' is a dict but is missing the required 'real' key"
                )
            # Check EXTRA_REAL_DOMAINS_TO_SPOOF (or legacy extra_real)
            extra_key = "EXTRA_REAL_DOMAINS_TO_SPOOF" if "EXTRA_REAL_DOMAINS_TO_SPOOF" in val else "extra_real"
            extra_val = val.get(extra_key)
            if extra_val is not None:
                if not isinstance(extra_val, list):
                    errors.append(f"  alias '{fake}' key '{extra_key}' must be a list of domains, got {extra_val!r}")
                elif not all(isinstance(x, str) for x in extra_val):
                    errors.append(f"  alias '{fake}' key '{extra_key}' must only contain strings, got {extra_val!r}")
            # Check SPOOF_ALL_DOMAINS (per-alias) — canonical key only after normalization
            # Fix I: SPOOF_ALL_UNMAPPED_DOMAINS fallback removed; config.py normalises it
            # to SPOOF_ALL_DOMAINS before _validate runs, so the legacy key is never seen.
            sad_alias = val.get("SPOOF_ALL_DOMAINS")
            if sad_alias is not None and not isinstance(sad_alias, bool):
                errors.append(f"  alias '{fake}' key 'SPOOF_ALL_DOMAINS' must be a boolean, got {sad_alias!r}")
            # Check SPOOFING_EXCLUDE_LIST (per-alias)
            sel_alias = val.get("SPOOFING_EXCLUDE_LIST")
            if sel_alias is not None:
                if not isinstance(sel_alias, list):
                    errors.append(f"  alias '{fake}' key 'SPOOFING_EXCLUDE_LIST' must be a list of strings, got {sel_alias!r}")
                elif not all(isinstance(x, str) for x in sel_alias):
                    errors.append(f"  alias '{fake}' key 'SPOOFING_EXCLUDE_LIST' must only contain strings, got {sel_alias!r}")

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
