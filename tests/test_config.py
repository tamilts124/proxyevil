"""Tests for config.py — schema validation, defaults, edge cases."""
import json
import pytest
import config as config_mod


def test_load_missing_file_returns_defaults(tmp_path):
    cfg = config_mod.load_config(str(tmp_path / "nope.json"))
    assert cfg["port"] == 8080
    assert cfg["aliases"] == {}


def test_load_merges_partial_config(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"port": 9999}))
    cfg = config_mod.load_config(str(p))
    assert cfg["port"] == 9999
    assert cfg["sidecar_port"] == 8081  # default preserved


def test_save_and_reload_roundtrip(tmp_path):
    p = tmp_path / "config.json"
    config_mod.save_config({"port": 1234, "aliases": {"a.local": "a.com"}}, str(p))
    cfg = config_mod.load_config(str(p))
    assert cfg["port"] == 1234
    assert cfg["aliases"]["a.local"] == "a.com"


def test_invalid_json_exits(tmp_path):
    p = tmp_path / "config.json"
    p.write_text("{ not valid json")
    with pytest.raises(SystemExit):
        config_mod.load_config(str(p))


def test_invalid_port_exits(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"port": 70000}))
    with pytest.raises(SystemExit):
        config_mod.load_config(str(p))


def test_invalid_max_body_bytes_exits(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"max_body_bytes": 10}))
    with pytest.raises(SystemExit):
        config_mod.load_config(str(p))


def test_alias_missing_real_key_exits(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"aliases": {"bad.local": {"extra_real": ["x.com"]}}}))
    with pytest.raises(SystemExit):
        config_mod.load_config(str(p))


def test_alias_bad_type_exits(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"aliases": {"bad.local": 12345}}))
    with pytest.raises(SystemExit):
        config_mod.load_config(str(p))


def test_blacklist_default_empty(tmp_path):
    cfg = config_mod.load_config(str(tmp_path / "nope.json"))
    assert cfg["blacklist"] == []


def test_blacklist_valid_list_accepted(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"blacklist": ["ads.example.com", "*.tracker.com"]}))
    cfg = config_mod.load_config(str(p))
    assert cfg["blacklist"] == ["ads.example.com", "*.tracker.com"]


def test_blacklist_non_list_exits(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"blacklist": "not-a-list"}))
    with pytest.raises(SystemExit):
        config_mod.load_config(str(p))


def test_blacklist_non_string_items_exits(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"blacklist": ["ok.com", 123]}))
    with pytest.raises(SystemExit):
        config_mod.load_config(str(p))


def test_legacy_spoof_key_normalized(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"SPOOF_ALL_UNMAPPED_DOMAINS": True}))
    cfg = config_mod.load_config(str(p))
    assert cfg["SPOOF_ALL_DOMAINS"] is True


def test_legacy_extra_real_normalized(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"aliases": {"a.local": {"real": "a.com", "extra_real": ["cdn.a.com"]}}}))
    cfg = config_mod.load_config(str(p))
    assert cfg["aliases"]["a.local"]["EXTRA_REAL_DOMAINS_TO_SPOOF"] == ["cdn.a.com"]


# ── Schema versioning / migration ───────────────────────────────────
def test_migrate_legacy_config_no_version_key(tmp_path):
    """A config predating schema_version (v0) must be migrated to current."""
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"port": 8080, "aliases": {}}))
    cfg = config_mod.load_config(str(p))
    assert cfg["schema_version"] == config_mod.SCHEMA_VERSION


def test_migrate_explicit_v0(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"schema_version": 0, "port": 8080, "aliases": {}}))
    cfg = config_mod.load_config(str(p))
    assert cfg["schema_version"] == config_mod.SCHEMA_VERSION


def test_current_version_config_untouched(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"schema_version": config_mod.SCHEMA_VERSION, "aliases": {}}))
    cfg = config_mod.load_config(str(p))
    assert cfg["schema_version"] == config_mod.SCHEMA_VERSION


def test_migrate_config_unit_no_path_registered(monkeypatch):
    """If no migration exists for an old version, _migrate_config must not
    crash — it logs a warning and leaves the config as-is."""
    monkeypatch.setattr(config_mod, "_MIGRATIONS", {})
    monkeypatch.setattr(config_mod, "SCHEMA_VERSION", 5)
    cfg = config_mod._migrate_config({"schema_version": 2})
    assert cfg["schema_version"] == 2  # left untouched, no migration path


def test_migrate_config_applies_chain(monkeypatch):
    """Simulate a future multi-step migration chain to verify the loop applies
    all steps in order rather than just the first."""
    def _v1_to_v2(c):
        c["schema_version"] = 2
        c["migrated_v1"] = True
        return c

    def _v2_to_v3(c):
        c["schema_version"] = 3
        c["migrated_v2"] = True
        return c

    monkeypatch.setattr(config_mod, "SCHEMA_VERSION", 3)
    monkeypatch.setattr(config_mod, "_MIGRATIONS", {1: _v1_to_v2, 2: _v2_to_v3})
    cfg = config_mod._migrate_config({"schema_version": 1})
    assert cfg["schema_version"] == 3
    assert cfg["migrated_v1"] is True
    assert cfg["migrated_v2"] is True


def test_migrate_config_no_infinite_loop_on_cycle(monkeypatch):
    """A misconfigured migration that doesn't advance schema_version must not
    hang the loader (cycle-detection safety net)."""
    def _noop(c):
        return c  # forgets to bump schema_version -- pathological case

    monkeypatch.setattr(config_mod, "SCHEMA_VERSION", 5)
    monkeypatch.setattr(config_mod, "_MIGRATIONS", {0: _noop})
    cfg = config_mod._migrate_config({"schema_version": 0})
    assert cfg["schema_version"] == 0  # unchanged, loop aborted safely
