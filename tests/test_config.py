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
