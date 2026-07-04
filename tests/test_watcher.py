"""Tests for watcher.py — config hot-reload retry logic and file-watch wiring."""
import sys
import time
import json
import threading
import pytest

import watcher
from alias_map import AliasMap
from stats import Stats


# ── Normal ───────────────────────────────────────────────────────────────
def test_load_with_retry_success(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"aliases": {"a.local": "a.com"}}))
    cfg = watcher._load_with_retry(str(p))
    assert cfg["aliases"]["a.local"] == "a.com"


# ── Medium: bounded retries, no infinite loop ─────────────────────────────
def test_load_with_retry_gives_up_after_max_attempts(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({}))  # no aliases — never satisfies the early-return condition
    start = time.time()
    cfg = watcher._load_with_retry(str(p))
    elapsed = time.time() - start
    assert cfg == {**cfg}  # returned something, didn't hang
    assert elapsed < 2.0   # bounded by _READ_RETRIES * _READ_RETRY_WAIT


def test_load_with_retry_missing_file_uses_defaults(tmp_path):
    cfg = watcher._load_with_retry(str(tmp_path / "nope.json"))
    assert cfg["aliases"] == {}


# ── High: watchfiles missing ───────────────────────────────────────────────
def test_start_config_watcher_returns_none_without_watchfiles(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "watchfiles", None)  # forces ImportError on `from watchfiles import watch`
    am = AliasMap({})
    result = watcher.start_config_watcher(str(tmp_path / "config.json"), am, {})
    assert result is None


# ── High: hot-reload wiring with a mocked watchfiles.watch ────────────────
def test_hot_reload_updates_alias_map_and_notifies_addon(tmp_path, monkeypatch):
    import watchfiles

    p = tmp_path / "config.json"
    p.write_text(json.dumps({"aliases": {"new.local": "new.com"}}))

    def fake_watch(path, debounce=500):
        yield {("modified", str(p))}  # one change event, then generator ends

    monkeypatch.setattr(watchfiles, "watch", fake_watch)

    am = AliasMap({})
    live_cfg = {}
    st = Stats()

    class FakeAddon:
        def __init__(self):
            self.notified = False

        def notify_reload(self):
            self.notified = True

    addon = FakeAddon()
    t = watcher.start_config_watcher(str(p), am, live_cfg, stats=st, addon=addon)
    assert t is not None
    t.join(timeout=3)
    assert am.real_for("new.local") == "new.com"
    assert live_cfg.get("aliases", {}).get("new.local") == "new.com"
    assert addon.notified is True


# ── Critical: invalid config during hot-reload doesn't crash the watcher ──
def test_hot_reload_keeps_previous_config_on_invalid_edit(tmp_path, monkeypatch):
    import watchfiles

    p = tmp_path / "config.json"
    p.write_text(json.dumps({"aliases": {"good.local": "good.com"}}))

    def fake_watch(path, debounce=500):
        yield {("modified", str(p))}

    monkeypatch.setattr(watchfiles, "watch", fake_watch)
    monkeypatch.setattr(watcher, "_load_with_retry",
                         lambda path: (_ for _ in ()).throw(SystemExit(1)))

    am = AliasMap({"good.local": "good.com"})
    live_cfg = {"aliases": {"good.local": "good.com"}}
    t = watcher.start_config_watcher(str(p), am, live_cfg)
    t.join(timeout=3)
    # Previous mapping must be untouched — no crash, no partial reload.
    assert am.real_for("good.local") == "good.com"
