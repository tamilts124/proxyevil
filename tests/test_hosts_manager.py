"""Tests for hosts_manager.py — privilege checks, atomic writes, debounce."""
import time
import pytest
import hosts_manager as hm


# ── Normal ───────────────────────────────────────────────────────────────
def test_get_hosts_path_returns_string():
    assert isinstance(hm.get_hosts_path(), str)


def test_write_hosts_now_builds_managed_block(tmp_path, monkeypatch):
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n")
    monkeypatch.setattr(hm, "get_hosts_path", lambda: str(hosts_file))
    hm._write_hosts_now({"mybook.local": "www.facebook.com"})
    content = hosts_file.read_text()
    assert "# --- proxyevil start ---" in content
    assert "127.0.0.1\tmybook.local" in content


def test_write_hosts_now_replaces_old_block(tmp_path, monkeypatch):
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text(
        "127.0.0.1 localhost\n"
        "# --- proxyevil start ---\n"
        "127.0.0.1\told.local\n"
        "# --- proxyevil end ---\n"
    )
    monkeypatch.setattr(hm, "get_hosts_path", lambda: str(hosts_file))
    hm._write_hosts_now({"new.local": "x.com"})
    content = hosts_file.read_text()
    assert "old.local" not in content
    assert "new.local" in content


# ── Medium: no-op / idempotency ───────────────────────────────────────────
def test_write_hosts_now_noop_when_unchanged(tmp_path, monkeypatch):
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text(
        "# --- proxyevil start ---\n127.0.0.1\ta.local\n# --- proxyevil end ---\n"
    )
    before = hosts_file.stat().st_mtime_ns
    monkeypatch.setattr(hm, "get_hosts_path", lambda: str(hosts_file))
    hm._write_hosts_now({"a.local": "a.com"})
    assert hosts_file.stat().st_mtime_ns == before  # untouched, no rewrite


# ── High: missing privileges / unreadable file ────────────────────────────
def test_update_hosts_file_skips_without_admin(monkeypatch):
    monkeypatch.setattr(hm, "is_admin", lambda: False)
    called = []
    monkeypatch.setattr(hm, "_write_hosts_now", lambda aliases: called.append(aliases))
    hm.update_hosts_file({"a.local": "a.com"})
    time.sleep(hm._DEBOUNCE_SECS + 0.3)
    assert called == []  # never reached the writer


def test_write_hosts_now_handles_unreadable_file(tmp_path, monkeypatch, caplog):
    missing = tmp_path / "does_not_exist" / "hosts"
    monkeypatch.setattr(hm, "get_hosts_path", lambda: str(missing))
    hm._write_hosts_now({"a.local": "a.com"})  # must not raise
