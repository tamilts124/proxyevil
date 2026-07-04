"""Tests for certs.py — mkcert invocation safety, path traversal, missing binary."""
import subprocess
import pytest
import certs


# ── Normal ───────────────────────────────────────────────────────────────
def test_collect_certs_finds_valid_pair(tmp_path):
    fake = "mybook.local"
    (tmp_path / f"{fake}.pem").write_bytes(b"CERT")
    (tmp_path / f"{fake}-key.pem").write_bytes(b"KEY")
    pairs = certs.collect_certs({fake: "www.facebook.com"}, str(tmp_path))
    assert pairs and pairs[0][0] == fake


def test_list_certs_missing_dir(tmp_path, capsys):
    certs.list_certs(str(tmp_path / "nope"))
    assert "does not exist" in capsys.readouterr().out


# ── High: missing mkcert binary ───────────────────────────────────────────
def test_setup_certs_missing_mkcert_exits(tmp_path, monkeypatch):
    monkeypatch.setattr(certs.shutil, "which", lambda name: None)
    with pytest.raises(SystemExit):
        certs.setup_certs({"a.local": "a.com"}, str(tmp_path))


def test_setup_certs_mkcert_failure_handled(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(certs.shutil, "which", lambda name: "/usr/bin/mkcert")

    class FakeResult:
        returncode = 1
        stderr = "mkcert exploded"

    monkeypatch.setattr(certs.subprocess, "run", lambda *a, **k: FakeResult())
    certs.setup_certs({"a.local": "a.com"}, str(tmp_path))  # must not raise
    assert "FAILED" in capsys.readouterr().out


# ── Critical: directory traversal / injection safety ──────────────────────
def test_directory_traversal_domain_rejected(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(certs.shutil, "which", lambda name: "/usr/bin/mkcert")
    calls = []
    monkeypatch.setattr(certs.subprocess, "run", lambda *a, **k: calls.append(a) or _ok())
    evil = "../../evil"
    certs.setup_certs({evil: "real.com"}, str(tmp_path))
    assert "SKIPPING unsafe" in capsys.readouterr().out
    assert not calls  # mkcert must never be invoked for the unsafe name
    assert not (tmp_path.parent.parent / "evil.pem").exists()


def test_collect_certs_skips_traversal_domain(tmp_path):
    evil = "../../evil"
    # Even if a stray file exists one level up, collect_certs must not find it
    # via the unsanitized path — validate() rejects it before any Path lookup.
    pairs = certs.collect_certs({evil: "real.com"}, str(tmp_path))
    assert pairs == []


def test_mkcert_invoked_with_arg_list_not_shell(tmp_path, monkeypatch):
    """Verify mkcert is invoked as an argument list (no shell=True), which is
    what prevents shell-metacharacter injection via a crafted domain name."""
    monkeypatch.setattr(certs.shutil, "which", lambda name: "/usr/bin/mkcert")
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _ok()

    monkeypatch.setattr(certs.subprocess, "run", fake_run)
    certs.setup_certs({"safe.local": "safe.com"}, str(tmp_path))
    assert isinstance(captured["args"], list)
    assert captured["kwargs"].get("shell", False) is False


def _ok():
    class R:
        returncode = 0
        stderr = ""
    return R()
