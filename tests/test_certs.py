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


# ── Renewal: expiry parsing & threshold logic ─────────────────────────────
def _make_cert(tmp_path, name, days_until_expiry):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta, timezone

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_until_expiry))
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / f"{name}.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_file


def test_needs_renewal_false_for_far_expiry(tmp_path):
    cert_file = _make_cert(tmp_path, "fresh.local", 90)
    assert certs.needs_renewal(cert_file, days_threshold=14) is False


def test_needs_renewal_true_for_near_expiry(tmp_path):
    cert_file = _make_cert(tmp_path, "stale.local", 5)
    assert certs.needs_renewal(cert_file, days_threshold=14) is True


def test_needs_renewal_true_for_missing_file(tmp_path):
    assert certs.needs_renewal(tmp_path / "nope.pem", days_threshold=14) is True


def test_cert_expiry_unparseable_returns_none(tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_bytes(b"not a cert")
    assert certs.cert_expiry(bad) is None


def test_check_and_renew_renews_expiring_cert(tmp_path, monkeypatch):
    name = "renewme.local"
    _make_cert(tmp_path, name, 3)
    (tmp_path / f"{name}-key.pem").write_bytes(b"KEY")
    monkeypatch.setattr(certs.shutil, "which", lambda n: "/usr/bin/mkcert")
    monkeypatch.setattr(certs.subprocess, "run", lambda *a, **k: _ok())
    renewed = certs.check_and_renew({name: "real.com"}, str(tmp_path), days_threshold=14)
    assert renewed == [name]


def test_check_and_renew_skips_fresh_cert(tmp_path, monkeypatch):
    name = "fresh2.local"
    _make_cert(tmp_path, name, 90)
    (tmp_path / f"{name}-key.pem").write_bytes(b"KEY")
    monkeypatch.setattr(certs.shutil, "which", lambda n: "/usr/bin/mkcert")
    calls = []
    monkeypatch.setattr(certs.subprocess, "run", lambda *a, **k: calls.append(1) or _ok())
    renewed = certs.check_and_renew({name: "real.com"}, str(tmp_path), days_threshold=14)
    assert renewed == []
    assert not calls


def test_check_and_renew_no_mkcert_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(certs.shutil, "which", lambda n: None)
    assert certs.check_and_renew({"x.local": "x.com"}, str(tmp_path)) == []
