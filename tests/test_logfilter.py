"""Tests for logfilter.install_log_filters / _MitmNoiseFilter."""
import logging

import pytest
from alias_map import AliasMap
from logfilter import install_log_filters, _MitmNoiseFilter, _MITM_LOGGERS


def _record(name, level, msg):
    return logging.LogRecord(name, level, "test", 0, msg, None, None)


@pytest.fixture(autouse=True)
def _clean_filters():
    """Ensure no _MitmNoiseFilter leaks between tests."""
    yield
    for name in (*_MITM_LOGGERS, ""):
        lgr = logging.getLogger(name)
        lgr.filters = [f for f in lgr.filters if not isinstance(f, _MitmNoiseFilter)]


# ── Normal ───────────────────────────────────────────────────────────────
def test_install_attaches_filter_to_all_channels():
    aliases = AliasMap({"mybook.local": "www.facebook.com"})
    install_log_filters(aliases, verbose=False)
    for name in _MITM_LOGGERS:
        lgr = logging.getLogger(name)
        assert any(isinstance(f, _MitmNoiseFilter) for f in lgr.filters)
    assert any(isinstance(f, _MitmNoiseFilter) for f in logging.getLogger().filters)


def test_lifecycle_chatter_suppressed_for_non_alias_domain():
    f = _MitmNoiseFilter({"mybook.local"}, verbose=False)
    rec = _record("mitmproxy.proxy.server", logging.INFO, "server connect unrelated.com:443")
    assert f.filter(rec) is False


def test_lifecycle_kept_for_alias_domain():
    f = _MitmNoiseFilter({"mybook.local"}, verbose=False)
    rec = _record("mitmproxy.proxy.server", logging.INFO, "server connect mybook.local:443")
    assert f.filter(rec) is True


# ── Medium: boundary ─────────────────────────────────────────────────────
def test_verbose_disables_lifecycle_suppression():
    f = _MitmNoiseFilter(set(), verbose=True)
    rec = _record("mitmproxy.proxy.server", logging.INFO, "client disconnect anything.com")
    assert f.filter(rec) is True


def test_empty_alias_set_still_suppresses_noise():
    f = _MitmNoiseFilter(set(), verbose=False)
    rec = _record("mitmproxy.proxy.server", logging.INFO, "server disconnect x.com:443")
    assert f.filter(rec) is False


def test_unrelated_message_passes_through():
    f = _MitmNoiseFilter({"mybook.local"}, verbose=False)
    rec = _record("proxyevil.addon", logging.INFO, "startup complete")
    assert f.filter(rec) is True


# ── High: downgraded/suppressed error classes ─────────────────────────────
def test_winerror_10054_downgraded_to_debug():
    f = _MitmNoiseFilter(set(), verbose=False)
    rec = _record("asyncio", logging.ERROR, "Unhandled error in task: WinError 10054")
    kept = f.filter(rec)
    assert kept is True
    assert rec.levelno == logging.DEBUG
    assert rec.levelname == "DEBUG"


def test_tls_handshake_failure_suppressed_by_default():
    f = _MitmNoiseFilter({"mybook.local"}, verbose=False)
    rec = _record("mitmproxy.proxy.layers.tls", logging.WARNING,
                   "Client TLS handshake failed for unrelated.com")
    assert f.filter(rec) is False


def test_tls_handshake_kept_when_alias_domain_mentioned():
    f = _MitmNoiseFilter({"mybook.local"}, verbose=False)
    rec = _record("mitmproxy.proxy.layers.tls", logging.WARNING,
                   "Client TLS handshake failed for mybook.local")
    assert f.filter(rec) is True


def test_connection_refused_suppressed_unless_verbose():
    f = _MitmNoiseFilter(set(), verbose=False)
    rec = _record("mitmproxy.proxy.server", logging.INFO,
                   "error establishing server connection: [WinError 1225]")
    assert f.filter(rec) is False

    f_verbose = _MitmNoiseFilter(set(), verbose=True)
    rec2 = _record("mitmproxy.proxy.server", logging.INFO,
                    "error establishing server connection: [WinError 1225]")
    assert f_verbose.filter(rec2) is True
    assert rec2.levelno == logging.DEBUG


# ── Critical/idempotency: repeated install doesn't stack filters ─────────
def test_repeated_install_is_idempotent():
    aliases = AliasMap({"mybook.local": "www.facebook.com"})
    install_log_filters(aliases, verbose=False)
    install_log_filters(aliases, verbose=True)
    for name in _MITM_LOGGERS:
        lgr = logging.getLogger(name)
        noise_filters = [f for f in lgr.filters if isinstance(f, _MitmNoiseFilter)]
        assert len(noise_filters) == 1
        assert noise_filters[0].verbose is True
