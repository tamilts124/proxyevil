"""Tests for sidecar.py — real HTTPServer on an ephemeral port, hit with urllib.
Covers endpoints, token auth, and Origin validation on mutating routes.
"""
import json
import threading
import urllib.request
import urllib.error
import pytest

from alias_map import AliasMap
from stats import Stats
import sidecar


def _start(cfg, port=0):
    am = AliasMap(cfg.get("aliases", {}))
    st = Stats()
    st.init(am.stats_keys)
    srv = sidecar.start_sidecar(am, st, "evil_data_test/stats.json",
                                 "127.0.0.1", 8080, port, cfg, config_path="")
    actual_port = srv.server_address[1]
    return srv, am, st, actual_port


def _get(port, path, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _post(port, path, body=b"", headers=None, method="POST"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body,
                                  headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


@pytest.fixture(scope="module")
def server():
    cfg = {"aliases": {"mybook.local": "www.facebook.com"}, "sidecar_token": ""}
    srv, am, st, port = _start(cfg)
    yield srv, am, st, port
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def server_with_token():
    cfg = {"aliases": {"mybook.local": "www.facebook.com"}, "sidecar_token": "secret123"}
    srv, am, st, port = _start(cfg)
    yield srv, am, st, port
    srv.shutdown()
    srv.server_close()


# ── Normal ───────────────────────────────────────────────────────────────
def test_health_endpoint(server):
    _, _, _, port = server
    status, body = _get(port, "/health")
    assert status == 200
    assert json.loads(body)["status"] == "ok"


def test_stats_json_endpoint(server):
    _, _, st, port = server
    st.hit("mybook.local", 5, "html")
    status, body = _get(port, "/stats.json")
    data = json.loads(body)
    assert data["aliases"]["mybook.local"]["requests"] == 1


def test_stats_json_includes_alias_cache_metrics(server):
    _, am, _, port = server
    am.fake_for("www.facebook.com")
    status, body = _get(port, "/stats.json")
    data = json.loads(body)
    assert "alias_cache" in data
    assert "hits" in data["alias_cache"] and "misses" in data["alias_cache"]


def test_hosts_endpoint_contains_alias(server):
    _, _, _, port = server
    status, body = _get(port, "/hosts")
    assert b"mybook.local" in body


def test_pac_endpoint(server):
    _, _, _, port = server
    status, body = _get(port, "/proxy.pac")
    assert status == 200 and b"mybook.local" in body


def test_dashboard_root(server):
    _, _, _, port = server
    status, body = _get(port, "/")
    assert status == 200 and b"<html" in body.lower()


def test_dashboard_includes_logs_panel(server):
    _, _, _, port = server
    status, body = _get(port, "/")
    assert status == 200
    assert b'id="logbox"' in body and b'id="logtbody"' in body
    assert b"/logs.json" in body  # refreshLogs() fetch target present


def test_reset_all_no_token_required_when_unset(server):
    _, _, st, port = server
    st.hit("mybook.local", 5)
    status, _ = _post(port, "/reset", b"")
    assert status == 200
    assert st.snapshot()["mybook.local"]["requests"] == 0


def test_logs_json_endpoint_returns_recent_requests(server):
    _, _, st, port = server
    st.log_request("mybook.local", "GET", "/x", 200, 10, "text/html")
    status, body = _get(port, "/logs.json")
    data = json.loads(body)
    assert status == 200
    assert data[0]["path"] == "/x"


def test_logs_json_limit_query_param(server):
    _, _, st, port = server
    for i in range(5):
        st.log_request("mybook.local", "GET", f"/l{i}", 200, 1, "text/html")
    status, body = _get(port, "/logs.json?limit=2")
    data = json.loads(body)
    assert status == 200 and len(data) == 2


def test_logs_json_bad_limit_falls_back_to_default(server):
    _, _, _, port = server
    status, body = _get(port, "/logs.json?limit=notanumber")
    assert status == 200
    assert isinstance(json.loads(body), list)


# ── Medium: unknown routes / bad methods ──────────────────────────────────
def test_unknown_get_route_404(server):
    _, _, _, port = server
    status, _ = _get(port, "/nope")
    assert status == 404


def test_post_unknown_route_405(server):
    _, _, _, port = server
    status, _ = _post(port, "/nope", b"")
    assert status == 405


# ── Critical: token auth + origin validation ──────────────────────────────
def test_post_reload_without_token_forbidden(server_with_token):
    _, _, _, port = server_with_token
    status, _ = _post(port, "/reload", b"")
    assert status == 403


def test_post_reload_with_wrong_token_forbidden(server_with_token):
    _, _, _, port = server_with_token
    status, _ = _post(port, "/stats/save", b"", headers={"X-Proxyevil-Token": "wrong"})
    assert status == 403


def test_post_reload_with_correct_token_allowed(server_with_token):
    _, _, _, port = server_with_token
    status, _ = _post(port, "/stats/save", b"", headers={"X-Proxyevil-Token": "secret123"})
    assert status == 200


def test_cross_origin_post_rejected(server):
    _, _, _, port = server
    status, _ = _post(port, "/reset", b"", headers={"Origin": "http://evil.example.com"})
    assert status == 403


def test_same_origin_post_allowed(server):
    _, _, _, port = server
    status, _ = _post(port, "/reset", b"", headers={"Origin": f"http://127.0.0.1:{port}"})
    assert status == 200


# ── Rate limiting: /stats.json and /logs.json ───────────────────────────────
def test_stats_json_rate_limited_after_threshold():
    cfg = {"aliases": {"a.local": "a.com"}}
    am = AliasMap(cfg["aliases"])
    st = Stats()
    st.init(am.stats_keys)
    srv = sidecar.start_sidecar(am, st, "evil_data_test/stats.json", "127.0.0.1", 8080, 0,
                                 cfg, config_path="", rate_limit_max=3, rate_limit_window_s=5.0)
    port = srv.server_address[1]
    try:
        codes = [_get(port, "/stats.json")[0] for _ in range(5)]
        assert codes[:3] == [200, 200, 200]
        assert 429 in codes[3:]
    finally:
        srv.shutdown()


def test_logs_json_rate_limit_independent_per_server():
    """Two separate sidecar instances must not share a rate-limit bucket."""
    cfg = {"aliases": {}}
    am1, am2 = AliasMap({}), AliasMap({})
    st1, st2 = Stats(), Stats()
    st1.init([]); st2.init([])
    srv1 = sidecar.start_sidecar(am1, st1, "evil_data_test/stats.json", "127.0.0.1", 8080, 0,
                                  cfg, config_path="", rate_limit_max=2, rate_limit_window_s=5.0)
    srv2 = sidecar.start_sidecar(am2, st2, "evil_data_test/stats.json", "127.0.0.1", 8080, 0,
                                  cfg, config_path="", rate_limit_max=2, rate_limit_window_s=5.0)
    try:
        p1, p2 = srv1.server_address[1], srv2.server_address[1]
        for _ in range(2):
            assert _get(p1, "/logs.json")[0] == 200
        assert _get(p1, "/logs.json")[0] == 429
        # srv2 has its own independent budget, unaffected by srv1's usage
        assert _get(p2, "/logs.json")[0] == 200
    finally:
        srv1.shutdown()
        srv2.shutdown()


def test_rate_limit_does_not_apply_to_dashboard():
    cfg = {"aliases": {}}
    am = AliasMap({})
    st = Stats(); st.init([])
    srv = sidecar.start_sidecar(am, st, "evil_data_test/stats.json", "127.0.0.1", 8080, 0,
                                 cfg, config_path="", rate_limit_max=1, rate_limit_window_s=5.0)
    port = srv.server_address[1]
    try:
        # exhaust the /stats.json budget
        assert _get(port, "/stats.json")[0] == 200
        assert _get(port, "/stats.json")[0] == 429
        # dashboard route is unrelated to the json rate limiter
        assert _get(port, "/")[0] == 200
    finally:
        srv.shutdown()
