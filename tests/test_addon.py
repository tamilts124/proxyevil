"""Tests for addon.DomainAliasAddon — mocked mitmproxy HTTPFlow objects.

Uses lightweight fake Request/Response/Flow classes instead of real
mitmproxy objects (addon.py only relies on attribute access, not isinstance
checks), keeping tests fast and dependency-free.
"""
import gzip
import pytest
from alias_map import AliasMap
from stats import Stats
from addon import DomainAliasAddon


class FakeHeaders(dict):
    """Case-insensitive-ish header stand-in supporting mitmproxy's extra API."""
    def get_all(self, key):
        return [v for k, v in self.items() if k.lower() == key.lower()]

    def add(self, key, value):
        # Real mitmproxy headers allow duplicate keys; approximate with a list marker.
        existing = self.get(key)
        if existing is None:
            self[key] = value
        else:
            self[key] = existing  # simplified: keep first for dict semantics
            super().__setitem__(f"{key}#{len(self.get_all(key))}", value)


class FakeRequest:
    def __init__(self, host, path="/", method="GET", headers=None, content=b"", scheme="https"):
        self.pretty_host = host
        self.host = host
        self.host_header = host
        self.authority = None
        self.path = path
        self.method = method
        self.headers = FakeHeaders(headers or {})
        self.content = content
        self.scheme = scheme


class FakeResponse:
    def __init__(self, headers=None, content=b"", status_code=200):
        self.headers = FakeHeaders(headers or {})
        self.content = content
        self.status_code = status_code


class FakeFlow:
    def __init__(self, request, response=None):
        self.request = request
        self.response = response
        self.metadata = {}
        self.error = None


@pytest.fixture
def aliases():
    return AliasMap({"mybook.local": "www.facebook.com"})


@pytest.fixture
def cfg():
    return {
        "rewrite": {"html": True, "js": True, "css": True, "json": True, "headers": True, "cookies": True},
        "strip_headers": ["Content-Security-Policy", "X-Frame-Options"],
        "SPOOFING_EXCLUDE_LIST": [],
        "data_dir": "evil_data_test",
    }


@pytest.fixture
def addon(aliases, cfg):
    return DomainAliasAddon(aliases, cfg, Stats())


# ── Normal ───────────────────────────────────────────────────────────────
def test_request_rewrites_host(addon):
    flow = FakeFlow(FakeRequest("mybook.local", "/x"))
    addon.request(flow)
    assert flow.request.host == "www.facebook.com"
    assert flow.metadata["proxyevil.real"] == "www.facebook.com"


def test_response_rewrites_location_header(addon):
    req = FakeRequest("mybook.local")
    resp = FakeResponse(headers={"location": "https://www.facebook.com/home"})
    flow = FakeFlow(req, resp)
    flow.metadata["proxyevil.fake"] = "mybook.local"
    addon.response(flow)
    assert "mybook.local" in flow.response.headers["location"]


def test_response_rewrites_setcookie_domain(addon):
    req = FakeRequest("mybook.local")
    resp = FakeResponse(headers={"set-cookie": "sid=abc; Domain=www.facebook.com; Path=/"})
    flow = FakeFlow(req, resp)
    flow.metadata["proxyevil.fake"] = "mybook.local"
    addon.response(flow)
    cookie = flow.response.headers["set-cookie"]
    assert "Domain=mybook.local" in cookie


# ── Medium: boundary ─────────────────────────────────────────────────────
def test_request_unmapped_host_ignored(addon):
    flow = FakeFlow(FakeRequest("unrelated.com", "/x"))
    addon.request(flow)
    assert flow.request.host == "unrelated.com"          # untouched
    assert "proxyevil.fake" not in flow.metadata


def test_response_without_request_context_ignored(addon):
    resp = FakeResponse(headers={"location": "https://www.facebook.com/"})
    flow = FakeFlow(FakeRequest("unrelated.com"), resp)   # no metadata set
    addon.response(flow)
    assert flow.response.headers["location"] == "https://www.facebook.com/"  # untouched


# ── Critical: security header stripping + SRI ─────────────────────────────
def test_strip_headers_removed(addon):
    req = FakeRequest("mybook.local")
    resp = FakeResponse(headers={
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "content-type": "text/html",
    })
    flow = FakeFlow(req, resp)
    flow.metadata["proxyevil.fake"] = "mybook.local"
    addon.response(flow)
    assert "content-security-policy" not in {k.lower() for k in flow.response.headers}
    assert "x-frame-options" not in {k.lower() for k in flow.response.headers}


def test_sri_integrity_stripped_from_html(addon):
    html = b'<script src="a.js" integrity="sha384-abc123"></script>'
    req = FakeRequest("mybook.local")
    resp = FakeResponse(headers={"content-type": "text/html; charset=utf-8"}, content=html)
    flow = FakeFlow(req, resp)
    flow.metadata["proxyevil.fake"] = "mybook.local"
    addon.response(flow)
    assert b"integrity=" not in flow.response.content


# ── High: corrupt/compressed body handling ────────────────────────────────
def test_corrupt_gzip_body_does_not_crash(addon):
    req = FakeRequest("mybook.local")
    resp = FakeResponse(headers={"content-type": "text/html", "content-encoding": "gzip"},
                         content=b"not actually gzip data")
    flow = FakeFlow(req, resp)
    flow.metadata["proxyevil.fake"] = "mybook.local"
    addon.response(flow)  # must not raise
    assert flow.response.status_code == 200


def test_valid_gzip_body_rewritten(addon):
    raw_html = b'<a href="https://www.facebook.com/x">link</a>'
    comp = gzip.compress(raw_html)
    req = FakeRequest("mybook.local")
    resp = FakeResponse(headers={"content-type": "text/html", "content-encoding": "gzip"}, content=comp)
    flow = FakeFlow(req, resp)
    flow.metadata["proxyevil.fake"] = "mybook.local"
    addon.response(flow)
    out = gzip.decompress(flow.response.content)
    assert b"mybook.local" in out and b"facebook.com" not in out


# ── Extreme: oversized body skipped safely ────────────────────────────────
def test_oversized_body_skipped(aliases):
    cfg = {
        "rewrite": {"html": True}, "strip_headers": [], "SPOOFING_EXCLUDE_LIST": [],
        "max_body_bytes": 10, "data_dir": "evil_data_test",
    }
    a = DomainAliasAddon(aliases, cfg, Stats())
    big = b"www.facebook.com " * 1000
    req = FakeRequest("mybook.local")
    resp = FakeResponse(headers={"content-type": "text/html"}, content=big)
    flow = FakeFlow(req, resp)
    flow.metadata["proxyevil.fake"] = "mybook.local"
    a.response(flow)
    assert flow.response.content == big  # untouched — over size limit
