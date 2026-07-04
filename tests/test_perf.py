"""Extreme-level: large HTML body rewrite perf/memory test.

Verifies that a multi-MB response body is rewritten within a bounded time
and without unbounded memory growth, and that bodies over max_body_bytes
are skipped cheaply (no decompression/regex work attempted).
"""
import time
import tracemalloc

import pytest
from alias_map import AliasMap
from stats import Stats
from addon import DomainAliasAddon
from tests.test_addon import FakeRequest, FakeResponse, FakeFlow


def _make_large_html(size_mb: int) -> bytes:
    chunk = b'<div><a href="https://www.facebook.com/x">l</a></div>\n'
    reps = (size_mb * 1024 * 1024) // len(chunk) + 1
    return chunk * reps


@pytest.fixture
def addon():
    aliases = AliasMap({"mybook.local": "www.facebook.com"})
    cfg = {
        "rewrite": {"html": True, "js": True, "css": True, "json": True,
                    "headers": True, "cookies": True},
        "strip_headers": [],
        "SPOOFING_EXCLUDE_LIST": [],
        "max_body_bytes": 20 * 1024 * 1024,  # 20MB — big enough to allow the test body through
        "data_dir": "evil_data_test",
    }
    return DomainAliasAddon(aliases, cfg, Stats())


def test_large_html_body_rewritten_within_time_and_memory(addon):
    body = _make_large_html(5)  # ~5MB
    req = FakeRequest("mybook.local")
    resp = FakeResponse(headers={"content-type": "text/html"}, content=body)
    flow = FakeFlow(req, resp)
    flow.metadata["proxyevil.fake"] = "mybook.local"

    tracemalloc.start()
    start = time.monotonic()
    addon.response(flow)
    elapsed = time.monotonic() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert b"facebook.com" not in flow.response.content
    assert b"mybook.local" in flow.response.content
    # Bound: should complete well under a few seconds even on slow CI, and
    # peak traced allocation should stay within a small multiple of body size
    # (guards against accidental O(n^2) string-concat rewrites).
    assert elapsed < 5.0
    assert peak < len(body) * 6


def test_body_over_limit_skipped_without_full_scan(addon):
    # Body larger than configured max_body_bytes must be skipped before any
    # regex/decompress work — verified indirectly via elapsed time staying tiny.
    addon.cfg["max_body_bytes"] = 1024  # 1KB limit
    body = _make_large_html(8)  # ~8MB, far over limit
    req = FakeRequest("mybook.local")
    resp = FakeResponse(headers={"content-type": "text/html"}, content=body)
    flow = FakeFlow(req, resp)
    flow.metadata["proxyevil.fake"] = "mybook.local"

    start = time.monotonic()
    addon.response(flow)
    elapsed = time.monotonic() - start

    assert flow.response.content == body  # untouched
    assert elapsed < 1.0
