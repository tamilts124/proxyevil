"""Tests for alias_map.AliasMap — normal, boundary, and concurrency levels."""
import threading
import pytest
from alias_map import AliasMap


@pytest.fixture
def am():
    return AliasMap({
        "mybook.local": "www.facebook.com",
        "mygoogle.local": {"real": "www.google.com", "extra_real": ["ggpht.com"]},
    })


# ── Normal ───────────────────────────────────────────────────────────────
def test_fake_for_real(am):
    assert am.fake_for("www.facebook.com") == "mybook.local"


def test_real_for_fake(am):
    assert am.real_for("mybook.local") == "www.facebook.com"


def test_subdomain_mapping(am):
    # real_for(): fake subdomain -> real subdomain, www. stripped on real side
    assert am.real_for("api.mybook.local") == "api.facebook.com"
    # fake_for(): only true subdomains of the exact registered real
    # ("www.facebook.com") map back — asymmetric by design (see alias_map.py).
    assert am.fake_for("api.www.facebook.com") == "api.mybook.local"


def test_rewrite_real_to_fake_body(am):
    text = 'Visit https://www.facebook.com/page'
    out = am.rewrite_real_to_fake(text)
    assert "mybook.local" in out and "facebook.com" not in out


def test_rewrite_fake_to_real_body(am):
    text = 'Host: mybook.local'
    out = am.rewrite_fake_to_real(text)
    assert "www.facebook.com" in out


def test_extra_real_domain_mapped(am):
    assert am.fake_for("ggpht.com") is not None


# ── Boundary / medium ────────────────────────────────────────────────────
def test_empty_aliases():
    empty = AliasMap({})
    assert empty.real_for("anything.local") is None
    assert empty.rewrite_real_to_fake("no change here") == "no change here"


def test_unknown_domain_unchanged(am):
    assert am.real_for("notmapped.local") is None
    text = "https://unrelated.com/x"
    assert am.rewrite_real_to_fake(text) == text


def test_disabled_alias_skipped():
    m = AliasMap({"x.local": {"real": "x.com", "enabled": False}})
    assert m.real_for("x.local") is None


def test_missing_real_key_raises_keyerror():
    with pytest.raises(KeyError):
        AliasMap({"bad.local": {"extra_real": ["y.com"]}})


def test_dynamic_alias_register_and_dup(am):
    assert am.register_dynamic_alias("new.local", "new.com") is True
    assert am.register_dynamic_alias("new.local", "new.com") is False  # dup


def test_circular_parent_chain_bounded():
    # Fix #6 guard: build a map then manually create a cycle via internals
    m = AliasMap({"a.local": "a.com"})
    with m._lock:
        m._parents["a.local"] = "a.local"  # self-referencing cycle
    root = m._get_root_fake("a.local")
    assert root == "a.local"  # terminates instead of looping forever


# ── Combined needle pre-check (perf: single-pass pattern) ─────────────────
def test_contains_real_needle_true_when_present(am):
    assert am.contains_real_needle(b"visit https://www.facebook.com/x now")


def test_contains_real_needle_false_when_absent(am):
    assert not am.contains_real_needle(b"nothing interesting here")


def test_contains_real_needle_false_when_no_aliases():
    m = AliasMap({})
    assert not m.contains_real_needle(b"www.facebook.com")


def test_contains_real_needle_matches_extra_real_domain(am):
    # ggpht.com is registered as an extra_real domain under mygoogle.local
    assert am.contains_real_needle(b"cdn served from ggpht.com today")


def test_combined_pattern_scales_with_many_aliases():
    aliases = {f"f{i}.local": f"real{i}.example.com" for i in range(500)}
    m = AliasMap(aliases)
    haystack = (b"nothing here " * 1000) + b"real499.example.com"
    assert m.contains_real_needle(haystack.lower())
    assert not m.contains_real_needle(b"nothing here " * 1000)


# ── Cache hit/miss metrics ─────────────────────────────────────────────────
def test_cache_stats_zero_lookups_hit_rate_none():
    m = AliasMap({})
    stats = m.cache_stats()
    assert stats["hits"] == 0 and stats["misses"] == 0
    assert stats["hit_rate"] is None


def test_cache_stats_counts_miss_then_hit(am):
    am.fake_for("www.facebook.com")   # first call: miss (populates cache)
    am.fake_for("www.facebook.com")   # second call: hit
    stats = am.cache_stats()
    assert stats["misses"] >= 1
    assert stats["hits"] >= 1
    assert 0 <= stats["hit_rate"] <= 1


def test_cache_stats_sizes_reflect_populated_entries(am):
    am.fake_for("www.facebook.com")
    am.real_for("mybook.local")
    stats = am.cache_stats()
    assert stats["fake_cache_size"] >= 1
    assert stats["real_cache_size"] >= 1


# ── Extreme / concurrency ────────────────────────────────────────────────
def test_concurrent_dynamic_registration():
    m = AliasMap({})
    errors = []

    def worker(i):
        try:
            m.register_dynamic_alias(f"t{i}.local", f"t{i}.com")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(m.mapping) == 50


# ── Extreme: reload() racing against concurrent rewrite calls ────────────
def test_concurrent_reload_during_rewrite_no_crash():
    """Hammer reload() from one thread while many threads call
    rewrite_real_to_fake/rewrite_fake_to_real concurrently. Must never raise
    (no KeyError/RuntimeError from torn state) and every result must be a str.
    """
    am = AliasMap({"a.local": "a.com"})
    errors = []
    stop = threading.Event()

    def reloader():
        n = 0
        while not stop.is_set():
            n += 1
            aliases = {f"host{n % 5}.local": f"host{n % 5}.com"} if n % 2 else {"a.local": "a.com"}
            try:
                am.reload(aliases)
            except Exception as exc:
                errors.append(exc)

    def worker():
        for _ in range(200):
            try:
                r1 = am.rewrite_real_to_fake("visit https://a.com/page and host2.com too")
                r2 = am.rewrite_fake_to_real("visit https://a.local/page and host2.local too")
                assert isinstance(r1, str) and isinstance(r2, str)
            except Exception as exc:
                errors.append(exc)

    rt = threading.Thread(target=reloader)
    workers = [threading.Thread(target=worker) for _ in range(8)]
    rt.start()
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    stop.set()
    rt.join(timeout=2)

    assert errors == []
