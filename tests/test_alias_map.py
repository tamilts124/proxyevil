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
