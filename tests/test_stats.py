"""Tests for stats.py — thread-safe counters, persistence, race conditions."""
import threading
import json
from stats import Stats


def test_hit_increments_counts():
    s = Stats()
    s.hit("a.local", bytes_delta=10, content_type="html")
    snap = s.snapshot()
    assert snap["a.local"]["requests"] == 1
    assert snap["a.local"]["bytes_rewritten"] == 10
    assert snap["a.local"]["rewrites"] == 1
    assert snap["a.local"]["rewrite_by_type"]["html"] == 1


def test_hit_zero_delta_not_counted_as_rewrite():
    s = Stats()
    s.hit("a.local", bytes_delta=0)
    snap = s.snapshot()
    assert snap["a.local"]["requests"] == 1
    assert snap["a.local"]["rewrites"] == 0


def test_error_increments():
    s = Stats()
    s.error("a.local")
    assert s.snapshot()["a.local"]["errors"] == 1


def test_reset_single_alias():
    s = Stats()
    s.hit("a.local")
    s.hit("b.local")
    s.reset("a.local")
    snap = s.snapshot()
    assert snap["a.local"]["requests"] == 0
    assert snap["b.local"]["requests"] == 1


def test_reset_all():
    s = Stats()
    s.hit("a.local")
    s.hit("b.local")
    s.reset()
    snap = s.snapshot()
    assert all(v["requests"] == 0 for k, v in snap.items() if k != "_gen")


def test_dump_and_load_roundtrip(tmp_path):
    s = Stats()
    s.hit("a.local", bytes_delta=5, content_type="js")
    p = tmp_path / "stats.json"
    s.dump(str(p))
    assert json.loads(p.read_text())["aliases"]["a.local"]["requests"] == 1

    s2 = Stats()
    s2.load(str(p))
    assert s2.snapshot()["a.local"]["requests"] == 1


def test_load_missing_file_noop(tmp_path):
    s = Stats()
    s.load(str(tmp_path / "nope.json"))  # should not raise
    assert s.snapshot() == {"_gen": 0}


def test_load_corrupt_file_noop(tmp_path):
    p = tmp_path / "stats.json"
    p.write_text("{not json")
    s = Stats()
    s.load(str(p))  # should not raise, logs warning
    assert s.snapshot() == {"_gen": 0}


# ── Extreme: concurrency ────────────────────────────────────────────────
def test_concurrent_hits_no_lost_updates():
    s = Stats()
    n_threads, n_hits = 20, 100

    def worker():
        for _ in range(n_hits):
            s.hit("shared.local", bytes_delta=1, content_type="json")

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    snap = s.snapshot()
    assert snap["shared.local"]["requests"] == n_threads * n_hits
    assert snap["shared.local"]["bytes_rewritten"] == n_threads * n_hits
