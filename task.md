# Proxyevil Task List

## Status legend
todo / in-progress / done / tested / blocked

## Tasks
- [x] Fix addon.py syntax corruption (duplicated class body + unterminated regex from prior cut-off session) — status: tested
- [x] Build tests/ scaffold + pytest config — status: tested
- [x] test_alias_map.py — status: tested (12 tests)
- [x] test_codec.py — status: tested (12 tests)
- [x] test_config.py — status: tested (10 tests)
- [x] test_stats.py — status: tested (9 tests)
- [x] test_addon.py — status: tested (10 tests)
  - bug found & fixed: SRI stripping silently discarded when body had no real-domain match; also "changed?" check compared post-strip text against itself. Both fixed in addon.py `_rewrite_body`.
- [x] requirements.txt mitmproxy pin loosened to <13.0 (installed: 12.2.3) — status: done
- [x] test_certs.py — mkcert missing/failure, shell-injection-safety (arg list not shell=True), directory traversal — status: tested (7 tests)
  - bug found & fixed: certs.py built filesystem paths directly from alias domain names with no validation — a domain like `../../evil` in config.json could escape cert_dir. Added `_is_safe_domain()` hostname validator in certs.py; unsafe names are now skipped with a warning in both setup_certs and collect_certs.
- [x] test_hosts_manager.py — privilege checks, atomic write, no-op idempotency, unreadable file — status: tested (6 tests)
- [x] test_sidecar.py — dashboard/PAC/stats endpoints, token auth, origin validation — status: tested (13 tests, real HTTPServer on ephemeral port)
  - note: module-scoped server fixtures used (one per token config) — many function-scoped HTTPServer/thread instances in one pytest run destabilized the test host process.
- [x] test_watcher.py — retry logic, watchfiles-missing fallback, hot-reload wiring, invalid-config resilience — status: tested (6 tests)
- [x] Extreme: large HTML body (multi-MB) rewrite perf/memory test — status: tested (tests/test_perf.py, 2 tests: 5MB body rewritten <5s/<6x mem, 8MB body over-limit skipped <1s)
- [x] addon.py line count re-check (post-fix, ~565 lines) — no split needed — status: done

## Current test count: 121 passing (`py -m pytest tests/`)
## All proactive extensions from prior round complete. New round queued below.

## Proactive extension ideas — round 2 (todo, not yet started)
- [ ] certs.py: automated certificate renewal (check mkcert CA/leaf expiry, regenerate before expiry) — status: todo
- [ ] sidecar dashboard: surface /logs.json ring buffer in the HTML dashboard view (currently JSON-only) — status: todo
- [ ] alias_map.py: LRU-cache eviction metrics (cache hit/miss counters) exposed via /stats.json — status: todo
## All planned test modules complete (alias_map, codec, config, stats, addon, certs, hosts_manager, sidecar, watcher).
## Next: proactive extensions — see below.

## Proactive extension ideas (todo, not yet started)
- [x] logfilter.py test coverage (currently untested module) — status: tested (tests/test_logfilter.py, 11 tests: noise suppression, WinError downgrade, TLS/lifecycle allow-list, idempotent install)
- [x] Sidecar: request logs viewer endpoint (recent N requests ring buffer) — status: tested
  - impl: Stats.log_request()/recent() thread-safe deque(maxlen=200) in stats.py; wired from addon.py response handler; GET /logs.json?limit=N in sidecar.py (7 new tests across stats+sidecar)
- [x] Sidecar: domain blacklist feature (block specific hosts from being proxied) — status: tested
  - impl: config.py `blacklist` key (list[str], validated), addon.py `_host_matches_blacklist()` (exact + "*.domain" wildcard, case/trailing-dot insensitive) checked at top of `request()` before alias resolution → 403 response, stats.error() recorded. 12 new tests (addon + config).
- [x] alias_map.py: cache the compiled real/fake regex needle scan with a single combined Aho-Corasick-style search for large alias counts — status: tested
  - impl: `_combined_byte_pattern()` builds one alternation regex over all real/fake needles at rebuild time (`_real_needle_pattern`/`_fake_needle_pattern`); new `AliasMap.contains_real_needle()` replaces addon.py's O(N_aliases × body_len) `any(n in body for n in needles)` loop with a single-pass regex search. 5 new tests incl. 500-alias scale check.
