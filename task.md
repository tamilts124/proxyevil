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

## Current test count: 86 passing (`py -m pytest tests/`)
## All planned test modules complete (alias_map, codec, config, stats, addon, certs, hosts_manager, sidecar, watcher).
## Next: proactive extensions — see below.

## Proactive extension ideas (todo, not yet started)
- [x] logfilter.py test coverage (currently untested module) — status: tested (tests/test_logfilter.py, 11 tests: noise suppression, WinError downgrade, TLS/lifecycle allow-list, idempotent install)
- [ ] Sidecar: request logs viewer endpoint (recent N requests ring buffer) — status: todo
- [ ] Sidecar: domain blacklist feature (block specific hosts from being proxied) — status: todo
- [ ] alias_map.py: cache the compiled real/fake regex needle scan with a single combined Aho-Corasick-style search for large alias counts — status: todo
