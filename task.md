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
- [ ] test_sidecar.py — dashboard/PAC/stats endpoints, token auth, origin validation — status: in-progress
- [ ] test_watcher.py — config hot-reload behavior — status: todo
- [ ] Extreme: large HTML body (multi-MB) rewrite perf/memory test — status: todo
- [x] addon.py line count re-check (post-fix, ~565 lines) — no split needed — status: done

## Current test count: 65 passing (`py -m pytest tests/`)
