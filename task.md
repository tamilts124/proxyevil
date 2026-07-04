# Proxyevil Task List

## Status legend
todo / in-progress / done / tested / blocked

## Tasks
- [x] Fix addon.py syntax corruption (duplicated class body + unterminated regex from prior cut-off session) — status: tested
  - notes: Removed corrupted duplicate DomainAliasAddon copy, restored `_is_ip_or_localhost`. All modules py_compile clean.
- [x] Build tests/ scaffold + pytest config — status: tested
  - notes: pytest.ini + tests/ package added. `py -m pytest tests/` green.
- [x] test_alias_map.py — normal/boundary/concurrency domain mapping tests — status: tested (12 tests, all pass)
- [x] test_codec.py — compression edge cases incl. corrupt bodies — status: tested (12 tests, all pass)
- [x] test_config.py — schema validation, invalid configs — status: tested (10 tests, all pass)
- [x] test_stats.py — thread-safety / concurrent counters — status: tested (9 tests, all pass)
- [x] test_addon.py — mocked HTTPFlow rewrite tests (headers, cookies, SRI strip, security headers, gzip, oversized body) — status: tested (10 tests, all pass)
  - bug found & fixed: SRI `integrity=` stripping was silently skipped whenever a response body had no real-domain reference (needle precheck bypassed it entirely), AND separately the "did anything change" check compared against the already-SRI-stripped text instead of the original, so SRI-only edits were discarded even when the precheck did run. Both fixed in addon.py `_rewrite_body`.
- [x] requirements.txt mitmproxy pin — status: done
  - notes: installed mitmproxy is 12.2.3; loosened pin to `<13.0`.
- [ ] test_hosts_manager.py — mocked hosts file + privilege/mkcert failures — status: todo
- [ ] test_sidecar.py — dashboard/PAC/stats endpoints, token auth, origin validation — status: todo
- [ ] test_watcher.py — config hot-reload behavior — status: todo
- [ ] Critical: shell-injection test for certs.py mkcert invocation (verify subprocess uses arg list, not shell=True with string interpolation) — status: todo
- [ ] Critical: directory-traversal test for alias fake/real domain names reaching filesystem paths (captures, certs) — status: todo
- [ ] Extreme: large HTML body (multi-MB) rewrite perf/memory test — status: todo
- [ ] addon.py line count re-check (post-fix) — currently ~565 lines, no split needed — status: done
