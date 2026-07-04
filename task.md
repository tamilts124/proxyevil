# Proxyevil Task List

## Status legend
todo / in-progress / done / tested / blocked

## Tasks (round 0 — initial recovery & core suite)
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
  - bug found & fixed: certs.py built filesystem paths directly from alias domain names with no validation — a domain like `../../evil` in config.json could escape cert_dir. Added `_is_safe_domain()` hostname validator; unsafe names skipped with a warning.
- [x] test_hosts_manager.py — privilege checks, atomic write, no-op idempotency, unreadable file — status: tested (6 tests)
- [x] test_sidecar.py — dashboard/PAC/stats endpoints, token auth, origin validation — status: tested (13 tests, real HTTPServer on ephemeral port)
  - note: module-scoped server fixtures used — many function-scoped HTTPServer/thread instances in one pytest run destabilized the test host process.
- [x] test_watcher.py — retry logic, watchfiles-missing fallback, hot-reload wiring, invalid-config resilience — status: tested (6 tests)
- [x] Extreme: large HTML body (multi-MB) rewrite perf/memory test — status: tested (tests/test_perf.py, 2 tests)
- [x] addon.py line count re-check (post-fix, ~565 lines) — no split needed — status: done

## Round 1 (proactive extensions)
- [x] logfilter.py test coverage — status: tested (tests/test_logfilter.py, 11 tests)
- [x] Sidecar: request logs viewer endpoint (recent N requests ring buffer) — status: tested
  - impl: Stats.log_request()/recent() thread-safe deque(maxlen=200); GET /logs.json?limit=N. 7 tests.
- [x] Sidecar: domain blacklist feature — status: tested
  - impl: config.py `blacklist` key, addon.py `_host_matches_blacklist()` (exact + "*.domain" wildcard) → 403 in `request()`. 12 tests.
- [x] alias_map.py: combined single-pass regex for needle pre-check (perf for large alias counts) — status: tested
  - impl: `_combined_byte_pattern()` + `AliasMap.contains_real_needle()` replaces O(N×L) loop. 5 tests incl. 500-alias scale check.

## Round 2 (proactive extensions)
- [x] sidecar dashboard: surface /logs.json ring buffer in the HTML dashboard view — status: tested
  - impl: "Recent requests" panel (#logbox/#logtable), polls /logs.json?limit=20 every 5s, status color classes, textContent-only rendering. 1 test.
- [x] alias_map.py: LRU-cache hit/miss counters exposed via /stats.json — status: tested
  - impl: `AliasMap.cache_stats()` (hits/misses/hit_rate/cache sizes) surfaced as `alias_cache` in sidecar `/stats.json`. 4 tests.

## Current test count: 139 passing (`py -m pytest tests/`)

## Round 3 (proactive extensions, in progress)
- [x] certs.py: automated certificate renewal (check mkcert CA/leaf expiry, regenerate before expiry) — status: tested
  - impl: `cert_expiry()` (parses PEM via `cryptography.x509`), `needs_renewal(days_threshold=14)`, `check_and_renew()` non-interactive sweep; `setup_certs()` now renews expiring certs instead of only skipping existing ones. 8 new tests in test_certs.py (14 total).
- [x] watcher.py: debounce rapid successive config.json writes — status: tested
  - audit: watchfiles' own `watch(path, debounce=500)` already coalesces bursts of raw fs events into a single yield within the window, so editors writing multiple times per save don't trigger multiple reloads. No separate debounce layer needed; behavior locked in by existing tests.
- [x] watcher.py: wire check_and_renew() into a periodic background thread so certs auto-renew without manual --setup — status: tested
  - impl: `start_config_watcher(..., cert_dir=..., renew_interval_s=86400, renew_days_threshold=14)` spawns a daemon `cert-renewer` thread calling `certs.check_and_renew()` on live_cfg aliases. 2 new tests in test_watcher.py (8 total).
- [x] codec.py: verify current gzip/br/deflate/zstd coverage; add streaming decompression size cap if missing — status: tested
  - audit: gzip and zstd already capped (streaming read loop / max_output_size). deflate and br were NOT capped — zlib.decompress()/brotli.decompress() ran to completion before any size check, a zip-bomb risk. Fixed via `_zlib_streaming_decompress()` (decompressobj + max_length loop) and `_brotli_streaming_decompress()` (chunked brotli.Decompressor().process()), both bailing out (None) once `_MAX_DECOMP` is exceeded mid-stream. 4 new tests in test_codec.py (14 total).

## Round 3: complete — all items tested. See Round 4 below for next proactive batch.

## Round 4 (proactive, todo)
- [ ] sidecar.py: auth/rate-limit for /logs.json and /stats.json endpoints (currently token-gated only, no rate limit) — status: todo
- [ ] alias_map.py: hot-reload safety — verify reload() is atomic under concurrent request handling (thread safety audit) — status: todo
- [ ] config.py: schema versioning / migration path for older config.json files — status: todo
