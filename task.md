# Proxyevil Task List

## Status legend
todo / in-progress / done / tested / blocked

## Tasks
- [x] Fix addon.py syntax corruption (duplicated class body + unterminated regex from prior cut-off session) — status: tested
  - notes: addon.py had the entire DomainAliasAddon class duplicated (corrupted first copy lines ~43-604, clean copy after). Removed corrupted duplicate, restored `_is_ip_or_localhost`. All modules now py_compile clean.
- [ ] Build tests/ scaffold + pytest config — status: in-progress
- [ ] test_alias_map.py — normal/boundary domain mapping tests — status: todo
- [ ] test_codec.py — compression edge cases incl. corrupt bodies — status: todo
- [ ] test_config.py — schema validation, invalid configs — status: todo
- [ ] test_addon.py — mocked HTTPFlow rewrite tests (headers, cookies, SRI strip, security headers) — status: todo
- [ ] test_stats.py — thread-safety / concurrent counters — status: todo
- [ ] test_hosts_manager.py — mocked hosts file + privilege failures — status: todo
- [ ] Split addon.py (currently >1000 lines pre-fix; re-check after fix) if still oversized — status: todo
- [ ] requirements.txt mitmproxy pin (<12.0) vs installed 12.2.3 mismatch — status: todo
