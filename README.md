# proxyevil

A local domain-alias MITM proxy. Map any fake local domain to a real upstream site — browse `mybook.local` and it transparently proxies `www.facebook.com`, rewriting every domain reference in both directions so the browser never knows the difference.

---

## How it works

```
Browser → mybook.local (fake domain)
  → proxyevil intercepts the CONNECT tunnel
  → presents a locally-trusted TLS cert for mybook.local
  → rewrites Host header → www.facebook.com
  → forwards request upstream over real HTTPS
  → rewrites all domain references in the response → mybook.local
  → returns to browser
```

Everything is bidirectional:

- **Outgoing** (browser → upstream): Host, Referer, Origin, Cookie, request body
- **Incoming** (upstream → browser): Location, Set-Cookie domain, HTML, JS, CSS, JSON bodies

SRI `integrity=` attributes are stripped automatically so hash mismatches don't break pages.

---

## Project structure

```
proxyevil/
├── proxy.py          # CLI entry point; boots mitmproxy + sidecar + watcher
├── addon.py          # mitmproxy addon — bidirectional domain rewriter
├── alias_map.py      # Bidirectional fake⇔real domain map; regex patterns; subdomain support
├── codec.py          # gzip / deflate / brotli decompress & recompress helpers
├── config.py         # JSON config loader, validator, and saver
├── sidecar.py        # HTTP status dashboard, PAC file, /reload, /reset endpoints
├── stats.py          # Thread-safe per-alias request + bytes counters
├── watcher.py        # inotify-backed config hot-reload (requires watchfiles)
├── config.json       # Alias definitions and tuning options
├── requirements.txt  # Python dependencies
├── certs/            # Auto-generated mkcert certs (created by --setup)
└── evil_data/        # mitmproxy internal state / CA store
```

### Module breakdown

| Module | What it does |
|---|---|
| `proxy.py` | CLI (argparse), `run_proxy()` coroutine, startup banner |
| `addon.py` | `DomainAliasAddon` — `request()` rewrites outgoing, `response()` rewrites incoming; strips SRI and security headers |
| `alias_map.py` | `AliasMap` — bidirectional fake⇔real map, subdomain support, compiled regex patterns for bulk body rewriting, per-lookup LRU cache |
| `codec.py` | `decompress` / `recompress` — transparent gzip, deflate, brotli handling |
| `config.py` | `load_config` / `save_config` / `_validate` — merges defaults, validates keys |
| `sidecar.py` | Tiny stdlib HTTP server: dashboard, PAC, `/hosts`, `/stats.json`, `POST /reload`, `POST /reset`, `GET /reset/<fake>` |
| `stats.py` | `Stats` — thread-safe hit counters, bytes-rewritten delta, last-seen timestamps |
| `watcher.py` | `start_config_watcher` — inotify via `watchfiles`; hot-reloads aliases + rewrite config + stats keys |

---

## Quick start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Install mkcert (one time)

Download from https://github.com/FiloSottile/mkcert/releases and place it in your PATH.

```bash
mkcert -install          # installs the local CA into your system/browser trust store
```

On **Windows**, run the above in an Administrator terminal.

### 3. Configure aliases

Edit `config.json`:

```json
{
  "aliases": {
    "mybook.local":   "www.facebook.com",
    "mygoogle.local": "www.google.com"
  }
}
```

Extended alias form (CDN / extra real domains):

```json
{
  "aliases": {
    "mybook.local": {
      "real":       "www.facebook.com",
      "extra_real": ["fbcdn.net", "fbsbx.com"]
    }
  }
}
```

### 4. Generate TLS certificates

```bash
python proxy.py --setup
```

This calls `mkcert` for each alias domain and stores certs in `certs/`.

### 5. Add hosts entries

```bash
python proxy.py --hosts
```

Prints the block to add. On Windows, edit `C:\Windows\System32\drivers\etc\hosts` as Administrator:

```
127.0.0.1  mybook.local
127.0.0.1  mygoogle.local
```

### 6. Start the proxy

```bash
python proxy.py
```

### 7. Configure your browser

**Option A — manual proxy** (works everywhere):

- HTTP Proxy: `127.0.0.1:8080`
- HTTPS Proxy: `127.0.0.1:8080`

**Option B — PAC file** (routes only alias domains through the proxy):

- PAC URL: `http://127.0.0.1:8081/proxy.pac`

### 8. Trust the mitmproxy CA (if you skipped mkcert)

Visit `http://mitm.it` in your browser while the proxy is running and follow the install instructions.

---

## CLI reference

```
python proxy.py [options]

  --config  -c PATH             Config file path (default: config.json)
  --host        HOST            Listen host (default: 127.0.0.1)
  --port    -p  PORT            Proxy port (default: 8080)
  --sidecar-port PORT           Status/PAC/stats port (default: 8081)
  --setup                       Generate TLS certs for all aliases, then exit
  --hosts                       Print /etc/hosts block, then exit
  --list                        List configured aliases, then exit
  --list-certs                  List generated TLS certs, then exit
  --add-alias FAKE REAL         Add a one-off alias (not persisted unless --save)
  --remove-alias FAKE           Remove an alias (not persisted unless --save)
  --save                        Persist --add-alias / --remove-alias to config.json
  --verbose -v                  Debug logging
  --version -V                  Show version
```

One-off alias without editing config:

```bash
python proxy.py --add-alias mytwitter.local twitter.com
```

Add and persist to config.json:

```bash
python proxy.py --add-alias mytwitter.local twitter.com --save
```

---

## Sidecar endpoints

The sidecar runs on `http://127.0.0.1:8081` by default.

| Endpoint | Method | Description |
|---|---|---|
| `/` or `/status` | GET | Live HTML dashboard (auto-refreshes every 5s) |
| `/proxy.pac` | GET | PAC file for browser auto-config |
| `/hosts` | GET | Plain-text `/etc/hosts` block |
| `/stats.json` | GET | Machine-readable stats (uptime, request counts, bytes rewritten, last seen) |
| `/reload` | POST | Hot-reload `config.json` without restarting |
| `/reset` | POST | Reset all stats counters |
| `/reset/<fake>` | GET | Reset stats for one alias (redirects back to dashboard) |

Curl examples:

```bash
curl -X POST http://127.0.0.1:8081/reload
curl -X POST http://127.0.0.1:8081/reset
curl http://127.0.0.1:8081/stats.json
```

---

## config.json reference

```jsonc
{
  "host": "127.0.0.1",       // proxy listen address
  "port": 8080,              // proxy listen port
  "sidecar_port": 8081,      // dashboard / PAC / stats port
  "data_dir": "evil_data",   // mitmproxy internal state directory
  "cert_dir": "certs",       // where mkcert certs are stored
  "verbose": false,

  // Simple alias: fake domain → real upstream
  "aliases": {
    "fake.local": "real.com"
  },

  // Extended alias: include extra real-side domains (CDNs, APIs)
  // "fake.local": {
  //   "real": "real.com",
  //   "extra_real": ["cdn.real.com", "api.real.com"]
  // },

  "rewrite": {
    "html":    true,   // rewrite HTML bodies
    "js":      true,   // rewrite JS bodies
    "css":     true,   // rewrite CSS bodies
    "json":    true,   // rewrite JSON bodies
    "headers": true,   // rewrite response headers (Location, etc.)
    "cookies": true    // rewrite Set-Cookie domain attributes
  },

  // Security headers stripped from upstream responses so the fake domain works:
  "strip_headers": [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options"
    // ... etc
  ]
}
```

---

## Known limitations

**HSTS preload** — Sites like Facebook and Google are on the browser's HSTS preload list. If your browser has ever visited the real site, it may refuse to connect to your fake domain via HTTP. The proxy serves HTTPS so this is usually fine, but if you see HSTS errors, clear the entry at `chrome://net-internals/#hsts`.

**Service Workers** — Some SPAs register service workers scoped to the real domain. These can intercept requests before the proxy sees them. Open DevTools → Application → Service Workers → Unregister.

**Brotli** — Install `pip install brotli` (already in `requirements.txt`) or compressed responses from modern CDNs won't be rewritten — they'll pass through unchanged.

**Login / OAuth** — OAuth flows redirect back to the real domain. The proxy rewrites the `Location:` header, but if the OAuth provider hard-codes the redirect URI it may reject the fake domain.

**Subdomain mapping** — Subdomains of a fake domain are automatically mapped to the equivalent subdomain of the real upstream (e.g. `api.mybook.local` → `api.facebook.com`). This is best-effort and may break sites with complex subdomain structures.

---

## Dependencies

| Package | Purpose |
|---|---|
| `mitmproxy` | Core HTTPS interception engine |
| `watchfiles` | inotify-backed config hot-reload; falls back gracefully if missing |
| `brotli` | Brotli decompression (optional but strongly recommended) |
| `mkcert` | External binary for TLS cert generation (not a pip package) |

---

## Related projects in ClaudeDir

- **proxysplit** — the original splitting/routing proxy this was inspired by
- **proxyvalt** — vault/credential proxy; domain rewriting borrowed some patterns from here
