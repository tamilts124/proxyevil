"""
proxy.py — Main entry point for proxyevil.

Boots mitmproxy DumpMaster with the DomainAliasAddon, starts the sidecar
HTTP server, and optionally enables the config file watcher.

Also serves as the CLI interface (argparse).
"""

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

from _version import __version__

try:
    from mitmproxy.options import Options         # type: ignore
    from mitmproxy.tools.dump import DumpMaster   # type: ignore
except ImportError:
    print("[ERROR] mitmproxy not found.  Run: pip install mitmproxy")
    sys.exit(1)

from alias_map  import AliasMap
from addon      import DomainAliasAddon
from certs      import setup_certs, list_certs, collect_certs
from config     import load_config, save_config, DEFAULTS
from logfilter  import install_log_filters
from sidecar    import start_sidecar, _hosts_block, _pac_file
from stats      import Stats
from watcher    import start_config_watcher

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("proxyevil")


# ── Banner ─────────────────────────────────────────────────────────────────────

def _print_banner(host: str, port: int, sidecar_port: int,
                  alias_map: AliasMap, data_dir: Path, cert_dir: str):
    aliases  = alias_map.mapping
    cert_p   = Path(cert_dir)
    w = 62
    print("=" * w)
    print(f"  🦹  proxyevil  v{__version__}")
    print(f"  Proxy   : {host}:{port}")
    print(f"  Status  : http://127.0.0.1:{sidecar_port}/")
    print(f"  PAC     : http://127.0.0.1:{sidecar_port}/proxy.pac")
    print(f"  Stats   : http://127.0.0.1:{sidecar_port}/stats.json")
    print(f"  Data    : {data_dir.resolve()}")
    print(f"  Aliases : {len(aliases)}")
    for fake, real in sorted(aliases.items()):
        cert_ok = (cert_p / f"{fake}.pem").exists() and (cert_p / f"{fake}-key.pem").exists()
        cert_icon = "🔒" if cert_ok else "⚠ "
        print(f"    {cert_icon} {fake:<28} → {real}")
    print()
    print("  /etc/hosts entries needed:")
    for fake in sorted(aliases.keys()):
        print(f"    127.0.0.1  {fake}")
    print()
    print("  Trust mitmproxy CA once: visit http://mitm.it in your browser")
    print("=" * w)


# ── --check ────────────────────────────────────────────────────────────────────

def _run_check(aliases: dict, cert_dir: str, cfg: dict):
    """Print a config/cert health summary and exit."""
    cert_p  = Path(cert_dir)
    ok      = True
    w       = max((len(f) for f in aliases), default=20)

    print(f"\n{'Fake domain':<{w}}  Real upstream                   Cert")
    print("-" * (w + 50))
    for fake, val in sorted(aliases.items()):
        real      = val if isinstance(val, str) else val.get("real", "?")
        cert_ok   = (cert_p / f"{fake}.pem").exists() and (cert_p / f"{fake}-key.pem").exists()
        cert_stat = "✓ present" if cert_ok else "✗ missing  (run --setup)"
        if not cert_ok:
            ok = False
        print(f"{fake:<{w}}  {real:<30}  {cert_stat}")

    print()
    rw = cfg.get("rewrite", DEFAULTS["rewrite"])
    print("Rewrite flags:", "  ".join(f"{k}={'on' if v else 'off'}" for k, v in rw.items()))
    body_mb = cfg.get("max_body_bytes", 10 * 1024 * 1024) // (1024 * 1024)
    print(f"Max body     : {body_mb} MB")
    print(f"Strip headers: {len(cfg.get('strip_headers', []))}")
    print(f"Access log   : {'on' if cfg.get('access_log') else 'off'}")
    print(f"Verbose      : {'on' if cfg.get('verbose') else 'off'}")
    print()
    if ok:
        print("✓ Config looks good.")
    else:
        print("⚠  Issues found — see above.")
    sys.exit(0 if ok else 1)


# ── --export ───────────────────────────────────────────────────────────────────

def _run_stats(stats_path):
    """Print a human-readable stats summary from the last saved dump and exit."""
    import json
    p = Path(stats_path)
    if not p.exists():
        print("[STATS] No stats file found — proxy has not run yet.")
        sys.exit(0)
    raw   = json.loads(p.read_text(encoding="utf-8"))
    saved = raw.get("saved_at", "?")
    data  = raw.get("aliases", {})
    w     = max((len(k) for k in data), default=20)
    print(f"\nStats saved: {saved}")
    print(f"{'Alias':<{w}}  {'Requests':>8}  {'Rewritten':>10}  {'Errors':>6}  Last seen")
    print("-" * (w + 46))
    for alias, st in sorted(data.items()):
        rw_bytes = st.get("bytes_rewritten", 0)
        rw_label = (
            f"{rw_bytes / 1048576:.1f} MB" if rw_bytes >= 1048576
            else f"{rw_bytes // 1024} KB"
        )
        print(
            f"{alias:<{w}}  {st.get('requests', 0):>8}  {rw_label:>10}"
            f"  {st.get('errors', 0):>6}  {st.get('last_seen', '—')}"
        )
    print()
    sys.exit(0)


def _run_export(aliases: dict, export_dir: str, host: str, proxy_port: int):
    """Write hosts block and PAC file to *export_dir* and exit.

    Creates the directory if it does not exist.  Writes:
      hosts.txt      — /etc/hosts block for all alias domains
      proxy.pac      — PAC file routing only alias domains through the proxy
    """
    out = Path(export_dir)
    out.mkdir(parents=True, exist_ok=True)

    hosts_path = out / "hosts.txt"
    pac_path   = out / "proxy.pac"

    hosts_text = _hosts_block(aliases)
    hosts_path.write_text(hosts_text, encoding="utf-8")
    print(f"[EXPORT] hosts   → {hosts_path.resolve()}")

    pac_text = _pac_file(aliases, host, proxy_port)
    pac_path.write_text(pac_text, encoding="utf-8")
    print(f"[EXPORT] pac     → {pac_path.resolve()}")
    print(f"[EXPORT] {len(aliases)} alias(es) exported.")
    sys.exit(0)


# ── Proxy runner ───────────────────────────────────────────────────────────────

async def run_proxy(
    host:         str,
    port:         int,
    sidecar_port: int,
    alias_map:    AliasMap,
    cfg:          dict,
    cert_dir:     str,
    config_path:  Optional[str],
    stats:        Stats,
    stats_path:   Path,
):
    data_dir = Path(cfg.get("data_dir", "evil_data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    confdir = str(data_dir / "mitmproxy_conf")
    Path(confdir).mkdir(parents=True, exist_ok=True)

    # Collect mkcert-generated certs and wire them into mitmproxy so it
    # presents the correct per-domain cert rather than its own CA leaf.
    cert_pairs = collect_certs(alias_map.mapping, cert_dir)
    if cert_pairs:
        log.info(f"[CERT] loading {len(cert_pairs)} mkcert cert(s) into mitmproxy")
    else:
        log.info("[CERT] no mkcert certs found — mitmproxy will use its auto-generated CA")

    opts = Options(
        listen_host=host,
        listen_port=port,
        ssl_insecure=True,
        confdir=confdir,
        certs=[f"{h}={p}" for h, p in cert_pairs],
    )
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    _addon = DomainAliasAddon(alias_map, cfg, stats)
    master.addons.add(_addon)

    start_sidecar(alias_map, stats, stats_path, host, port, sidecar_port, cfg, config_path or "", addon=_addon)

    if config_path:
        start_config_watcher(config_path, alias_map, cfg, stats, addon=_addon)

    # Install log noise suppression AFTER the master/addon are wired up but
    # BEFORE we start serving, so the first requests are already filtered.
    verbose = cfg.get("verbose", False)
    install_log_filters(alias_map, verbose=verbose)

    _print_banner(host, port, sidecar_port, alias_map, data_dir, cert_dir)

    # Graceful shutdown on SIGTERM (Docker / systemd) in addition to Ctrl-C
    loop = asyncio.get_running_loop()

    def _on_sigterm(*_):
        log.info("[*] SIGTERM received — shutting down…")
        stats.dump(stats_path)
        loop.call_soon_threadsafe(master.shutdown)

    try:
        signal.signal(signal.SIGTERM, _on_sigterm)
    except (OSError, ValueError):
        pass  # Windows or non-main thread — best effort

    try:
        await master.run()
    except KeyboardInterrupt:
        print("\n[*] Stopping proxyevil…")
        stats.dump(stats_path)
        master.shutdown()


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="proxyevil — domain-alias MITM proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version",      "-V", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config",       "-c", default=None,     help="Path to config.json")
    parser.add_argument("--host",               default=None,     help="Listen host (default 127.0.0.1)")
    parser.add_argument("--port",         "-p", type=int,         help="Proxy port (default 8080)")
    parser.add_argument("--sidecar-port",       type=int,         help="Status/PAC port (default 8081)")
    parser.add_argument("--setup",        action="store_true",    help="Generate TLS certs then exit")
    parser.add_argument("--check",        action="store_true",    help="Validate config and cert status then exit")
    parser.add_argument("--hosts",        action="store_true",    help="Print /etc/hosts block then exit")
    parser.add_argument("--list",         action="store_true",    help="List configured aliases then exit")
    parser.add_argument("--list-certs",   action="store_true",    help="List generated TLS certs then exit")
    parser.add_argument("--add-alias",    nargs=2, metavar=("FAKE", "REAL"),
                        help="Add a one-off alias (e.g. --add-alias mybook.local www.facebook.com)")
    parser.add_argument("--remove-alias", metavar="FAKE",
                        help="Remove alias for FAKE domain (use with --save to persist)")
    parser.add_argument("--disable-alias", metavar="FAKE",
                        help="Disable alias (keeps config entry, sets enabled=false)")
    parser.add_argument("--enable-alias", metavar="FAKE",
                        help="Re-enable a previously disabled alias")
    parser.add_argument("--export", metavar="DIR",
                        help="Export hosts block + PAC file to DIR and exit")
    parser.add_argument("--stats",         action="store_true",
                        help="Print per-alias stats summary then exit")
    parser.add_argument("--save",         action="store_true",
                        help="Persist --add-alias / --remove-alias to config.json")
    parser.add_argument("--verbose",      "-v", action="store_true")
    args = parser.parse_args()

    config_path = args.config or str(Path(__file__).parent / "config.json")
    cfg         = load_config(config_path)

    host         = args.host         or cfg.get("host",         "127.0.0.1")
    port         = args.port         or cfg.get("port",         8080)
    sidecar_port = args.sidecar_port or cfg.get("sidecar_port", 8081)
    cert_dir     = cfg.get("cert_dir", str(Path(__file__).parent / "certs"))

    if args.verbose or cfg.get("verbose"):
        logging.getLogger().setLevel(logging.DEBUG)

    aliases: dict = dict(cfg.get("aliases", {}))

    if args.add_alias:
        fake, real        = args.add_alias
        aliases[fake.lower()] = real.lower()
        log.info(f"[ALIAS] added: {fake} → {real}")
        if args.save:
            cfg["aliases"] = aliases
            save_config(cfg, config_path)

    if args.remove_alias:
        key = args.remove_alias.lower()
        if key in aliases:
            del aliases[key]
            # Also drop any extra_real entries whose value pointed at this fake.
            # Without this they linger in AliasMap._real_to_fake until restart.
            if isinstance(cfg.get("aliases", {}).get(key), dict):
                for extra in cfg["aliases"][key].get("extra_real", []):
                    aliases.pop(extra, None)
            log.info(f"[ALIAS] removed: {key}")
            if args.save:
                cfg["aliases"] = aliases
                save_config(cfg, config_path)
        else:
            print(f"[WARN] --remove-alias: '{key}' not found in aliases")

    if args.disable_alias:
        key = args.disable_alias.lower()
        raw_aliases = cfg.get("aliases", {})
        if key in raw_aliases:
            val = raw_aliases[key]
            if isinstance(val, str):
                raw_aliases[key] = {"real": val, "enabled": False}
            else:
                raw_aliases[key]["enabled"] = False
            log.info(f"[ALIAS] disabled: {key}")
            if args.save:
                cfg["aliases"] = raw_aliases
                save_config(cfg, config_path)
            # Refresh working aliases dict used for this run
            aliases = {k: v for k, v in raw_aliases.items()
                       if not (isinstance(v, dict) and not v.get("enabled", True))}
        else:
            print(f"[WARN] --disable-alias: '{key}' not found in aliases")

    if args.enable_alias:
        key = args.enable_alias.lower()
        raw_aliases = cfg.get("aliases", {})
        if key in raw_aliases:
            val = raw_aliases[key]
            if isinstance(val, dict):
                val["enabled"] = True
                raw_aliases[key] = val
            log.info(f"[ALIAS] enabled: {key}")
            if args.save:
                cfg["aliases"] = raw_aliases
                save_config(cfg, config_path)
            aliases = {k: v for k, v in raw_aliases.items()
                       if not (isinstance(v, dict) and not v.get("enabled", True))}
        else:
            print(f"[WARN] --enable-alias: '{key}' not found in aliases")

    if not aliases:
        print("[ERROR] No aliases configured.")
        print('        Edit config.json → "aliases": {"mybook.local": "www.facebook.com"}')
        print("        Or: python proxy.py --add-alias mybook.local www.facebook.com")
        sys.exit(1)

    alias_map = AliasMap(aliases)
    stats     = Stats()
    stats.init(alias_map.stats_keys)

    # Restore stats from the previous run if the dump file exists.
    stats_path = Path(cfg.get("data_dir", "evil_data")) / "stats.json"
    stats.load(stats_path)

    if args.hosts:
        print(_hosts_block(aliases))
        sys.exit(0)

    if args.export:
        _run_export(aliases, args.export, host, port)

    if args.check:
        _run_check(aliases, cert_dir, cfg)

    if args.list:
        w = max((len(f) for f in aliases), default=20)
        print(f"{'Fake domain':<{w}}  →  Real upstream")
        print("-" * (w + 20))
        for fake, val in sorted(aliases.items()):
            real   = val if isinstance(val, str) else val["real"]
            extras = [] if isinstance(val, str) else val.get("extra_real", [])
            print(f"{fake:<{w}}  →  {real}")
            for e in extras:
                print(f"  {'(cdn)':<{w - 2}}       {e}")
        sys.exit(0)

    if args.list_certs:
        list_certs(cert_dir)
        sys.exit(0)

    if args.stats:
        _run_stats(stats_path)

    if args.setup:
        setup_certs(aliases, cert_dir)
        sys.exit(0)

    asyncio.run(run_proxy(
        host, port, sidecar_port, alias_map, cfg,
        cert_dir, config_path, stats, stats_path,
    ))


if __name__ == "__main__":
    main()
