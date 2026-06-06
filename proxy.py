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
from hosts_manager import is_admin, update_hosts_file

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("proxyevil")


# Fix #12: warn early about missing optional codec dependencies
def _warn_missing_codecs():
    try:
        import brotli  # noqa: F401
    except ImportError:
        log.warning("[CODEC] brotli not installed — brotli-encoded bodies will pass through unrewritten. Run: pip install brotli")
    try:
        import zstandard  # noqa: F401
    except ImportError:
        log.warning("[CODEC] zstandard not installed — zstd-encoded bodies (Cloudflare etc.) will pass through unrewritten. Run: pip install zstandard")


# ── Banner ─────────────────────────────────────────────────────────────────────

def _print_banner(host: str, port: int, sidecar_port: int,
                  alias_map: AliasMap, data_dir: Path, cert_dir: str):
    aliases  = alias_map.mapping
    cert_p   = Path(cert_dir)
    w = 62
    print(f"\n{'=' * w}")
    print(f"  🦹  proxyevil  v{__version__}")
    print(f"  Proxy   : {host}:{port}")
    print(f"  Status  : http://127.0.0.1:{sidecar_port}/")
    print(f"  PAC     : http://127.0.0.1:{sidecar_port}/proxy.pac")
    print(f"  Stats   : http://127.0.0.1:{sidecar_port}/stats.json")
    print(f"  Data    : {data_dir.resolve()}")
    print(f"\n  Aliases : {len(aliases)}")
    for fake, real in sorted(aliases.items()):
        cert_ok = (cert_p / f"{fake}.pem").exists() and (cert_p / f"{fake}-key.pem").exists()
        cert_icon = "🔒" if cert_ok else "► "
        print(f"    {cert_icon} {fake:<28} → {real}")
    print("\n  Automatically added to system hosts file:")
    for fake in sorted(aliases.keys()):
        print(f"    127.0.0.1  {fake}")
    print()
    print("  Trust mitmproxy CA once: visit http://mitm.it in your browser")
    print(f"{'=' * w}\n")


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
        cert_stat = "[OK] present" if cert_ok else "[MISSING] (run --setup)"
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
    token = cfg.get("sidecar_token", "")
    print(f"Sidecar auth : {'on (token set)' if token else 'off (no token configured)'}")
    print()
    if ok:
        print("[PASS] Config looks good.")
    else:
        print("[WARNING] Issues found - see above.")
    sys.exit(0 if ok else 1)


# ── --stats ────────────────────────────────────────────────────────────────────

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


def _run_export(aliases: dict, export_dir: str, host: str, proxy_port: int, cfg: dict):
    """Write hosts block and PAC file to *export_dir* and exit."""
    out = Path(export_dir)
    out.mkdir(parents=True, exist_ok=True)

    hosts_path = out / "hosts.txt"
    pac_path   = out / "proxy.pac"

    hosts_text = _hosts_block(aliases)
    hosts_path.write_text(hosts_text, encoding="utf-8")
    print(f"[EXPORT] hosts   → {hosts_path.resolve()}")

    # Fix #13: use canonical SPOOF_ALL_DOMAINS key (config.py normalises legacy key on load)
    spoof_all = cfg.get("SPOOF_ALL_DOMAINS", False) or any(
        isinstance(v, dict) and v.get("SPOOF_ALL_DOMAINS", False)
        for v in aliases.values()
    )
    pac_text = _pac_file(aliases, host, proxy_port, spoof_all)
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
    cert_dir:     "str | Path",  # Fix J: accept both str and Path consistently
    config_path:  Optional[str],
    stats:        Stats,
    stats_path:   Path,
):
    data_dir = Path(cfg.get("data_dir", "evil_data"))
    data_dir.mkdir(parents=True, exist_ok=True)

    p_cert_dir = Path(cert_dir)
    p_cert_dir.mkdir(parents=True, exist_ok=True)
    confdir = str(p_cert_dir / "mitmproxy_conf")
    Path(confdir).mkdir(parents=True, exist_ok=True)

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
        start_config_watcher(config_path, alias_map, cfg, stats, addon=_addon,
                             verbose=cfg.get("verbose", False))

    verbose = cfg.get("verbose", False)
    install_log_filters(alias_map, verbose=verbose)

    _print_banner(host, port, sidecar_port, alias_map, data_dir, cert_dir)

    loop = asyncio.get_running_loop()
    _stats_dumped = False

    def _dump_stats_once():
        nonlocal _stats_dumped
        if not _stats_dumped:
            _stats_dumped = True
            stats.dump(stats_path)

    def _on_sigterm(*_):
        log.info("[*] SIGTERM received — shutting down…")
        _dump_stats_once()
        loop.call_soon_threadsafe(master.shutdown)

    try:
        signal.signal(signal.SIGTERM, _on_sigterm)
    except (OSError, ValueError):
        pass

    if cfg.get("auto_install_ca", False):
        async def _auto_install_ca():
            import os, subprocess
            if os.name != 'nt':
                return
            ca_path     = Path(confdir) / "mitmproxy-ca-cert.cer"
            marker_path = Path(confdir) / ".ca_installed"
            for _ in range(20):
                if ca_path.exists():
                    break
                await asyncio.sleep(0.5)
            if ca_path.exists() and not marker_path.exists():
                log.info(f"[CERT] Auto-installing {ca_path.name} to Windows Trusted Root Store "
                         f"(auto_install_ca=true in config)...")
                try:
                    subprocess.run(
                        ["certutil", "-addstore", "root", str(ca_path)],
                        check=True, capture_output=True,
                    )
                    marker_path.touch()
                    log.info("[CERT] ✓ CA Certificate successfully installed!")
                except subprocess.CalledProcessError as e:
                    stderr = e.stderr.decode('utf-8', errors='ignore') if e.stderr else ""
                    log.warning(f"[CERT] Auto-install failed: {stderr}")
        loop.create_task(_auto_install_ca())
    else:
        log.debug("[CERT] auto_install_ca is false — skipping automatic CA installation")

    try:
        await master.run()
    except KeyboardInterrupt:
        print("\n[*] Stopping proxyevil…")
        _dump_stats_once()
        master.shutdown()


# ── CLI helpers (#23: split main() into focused sub-functions) ────────────────

def _apply_cli_mutations(args, cfg: dict, aliases: dict, config_path: str) -> dict:
    """Apply --add-alias / --remove-alias / --disable-alias / --enable-alias.
    Returns the (possibly mutated) aliases dict.
    """
    # Fix #8: config_path is now passed in — no need to recompute here.
    if args.add_alias:
        fake, real        = args.add_alias
        aliases[fake.lower()] = real.lower()
        log.info(f"[ALIAS] added: {fake} \u2192 {real}")
        if args.save:
            cfg["aliases"][fake.lower()] = real.lower()
            save_config(cfg, config_path)

    if args.remove_alias:
        key = args.remove_alias.lower()
        if key in aliases:
            del aliases[key]
            log.info(f"[ALIAS] removed: {key}")
            if args.save:
                cfg["aliases"].pop(key, None)
                save_config(cfg, config_path)
        else:
            print(f"[WARN] --remove-alias: '{key}' not found in aliases")

    if args.disable_alias:
        key = args.disable_alias.lower()
        raw_aliases = dict(cfg.get("aliases", {}))  # copy — don't mutate live cfg unless --save
        if key in raw_aliases:
            val = raw_aliases[key]
            if isinstance(val, str):
                raw_aliases[key] = {"real": val, "enabled": False}
            else:
                raw_aliases[key] = dict(val)
                raw_aliases[key]["enabled"] = False
            log.info(f"[ALIAS] disabled: {key}")
            if args.save:
                cfg["aliases"] = raw_aliases
                save_config(cfg, config_path)
            aliases = {k: v for k, v in raw_aliases.items()
                       if not (isinstance(v, dict) and not v.get("enabled", True))}
        else:
            print(f"[WARN] --disable-alias: '{key}' not found in aliases")

    if args.enable_alias:
        key = args.enable_alias.lower()
        raw_aliases = dict(cfg.get("aliases", {}))  # copy — don't mutate live cfg unless --save
        if key in raw_aliases:
            val = raw_aliases[key]
            if isinstance(val, dict):
                val = dict(val)
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

    return aliases


def _run_info_commands(args, aliases: dict,
                       host: str, port: int, cert_dir: str, cfg: dict):
    """Handle all info/setup-only flags (all exit when matched).
    Fix #18: AliasMap is not built before this runs — none of these paths need it.
    """

    if args.hosts:
        print(_hosts_block(aliases))
        sys.exit(0)

    if args.export:
        _run_export(aliases, args.export, host, port, cfg)

    if args.check:
        _run_check(aliases, cert_dir, cfg)

    if args.list:
        w = max((len(f) for f in aliases), default=20)
        print(f"{'Fake domain':<{w}}  \u2192  Real upstream")
        print("-" * (w + 20))
        for fake, val in sorted(aliases.items()):
            real       = val if isinstance(val, str) else val["real"]
            extra_list = [] if isinstance(val, str) else (val.get("EXTRA_REAL_DOMAINS_TO_SPOOF") or val.get("extra_real") or [])
            print(f"{fake:<{w}}  \u2192  {real}")
            for e in extra_list:
                print(f"  {'(cdn)':<{w - 2}}       {e}")
        sys.exit(0)

    if args.list_certs:
        list_certs(cert_dir)
        sys.exit(0)

    if args.setup:
        setup_certs(aliases, cert_dir)
        sys.exit(0)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    # Fix #20: parse args before the admin check so --no-hosts can skip it.
    parser = argparse.ArgumentParser(
        description="proxyevil — domain-alias MITM proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version",       "-V", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config",        "-c", default=None,     help="Path to config.json")
    parser.add_argument("--host",                default=None,     help="Listen host (default 127.0.0.1)")
    parser.add_argument("--port",          "-p", type=int,         help="Proxy port (default 8080)")
    parser.add_argument("--sidecar-port",        type=int,         help="Status/PAC port (default 8081)")
    parser.add_argument("--setup",         action="store_true",    help="Generate TLS certs then exit")
    parser.add_argument("--check",         action="store_true",    help="Validate config and cert status then exit")
    parser.add_argument("--hosts",         action="store_true",    help="Print /etc/hosts block then exit")
    parser.add_argument("--no-hosts",      action="store_true",
                        help="Skip hosts file modification (allows running without Administrator/root)")
    parser.add_argument("--list",          action="store_true",    help="List configured aliases then exit")
    parser.add_argument("--list-certs",    action="store_true",    help="List generated TLS certs then exit")
    parser.add_argument("--add-alias",     nargs=2, metavar=("FAKE", "REAL"),
                        help="Add a one-off alias (e.g. --add-alias mybook.local www.facebook.com)")
    parser.add_argument("--remove-alias",  metavar="FAKE",
                        help="Remove alias for FAKE domain (use with --save to persist)")
    parser.add_argument("--disable-alias", metavar="FAKE",
                        help="Disable alias (keeps config entry, sets enabled=false)")
    parser.add_argument("--enable-alias",  metavar="FAKE",
                        help="Re-enable a previously disabled alias")
    parser.add_argument("--export",        metavar="DIR",
                        help="Export hosts block + PAC file to DIR and exit")
    parser.add_argument("--stats",         action="store_true",
                        help="Print per-alias stats summary then exit")
    parser.add_argument("--save",          action="store_true",
                        help="Persist --add-alias / --remove-alias to config.json")
    parser.add_argument("--verbose",       "-v", action="store_true")
    args = parser.parse_args()

    # Fix #20: only require admin when hosts file will be written
    needs_admin = not args.no_hosts
    if needs_admin and not is_admin():
        print("[ERROR] proxyevil must be run as Administrator/root to modify the hosts file.")
        print("        Use --no-hosts to skip hosts file modification and run without elevation.")
        sys.exit(1)

    config_path = args.config or str(Path(__file__).parent / "config.json")
    cfg         = load_config(config_path)

    host         = args.host         or cfg.get("host",         "127.0.0.1")
    port         = args.port         or cfg.get("port",         8080)
    sidecar_port = args.sidecar_port or cfg.get("sidecar_port", 8081)
    cert_dir     = cfg.get("cert_dir", str(Path(__file__).parent / "certs"))

    if args.verbose or cfg.get("verbose"):
        logging.getLogger().setLevel(logging.DEBUG)

    # Fix #12: warn about missing optional codecs before anything else
    _warn_missing_codecs()

    aliases: dict = dict(cfg.get("aliases", {}))
    aliases = _apply_cli_mutations(args, cfg, aliases, config_path)

    if not aliases:
        print("[ERROR] No aliases configured.")
        print('        Edit config.json → "aliases": {"mybook.local": "www.facebook.com"}')
        print("        Or: python proxy.py --add-alias mybook.local www.facebook.com")
        sys.exit(1)

    # Fix #3: resolve stats_path and check --stats BEFORE building AliasMap
    # (avoids building the map for a read-only stats query)
    stats_path = Path(cfg.get("data_dir", "evil_data")) / "stats.json"
    if args.stats:
        _run_stats(stats_path)   # always calls sys.exit()

    # Fix #18: run info-only commands before building AliasMap (they don't need it)
    _run_info_commands(args, aliases, host, port, cert_dir, cfg)

    alias_map = AliasMap(aliases)

    if not args.no_hosts:
        root_aliases = {k: v if isinstance(v, str) else v.get("real", "") for k, v in aliases.items()}
        update_hosts_file(root_aliases)

    stats = Stats()
    stats.init(alias_map.stats_keys)
    stats.load(stats_path)

    asyncio.run(run_proxy(
        host, port, sidecar_port, alias_map, cfg,
        cert_dir, config_path, stats, stats_path,
    ))


if __name__ == "__main__":
    main()
