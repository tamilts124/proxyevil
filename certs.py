"""
certs.py — TLS certificate generation via mkcert and cert discovery for mitmproxy.
"""

import hashlib
import logging
import shutil
import subprocess
import sys
from pathlib import Path

log = logging.getLogger("proxyevil.certs")


def setup_certs(aliases: dict, cert_dir: str):
    """Generate per-alias TLS certificates using mkcert.

    Skips domains that already have certs.  Exits with an error message if
    mkcert is not on PATH.
    """
    p = Path(cert_dir)
    p.mkdir(parents=True, exist_ok=True)

    if not shutil.which("mkcert"):
        print(
            "[CERT] ERROR: mkcert not found.\n"
            "       Install from https://github.com/FiloSottile/mkcert/releases\n"
            "       Then run: mkcert -install"
        )
        sys.exit(1)

    any_generated = False
    for fake in aliases.keys():
        cert_file = p / f"{fake}.pem"
        key_file  = p / f"{fake}-key.pem"
        if cert_file.exists() and key_file.exists():
            print(f"[CERT] already exists: {cert_file.name}")
            continue
        print(f"[CERT] generating cert for {fake} …")
        result = subprocess.run(
            [
                "mkcert",
                "-cert-file", str(cert_file),
                "-key-file",  str(key_file),
                fake,
                f"*.{fake}",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"[CERT] FAILED for {fake}:\n{result.stderr}")
        else:
            print(f"[CERT] ✓ {cert_file.name}")
            any_generated = True

    print(f"\n[CERT] All certs in: {p.resolve()}")
    if any_generated:
        print("[CERT] Restart the proxy (or run --setup again) to load new certs.")


def collect_certs(aliases: dict, cert_dir: str) -> list[tuple[str, str]]:
    """Return a list of (hostname, cert_pem_path) pairs for all aliases that
    have a mkcert-generated cert on disk.

    This is passed to mitmproxy's ``certs`` option so it presents the correct
    per-domain certificate instead of its own auto-generated CA leaf.
    """
    p     = Path(cert_dir)
    pairs = []
    for fake in aliases.keys():
        cert_file = p / f"{fake}.pem"
        key_file  = p / f"{fake}-key.pem"
        if cert_file.exists() and key_file.exists():
            # mitmproxy expects "hostname=path/to/cert+key.pem" — the .pem file
            # must contain both cert and key concatenated, OR we pass the cert
            # file and mitmproxy finds the key by the -key.pem convention.
            # We build a combined pem so mitmproxy always finds both in one file.
            combined = p / f"{fake}-combined.pem"
            # Rebuild combined pem only when content has changed.
            # Hash-based check is reliable on FAT32 (2 s mtime resolution)
            # and on Docker read-only mounts where mtime is unreliable.
            cert_bytes = cert_file.read_bytes() + b"\n" + key_file.read_bytes()
            src_hash   = hashlib.md5(cert_bytes, usedforsecurity=False).hexdigest()
            stamp_file = p / f"{fake}-combined.md5"
            if not combined.exists() or not stamp_file.exists() or stamp_file.read_text().strip() != src_hash:
                try:
                    combined.write_bytes(cert_bytes)
                    stamp_file.write_text(src_hash)
                except OSError as exc:
                    log.warning(f"[CERT] could not write combined pem for {fake}: {exc}")
                    continue  # skip this alias; mitmproxy will use its own CA
            pairs.append((fake, str(combined)))
            log.debug(f"[CERT] loaded cert for {fake}")
        else:
            log.debug(f"[CERT] no cert found for {fake} — mitmproxy will use its own CA leaf")
    return pairs


def list_certs(cert_dir: str):
    """Print a summary of certs found in *cert_dir*."""
    p = Path(cert_dir)
    if not p.exists():
        print(f"[CERT] cert_dir '{p}' does not exist")
        return
    certs = sorted(c for c in p.glob("*.pem") if "combined" not in c.name and not c.name.endswith("-key.pem"))
    if not certs:
        print(f"[CERT] no certs found in {p.resolve()}")
        return
    print(f"[CERT] {len(certs)} cert file(s) in {p.resolve()}:")
    for c in certs:
        print(f"  {c.name}")
