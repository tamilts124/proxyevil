"""
logfilter.py — Noise suppression for mitmproxy's internal loggers.

Problems solved
---------------
1.  TLS handshake WARNING for every non-alias domain the browser touches
    (googleapis.com, gvt2.com, etc.).  mitmproxy still intercepts those
    CONNECT tunnels but, because they are in ignore_hosts, it passes them
    through transparently.  The TLS warning fires during the brief window
    before the ignore_hosts check kicks in, or for non-CONNECT plaintext.

2.  ERROR / Unhandled error in task — WinError 10054 / ConnectionResetError
    raised inside asyncio's proactor when a remote host drops a TCP
    connection.  This is a known Windows asyncio / mitmproxy issue and is
    completely harmless; we downgrade it to DEBUG.

3.  INFO connect/disconnect chatter for domains that are NOT in the alias
    map.  When the browser sends all its background requests through the
    proxy these lines flood the console.  We suppress them unless --verbose.

Usage
-----
    from logfilter import install_log_filters
    install_log_filters(alias_map, verbose=False)

Call this once, after the AliasMap is built and before asyncio.run().
Filters are applied to the root logger so they catch every handler.
"""

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from alias_map import AliasMap

# ── patterns that identify the noisy messages ─────────────────────────────────

# "Client TLS handshake failed. The client does not trust the proxy's
#  certificate for beacons2.gvt2.com ..."
_TLS_HANDSHAKE_RE = re.compile(
    r"Client TLS handshake failed",
    re.IGNORECASE,
)

# "Unhandled error in task." followed (a few lines later or in one record)
# by WinError 10054 / ConnectionResetError / socket shutdown errors.
# mitmproxy emits these as a single log record whose message starts with
# "Unhandled error in task."
_WINERROR_RE = re.compile(
    r"Unhandled error in task|"
    r"WinError 10054|"
    r"ConnectionResetError|"
    r"socket\.shutdown|"
    r"SHUT_RDWR",
    re.IGNORECASE,
)

# "error establishing server connection: [WinError 1225] ..."
# These fire when a non-alias CONNECT target actively refuses the TCP
# connection.  Harmless noise.
_CONN_REFUSED_RE = re.compile(
    r"error establishing server connection.*WinError",
    re.IGNORECASE,
)

# "client connect", "client disconnect", "server connect X:443",
# "server disconnect X:443"  — lifecycle chatter from mitmproxy's
# proxy.server and proxy.client log channels.
_LIFECYCLE_RE = re.compile(
    r"^(?:client|server) (?:connect|disconnect)\b",
    re.IGNORECASE,
)


class _MitmNoiseFilter(logging.Filter):
    """Drop (or downgrade) mitmproxy log records that are pure noise.

    Parameters
    ----------
    alias_domains:
        Set of fake domain names that proxyevil owns.  Lifecycle messages
        that mention one of these domains are *kept* (they are meaningful).
    verbose:
        When True, lifecycle messages are kept regardless of domain.
    """

    def __init__(self, alias_domains: set[str], verbose: bool = False):
        super().__init__()
        self.alias_domains = alias_domains
        self.verbose       = verbose

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()

        # ── WinError 10054 / ConnectionResetError ─────────────────────────────
        # Downgrade ERROR → DEBUG so it disappears at INFO level but is still
        # visible with --verbose.
        if record.levelno >= logging.ERROR and _WINERROR_RE.search(msg):
            record.levelno   = logging.DEBUG
            record.levelname = "DEBUG"
            return True  # let through at new (DEBUG) level; root handler drops it

        # ── TLS handshake failure for non-alias domain ────────────────────────
        if record.levelno >= logging.WARNING and _TLS_HANDSHAKE_RE.search(msg):
            # Keep if it mentions one of our alias domains (shouldn't happen,
            # but better safe) or if verbose.
            if self.verbose or any(d in msg for d in self.alias_domains):
                return True
            return False  # suppress

        # ── WinError 1225 — connection refused on non-alias CONNECT ──────────
        if _CONN_REFUSED_RE.search(msg):
            if self.verbose:
                record.levelno   = logging.DEBUG
                record.levelname = "DEBUG"
                return True
            return False

        # ── lifecycle connect/disconnect chatter ──────────────────────────────
        if not self.verbose and _LIFECYCLE_RE.match(msg):
            # Keep if the message names one of our alias domains.
            if any(d in msg for d in self.alias_domains):
                return True
            return False  # suppress background traffic

        return True  # keep everything else


# ── mitmproxy logger names that emit the noisy records ────────────────────────
# mitmproxy uses Python's logging under the hood; these are its internal
# channel names.  We attach the filter to each individually so the root
# logger's handlers (which may be very broad) are not accidentally silenced
# for other modules.
_MITM_LOGGERS = (
    "mitmproxy",
    "mitmproxy.proxy",
    "mitmproxy.proxy.server",
    "mitmproxy.proxy.layers",
    "mitmproxy.proxy.layers.tls",
    "mitmproxy.connection",
    "asyncio",          # WinError 10054 surfaces here on Windows
)


def install_log_filters(alias_map: "AliasMap", verbose: bool = False) -> None:
    """Attach noise-suppression filters to mitmproxy's internal loggers.

    Safe to call multiple times (idempotent — removes any previous
    ``_MitmNoiseFilter`` instances before installing a fresh one so that a
    hot-reload with a changed alias map is reflected immediately).

    Parameters
    ----------
    alias_map:
        The live AliasMap instance.  The filter snapshots the current
        fake-domain set; call this function again after a reload if the
        alias set changes and you want the filter updated.
    verbose:
        Pass True when --verbose is active; suppression is mostly disabled.
    """
    alias_domains = set(alias_map.mapping.keys())
    new_filter    = _MitmNoiseFilter(alias_domains, verbose=verbose)

    for name in _MITM_LOGGERS:
        lgr = logging.getLogger(name)
        # Remove any stale instance from a previous call.
        lgr.filters = [f for f in lgr.filters if not isinstance(f, _MitmNoiseFilter)]
        lgr.addFilter(new_filter)

    # Also attach to the root logger to catch records that bubble up without
    # a named channel.
    root = logging.getLogger()
    root.filters = [f for f in root.filters if not isinstance(f, _MitmNoiseFilter)]
    root.addFilter(new_filter)

    log = logging.getLogger("proxyevil.logfilter")
    action = "verbose — minimal suppression" if verbose else "suppressing TLS/lifecycle noise"
    log.debug(f"[LOGFILTER] installed ({action}) for {len(alias_domains)} alias domain(s)")
