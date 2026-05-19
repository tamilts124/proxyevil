"""
codec.py — Body decompression and recompression helpers.

Handles gzip, deflate/zlib, brotli, and zstd transparently so the rewriter
can work on plain text regardless of what the upstream sent.
"""

import gzip
import logging
import zlib
from typing import Tuple

log = logging.getLogger("proxyevil.codec")

# Maximum decompressed output size (64 MB).  Checked for brotli and zstd which
# don't expose a streaming API here; gzip/deflate raise MemoryError naturally.
_MAX_DECOMP = 64 * 1024 * 1024


def decompress(data: bytes, encoding: str) -> Tuple[bytes, bool, str]:
    """Decompress *data* according to *encoding*.

    Returns ``(bytes, did_decompress, actual_enc)``.  Callers must check the
    flag: if it is ``False`` the original bytes are returned unchanged and the
    Content-Encoding header must be left intact.  ``actual_enc`` distinguishes
    between ``'deflate'`` (zlib-wrapped) and ``'deflate-raw'`` (raw deflate)
    so ``recompress()`` can mirror the original format exactly.
    """
    enc = encoding.lower()
    try:
        if enc == "gzip":
            return gzip.decompress(data), True, enc
        if enc in ("deflate", "zlib"):
            try:
                return zlib.decompress(data), True, "deflate"
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS), True, "deflate-raw"
        if enc == "br":
            try:
                import brotli  # type: ignore
                out = brotli.decompress(data)
                if len(out) > _MAX_DECOMP:
                    log.warning(f"[CODEC] br decompressed size {len(out)} exceeds limit {_MAX_DECOMP} — skipping")
                    return data, False, enc
                return out, True, enc
            except ImportError:
                log.warning("[CODEC] brotli not installed — skipping br body (pip install brotli)")
                return data, False, enc
        if enc == "zstd":
            try:
                import zstandard as zstd  # type: ignore
                out = zstd.ZstdDecompressor().decompress(data, max_output_size=_MAX_DECOMP)
                return out, True, enc
            except ImportError:
                log.warning("[CODEC] zstandard not installed — skipping zstd body (pip install zstandard)")
                return data, False, enc
    except Exception as exc:
        log.debug(f"[CODEC] decompress({encoding}) failed: {exc}")
    return data, False, enc


def recompress(data: bytes, encoding: str) -> bytes:
    """Recompress *data* using *encoding*. Returns original bytes on failure.

    Accepts ``'deflate-raw'`` (returned by ``decompress()`` when the upstream
    used raw deflate without the zlib wrapper) and mirrors it faithfully.
    """
    enc = encoding.lower()
    try:
        if enc == "gzip":
            return gzip.compress(data)
        if enc == "deflate":
            return zlib.compress(data)
        if enc == "deflate-raw":
            # Recompress as raw deflate (no zlib header/trailer) to match what
            # the server originally sent and what the client expects.
            co = zlib.compressobj(wbits=-zlib.MAX_WBITS)
            return co.compress(data) + co.flush()
        if enc == "br":
            try:
                import brotli  # type: ignore
                return brotli.compress(data)
            except ImportError:
                return data
        if enc == "zstd":
            try:
                import zstandard as zstd  # type: ignore
                return zstd.ZstdCompressor().compress(data)
            except ImportError:
                return data
    except Exception as exc:
        log.debug(f"[CODEC] recompress({encoding}) failed: {exc}")
    return data
