"""Tests for codec.py — compression/decompression, including corrupt-input fallback."""
import gzip
import zlib
import pytest
from codec import decompress, recompress


# ── Normal ───────────────────────────────────────────────────────────────
def test_gzip_roundtrip():
    raw = b"hello world" * 100
    comp = gzip.compress(raw)
    out, ok, enc = decompress(comp, "gzip")
    assert ok and out == raw and enc == "gzip"
    recomp, rok = recompress(out, "gzip")
    assert rok
    out2, ok2, _ = decompress(recomp, "gzip")
    assert ok2 and out2 == raw


def test_deflate_roundtrip():
    raw = b"deflate me"
    comp = zlib.compress(raw)
    out, ok, enc = decompress(comp, "deflate")
    assert ok and out == raw and enc == "deflate"


def test_deflate_raw_roundtrip():
    raw = b"raw deflate payload"
    co = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    comp = co.compress(raw) + co.flush()
    out, ok, enc = decompress(comp, "deflate")
    assert ok and out == raw and enc == "deflate-raw"
    recomp, rok = recompress(out, "deflate-raw")
    assert rok


# ── Boundary / medium ────────────────────────────────────────────────────
def test_unknown_encoding_passthrough():
    out, ok, enc = decompress(b"plain", "identity")
    assert ok is False and out == b"plain"


def test_empty_bytes_gzip():
    # Empty gzip stream: GzipFile hits EOF immediately with no error —
    # decompress() treats this as a successful (empty) decompression.
    out, ok, enc = decompress(b"", "gzip")
    assert ok is True and out == b""


# ── High: corrupt / failure handling ──────────────────────────────────────
def test_corrupt_gzip_falls_back():
    out, ok, enc = decompress(b"not really gzip data", "gzip")
    assert ok is False
    assert out == b"not really gzip data"  # unchanged, safe fallback


def test_corrupt_deflate_falls_back():
    out, ok, enc = decompress(b"\x00\x01\x02garbage", "deflate")
    assert ok is False


def test_corrupt_brotli_falls_back():
    out, ok, enc = decompress(b"garbage-not-brotli", "br")
    assert ok is False
    assert out == b"garbage-not-brotli"


def test_corrupt_zstd_falls_back():
    out, ok, enc = decompress(b"garbage-not-zstd", "zstd")
    assert ok is False


def test_recompress_unknown_encoding_fails_safely():
    out, ok = recompress(b"data", "identity")
    assert ok is False and out == b"data"


# ── Extreme: streaming decompression size cap (zip-bomb style protection) ────
def test_deflate_decompress_respects_size_cap(monkeypatch):
    import codec
    monkeypatch.setattr(codec, "_MAX_DECOMP", 1024)
    big = b"A" * (1024 * 1024)
    comp = zlib.compress(big)
    out, ok, enc = codec.decompress(comp, "deflate")
    assert ok is False
    assert out == comp


def test_deflate_decompress_under_cap_succeeds(monkeypatch):
    import codec
    monkeypatch.setattr(codec, "_MAX_DECOMP", 1024 * 1024)
    data = b"hello world" * 10
    comp = zlib.compress(data)
    out, ok, enc = codec.decompress(comp, "deflate")
    assert ok is True and out == data and enc == "deflate"


def test_brotli_decompress_respects_size_cap(monkeypatch):
    brotli = pytest.importorskip("brotli")
    import codec
    monkeypatch.setattr(codec, "_MAX_DECOMP", 1024)
    big = b"B" * (1024 * 1024)
    comp = brotli.compress(big)
    out, ok, enc = codec.decompress(comp, "br")
    assert ok is False
    assert out == comp


def test_brotli_decompress_under_cap_succeeds():
    brotli = pytest.importorskip("brotli")
    import codec
    data = b"hello brotli" * 10
    comp = brotli.compress(data)
    out, ok, enc = codec.decompress(comp, "br")
    assert ok is True and out == data
