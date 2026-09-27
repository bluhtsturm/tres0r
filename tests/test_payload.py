import importlib
import io
import json
import os
import zlib

import pytest

from tres0r import payload
from tres0r.errors import FormatError, IntegrityError
from tres0r.payload import BlockReader, IndexEntry, PayloadWriter, RandomAccessPayload
from tres0r.stream import CHUNK_SIZE, ENC_CHUNK_SIZE, DecryptingReader, EncryptingWriter

KEY = bytes(range(32))


def _available_backends():
    found = []
    for module, name in (("compression.zstd", "stdlib"), ("zstandard", "zstandard")):
        try:
            importlib.import_module(module)
            found.append(name)
        except ImportError:
            pass
    return found


def write_payload(chunks, compress=False, marks_at=()):
    """chunks: Liste von bytes; vor den Indizes in marks_at wird ein Seek-Punkt gesetzt."""
    out = io.BytesIO()
    enc = EncryptingWriter(out, KEY)
    writer = PayloadWriter(enc, compress)
    marks = []
    for i, data in enumerate(chunks):
        if i in marks_at:
            marks.append((writer.tell(), writer.mark()))
        writer.write(data)
    writer.close()
    enc.write_zeros(1000)  # Padding
    enc.finish()
    return out.getvalue(), marks


def read_all(blob, compress=False):
    reader = DecryptingReader(io.BytesIO(blob), KEY)
    blocks, data = payload.decoded_reader(reader, int(compress))
    result = data.read()
    blocks.drain()
    reader.finish()
    return result


# --- Blöcke -----------------------------------------------------------------
@pytest.mark.parametrize("sizes", [[], [0], [1], [payload.MAX_BLOCK], [payload.MAX_BLOCK + 1, 5, 3 * CHUNK_SIZE]])
def test_block_roundtrip(sizes):
    parts = [os.urandom(n) for n in sizes]
    blob, _ = write_payload(parts)
    assert read_all(blob) == b"".join(parts)


def test_block_reader_limits():
    with pytest.raises(FormatError, match="zu groß"):
        BlockReader(io.BytesIO((payload.MAX_READ_BLOCK + 1).to_bytes(4, "big"))).read()
    with pytest.raises(FormatError, match="abgeschnitten"):
        BlockReader(io.BytesIO((10).to_bytes(4, "big") + b"kurz")).read()
    reader = BlockReader(io.BytesIO((3).to_bytes(4, "big") + b"abc" + bytes(4) + b"PADDING"))
    assert reader.read() == b"abc" and reader.read() == b"" and reader.done


# --- Kompression ------------------------------------------------------------
@pytest.mark.skipif(not _available_backends(), reason="kein zstd")
def test_compressed_roundtrip_and_marks():
    parts = [b"A" * 700_000, os.urandom(200_000), b"B" * 1_500_000, b"ende"]
    blob, marks = write_payload(parts, compress=True, marks_at={1, 2, 3})
    plain = b"".join(parts)
    assert read_all(blob, compress=True) == plain
    assert len(blob) < len(plain) // 2
    # Von jedem Seek-Punkt aus dekodieren
    access = RandomAccessPayload(io.BytesIO(blob), KEY, 0, len(blob))
    for position, (offset, skip) in marks:
        _, data = payload.decoded_reader(access.open_at(offset), 1)
        payload.skip(data, skip)
        assert data.read(50) == plain[position:position + 50]


@pytest.mark.parametrize("backend", ["stdlib", "zstandard"])
def test_backends_are_interchangeable(backend, monkeypatch):
    """Mit dem einen Backend geschrieben, mit dem anderen gelesen (RFC 8878)."""
    available = _available_backends()
    if len(available) < 2:
        pytest.skip("braucht beide zstd-Backends (Python >= 3.14 + zstandard)")
    other = "zstandard" if backend == "stdlib" else "stdlib"
    monkeypatch.setattr(payload, "zstd_backend", lambda: backend)
    blob, _ = write_payload([b"hallo " * 100_000], compress=True)
    monkeypatch.setattr(payload, "zstd_backend", lambda: other)
    assert read_all(blob, compress=True) == b"hallo " * 100_000


def test_missing_zstd_gives_clear_error(monkeypatch):
    monkeypatch.setattr(payload, "zstd_backend", lambda: None)
    with pytest.raises(payload.Tres0rError, match="zstandard"):
        payload.FrameCompressor()


# --- Seek-Punkte ohne Kompression ------------------------------------------
def test_uncompressed_marks_are_exact():
    parts = [os.urandom(n) for n in (100, 70_000, 1, 200_000)]
    blob, marks = write_payload(parts, marks_at={0, 1, 2, 3})
    plain = b"".join(parts)
    access = RandomAccessPayload(io.BytesIO(blob), KEY, 0, len(blob))
    for position, (offset, skip) in marks:
        assert skip == 0
        _, data = payload.decoded_reader(access.open_at(offset), 0)
        assert data.read(30) == plain[position:position + 30]


# --- Wahlfreier Zugriff -----------------------------------------------------
def test_random_access_reads_and_detects_damage():
    blob, _ = write_payload([os.urandom(5 * CHUNK_SIZE)])
    access = RandomAccessPayload(io.BytesIO(blob), KEY, 0, len(blob))
    stream_plain = DecryptingReader(io.BytesIO(blob), KEY).read()
    assert access.plaintext_size == len(stream_plain)
    for offset, size in [(0, 10), (CHUNK_SIZE - 3, 10), (3 * CHUNK_SIZE + 7, 2 * CHUNK_SIZE)]:
        assert access.pread(offset, size) == stream_plain[offset:offset + size]
    with pytest.raises(FormatError):
        access.pread(access.plaintext_size - 1, 2)

    bad = bytearray(blob)
    bad[2 * ENC_CHUNK_SIZE + 5] ^= 1
    damaged = RandomAccessPayload(io.BytesIO(bytes(bad)), KEY, 0, len(bad))
    assert damaged.pread(0, 10) == stream_plain[:10]  # andere Chunks bleiben lesbar
    with pytest.raises(IntegrityError):
        damaged.pread(2 * CHUNK_SIZE, 10)


@pytest.mark.parametrize("cut", ["letzter Chunk", "halber Chunk", "ein Byte"])
def test_random_access_detects_truncation_at_end(cut):
    blob, _ = write_payload([os.urandom(3 * CHUNK_SIZE + 100)])
    keep = {"letzter Chunk": (len(blob) // ENC_CHUNK_SIZE) * ENC_CHUNK_SIZE,
            "halber Chunk": len(blob) - 60, "ein Byte": len(blob) - 1}[cut]
    short = blob[:keep]
    with pytest.raises(IntegrityError):
        access = RandomAccessPayload(io.BytesIO(short), KEY, 0, len(short))
        access.pread(access.plaintext_size - 16, 16)


# --- Index ------------------------------------------------------------------
def _with_index(entries, extra=b""):
    out = io.BytesIO()
    enc = EncryptingWriter(out, KEY)
    enc.write(b"daten")
    enc.write(extra or payload.index_trailer(payload.encode_index(entries)))
    enc.finish()
    blob = out.getvalue()
    return RandomAccessPayload(io.BytesIO(blob), KEY, 0, len(blob))


def test_index_roundtrip():
    entries = [IndexEntry("Ordner", "d", 0, 1, 0, 0),
               IndexEntry("Ordner/Überraschung.txt", "f", 5, 2, 10, 3, "a" * 64),
               IndexEntry("Ordner/verweis", "l", 0, 3, 20, 0, link="Überraschung.txt")]
    assert payload.read_index(_with_index(entries)) == entries


@pytest.mark.parametrize("trailer", [
    b"kein index",
    payload._TRAILER.pack(10**12, payload.INDEX_MAGIC),
    zlib.compress(b"kein json") + payload._TRAILER.pack(len(zlib.compress(b"kein json")), payload.INDEX_MAGIC),
    payload.index_trailer(zlib.compress(json.dumps({"v": 99, "entries": []}).encode())),
    payload.index_trailer(zlib.compress(json.dumps({"v": 1, "entries": [{"n": 1}]}).encode())),
    payload.index_trailer(zlib.compress(json.dumps(
        {"v": 1, "entries": [{"n": "x", "t": "f", "s": -1, "m": 0, "o": 0, "k": 0}]}).encode())),
])
def test_broken_index_is_rejected(trailer):
    with pytest.raises(FormatError):
        payload.read_index(_with_index([], extra=trailer))


def test_index_zip_bomb_is_bounded(monkeypatch):
    monkeypatch.setattr(payload, "MAX_INDEX_JSON", 1000)
    entries = [IndexEntry(f"datei{i}", "f", 0, 0, 0, 0) for i in range(200)]
    with pytest.raises(FormatError, match="zu groß"):
        payload.read_index(_with_index(entries))


@pytest.mark.skipif(not _available_backends(), reason="kein zstd")
@pytest.mark.parametrize("damage", ["magic", "halbiert", "letztes Byte", "zwei Frames, zweiter halb"])
def test_corrupt_zstd_is_format_error(damage):
    """Fuzzer-Fund: Dekodierfehler kamen als ZstdError/EOFError an, und zstandard
    lieferte bei abgeschnittenen Frames stillschweigend weniger Daten."""
    compressor = payload.FrameCompressor()
    frame = compressor.compress(os.urandom(5000) + b"A" * 50_000) + compressor.end_frame()
    data = {
        "magic": b"\x00" * 4 + frame[4:],
        "halbiert": frame[: len(frame) // 2],
        "letztes Byte": frame[:-1],
        "zwei Frames, zweiter halb": frame + frame[: len(frame) // 2],
    }[damage]
    framed = len(data).to_bytes(4, "big") + data + bytes(4)  # ein Block + Terminator
    stream = payload.open_decompressor(payload.BlockReader(io.BytesIO(framed)))
    with pytest.raises(FormatError):
        while stream.read(4096):
            pass


@pytest.mark.skipif(not _available_backends(), reason="kein zstd")
def test_zstd_output_is_fed_in_small_steps():
    """Ein hoch komprimierbarer Frame wird schrittweise ausgegeben, nicht auf einmal."""
    compressor = payload.FrameCompressor(level=19)
    frame = compressor.compress(bytes(64 << 20)) + compressor.end_frame()  # 64 MiB Nullen
    framed = len(frame).to_bytes(4, "big") + frame + bytes(4)
    reader = payload.open_decompressor(payload.BlockReader(io.BytesIO(framed)))
    first = reader.read(1)
    assert first == b"\x00" and len(reader._buf) < 40 << 20
    total = 1
    while chunk := reader.read(1 << 20):
        total += len(chunk)
    assert total == 64 << 20
