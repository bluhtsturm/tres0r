import io
import os
import threading
import time

import pytest

from tres0r import container, payload
from tres0r.errors import Cancelled, IntegrityError
from tres0r.progress import CancelToken, Monitor

from conftest import FAST, PASSWORD, snapshot

needs_zstd = pytest.mark.skipif(payload.zstd_backend() is None, reason="kein zstd")


def prefetch_threads() -> list:
    return [t for t in threading.enumerate() if t.name == "tres0r-prefetch"]


@pytest.fixture
def cores(monkeypatch):
    monkeypatch.setattr(os, "cpu_count", lambda: 4)


class Broken(io.RawIOBase):
    """Liefert 3 MiB, dann einen Fehler – wie ein manipulierter Chunk."""

    def __init__(self):
        self.sent = 0

    def read(self, n=-1):
        if self.sent >= 3 << 20:
            raise IntegrityError("Chunk 48 ist beschädigt")
        self.sent += 1 << 20
        return bytes([self.sent >> 20]) * (1 << 20)


def test_reads_exactly_like_the_source():
    data = os.urandom(5_000_000)
    for size in (1, 7, 4096, 1 << 20, 3_000_001, -1):
        reader = payload.Prefetcher(io.BytesIO(data), chunk=65536, depth=3)
        got = b"".join(iter(lambda: reader.read(size), b"")) if size != -1 else reader.read()
        reader.close()
        assert got == data
    assert not prefetch_threads()


def test_error_arrives_at_its_position():
    reader = payload.Prefetcher(Broken(), chunk=1 << 20)
    assert len(reader.read(3 << 20)) == 3 << 20  # alles vor dem Fehler kommt an
    with pytest.raises(IntegrityError, match="Chunk 48"):
        reader.read(1)
    reader.close()
    assert not prefetch_threads()


def test_close_stops_a_blocked_producer():
    endless = io.RawIOBase()
    endless.read = lambda n=-1: b"x" * n
    reader = payload.Prefetcher(endless, chunk=1 << 16, depth=2)
    reader.read(10)
    time.sleep(0.2)  # Warteschlange voll, Erzeuger blockiert
    started = time.perf_counter()
    reader.close()
    reader.close()  # zweimal ist harmlos
    assert time.perf_counter() - started < 2 and not prefetch_threads()


@needs_zstd
def test_all_read_paths_with_prefetch(tmp_path, sample_tree, cores):
    out = container.create(sample_tree, tmp_path / "z.tres0r", PASSWORD, FAST, compress=True).path
    assert container.verify(out, PASSWORD).files == 6
    assert len(container.list_contents(out, PASSWORD)) == 10
    container.extract(out, tmp_path / "z", PASSWORD)
    assert snapshot(tmp_path / "z" / "Projekt") == snapshot(sample_tree[0])
    assert container.diff(out, sample_tree, PASSWORD).identical
    container.append(out, [sample_tree[1]], PASSWORD, compress=True)
    assert container.verify(out, PASSWORD).segments == 2
    plain = container.create(sample_tree, tmp_path / "p.tres0r", PASSWORD, FAST, compress=True).path
    with open(plain, "rb") as source:  # Pipe-Pfad (ohne Index)
        container.extract_stream(source, tmp_path / "pipe", PASSWORD)
    assert not prefetch_threads()


@needs_zstd
def test_tampering_and_cancel_leave_no_threads(tmp_path, sample_tree, cores):
    out = container.create(sample_tree, tmp_path / "z.tres0r", PASSWORD, FAST, compress=True).path
    raw = bytearray(out.read_bytes())
    raw[container.inspect(out).header_len + 70_000] ^= 1
    broken = tmp_path / "kaputt.tres0r"
    broken.write_bytes(bytes(raw))
    with pytest.raises(IntegrityError):
        container.verify(broken, PASSWORD)
    dest = tmp_path / "ziel"
    dest.mkdir()
    with pytest.raises(IntegrityError):
        container.extract(broken, dest, PASSWORD)
    assert os.listdir(dest) == []
    token = CancelToken()
    monitor = Monitor(lambda e: token.cancel() if e.phase == "prüfen" and e.done else None, cancel=token, interval=0)
    with pytest.raises(Cancelled):
        container.verify(out, PASSWORD, progress=monitor)
    time.sleep(0.2)
    assert not prefetch_threads()
