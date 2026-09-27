"""Parallelarbeit, wo sie tatsächlich etwas bringt.

Gemessen (tests/…, README "Leistung"): ``hashlib`` gibt Pythons GIL während
SHA-256 frei, ``cryptography``s ChaCha20-Poly1305 hält ihn weitgehend. Deshalb
wird nicht die Verschlüsselung verteilt, sondern das Hashen läuft auf einem
zweiten Kern parallel dazu. zstd hat eigene Worker-Threads in C.

Mit ``threads=1`` bleibt alles im aufrufenden Thread (bisheriges Verhalten).
"""
from __future__ import annotations

import os
import queue
import threading

MAX_AUTO_THREADS = 8


def resolve_threads(threads: int | None) -> int:
    """None = automatisch (Anzahl Kerne, höchstens 8); sonst mindestens 1."""
    if threads is None:
        return max(1, min(MAX_AUTO_THREADS, os.cpu_count() or 1))
    if threads < 1:
        raise ValueError("Anzahl Threads muss mindestens 1 sein.")
    return threads


class InlineHasher:
    """Hasht direkt im aufrufenden Thread."""

    def update(self, digest, data: bytes) -> None:
        digest.update(data)

    def hexdigest(self, digest) -> str:
        return digest.hexdigest()

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class HashWorker(InlineHasher):
    """Hasht in einem Hintergrund-Thread; Reihenfolge per FIFO-Warteschlange.

    ``update`` übergibt unveränderliche ``bytes`` und kehrt sofort zurück;
    ``hexdigest`` wartet, bis alle Teile dieses Hashes verarbeitet sind.
    Die Warteschlange ist begrenzt (Speicher: höchstens ``maxsize`` Blöcke).
    """

    def __init__(self, maxsize: int = 16) -> None:
        self._queue: queue.Queue = queue.Queue(maxsize)
        self._thread = threading.Thread(target=self._run, name="tres0r-hash", daemon=True)
        self._thread.start()
        self._closed = False

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            digest, data, done = item
            if done is not None:
                done.set()
            else:
                digest.update(data)

    def update(self, digest, data: bytes) -> None:
        self._queue.put((digest, bytes(data), None))

    def hexdigest(self, digest) -> str:
        done = threading.Event()
        self._queue.put((digest, None, done))
        done.wait()
        return digest.hexdigest()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._queue.put(None)
            self._thread.join()


def hasher(threads: int) -> InlineHasher:
    return HashWorker() if threads > 1 else InlineHasher()
