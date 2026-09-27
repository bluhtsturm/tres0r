"""Nutzdaten-Schicht von Format v2.

Der verschlüsselte Klartext (siehe stream.py) ist so aufgebaut:

    Blöcke:     [u32 Länge][Daten] … [u32 0]       <- Terminator
    Padding:    Nullbytes (Padmé)
    Index:      zlib(JSON) | u64 Länge | "TRS0IDX\\x01"   <- nur bei Flag "Index"

"Daten" sind der tar-Stream bzw. der Rohdatenstrom, bei Kompression als
zstd-Frames. Die Block-Rahmung sorgt dafür, dass Leser das Datenende kennen –
ohne sie könnten Dekompressor und Rohdaten-Leser Padding und Index nicht von
den Nutzdaten unterscheiden.

Wahlfreier Zugriff: Jeder Chunk ist über seinen Zähler einzeln
entschlüsselbar. Einstiegspunkte ("Seek-Punkte") liegen immer an einem
Blockanfang; bei Kompression zusätzlich an einem Frame-Anfang. Der Index
speichert je Eintrag (Blockoffset, zu überspringende dekodierte Bytes).
Unkomprimiert beginnt jeder tar-Eintrag in einem neuen Block (Skip 0);
komprimiert beginnt spätestens alle FRAME_TARGET Byte ein neuer zstd-Frame,
damit das Kompressionsverhältnis bei vielen kleinen Dateien nicht leidet.
"""
from __future__ import annotations

import importlib
import io
import json
import queue
import struct
import threading
import zlib
from dataclasses import dataclass
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .errors import FormatError, IntegrityError, Tres0rError
from .stream import CHUNK_SIZE, ENC_CHUNK_SIZE, TAG_LEN, EncryptingWriter, _nonce

_BLOCK = struct.Struct(">I")
MAX_BLOCK = 1 << 20  # beim Schreiben
MAX_READ_BLOCK = 4 << 20  # beim Lesen akzeptiert (DoS-Grenze)
FRAME_TARGET = 1 << 20
INDEX_MAGIC = b"TRS0IDX\x01"
_TRAILER = struct.Struct(">Q8s")
MAX_INDEX_BLOB = 256 << 20
MAX_INDEX_JSON = 1 << 30
INDEX_VERSION = 1


# ---------------------------------------------------------------------------
# zstd (Standardbibliothek ab Python 3.14 oder Paket "zstandard")
# ---------------------------------------------------------------------------
def zstd_backend() -> str | None:
    for module, name in (("compression.zstd", "stdlib"), ("zstandard", "zstandard")):
        try:
            importlib.import_module(module)  # compression.zstd: Python >= 3.14
            return name
        except ImportError:
            continue
    return None


def _require_zstd() -> str:
    backend = zstd_backend()
    if backend is None:
        raise Tres0rError("zstd nicht verfügbar: Python ab 3.14 verwenden oder 'pip install zstandard'.")
    return backend


class FrameCompressor:
    """Komprimiert fortlaufend; end_frame() schließt den aktuellen zstd-Frame.

    ``threads`` > 1 nutzt zstds eigene Worker-Threads (C, unabhängig vom GIL).
    Parallelisiert wird innerhalb eines Frames – das hilft vor allem bei großen
    Dateien; die Ausgabe ist ein normaler zstd-Datenstrom.
    """

    def __init__(self, level: int = 3, threads: int = 1) -> None:
        self._backend = _require_zstd()
        self._level = level
        workers = threads if threads > 1 else 0
        if self._backend == "stdlib":
            from compression import zstd

            parameter = zstd.CompressionParameter
            options = {parameter.compression_level: level}
            if workers and parameter.nb_workers.bounds()[1] > 0:  # libzstd mit Thread-Unterstützung?
                options[parameter.nb_workers] = workers
            self._c = zstd.ZstdCompressor(options=options)
        else:
            import zstandard

            self._cctx = zstandard.ZstdCompressor(level=level, threads=workers)
            self._c = self._cctx.compressobj()

    def compress(self, data: bytes) -> bytes:
        if self._backend == "stdlib":
            return self._c.compress(data, mode=self._c.CONTINUE)
        return self._c.compress(data)

    def end_frame(self) -> bytes:
        if self._backend == "stdlib":
            return self._c.flush(mode=self._c.FLUSH_FRAME)
        import zstandard

        out = self._c.flush(zstandard.COMPRESSOBJ_FLUSH_FINISH)
        self._c = self._cctx.compressobj()
        return out


FEED_SIZE = 1024  # Eingabeportion pro Dekompressionsschritt (begrenzt Ausgabespitzen)


class _FrameReader:
    """Liest aufeinanderfolgende zstd-Frames – für beide Backends gleich streng.

    * Ein letzter Frame, der mittendrin endet, ist ein FormatError (zstandards
      eigener stream_reader liefert hier stillschweigend weniger Daten).
    * Dekodierfehler der Backends werden zu FormatError; Fehler der Schichten
      darunter (IntegrityError, FormatError aus den Blöcken) bleiben unverändert.
    * Eingabe wird in kleinen Portionen verarbeitet: Ein präparierter Frame aus
      RLE-Blöcken macht aus 4 Byte 128 KiB – pro Schritt entstehen so höchstens
      ca. 32 MiB statt beliebig viel auf einmal.
    """

    def __init__(self, source: BinaryIO, new_decompressor, errors: tuple[type[BaseException], ...]) -> None:
        self._src, self._new, self._errors = source, new_decompressor, errors
        self._d = None
        self._pending = b""
        self._buf = bytearray()
        self._done = False

    def _step(self) -> bool:
        """Ein Dekompressionsschritt. False am sauberen Ende."""
        if self._pending:
            data, self._pending = self._pending[:FEED_SIZE], self._pending[FEED_SIZE:]
        else:
            data = self._src.read(FEED_SIZE)
            if not data:
                if self._d is not None and not self._d.eof:
                    raise FormatError("Komprimierte Daten enden mitten in einem Frame.")
                return False
        if self._d is None or self._d.eof:
            self._d = self._new()
        try:
            out = self._d.decompress(data)
        except Tres0rError:
            raise
        except self._errors as e:
            raise FormatError(f"Komprimierte Daten sind beschädigt: {e}") from None
        if self._d.eof and self._d.unused_data:
            self._pending = bytes(self._d.unused_data) + self._pending
        self._buf += out
        return True

    def read(self, size: int = -1) -> bytes:
        want = None if size is None or size < 0 else size
        while not self._done and (want is None or len(self._buf) < want):
            if not self._step():
                self._done = True
        n = len(self._buf) if want is None else min(want, len(self._buf))
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    def readable(self) -> bool:
        return True


def open_decompressor(source: BinaryIO) -> BinaryIO:
    """Liest beliebig viele aufeinanderfolgende zstd-Frames aus ``source``."""
    if _require_zstd() == "stdlib":
        from compression import zstd

        return _FrameReader(source, zstd.ZstdDecompressor, (zstd.ZstdError, EOFError, ValueError))
    import zstandard

    return _FrameReader(source, lambda: zstandard.ZstdDecompressor().decompressobj(),
                        (zstandard.ZstdError, EOFError, ValueError))


# ---------------------------------------------------------------------------
# Block-Rahmung
# ---------------------------------------------------------------------------
class BlockWriter:
    def __init__(self, out: EncryptingWriter) -> None:
        self._out = out
        self._buf = bytearray()

    @property
    def offset(self) -> int:
        """Klartext-Offset, an dem der nächste Block beginnt (nach cut())."""
        return self._out.plain_bytes + (len(self._buf) + _BLOCK.size if self._buf else 0)

    def write(self, data: bytes) -> None:
        self._buf += data
        while len(self._buf) >= MAX_BLOCK:
            self._emit(bytes(self._buf[:MAX_BLOCK]))
            del self._buf[:MAX_BLOCK]

    def cut(self) -> None:
        if self._buf:
            self._emit(bytes(self._buf))
            self._buf.clear()

    def close(self) -> None:
        self.cut()
        self._out.write(_BLOCK.pack(0))

    def _emit(self, block: bytes) -> None:
        self._out.write(_BLOCK.pack(len(block)))
        self._out.write(block)


class BlockReader:
    """Dateiähnlich: liefert den Inhalt der Blöcke bis zum Terminator."""

    def __init__(self, source: BinaryIO) -> None:
        self._src = source
        self._left = 0
        self.done = False
        self.before_drain: list = []  # z. B. Prefetcher.close – niemand darf mehr parallel lesen

    def _read_exact(self, n: int) -> bytes:
        data = self._src.read(n)
        if len(data) == n:
            return data  # Normalfall: ein Aufruf, keine Kopie
        parts, have = [data], len(data)
        while have < n:
            part = self._src.read(n - have)
            if not part:
                raise FormatError("Blockstruktur abgeschnitten.")
            parts.append(part)
            have += len(part)
        return b"".join(parts)

    def read(self, size: int = -1) -> bytes:
        """Wie bei Dateien: ohne ``size`` alles bis zum Terminator, sonst bis zu
        ``size`` Byte – auch über Blockgrenzen hinweg."""
        want = None if size is None or size < 0 else size
        parts = []
        while not self.done and (want is None or want > 0):
            if self._left == 0:
                (length,) = _BLOCK.unpack(self._read_exact(_BLOCK.size))
                if length == 0:
                    self.done = True
                    break
                if length > MAX_READ_BLOCK:
                    raise FormatError(f"Block zu groß ({length} Byte).")
                self._left = length
            n = self._left if want is None else min(want, self._left)
            parts.append(self._read_exact(n))
            self._left -= n
            if want is not None:
                want -= n
        return parts[0] if len(parts) == 1 else b"".join(parts)

    def readinto(self, buffer) -> int:  # für io.BufferedReader / Dekompressoren
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def readable(self) -> bool:
        return True

    def drain(self) -> None:
        for hook in self.before_drain:
            hook()
        while self.read(1 << 20):
            pass


def decoded_reader(plain: BinaryIO, compression: int) -> tuple[BlockReader, BinaryIO]:
    """(BlockReader, lesbarer dekodierter Datenstrom)."""
    blocks = BlockReader(plain)
    if compression:
        return blocks, open_decompressor(blocks)
    return blocks, blocks


class Prefetcher(io.RawIOBase):
    """Liest einen Datenstrom in einem Hintergrund-Thread vor.

    Für komprimierte Container: Entschlüsseln und zstd laufen im Hintergrund,
    tar-Verarbeitung und Hashen im Hauptthread. zstd gibt den GIL frei (gemessen,
    beide Backends), dadurch überlappen sich Dekompression und Python-Arbeit auf
    mehreren Kernen. Höchstens ``depth`` Portionen à ``chunk`` Byte liegen bereit
    (Speicher begrenzt). Fehler kommen an der Stelle im Datenstrom an, an der sie
    auftreten. ``close()`` hält den Thread an (vor dem Abschluss des Datenstroms
    und bei jedem vorzeitigen Ende).
    """

    def __init__(self, source: BinaryIO, chunk: int = 1 << 20, depth: int = 8) -> None:
        super().__init__()
        self._source, self._chunk = source, chunk
        self._queue: queue.Queue = queue.Queue(depth)
        self._stop = threading.Event()
        self._current, self._offset, self._ended = b"", 0, False
        self._thread = threading.Thread(target=self._run, name="tres0r-prefetch", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                data = self._source.read(self._chunk)
                self._put(data)
                if not data:
                    return
        except BaseException as error:  # an den Hauptthread weiterreichen
            self._put(error)

    def _put(self, item) -> None:
        while not self._stop.is_set():
            try:
                self._queue.put(item, timeout=0.1)
                return
            except queue.Full:
                continue

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        parts, want = [], None if size is None or size < 0 else size
        while want is None or want > 0:
            if self._offset >= len(self._current):
                if self._ended:
                    break
                item = self._queue.get()
                if isinstance(item, BaseException):
                    self._ended = True
                    raise item
                if not item:
                    self._ended = True
                    break
                self._current, self._offset = item, 0
            take = len(self._current) - self._offset if want is None else min(want, len(self._current) - self._offset)
            parts.append(self._current[self._offset:self._offset + take])
            self._offset += take
            if want is not None:
                want -= take
        return parts[0] if len(parts) == 1 else b"".join(parts)

    def close(self) -> None:
        if not self._stop.is_set():
            self._stop.set()
            while True:  # einen wartenden put() freigeben
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    break
            self._thread.join()
        super().close()


def skip(stream: BinaryIO, count: int) -> None:
    while count > 0:
        data = stream.read(min(count, 1 << 20))
        if not data:
            raise FormatError("Einstiegspunkt liegt hinter dem Datenende.")
        count -= len(data)


# ---------------------------------------------------------------------------
# Schreiben mit Seek-Punkten
# ---------------------------------------------------------------------------
class PayloadWriter:
    """Dateiähnliches Ziel für tarfile ("w"-Modus braucht write + tell)."""

    def __init__(self, out: EncryptingWriter, compress: bool, level: int = 3, threads: int = 1) -> None:
        self.blocks = BlockWriter(out)
        self._compressor = FrameCompressor(level, threads) if compress else None
        self._pos = 0
        self._frame_start = self.blocks.offset
        self._frame_in = 0

    def write(self, data: bytes) -> int:
        n = len(data)
        self._pos += n
        if self._compressor is None:
            self.blocks.write(data)
        else:
            self._frame_in += n
            out = self._compressor.compress(bytes(data))
            if out:
                self.blocks.write(out)
        return n

    def tell(self) -> int:
        return self._pos

    def _end_frame(self) -> None:
        self.blocks.write(self._compressor.end_frame())
        self.blocks.cut()
        self._frame_start = self.blocks.offset
        self._frame_in = 0

    def mark(self) -> tuple[int, int]:
        """Seek-Punkt für das nächste Byte: (Blockoffset, zu überspringende Bytes)."""
        if self._compressor is None:
            self.blocks.cut()
            return self.blocks.offset, 0
        if self._frame_in >= FRAME_TARGET:
            self._end_frame()
        return self._frame_start, self._frame_in

    def close(self) -> None:
        if self._compressor is not None and self._frame_in:
            self._end_frame()
        self.blocks.close()


# ---------------------------------------------------------------------------
# Wahlfreier Zugriff
# ---------------------------------------------------------------------------
class RandomAccessPayload:
    """Entschlüsselt einzelne Chunks nach Bedarf (Datei muss seekbar sein).

    Jeder Chunk ist authentifiziert und über den Zähler an seine Position
    gebunden. Der letzte Chunk trägt das Abschluss-Flag; wird er gelesen (das
    passiert bei jedem Indexzugriff), fällt auch Abschneiden auf.
    """

    def __init__(self, f: BinaryIO, key: bytes, start: int, size: int) -> None:
        if size < TAG_LEN or 0 < size % ENC_CHUNK_SIZE < TAG_LEN:
            raise IntegrityError("Container ist abgeschnitten.")
        self._f, self._start = f, start
        self._aead = ChaCha20Poly1305(key)
        self.chunks = -(-size // ENC_CHUNK_SIZE)
        self._size = size
        self.plaintext_size = size - self.chunks * TAG_LEN
        self._cache: tuple[int, bytes] | None = None

    def _chunk(self, i: int) -> bytes:
        if self._cache and self._cache[0] == i:
            return self._cache[1]
        offset = i * ENC_CHUNK_SIZE
        self._f.seek(self._start + offset)
        enc = self._f.read(min(ENC_CHUNK_SIZE, self._size - offset))
        last = i == self.chunks - 1
        try:
            plain = self._aead.decrypt(_nonce(i, last), enc, None)
        except InvalidTag:
            raise IntegrityError(f"Chunk {i} ist beschädigt oder manipuliert.") from None
        if last and not plain and i > 0:
            raise IntegrityError("Unzulässiger leerer Abschluss-Chunk.")
        self._cache = (i, plain)
        return plain

    def pread(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.plaintext_size:
            raise FormatError("Lesezugriff außerhalb der Nutzdaten.")
        parts = []
        while size > 0:
            i, within = divmod(offset, CHUNK_SIZE)
            part = self._chunk(i)[within: within + size]
            parts.append(part)
            offset += len(part)
            size -= len(part)
        return b"".join(parts)

    def open_at(self, offset: int) -> BinaryIO:
        return _View(self, offset)


class _View(io.RawIOBase):
    def __init__(self, payload: RandomAccessPayload, offset: int) -> None:
        self._p, self._pos = payload, offset

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        remaining = self._p.plaintext_size - self._pos
        n = remaining if size is None or size < 0 else min(size, remaining)
        data = self._p.pread(self._pos, max(0, n))
        self._pos += len(data)
        return data

    def readinto(self, buffer) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------
KINDS = {"f": "datei", "d": "ordner", "l": "link", "h": "link", "o": "sonstiges"}


@dataclass
class IndexEntry:
    name: str
    kind: str  # f, d, l (Symlink), h (Hardlink), o
    size: int
    mtime: int
    offset: int
    skip: int
    sha256: str | None = None
    link: str | None = None

    def to_json(self) -> dict:
        data = {"n": self.name, "t": self.kind, "s": self.size, "m": self.mtime, "o": self.offset, "k": self.skip}
        if self.sha256:
            data["h"] = self.sha256
        if self.link is not None:
            data["l"] = self.link
        return data


_HEX = frozenset("0123456789abcdef")


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _entry(raw) -> IndexEntry:
    """Einen Indexeintrag streng prüfen, bevor irgendein Feld benutzt wird."""
    bad = FormatError("Inhaltsverzeichnis ist fehlerhaft.")
    if not isinstance(raw, dict):
        raise bad
    try:
        name, kind, size, mtime, offset, skip = (raw[k] for k in ("n", "t", "s", "m", "o", "k"))
    except KeyError:
        raise bad from None
    sha256, link = raw.get("h"), raw.get("l")
    valid = (
        isinstance(name, str)
        and isinstance(kind, str) and kind in KINDS
        and all(_is_int(v) and v >= 0 for v in (size, offset, skip))
        and _is_int(mtime)
        and (sha256 is None or (isinstance(sha256, str) and len(sha256) == 64 and set(sha256) <= _HEX))
        and (link is None or isinstance(link, str))
    )
    if not valid:
        raise bad
    return IndexEntry(name, kind, size, mtime, offset, skip, sha256, link)


def encode_index(entries: list[IndexEntry]) -> bytes:
    doc = {"v": INDEX_VERSION, "entries": [e.to_json() for e in entries]}
    # ensure_ascii: Linux-Dateinamen ohne gültiges UTF-8 enthalten einzelne Surrogate
    # (surrogateescape). Als \\udcXX-Escape bleiben sie im JSON erhalten und kommen
    # beim Lesen unverändert zurück; roh ließen sie sich gar nicht als UTF-8 kodieren.
    return zlib.compress(json.dumps(doc, ensure_ascii=True, separators=(",", ":")).encode("ascii"), 6)


def index_trailer(blob: bytes) -> bytes:
    return blob + _TRAILER.pack(len(blob), INDEX_MAGIC)


def read_index(payload: RandomAccessPayload, reserved_tail: int = 0) -> list[IndexEntry]:
    """Inhaltsverzeichnis lesen; ``reserved_tail`` = Byte danach (Signaturanhang)."""
    size = payload.plaintext_size - reserved_tail
    if size < _TRAILER.size:
        raise FormatError("Inhaltsverzeichnis fehlt.")
    length, magic = _TRAILER.unpack(payload.pread(size - _TRAILER.size, _TRAILER.size))
    if magic != INDEX_MAGIC or length > min(MAX_INDEX_BLOB, size - _TRAILER.size):
        raise FormatError("Inhaltsverzeichnis fehlt oder ist beschädigt.")
    blob = payload.pread(size - _TRAILER.size - length, length)
    inflater = zlib.decompressobj()
    try:
        raw = inflater.decompress(blob, MAX_INDEX_JSON)
    except zlib.error:
        raise FormatError("Inhaltsverzeichnis ist beschädigt.") from None
    if inflater.unconsumed_tail:
        raise FormatError("Inhaltsverzeichnis ist zu groß.")
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError):  # RecursionError: präparierte, tief verschachtelte JSON
        raise FormatError("Inhaltsverzeichnis ist beschädigt.") from None
    if not isinstance(doc, dict) or doc.get("v") != INDEX_VERSION or not isinstance(doc.get("entries"), list):
        raise FormatError("Unbekannte Version des Inhaltsverzeichnisses.")
    return [_entry(e) for e in doc["entries"]]
