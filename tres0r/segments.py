"""Angehängte Segmente (FORMAT.md, Abschnitt 10).

Ein Container mit Header-Flag ``FLAG_SEGMENTS`` besteht nach dem Header aus
mehreren eigenständig verschlüsselten Nutzdatenströmen (Segmenten) und endet
mit einer authentifizierten Segmenttabelle:

    Header | Segment 0 | [alte Tabelle, entwertet] | Segment 1 | … | Tabelle

Tabelle (Trailer):   table_nonce(16) ‖ ct ‖ u32 len(ct) ‖ "TRS0SEG\\x01"
    ct = ChaCha20-Poly1305(K_T, 0^12, Klartext, AAD = "tres0r v2 segment table" ‖ stream_nonce)
    K_T = HKDF(DEK, table_nonce, "tres0r v2 segment table")
    Klartext = u8 version=1 ‖ u32 n ‖ n × (u64 offset ‖ u64 länge ‖ nonce(16) ‖ u8 compression ‖ u8 flags)

Offsets zählen ab Nutzdatenbeginn (Header-Ende), damit Schlüsseländerungen –
die den Header länger oder kürzer machen – die Tabelle nicht berühren.
Segment 0 nutzt Nonce, Kompression und Flags des Headers (ohne FLAG_SEGMENTS).

Nach jedem erfolgreichen Anhängen wird die Kennung der vorherigen Tabelle
überschrieben: Wer die Datei dort abschneidet, erhält keinen gültigen Container.
"""
from __future__ import annotations

import io
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import header2 as v2
from . import rng
from .errors import FormatError, IntegrityError

MAGIC = b"TRS0SEG\x01"
TABLE_VERSION = 1
MAX_SEGMENTS = 4096
_INFO_TABLE = b"tres0r v2 segment table"
_ENTRY = struct.Struct(">QQ16sBB")
_TAIL = struct.Struct(">I8s")
SEGMENT_FLAGS = v2.FLAG_INDEX | v2.FLAG_SIGNED


@dataclass(frozen=True)
class SegmentEntry:
    offset: int  # relativ zum Nutzdatenbeginn
    length: int  # Chiffretext-Bytes
    nonce: bytes
    compression: int
    flags: int  # nur FLAG_INDEX / FLAG_SIGNED


def encode_table(dek: bytes, stream_nonce: bytes, entries: list[SegmentEntry]) -> bytes:
    plain = bytes([TABLE_VERSION]) + struct.pack(">I", len(entries)) + b"".join(
        _ENTRY.pack(e.offset, e.length, e.nonce, e.compression, e.flags) for e in entries)
    table_nonce = rng.random_bytes(16)
    key = v2._hkdf(dek, table_nonce, _INFO_TABLE)
    ct = ChaCha20Poly1305(key).encrypt(bytes(12), plain, _INFO_TABLE + stream_nonce)
    return table_nonce + ct + _TAIL.pack(len(ct), MAGIC)


def _decode(dek: bytes, stream_nonce: bytes, blob: bytes) -> list[SegmentEntry]:
    table_nonce, ct = blob[:16], blob[16:]
    try:
        plain = ChaCha20Poly1305(v2._hkdf(dek, table_nonce, _INFO_TABLE)).decrypt(
            bytes(12), ct, _INFO_TABLE + stream_nonce)
    except InvalidTag:
        raise IntegrityError("Segmenttabelle ist beschädigt oder manipuliert.") from None
    if len(plain) < 5 or plain[0] != TABLE_VERSION:
        raise FormatError("Unbekannte Version der Segmenttabelle.")
    count = struct.unpack(">I", plain[1:5])[0]
    if not 1 <= count <= MAX_SEGMENTS or len(plain) != 5 + count * _ENTRY.size:
        raise FormatError("Segmenttabelle hat eine ungültige Länge.")
    return [SegmentEntry(*_ENTRY.unpack_from(plain, 5 + i * _ENTRY.size)) for i in range(count)]


def _validate(entries: list[SegmentEntry], table_offset: int) -> None:
    """Segmente: ab 0, aufsteigend, überlappungsfrei, vor der Tabelle."""
    if entries[0].offset != 0:
        raise FormatError("Segment 0 muss am Nutzdatenbeginn liegen.")
    end = 0
    for i, e in enumerate(entries):
        if e.offset < end or e.length < 16 or e.offset + e.length > table_offset:
            raise FormatError(f"Segment {i} liegt außerhalb der gültigen Grenzen.")
        if e.compression not in (v2.COMPRESS_NONE, v2.COMPRESS_ZSTD) or e.flags & ~SEGMENT_FLAGS:
            raise FormatError(f"Segment {i} hat unbekannte Eigenschaften.")
        end = e.offset + e.length


def read_table(f, total: int, payload_start: int, dek: bytes, stream_nonce: bytes
               ) -> tuple[list[SegmentEntry], int]:
    """Tabelle am Dateiende lesen und prüfen: (Einträge, absoluter Tabellenbeginn)."""
    if total - payload_start < _TAIL.size + 32:
        raise FormatError("Segmenttabelle fehlt – Anhängen unterbrochen? 'tres0r repair' hilft.")
    f.seek(total - _TAIL.size)
    length, magic = _TAIL.unpack(f.read(_TAIL.size))
    start = total - _TAIL.size - length - 16
    if magic != MAGIC or length < 16 or start < payload_start:
        raise FormatError("Segmenttabelle fehlt – Anhängen unterbrochen? 'tres0r repair' hilft.")
    f.seek(start)
    entries = _decode(dek, stream_nonce, f.read(16 + length))
    _validate(entries, start - payload_start)
    return entries, start


def find_last_table(f, total: int, payload_start: int, dek: bytes, stream_nonce: bytes
                    ) -> tuple[list[SegmentEntry], int] | None:
    """Rückwärts nach der letzten gültigen Tabelle suchen (für repair): (Einträge, Tabellenende)."""
    window = 1 << 20
    position = total
    while position > payload_start:
        low = max(payload_start, position - window)
        f.seek(low)
        chunk = f.read(position - low + len(MAGIC))
        at = len(chunk)
        while (at := chunk.rfind(MAGIC, 0, at)) != -1:
            end = low + at + len(MAGIC)
            try:
                return read_table(_Truncated(f, end), end, payload_start, dek, stream_nonce)[0], end
            except (FormatError, IntegrityError):
                pass
        position = low
    return None


class _Truncated(io.RawIOBase):
    """Sicht auf eine Datei, als wäre sie bei ``end`` zu Ende."""

    def __init__(self, f, end: int) -> None:
        self.f, self.end = f, end

    def seek(self, pos: int, whence: int = 0) -> int:
        return self.f.seek(pos, whence)

    def read(self, n: int = -1) -> bytes:
        left = self.end - self.f.tell()
        return self.f.read(left if n is None or n < 0 else min(n, max(0, left)))


class Window:
    """Ausschnitt [start, start+länge) einer Datei mit absoluten Positionen.

    Der Entschlüsseler erkennt so das Ende eines Segments wie ein Dateiende.
    """

    def __init__(self, f, start: int, length: int) -> None:
        self.f, self.start, self.end = f, start, start + length
        self._pos = start

    def seek(self, pos: int, whence: int = 0) -> int:
        if whence == io.SEEK_END:
            pos = self.end + pos
        elif whence == io.SEEK_CUR:
            pos = self._pos + pos
        self._pos = pos
        return pos

    def tell(self) -> int:
        return self._pos

    def read(self, n: int = -1) -> bytes:
        left = self.end - self._pos
        if left <= 0:
            return b""
        self.f.seek(self._pos)
        data = self.f.read(left if n is None or n < 0 else min(n, left))
        self._pos += len(data)
        return data

    def peek(self, n: int = 1) -> bytes:
        if self._pos >= self.end:
            return b""
        self.f.seek(self._pos)
        return self.f.read(1)


# --- Journal (Absturzsicherheit beim Anhängen) -------------------------------
def journal_path(container: Path) -> Path:
    return container.with_name(f".{container.name}.tres0r-append")


def write_journal(container: Path, size: int, header: bytes | None) -> None:
    data = json.dumps({"size": size, "header": header.hex() if header is not None else None}).encode()
    path = journal_path(container)
    with open(path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def read_journal(container: Path) -> dict | None:
    try:
        data = json.loads(journal_path(container).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("size"), int):
        return None
    return data
