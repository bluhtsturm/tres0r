"""Chunkweise authentifizierte Verschlüsselung (STREAM-Konstruktion).

Der Klartext wird in 64-KiB-Chunks zerlegt, jeder Chunk einzeln mit
ChaCha20-Poly1305 verschlüsselt. Nonce = 11 Byte Chunk-Zähler (big endian)
+ 1 Byte Abschluss-Flag (0x01 nur beim letzten Chunk). Dadurch fallen auf:

* veränderte Bytes             -> Tag ungültig
* vertauschte/doppelte Chunks  -> falscher Zähler in der Nonce
* abgeschnittene Datei         -> letzter vorhandener Chunk hat kein Abschluss-Flag
* angehängte Daten             -> Abschluss-Chunk ist nicht mehr der letzte

Vorbild ist das Payload-Format von age (age-encryption.org/v1).
"""
from __future__ import annotations

from typing import BinaryIO, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .errors import IntegrityError, Tres0rError

CHUNK_SIZE = 64 * 1024
TAG_LEN = 16
ENC_CHUNK_SIZE = CHUNK_SIZE + TAG_LEN
_COUNTER_LEN = 11
_MAX_COUNTER = 2 ** (8 * _COUNTER_LEN) - 1

ByteCounter = Callable[[int], None]


def _nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(_COUNTER_LEN, "big") + (b"\x01" if last else b"\x00")


def encrypted_size(plain_size: int) -> int:
    """Größe des verschlüsselten Streams für eine Klartextgröße."""
    chunks = max(1, -(-plain_size // CHUNK_SIZE))
    return plain_size + chunks * TAG_LEN


class EncryptingWriter:
    """Dateiähnliches Objekt: nimmt Klartext per write() an, schreibt Chunks.

    Nach dem letzten write() muss finish() aufgerufen werden – erst dann wird
    der Abschluss-Chunk geschrieben. Ohne finish() ist die Ausgabe absichtlich
    unvollständig und wird beim Entschlüsseln abgelehnt.
    """

    def __init__(self, out: BinaryIO, key: bytes, on_bytes: ByteCounter | None = None) -> None:
        self._out = out
        self._aead = ChaCha20Poly1305(key)
        self._buf = bytearray()
        self._counter = 0
        self._finished = False
        self._on_bytes = on_bytes
        self.plain_bytes = 0  # bisher angenommener Klartext (für Padding)
        self.digest = None  # optional hashlib-Objekt über den Klartext (für Signaturen)

    def write(self, data: bytes) -> int:
        if self._finished:
            raise ValueError("Stream ist bereits abgeschlossen.")
        self._buf += data
        self.plain_bytes += len(data)
        if self.digest is not None:
            self.digest.update(data)
        # Mindestens einen vollen Chunk zurückhalten: Erst beim nächsten
        # write() oder bei finish() steht fest, ob er der letzte ist.
        while len(self._buf) > CHUNK_SIZE:
            self._emit(bytes(self._buf[:CHUNK_SIZE]), last=False)
            del self._buf[:CHUNK_SIZE]
        return len(data)

    def write_zeros(self, count: int) -> None:
        """``count`` Nullbytes schreiben, ohne sie komplett im RAM anzulegen."""
        block = memoryview(bytes(min(count, 1 << 20)))
        while count > 0:
            n = min(count, len(block))
            self.write(block[:n])
            count -= n

    def finish(self) -> None:
        if self._finished:
            return
        self._emit(bytes(self._buf), last=True)
        self._buf.clear()
        self._finished = True

    def _emit(self, chunk: bytes, last: bool) -> None:
        if self._counter > _MAX_COUNTER:
            raise Tres0rError("Stream zu lang.")
        self._out.write(self._aead.encrypt(_nonce(self._counter, last), chunk, None))
        self._counter += 1
        if self._on_bytes:
            self._on_bytes(len(chunk))


class DecryptingReader:
    """Dateiähnliches Objekt: liefert per read() authentifizierten Klartext.

    Jeder Chunk wird vor der Herausgabe geprüft. Ob der Stream *vollständig*
    ist, steht aber erst nach dem Abschluss-Chunk fest – Aufrufer müssen
    deshalb finish() aufrufen, bevor sie dem Gesamtergebnis vertrauen.
    """

    def __init__(self, src: BinaryIO, key: bytes, on_bytes: ByteCounter | None = None, hasher=None) -> None:
        self._src = src
        self._hasher = hasher  # optional: bekommt jeden authentifizierten Klartext-Chunk
        self._aead = ChaCha20Poly1305(key)
        self._cur = b""  # aktueller Klartext-Chunk …
        self._off = 0  # … und Leseposition darin (kein Umkopieren bei jedem read)
        self._counter = 0
        self._done = False
        self._peek = b""
        self._can_peek = hasattr(src, "peek")  # BufferedReader: Folgebyte ansehen, ohne zu lesen
        self._on_bytes = on_bytes

    def _read_exact(self, n: int) -> bytes:
        if not self._peek:
            data = self._src.read(n)
            if len(data) == n or not data:
                return data  # Normalfall: ein Aufruf, keine Kopie
            parts, have = [data], len(data)
        else:
            parts, have = [self._peek], len(self._peek)
            self._peek = b""
        while have < n:
            part = self._src.read(n - have)
            if not part:
                break
            parts.append(part)
            have += len(part)
        return b"".join(parts)

    def _at_end(self) -> bool:
        """Folgt nach dem aktuellen Chunk nichts mehr?"""
        if self._can_peek:
            return not self._src.peek(1)
        self._peek = self._read_exact(1)
        return not self._peek

    def _next_chunk(self) -> bool:
        if self._done:
            return False
        if self._counter > _MAX_COUNTER:
            raise IntegrityError("Stream zu lang.")

        enc = self._read_exact(ENC_CHUNK_SIZE)
        # Voller Chunk: nur der letzte, wenn danach nichts mehr kommt.
        last = self._at_end() if len(enc) == ENC_CHUNK_SIZE else True
        if len(enc) < TAG_LEN:
            raise IntegrityError("Container ist abgeschnitten (Abschluss fehlt).")

        try:
            plain = self._aead.decrypt(_nonce(self._counter, last), enc, None)
        except InvalidTag:
            raise IntegrityError(
                f"Chunk {self._counter} ist beschädigt oder manipuliert, "
                "oder die Datei wurde abgeschnitten bzw. verlängert."
            ) from None
        if last and not plain and self._counter > 0:
            raise IntegrityError("Unzulässiger leerer Abschluss-Chunk.")

        if self._on_bytes:
            self._on_bytes(len(enc))
        if self._hasher is not None:
            self._hasher.update(plain)
        self._counter += 1
        self._cur, self._off = plain, 0
        self._done = last
        return True

    def read(self, size: int = -1) -> bytes:
        want = None if size is None or size < 0 else size
        parts = []
        while want is None or want > 0:
            available = len(self._cur) - self._off
            if available == 0:
                if not self._next_chunk():
                    break
                continue
            take = available if want is None else min(available, want)
            if self._off == 0 and take == len(self._cur):
                parts.append(self._cur)  # ganzer Chunk: ohne Kopie
            else:
                parts.append(self._cur[self._off:self._off + take])
            self._off += take
            if want is not None:
                want -= take
        if len(parts) == 1:
            return parts[0]
        return b"".join(parts)

    def finish(self) -> None:
        """Rest lesen und prüfen, dass der Abschluss-Chunk authentisch ist."""
        self._cur, self._off = b"", 0
        while self._next_chunk():
            self._cur, self._off = b"", 0

    @property
    def verified(self) -> bool:
        """True, sobald der Abschluss-Chunk erfolgreich geprüft wurde."""
        return self._done
