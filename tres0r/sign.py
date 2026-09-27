"""Signierte Container (Format v2, Flag-Bit 1).

Der Signaturanhang steht ganz am Ende des Klartexts – innerhalb der
Verschlüsselung, damit nur Schlüsselinhaber sehen, wer signiert hat:

    u8 alg (1 = Ed25519) ‖ Prüfschlüssel(32) ‖ Signatur(64) ‖ "TRS0SIG\\x01"   = 105 Byte

Signiert wird

    "tres0r v2 signature" ‖ 0x00 ‖ u8 payload_type ‖ u8 compression ‖ u8 flags
    ‖ stream_nonce(16) ‖ SHA-256(Klartext ohne die letzten 105 Byte)

Bewusst NICHT signiert sind die Keyslots und die Header-MAC: Schlüssel lassen
sich hinzufügen/entfernen, ohne die Signatur zu brechen. Die Signatur sagt
"der Inhaber des Schlüssels hat genau diesen Inhalt erstellt" – nicht "er hat
diese Empfänger gewählt". Weil der Hash den gesamten Klartext abdeckt (Daten,
Padding, Inhaltsverzeichnis), kann auch ein anderer Empfänger desselben
Containers, der den Datenschlüssel kennt, nichts unbemerkt austauschen.
"""
from __future__ import annotations

import hashlib
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import FormatError

ALG_ED25519 = 1
MAGIC = b"TRS0SIG\x01"
_TRAILER = struct.Struct(">B32s64s8s")
TRAILER_LEN = _TRAILER.size  # 105
_CONTEXT = b"tres0r v2 signature\x00"


from .errors import SignatureError  # noqa: E402 – früher hier definiert, Name bleibt gültig


def message(payload_type: int, compression: int, flags: int, stream_nonce: bytes, digest: bytes) -> bytes:
    return _CONTEXT + bytes([payload_type, compression, flags]) + stream_nonce + digest


def _message_for(header, digest: bytes) -> bytes:
    return message(header.payload_type, header.compression, header.flags, header.stream_nonce, digest)


def trailer(key: Ed25519PrivateKey, header, digest: bytes) -> bytes:
    signature = key.sign(_message_for(header, digest))
    return _TRAILER.pack(ALG_ED25519, key.public_key().public_bytes_raw(), signature, MAGIC)


def verify(header, digest: bytes, tail: bytes) -> Ed25519PublicKey:
    """Anhang prüfen; gibt den Prüfschlüssel des Signierenden zurück."""
    if len(tail) != TRAILER_LEN:
        raise SignatureError("Signatur fehlt – Container zu kurz.")
    alg, public, signature, magic = _TRAILER.unpack(tail)
    if magic != MAGIC:
        raise FormatError("Signaturanhang fehlt oder ist beschädigt.")
    if alg != ALG_ED25519:
        raise FormatError(f"Unbekanntes Signaturverfahren {alg}.")
    try:
        key = Ed25519PublicKey.from_public_bytes(public)
        key.verify(signature, _message_for(header, digest))
    except (InvalidSignature, ValueError):
        raise SignatureError("Signatur ist ungültig – Inhalt nach dem Signieren verändert.") from None
    return key


def require(signer: Ed25519PublicKey | None, expected) -> None:
    """Erwartete Prüfschlüssel durchsetzen (None/leer = keine Anforderung)."""
    if not expected:
        return
    if signer is None:
        raise SignatureError("Container ist nicht signiert, eine Signatur wird aber verlangt.")
    wanted = {k.public_bytes_raw() for k in expected}
    if signer.public_bytes_raw() not in wanted:
        raise SignatureError("Container ist von einem anderen Schlüssel signiert als erwartet.")


class TailHasher:
    """Hasht einen sequentiell gelesenen Klartext bis auf die letzten ``keep`` Byte.

    Beim Lesen ist das Ende erst am Schluss bekannt; so steht dann sowohl der
    Hash über alles davor als auch der Anhang selbst zur Verfügung.
    """

    def __init__(self, keep: int = TRAILER_LEN) -> None:
        self._hash = hashlib.sha256()
        self._tail = bytearray()
        self._keep = keep

    def update(self, data: bytes) -> None:
        self._tail += data
        excess = len(self._tail) - self._keep
        if excess > 0:
            self._hash.update(self._tail[:excess])
            del self._tail[:excess]

    def finish(self) -> tuple[bytes, bytes]:
        return self._hash.digest(), bytes(self._tail)
