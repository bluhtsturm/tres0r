"""Container-Header (Formatversion 1) – wird weiterhin gelesen, aber nicht mehr geschrieben.

Layout (big endian, 107 Byte):

    Offset  Länge  Feld
         0      4  Magic "TRS0"
         4      1  Formatversion (1)
         5      1  KDF-ID (1 = Argon2id)
         6      4  Argon2id-Speicher in KiB
        10      4  Argon2id-Iterationen
        14      1  Argon2id-Parallelität (Lanes)
        15     16  Salt
        31     16  Stream-Nonce (für die Ableitung des Payload-Schlüssels)
        47     12  Nonce für den Keyslot
        59     48  Keyslot: Datenschlüssel (32) + Poly1305-Tag (16)

Schlüsselhierarchie:

    KEK         = Argon2id(Passwort, Salt, Parameter)
    DEK         = 32 zufällige Byte, im Keyslot mit KEK verschlüsselt;
                  Bytes 0–58 des Headers sind dabei Associated Data
    Payload-Key = HKDF-SHA256(DEK, salt=Stream-Nonce, info="tres0r v1 payload key")

Weil Bytes 0–58 als AAD in den Keyslot eingehen, fällt jede Änderung am
Header (z. B. ein Downgrade der Argon2-Parameter) beim Entsperren auf.
Passwort oder Stufe lassen sich ändern, indem nur der Keyslot neu
geschrieben wird – die Nutzdaten bleiben unverändert.
"""
from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass, replace
from typing import BinaryIO, ClassVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import FormatError, UnsupportedVersion, WrongPassword
from .kdf import KDF_ARGON2ID, KEY_LEN, SALT_LEN, KdfParams, derive_key

MAGIC = b"TRS0"
VERSION = 1
STREAM_NONCE_LEN = 16
WRAP_NONCE_LEN = 12
WRAPPED_KEY_LEN = KEY_LEN + 16

_PREFIX = struct.Struct(">4sBBIIB16s16s12s")
PREFIX_LEN = _PREFIX.size
HEADER_LEN = PREFIX_LEN + WRAPPED_KEY_LEN
_PAYLOAD_INFO = b"tres0r v1 payload key"


@dataclass(frozen=True)
class Header:
    kdf: KdfParams
    salt: bytes
    stream_nonce: bytes
    wrap_nonce: bytes
    wrapped_key: bytes = b""

    version: ClassVar[int] = VERSION
    header_len: ClassVar[int] = HEADER_LEN

    # -- Serialisierung ---------------------------------------------------
    def _prefix(self) -> bytes:
        return _PREFIX.pack(
            MAGIC,
            VERSION,
            KDF_ARGON2ID,
            self.kdf.memory_kib,
            self.kdf.iterations,
            self.kdf.lanes,
            self.salt,
            self.stream_nonce,
            self.wrap_nonce,
        )

    def to_bytes(self) -> bytes:
        if len(self.wrapped_key) != WRAPPED_KEY_LEN:
            raise FormatError("Header ohne gültigen Keyslot kann nicht geschrieben werden.")
        return self._prefix() + self.wrapped_key

    @classmethod
    def from_bytes(cls, data: bytes) -> Header:
        if data[:4] != MAGIC:
            raise FormatError("Keine tres0r-Datei (Kennung fehlt).")
        if len(data) < 5:
            raise FormatError("Header unvollständig – Datei abgeschnitten?")
        if data[4] != VERSION:
            raise UnsupportedVersion(
                f"Formatversion {data[4]} wird nicht unterstützt (diese Version kann {VERSION})."
            )
        if len(data) < HEADER_LEN:
            raise FormatError("Header unvollständig – Datei abgeschnitten?")

        _, _, kdf_id, memory, iterations, lanes, salt, stream_nonce, wrap_nonce = _PREFIX.unpack_from(data)
        if kdf_id != KDF_ARGON2ID:
            raise FormatError(f"Unbekannte Schlüsselableitung (ID {kdf_id}).")
        params = KdfParams(memory_kib=memory, iterations=iterations, lanes=lanes)
        params.validate()  # vor jeder teuren Berechnung
        return cls(params, salt, stream_nonce, wrap_nonce, bytes(data[PREFIX_LEN:HEADER_LEN]))

    # -- Schlüssel --------------------------------------------------------
    @classmethod
    def create(cls, password: str | bytes, params: KdfParams) -> tuple[Header, bytes]:
        """Neuen Header samt zufälligem Datenschlüssel (DEK) erzeugen."""
        dek = secrets.token_bytes(KEY_LEN)
        header = cls(
            kdf=params,
            salt=secrets.token_bytes(SALT_LEN),
            stream_nonce=secrets.token_bytes(STREAM_NONCE_LEN),
            wrap_nonce=secrets.token_bytes(WRAP_NONCE_LEN),
        )
        return header._wrap(dek, password), dek

    def _wrap(self, dek: bytes, password: str | bytes) -> Header:
        kek = derive_key(password, self.salt, self.kdf)
        wrapped = ChaCha20Poly1305(kek).encrypt(self.wrap_nonce, dek, self._prefix())
        return replace(self, wrapped_key=wrapped)

    def unlock(self, password: str | bytes) -> bytes:
        """Datenschlüssel mit dem Passwort freischalten."""
        kek = derive_key(password, self.salt, self.kdf)
        try:
            return ChaCha20Poly1305(kek).decrypt(self.wrap_nonce, self.wrapped_key, self._prefix())
        except InvalidTag:
            raise WrongPassword("Falsches Passwort oder manipulierter Header.") from None

    def rewrap(self, dek: bytes, new_password: str | bytes, params: KdfParams | None = None) -> Header:
        """Keyslot für neues Passwort und/oder neue Stufe erzeugen.

        Salt und Keyslot-Nonce werden neu gewürfelt, DEK und Stream-Nonce
        bleiben – die Nutzdaten müssen daher nicht neu verschlüsselt werden.
        """
        fresh = replace(
            self,
            kdf=params or self.kdf,
            salt=secrets.token_bytes(SALT_LEN),
            wrap_nonce=secrets.token_bytes(WRAP_NONCE_LEN),
            wrapped_key=b"",
        )
        return fresh._wrap(dek, new_password)

    def payload_key(self, dek: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_LEN,
            salt=self.stream_nonce,
            info=_PAYLOAD_INFO,
        ).derive(dek)


def read_header(f: BinaryIO) -> Header:
    return Header.from_bytes(f.read(HEADER_LEN))
