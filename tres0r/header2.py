"""Container-Header, Formatversion 2.

Layout (big endian):

    Offset  Länge  Feld
         0      4  Magic "TRS0"
         4      1  Formatversion (2)
         5      2  Header-Länge gesamt (inkl. MAC)
         7      1  Nutzdatentyp: 0 = tar, 1 = roh (Datenstrom)
         8      1  Kompression: 0 = keine, 1 = zstd
         9      1  Flags: Bit 0 = Index am Ende, Bit 1 = signiert
        10     16  Stream-Nonce
        26      1  Anzahl Keyslots (1–16)
        27      …  Keyslots: Typ (1) | Länge (2) | Inhalt
      Ende-32  32  HMAC-SHA256 über alle vorherigen Header-Bytes

Keyslot-Typen (Inhalt; "DEK" = 32 Byte, verschlüsselt mit ChaCha20-Poly1305
unter einem Slot-Schlüssel "KEK", Nonce 0, Associated Data = Typ + Parameter):

    1 Passwort      KDF-ID | Argon2id m, t, p | Salt(16) | DEK(48)
                    KEK = Argon2id(Passwort, Salt)
    2 Schlüssel     Salt(16) | DEK(48)
                    KEK = HKDF(kanonische Phrase, Salt) – nur für generierte
                    Geheimnisse mit hoher Entropie (Wiederherstellungsphrase)
    3 X25519        Ephemerer öffentlicher Schlüssel(32) | DEK(48)
                    KEK = HKDF(X25519(eph, Empfänger), eph ‖ Empfänger)
    4 reserviert    ML-KEM-768 + X25519 (Post-Quanten-Hybrid)

Jeder KEK ist einmalig (zufälliges Salt bzw. ephemerer Schlüssel), daher ist
die feste Nonce 0 unbedenklich. Unbekannte Slot-Typen werden beim Entsperren
übersprungen und beim Umschreiben unverändert übernommen.

Header-MAC und Key-Commitment: Der MAC-Schlüssel wird aus dem DEK abgeleitet.
ChaCha20-Poly1305 bindet einen Chiffretext nicht fest an einen Schlüssel – ein
präparierter Slot könnte unter mehreren Passwörtern "gültig" entschlüsseln
(Partitioning-Oracle-Angriffe). Der HMAC über den ganzen Header passt aber
höchstens zu einem dieser DEKs. Erst nach erfolgreicher MAC-Prüfung gilt ein
Container als entsperrt. Nebenbei schützt der MAC alle übrigen Header-Felder.

Welcher Empfänger einen X25519-Slot öffnen kann, steht nirgends im Klartext.
"""
from __future__ import annotations

import hmac
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, ClassVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import header as v1
from . import rng
from .errors import FormatError, IntegrityError, Tres0rError, UnsupportedVersion, WrongPassword
from .kdf import KDF_ARGON2ID, KEY_LEN, SALT_LEN, KdfParams, derive_key, level_of
from . import shamir
from .keys import Credentials, canonical_secret, keyfile_id

MAGIC = v1.MAGIC
VERSION = 2

PAYLOAD_TAR, PAYLOAD_RAW = 0, 1
COMPRESS_NONE, COMPRESS_ZSTD = 0, 1
FLAG_INDEX = 0x01
FLAG_SIGNED = 0x02  # Signaturanhang am Ende des Klartexts (sign.py)
FLAG_SEGMENTS = 0x04  # angehängte Segmente, Segmenttabelle am Dateiende (segments.py)
_KNOWN_FLAGS = FLAG_INDEX | FLAG_SIGNED | FLAG_SEGMENTS

SLOT_PASSWORD, SLOT_SECRET, SLOT_X25519, SLOT_MLKEM768_X25519 = 1, 2, 3, 4
SLOT_PASSWORD_KEYFILE, SLOT_THRESHOLD, SLOT_FIDO2 = 5, 6, 7
SLOT_NAMES = {
    SLOT_PASSWORD: "Passwort",
    SLOT_SECRET: "Wiederherstellung",
    SLOT_X25519: "Empfänger (X25519)",
    SLOT_MLKEM768_X25519: "Empfänger (ML-KEM-768 + X25519)",
    SLOT_PASSWORD_KEYFILE: "Passwort + Keyfile",
    SLOT_THRESHOLD: "Schwellwert",
    SLOT_FIDO2: "Passwort + FIDO2-Token",
}
_ARGON2_SLOTS = (SLOT_PASSWORD, SLOT_PASSWORD_KEYFILE, SLOT_FIDO2)
FIDO2_SALT_LEN = 32
MAX_CREDENTIAL_ID = 1023

_FIXED = struct.Struct(">4sBHBBB16sB")
_SLOT_HEAD = struct.Struct(">BH")
_PW_PARAMS = struct.Struct(">BIIB16s")
_THRESHOLD = struct.Struct(">BB8s16s")
MAC_LEN = 32
WRAPPED_LEN = KEY_LEN + 16
MIN_HEADER_LEN = _FIXED.size + MAC_LEN
MAX_HEADER_LEN = 0xFFFF
MAX_SLOTS = 16
MAX_PASSWORD_SLOTS = 4  # jeder kostet beim Entsperren eine volle Argon2id-Runde
_BODY_LEN = {
    SLOT_PASSWORD: _PW_PARAMS.size + WRAPPED_LEN,
    SLOT_SECRET: SALT_LEN + WRAPPED_LEN,
    SLOT_X25519: 32 + WRAPPED_LEN,
    SLOT_PASSWORD_KEYFILE: _PW_PARAMS.size + 16 + WRAPPED_LEN,
    SLOT_THRESHOLD: _THRESHOLD.size + WRAPPED_LEN,
}
_ZERO_NONCE = bytes(12)
_INFO_SECRET = b"tres0r v2 secret slot"
_INFO_X25519 = b"tres0r v2 x25519 slot"
_INFO_MAC = b"tres0r v2 header mac"
_INFO_KEYFILE = b"tres0r v2 password+keyfile slot"
_INFO_THRESHOLD = b"tres0r v2 threshold slot"
_INFO_FIDO2 = b"tres0r v2 password+fido2 slot"
_INFO_PAYLOAD = b"tres0r v2 payload key"


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, info=info).derive(ikm)


# ---------------------------------------------------------------------------
# Keyslots
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Slot:
    type: int
    body: bytes

    @property
    def known(self) -> bool:
        return self.type in _BODY_LEN

    @property
    def params(self) -> bytes:
        return self.body[:-WRAPPED_LEN]

    @property
    def wrapped(self) -> bytes:
        return self.body[-WRAPPED_LEN:]

    def _aad(self) -> bytes:
        return bytes([self.type]) + self.params

    def _unwrap(self, kek: bytes) -> bytes | None:
        try:
            return ChaCha20Poly1305(kek).decrypt(_ZERO_NONCE, self.wrapped, self._aad())
        except InvalidTag:
            return None

    @property
    def kdf(self) -> KdfParams | None:
        if self.type not in _ARGON2_SLOTS:
            return None
        _, memory, iterations, lanes, _ = _PW_PARAMS.unpack(self.params[:_PW_PARAMS.size])
        return KdfParams(memory_kib=memory, iterations=iterations, lanes=lanes)

    @property
    def salt(self) -> bytes:
        if self.type in _ARGON2_SLOTS:
            return self.params[_PW_PARAMS.size - SALT_LEN:_PW_PARAMS.size]
        if self.type == SLOT_THRESHOLD:
            return self.params[-SALT_LEN:]
        return self.params[:SALT_LEN]

    @property
    def keyfile_id(self) -> bytes | None:
        return self.params[_PW_PARAMS.size:] if self.type == SLOT_PASSWORD_KEYFILE else None

    @property
    def fido2(self) -> tuple[str, bytes, bytes] | None:
        """(RP-ID, Credential-ID, hmac-Salt) eines Passwort+FIDO2-Slots."""
        if self.type != SLOT_FIDO2:
            return None
        rest = self.params[_PW_PARAMS.size:]
        salt, rp_len = rest[:FIDO2_SALT_LEN], rest[FIDO2_SALT_LEN]
        rp = rest[FIDO2_SALT_LEN + 1:FIDO2_SALT_LEN + 1 + rp_len]
        at = FIDO2_SALT_LEN + 1 + rp_len
        cred_len = struct.unpack(">H", rest[at:at + 2])[0]
        return rp.decode("utf-8"), rest[at + 2:at + 2 + cred_len], salt

    @property
    def threshold(self) -> tuple[int, int, bytes] | None:
        """(k, n, set_id) eines Schwellwert-Slots."""
        if self.type != SLOT_THRESHOLD:
            return None
        k, n, set_id, _ = _THRESHOLD.unpack(self.params)
        return k, n, set_id

    def describe(self) -> str:
        name = SLOT_NAMES.get(self.type, f"unbekannter Typ {self.type}")
        if self.type in _ARGON2_SLOTS:
            level = level_of(self.kdf)
            return f"{name} (Stufe {level}, {self.kdf.describe()})" if level else f"{name} ({self.kdf.describe()})"
        if self.type == SLOT_THRESHOLD:
            k, n, _ = self.threshold
            return f"{name} ({k} von {n} Anteilen)"
        return name

    def validate(self) -> None:
        expected = _BODY_LEN.get(self.type)
        if expected is not None and len(self.body) != expected:
            raise FormatError(f"Keyslot vom Typ {self.type} hat die falsche Länge.")
        if self.type == SLOT_FIDO2 and len(self.body) < _PW_PARAMS.size + FIDO2_SALT_LEN + 1 + 1 + 2 + 1 + WRAPPED_LEN:
            raise FormatError("FIDO2-Keyslot ist zu kurz.")  # vor jedem Zugriff auf die Felder
        if self.type in _ARGON2_SLOTS:
            if self.params[0] != KDF_ARGON2ID:
                raise FormatError(f"Unbekannte Schlüsselableitung (ID {self.params[0]}).")
            self.kdf.validate()
        if self.type == SLOT_THRESHOLD:
            k, n, _ = self.threshold
            if not 2 <= k <= n <= shamir.MAX_SHARES:
                raise FormatError(f"Ungültiger Schwellwert {k} von {n}.")
        if self.type == SLOT_FIDO2:
            rest = self.body[_PW_PARAMS.size:len(self.body) - WRAPPED_LEN] if len(self.body) >= _PW_PARAMS.size + WRAPPED_LEN else b""
            if len(rest) < FIDO2_SALT_LEN + 1:
                raise FormatError("FIDO2-Keyslot ist zu kurz.")
            rp_len = rest[FIDO2_SALT_LEN]
            at = FIDO2_SALT_LEN + 1 + rp_len
            if rp_len == 0 or len(rest) < at + 2:
                raise FormatError("FIDO2-Keyslot hat eine ungültige RP-ID.")
            cred_len = struct.unpack(">H", rest[at:at + 2])[0]
            if not 1 <= cred_len <= MAX_CREDENTIAL_ID or len(rest) != at + 2 + cred_len:
                raise FormatError("FIDO2-Keyslot hat eine ungültige Credential-ID.")
            try:
                rest[FIDO2_SALT_LEN + 1:at].decode("utf-8")
            except UnicodeDecodeError:
                raise FormatError("FIDO2-Keyslot hat eine ungültige RP-ID.") from None


def _wrap(slot_type: int, params: bytes, kek: bytes, dek: bytes) -> Slot:
    wrapped = ChaCha20Poly1305(kek).encrypt(_ZERO_NONCE, dek, bytes([slot_type]) + params)
    return Slot(slot_type, params + wrapped)


def password_slot(dek: bytes, password: str | bytes, params: KdfParams) -> Slot:
    params.validate()
    salt = rng.random_bytes(SALT_LEN)
    raw = _PW_PARAMS.pack(KDF_ARGON2ID, params.memory_kib, params.iterations, params.lanes, salt)
    return _wrap(SLOT_PASSWORD, raw, derive_key(password, salt, params), dek)


def secret_slot(dek: bytes, secret: str | bytes) -> Slot:
    salt = rng.random_bytes(SALT_LEN)
    return _wrap(SLOT_SECRET, salt, _hkdf(canonical_secret(secret), salt, _INFO_SECRET), dek)


def password_keyfile_slot(dek: bytes, password: str | bytes, keyfile: bytes, params: KdfParams) -> Slot:
    """Passwort UND Keyfile: KEK = HKDF(Argon2id(P) ‖ K, Salt)."""
    params.validate()
    salt = rng.random_bytes(SALT_LEN)
    raw = _PW_PARAMS.pack(KDF_ARGON2ID, params.memory_kib, params.iterations, params.lanes, salt) + keyfile_id(keyfile)
    kek = _hkdf(derive_key(password, salt, params) + keyfile, salt, _INFO_KEYFILE)
    return _wrap(SLOT_PASSWORD_KEYFILE, raw, kek, dek)


def password_fido2_slot(dek: bytes, password: str | bytes, params: KdfParams, rp_id: str,
                        credential_id: bytes, hmac_salt: bytes, hmac_value: bytes) -> Slot:
    """Passwort UND FIDO2-Token: KEK = HKDF(Argon2id(P) ‖ hmac-secret(Token, hmac_salt), Salt)."""
    params.validate()
    rp = rp_id.encode("utf-8")
    if not (1 <= len(rp) <= 255 and 1 <= len(credential_id) <= MAX_CREDENTIAL_ID
            and len(hmac_salt) == FIDO2_SALT_LEN and len(hmac_value) == 32):
        raise ValueError("Ungültige FIDO2-Parameter.")
    salt = rng.random_bytes(SALT_LEN)
    raw = (_PW_PARAMS.pack(KDF_ARGON2ID, params.memory_kib, params.iterations, params.lanes, salt) + hmac_salt
           + bytes([len(rp)]) + rp + struct.pack(">H", len(credential_id)) + credential_id)
    kek = _hkdf(derive_key(password, salt, params) + hmac_value, salt, _INFO_FIDO2)
    return _wrap(SLOT_FIDO2, raw, kek, dek)


def threshold_slot(dek: bytes, k: int, n: int) -> tuple[Slot, list[shamir.Share]]:
    """Schwellwert-Slot: KEK = HKDF(S, Salt) mit S aus k von n Shamir-Anteilen."""
    secret = rng.random_bytes(shamir.SECRET_LEN)
    shares = shamir.split(secret, k, n)
    salt = rng.random_bytes(SALT_LEN)
    raw = _THRESHOLD.pack(k, n, shares[0].set_id, salt)
    return _wrap(SLOT_THRESHOLD, raw, _hkdf(secret, salt, _INFO_THRESHOLD), dek), shares


def x25519_slot(dek: bytes, recipient: X25519PublicKey) -> Slot:
    ephemeral = rng.x25519_private_key()
    epk = ephemeral.public_key().public_bytes_raw()
    shared = ephemeral.exchange(recipient)
    kek = _hkdf(shared, epk + recipient.public_bytes_raw(), _INFO_X25519)
    return _wrap(SLOT_X25519, epk, kek, dek)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
@dataclass
class HeaderV2:
    payload_type: int
    compression: int
    flags: int
    stream_nonce: bytes
    slots: list[Slot]
    mac: bytes = b""
    raw: bytes = field(default=b"", repr=False)

    version: ClassVar[int] = VERSION

    # -- Serialisierung ---------------------------------------------------
    def _unsigned(self) -> bytes:
        slot_bytes = b"".join(_SLOT_HEAD.pack(s.type, len(s.body)) + s.body for s in self.slots)
        length = _FIXED.size + len(slot_bytes) + MAC_LEN
        if length > MAX_HEADER_LEN:
            raise FormatError("Header wird zu groß.")
        return _FIXED.pack(MAGIC, VERSION, length, self.payload_type, self.compression, self.flags,
                           self.stream_nonce, len(self.slots)) + slot_bytes

    @property
    def header_len(self) -> int:
        return len(self.raw)

    @property
    def has_index(self) -> bool:
        return bool(self.flags & FLAG_INDEX)

    @property
    def signed(self) -> bool:
        return bool(self.flags & FLAG_SIGNED)

    @classmethod
    def from_bytes(cls, data: bytes) -> HeaderV2:
        if len(data) < MIN_HEADER_LEN:
            raise FormatError("Header unvollständig – Datei abgeschnitten?")
        magic, version, length, ptype, compression, flags, nonce, count = _FIXED.unpack_from(data)
        if magic != MAGIC or version != VERSION:
            raise FormatError("Kein Header der Formatversion 2.")
        if length != len(data):
            raise FormatError("Header-Länge stimmt nicht – Datei abgeschnitten?")
        if ptype not in (PAYLOAD_TAR, PAYLOAD_RAW):
            raise FormatError(f"Unbekannter Nutzdatentyp {ptype}.")
        if compression not in (COMPRESS_NONE, COMPRESS_ZSTD):
            raise FormatError(f"Unbekannte Kompression {compression}.")
        if flags & ~_KNOWN_FLAGS:
            raise FormatError(f"Unbekannte Flags {flags:#x}.")
        if ptype == PAYLOAD_RAW and flags & FLAG_SEGMENTS:
            raise FormatError("Rohdaten-Container können keine angehängten Segmente haben.")
        if ptype == PAYLOAD_RAW and flags & FLAG_INDEX:
            raise FormatError("Rohdaten-Container mit Index ist unzulässig.")
        if not 1 <= count <= MAX_SLOTS:
            raise FormatError(f"Ungültige Anzahl Keyslots ({count}).")

        slots, pos, end = [], _FIXED.size, len(data) - MAC_LEN
        for _ in range(count):
            if pos + _SLOT_HEAD.size > end:
                raise FormatError("Keyslot-Liste abgeschnitten.")
            slot_type, slot_len = _SLOT_HEAD.unpack_from(data, pos)
            pos += _SLOT_HEAD.size
            if pos + slot_len > end:
                raise FormatError("Keyslot abgeschnitten.")
            slot = Slot(slot_type, bytes(data[pos:pos + slot_len]))
            slot.validate()  # u. a. Argon2-Obergrenzen, bevor irgendetwas berechnet wird
            slots.append(slot)
            pos += slot_len
        if pos != end:
            raise FormatError("Überzählige Bytes im Header.")
        if sum(s.type in _ARGON2_SLOTS for s in slots) > MAX_PASSWORD_SLOTS:
            raise FormatError(f"Mehr als {MAX_PASSWORD_SLOTS} Passwort-Slots.")
        return cls(ptype, compression, flags, bytes(nonce), slots, bytes(data[end:]), bytes(data))

    # -- Schlüssel --------------------------------------------------------
    @staticmethod
    def mac_key(dek: bytes, stream_nonce: bytes) -> bytes:
        return _hkdf(dek, stream_nonce, _INFO_MAC)

    def payload_key(self, dek: bytes) -> bytes:
        return payload_key_for(dek, self.stream_nonce)

    @property
    def segmented(self) -> bool:
        return bool(self.flags & FLAG_SEGMENTS)

    def _compute_mac(self, dek: bytes) -> bytes:
        return hmac.new(self.mac_key(dek, self.stream_nonce), self.raw[:-MAC_LEN], "sha256").digest()

    def _sign(self, dek: bytes) -> HeaderV2:
        unsigned = self._unsigned()
        mac = hmac.new(self.mac_key(dek, self.stream_nonce), unsigned, "sha256").digest()
        self.mac, self.raw = mac, unsigned + mac
        return self

    def to_bytes(self) -> bytes:
        return self.raw

    @classmethod
    def create(cls, dek: bytes, slots: list[Slot], *, payload_type: int = PAYLOAD_TAR,
               compression: int = COMPRESS_NONE, flags: int = 0) -> HeaderV2:
        _check_slots(slots)
        header = cls(payload_type, compression, flags, rng.random_bytes(16), list(slots))
        return header._sign(dek)

    def with_flags(self, dek: bytes, flags: int) -> HeaderV2:
        """Gleicher Container, andere Flags – gleiche Länge (für Änderungen an Ort und Stelle)."""
        return HeaderV2(self.payload_type, self.compression, flags, self.stream_nonce, list(self.slots))._sign(dek)

    def with_slots(self, dek: bytes, slots: list[Slot]) -> HeaderV2:
        """Gleicher Container, andere Keyslots (Nutzdaten bleiben gültig)."""
        _check_slots(slots)
        return HeaderV2(self.payload_type, self.compression, self.flags, self.stream_nonce,
                        list(slots))._sign(dek)

    def unlock(self, credentials: Credentials | str | bytes | None) -> tuple[bytes, int]:
        """DEK und Index des passenden Slots. Billige Wege zuerst:
        X25519-Identitäten, dann Wiederherstellungs-Slots (HKDF), zuletzt
        Passwort-Slots (Argon2id)."""
        creds = Credentials.coerce(credentials)

        def accept(dek: bytes, index: int) -> tuple[bytes, int]:
            if not hmac.compare_digest(self._compute_mac(dek), self.mac):
                raise IntegrityError("Header-Prüfsumme falsch – Header manipuliert oder Container präpariert.")
            return dek, index

        for identity in creds.identities:
            own = identity.public_key().public_bytes_raw()
            for i, slot in enumerate(self.slots):
                if slot.type != SLOT_X25519:
                    continue
                epk = slot.params
                try:
                    shared = identity.exchange(X25519PublicKey.from_public_bytes(epk))
                except ValueError:  # Low-Order-Punkt
                    continue
                if not any(shared):
                    continue
                dek = slot._unwrap(_hkdf(shared, epk + own, _INFO_X25519))
                if dek is not None:
                    return accept(dek, i)

        hints = []
        # Schwellwert-Slots: aus Anteilen, ganz ohne Passwort
        for i, slot in enumerate(self.slots):
            if slot.type != SLOT_THRESHOLD or not creds.shares:
                continue
            k, n, set_id = slot.threshold
            matching = [sh for sh in creds.shares if sh.set_id == set_id]
            if not matching:
                continue
            try:
                secret = shamir.combine(matching)
            except WrongPassword as e:
                hints.append(str(e))
                continue
            dek = slot._unwrap(_hkdf(secret, slot.salt, _INFO_THRESHOLD))
            if dek is not None:
                return accept(dek, i)
            hints.append("Die Anteile passen nicht zu diesem Container.")

        secret_slots = [(i, s) for i, s in enumerate(self.slots) if s.type == SLOT_SECRET]
        password_slots = [(i, s) for i, s in enumerate(self.slots) if s.type == SLOT_PASSWORD]
        keyfile_slots = [(i, s) for i, s in enumerate(self.slots) if s.type == SLOT_PASSWORD_KEYFILE]
        usable_keyfile_slots = [(i, s, [kf for kf in creds.keyfiles if keyfile_id(kf) == s.keyfile_id])
                                for i, s in keyfile_slots]
        usable_keyfile_slots = [(i, s, kfs) for i, s, kfs in usable_keyfile_slots if kfs]
        fido2_slots = [(i, s) for i, s in enumerate(self.slots) if s.type == SLOT_FIDO2]
        use_fido2 = bool(fido2_slots) and creds.fido2 is not None
        if keyfile_slots and not usable_keyfile_slots and not secret_slots and not password_slots:
            hints.append("Dieser Container braucht zusätzlich das passende Keyfile (--keyfile).")
        if fido2_slots and not use_fido2 and not secret_slots and not password_slots and not usable_keyfile_slots:
            hints.append("Dieser Container braucht zusätzlich den FIDO2-Token (--fido2).")
        if not secret_slots and not password_slots and not usable_keyfile_slots and not use_fido2:
            raise WrongPassword(hints[0] if hints else "Keine passende Identität für diesen Container.")
        candidates = creds.password_candidates()
        if not candidates:
            raise WrongPassword(hints[0] if hints else "Kein Passwort bzw. keine passende Identität angegeben.")

        for candidate in candidates:
            key = canonical_secret(candidate)
            for i, slot in secret_slots:
                dek = slot._unwrap(_hkdf(key, slot.params, _INFO_SECRET))
                if dek is not None:
                    return accept(dek, i)
        for candidate in candidates:
            for i, slot in password_slots:
                dek = slot._unwrap(derive_key(candidate, slot.salt, slot.kdf))
                if dek is not None:
                    return accept(dek, i)
            for i, slot, keyfiles in usable_keyfile_slots:
                stretched = derive_key(candidate, slot.salt, slot.kdf)
                for keyfile in keyfiles:
                    dek = slot._unwrap(_hkdf(stretched + keyfile, slot.salt, _INFO_KEYFILE))
                    if dek is not None:
                        return accept(dek, i)
        for i, slot in fido2_slots if use_fido2 else ():
            try:
                value = creds.fido2(*slot.fido2)  # Berührung (bei mehreren Kandidaten nur einmal)
            except WrongPassword as e:
                hints.append(str(e))
                continue
            for candidate in candidates:
                dek = slot._unwrap(_hkdf(derive_key(candidate, slot.salt, slot.kdf) + value, slot.salt, _INFO_FIDO2))
                if dek is not None:
                    return accept(dek, i)
        if keyfile_slots and not usable_keyfile_slots:
            hints.append("Hinweis: Dieser Container hat Slots, die zusätzlich ein Keyfile brauchen.")
        raise WrongPassword("Falsches Passwort bzw. kein passender Schlüssel." + (f" {hints[-1]}" if hints else ""))


def payload_key_for(dek: bytes, stream_nonce: bytes) -> bytes:
    """Schlüssel eines Nutzdatenstroms (Segment 0: Nonce aus dem Header)."""
    return _hkdf(dek, stream_nonce, _INFO_PAYLOAD)


def _check_slots(slots: list[Slot]) -> None:
    if not 1 <= len(slots) <= MAX_SLOTS:
        raise Tres0rError(f"Ein Container braucht 1 bis {MAX_SLOTS} Keyslots.")
    if sum(s.type in _ARGON2_SLOTS for s in slots) > MAX_PASSWORD_SLOTS:
        raise Tres0rError(f"Höchstens {MAX_PASSWORD_SLOTS} Passwort-Slots pro Container.")


# ---------------------------------------------------------------------------
# Lesen (beide Formatversionen)
# ---------------------------------------------------------------------------
def _read_exact(f: BinaryIO, n: int) -> bytes:
    parts, have = [], 0
    while have < n:
        part = f.read(n - have)
        if not part:
            break
        parts.append(part)
        have += len(part)
    return b"".join(parts)


def read_header(f: BinaryIO) -> v1.Header | HeaderV2:
    head = _read_exact(f, 7)
    if head[:4] != MAGIC:
        raise FormatError("Keine tres0r-Datei (Kennung fehlt).")
    if len(head) < 5:
        raise FormatError("Header unvollständig – Datei abgeschnitten?")
    if head[4] == v1.VERSION:
        return v1.Header.from_bytes(head + _read_exact(f, v1.HEADER_LEN - len(head)))
    if head[4] != VERSION:
        raise UnsupportedVersion(f"Formatversion {head[4]} wird nicht unterstützt (bekannt: 1, 2).")
    if len(head) < 7:
        raise FormatError("Header unvollständig – Datei abgeschnitten?")
    length = int.from_bytes(head[5:7], "big")
    if length < MIN_HEADER_LEN:
        raise FormatError("Header-Länge ungültig.")
    return HeaderV2.from_bytes(head + _read_exact(f, length - len(head)))
