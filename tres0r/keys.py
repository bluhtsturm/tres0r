"""Schlüssel für Format v2: X25519-Identitäten, Empfänger, Signaturschlüssel,
Wiederherstellungsphrasen.

Textformate (Base32 ohne Padding, 4 Byte SHA-256-Prüfsumme gegen Tippfehler):

    Empfänger (X25519, öffentlich):          tres0r-pub-<58 Zeichen, klein>
    Identität (X25519, privat):              TRES0R-SECRET-<58 Zeichen, groß>
    Prüfschlüssel (Ed25519, öffentlich):     tres0r-sig-<58 Zeichen, klein>
    Signaturschlüssel (Ed25519, privat):     TRES0R-SIGN-SECRET-<58 Zeichen, groß>

Eine Identitätsdatei enthält eine oder mehrere private Schlüssel (beider Arten);
Zeilen mit "#" sind Kommentare. Sie wird mit Rechten 0600 angelegt und ist
standardmäßig mit einer Passphrase geschützt: Die geschützte Datei ist ein
tres0r-Rohdaten-Container mit Passwort-Slot (Stufe "stark"), dessen Inhalt die
Textform ist – ``tres0r decrypt`` zeigt sie also auch an.

Wiederherstellungsphrasen sind 20 zufällige Wörter aus den pwgen-Listen
(ca. 258 Bit). Wegen dieser Entropie braucht ihr Keyslot kein Argon2, sondern
nur HKDF – das Entsperren ist sofort erledigt.
"""
from __future__ import annotations

import base64
import hashlib
import os
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from . import passgen, rng
from .errors import Tres0rError, WrongPassword

PUB_PREFIX = "tres0r-pub-"
SECRET_PREFIX = "TRES0R-SECRET-"
SIGN_PUB_PREFIX = "tres0r-sig-"
SIGN_SECRET_PREFIX = "TRES0R-SIGN-SECRET-"
RECOVERY_WORDS = 20
ENCRYPTED_MAGIC = b"TRS0"  # geschützte Identitätsdatei = tres0r-Container


from .errors import KeyFormatError  # noqa: E402 – früher hier definiert, Name bleibt gültig


def _checksum(kind: bytes, raw: bytes) -> bytes:
    return hashlib.sha256(b"tres0r " + kind + b" " + raw).digest()[:4]


def _b32encode(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").rstrip("=")


def _b32decode(text: str) -> bytes:
    text = text.strip().upper()
    try:
        return base64.b32decode(text + "=" * (-len(text) % 8))
    except ValueError:  # binascii.Error ist eine Unterklasse
        raise KeyFormatError("Ungültige Zeichen im Schlüssel.") from None


def _decode(text: str, prefix: str, kind: bytes) -> bytes:
    text = text.strip()
    if not text.upper().startswith(prefix.upper()):
        raise KeyFormatError(f"Schlüssel muss mit '{prefix}' beginnen.")
    body = text[len(prefix):]
    data = _b32decode(body)
    if len(data) != 36:
        raise KeyFormatError("Schlüssel hat die falsche Länge.")
    # Nur die kanonische Schreibweise zulassen: Das letzte Base32-Zeichen trägt
    # 2 Füllbits, die b32decode sonst stillschweigend ignoriert.
    if _b32encode(data) != body.strip().upper():
        raise KeyFormatError("Ungültige Schreibweise – Tippfehler im Schlüssel?")
    raw, check = data[:32], data[32:]
    if _checksum(kind, raw) != check:
        raise KeyFormatError("Prüfsumme stimmt nicht – Tippfehler im Schlüssel?")
    return raw


# ---------------------------------------------------------------------------
# X25519
# ---------------------------------------------------------------------------
def encode_recipient(key: X25519PublicKey) -> str:
    """Öffentlichen X25519-Schlüssel (``key``) als ``tres0r-pub-…`` kodieren."""
    raw = key.public_bytes_raw()
    return PUB_PREFIX + _b32encode(raw + _checksum(b"pub", raw)).lower()


def parse_recipient(text: str) -> X25519PublicKey:
    """``tres0r-pub-…`` aus ``text`` lesen; ``KeyFormatError`` bei Tippfehlern."""
    return X25519PublicKey.from_public_bytes(_decode(text, PUB_PREFIX, b"pub"))


def encode_identity(key: X25519PrivateKey) -> str:
    """Privaten X25519-Schlüssel (``key``) als ``TRES0R-SECRET-…`` kodieren."""
    raw = key.private_bytes_raw()
    return SECRET_PREFIX + _b32encode(raw + _checksum(b"secret", raw)).upper()


def parse_identity(text: str) -> X25519PrivateKey:
    """``TRES0R-SECRET-…`` aus ``text`` lesen; ``KeyFormatError`` bei Tippfehlern."""
    return X25519PrivateKey.from_private_bytes(_decode(text, SECRET_PREFIX, b"secret"))


def generate_identity() -> X25519PrivateKey:
    """Neue X25519-Identität (privater Schlüssel zum Entschlüsseln)."""
    return rng.x25519_private_key()


# ---------------------------------------------------------------------------
# Ed25519 (Signaturen)
# ---------------------------------------------------------------------------
def encode_verify_key(key: Ed25519PublicKey) -> str:
    """Ed25519-Prüfschlüssel (``key``) als ``tres0r-sig-…`` kodieren."""
    raw = key.public_bytes_raw()
    return SIGN_PUB_PREFIX + _b32encode(raw + _checksum(b"sign-pub", raw)).lower()


def parse_verify_key(text: str) -> Ed25519PublicKey:
    """``tres0r-sig-…`` aus ``text`` lesen; ``KeyFormatError`` bei Tippfehlern."""
    return Ed25519PublicKey.from_public_bytes(_decode(text, SIGN_PUB_PREFIX, b"sign-pub"))


def encode_signing_key(key: Ed25519PrivateKey) -> str:
    """Ed25519-Signaturschlüssel (``key``) als Text kodieren."""
    raw = key.private_bytes_raw()
    return SIGN_SECRET_PREFIX + _b32encode(raw + _checksum(b"sign-secret", raw)).upper()


def parse_signing_key(text: str) -> Ed25519PrivateKey:
    """Signaturschlüssel aus ``text`` lesen; ``KeyFormatError`` bei Tippfehlern."""
    return Ed25519PrivateKey.from_private_bytes(_decode(text, SIGN_SECRET_PREFIX, b"sign-secret"))


def generate_signing_key() -> Ed25519PrivateKey:
    """Neuer Ed25519-Signaturschlüssel."""
    return Ed25519PrivateKey.from_private_bytes(rng.random_bytes(32))


def public_text(key: X25519PrivateKey | Ed25519PrivateKey) -> str:
    """Öffentlicher Teil als Text – Empfänger- oder Prüfschlüssel.

    ``key``: privater X25519- oder Ed25519-Schlüssel.
    """
    if isinstance(key, Ed25519PrivateKey):
        return encode_verify_key(key.public_key())
    return encode_recipient(key.public_key())


# ---------------------------------------------------------------------------
# Identitätsdateien
# ---------------------------------------------------------------------------
PrivateKey = X25519PrivateKey | Ed25519PrivateKey
Passphrase = str | Callable[[], str] | None


def identity_file_text(keys: PrivateKey | list[PrivateKey]) -> str:
    keys = keys if isinstance(keys, list) else [keys]
    created = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    lines = ["# tres0r-Identität (private Schlüssel) – geheim halten!", f"# erstellt: {created}"]
    for key in keys:
        kind = "Prüfschlüssel" if isinstance(key, Ed25519PrivateKey) else "öffentlicher Schlüssel"
        lines.append(f"# {kind}: {public_text(key)}")
    for key in keys:
        lines.append(encode_signing_key(key) if isinstance(key, Ed25519PrivateKey) else encode_identity(key))
    return "\n".join(lines) + "\n"


def _encrypt_text(text: str, passphrase: str, params) -> bytes:
    import io

    from . import container  # spät importiert: container importiert keys

    out = io.BytesIO()
    container.encrypt_stream(io.BytesIO(text.encode("utf-8")), out, passphrase, params)
    return out.getvalue()


def _write_new(path: str | os.PathLike[str], data: bytes) -> None:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise Tres0rError(f"{path} existiert bereits – wird nicht überschrieben.") from None
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def write_identity_file(
    path: str | os.PathLike[str],
    keys: PrivateKey | list[PrivateKey],
    passphrase: str | None = None,
    params=None,
) -> None:
    """Neue Identitätsdatei mit Rechten 0600 anlegen; überschreibt nie.

    Mit ``passphrase`` wird sie als tres0r-Container verschlüsselt
    (Standardstufe "stark", da die Datei genau gegen Offline-Raten schützen soll).

    ``keys``: ein oder mehrere private Schlüssel; ``params``: Argon2id für den Schutz mit ``passphrase``.
    """
    text = identity_file_text(keys)
    if passphrase is None:
        _write_new(path, text.encode("utf-8"))
        return
    from .kdf import LEVELS

    _write_new(path, _encrypt_text(text, passphrase, params or LEVELS["stark"]))


def is_protected(path: str | os.PathLike[str]) -> bool:
    """Ist die Identitätsdatei mit einer Passphrase geschützt?"""
    with open(path, "rb") as f:
        return f.read(4) == ENCRYPTED_MAGIC


def protect_identity_file(path: str | os.PathLike[str], passphrase: str, params=None) -> None:
    """Bestehende ungeschützte Identitätsdatei verschlüsseln (atomar ersetzt, 0600)."""
    from . import container
    from .kdf import LEVELS

    if is_protected(path):
        raise Tres0rError(f"{path} ist bereits geschützt.")
    text = Path(path).read_text(encoding="utf-8")
    _parse_key_text(text, str(path))  # nur gültige Identitätsdateien verschlüsseln
    data = _encrypt_text(text, passphrase, params or LEVELS["stark"])
    with container.atomic_output(path, overwrite=True) as out:
        out.write(data)
    if os.name == "posix":
        os.chmod(path, 0o600)


def _read_key_text(path: str | os.PathLike[str], passphrase: Passphrase) -> str:
    data = Path(path).read_bytes()
    if not data.startswith(ENCRYPTED_MAGIC):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise KeyFormatError(f"{path} ist keine Identitätsdatei.") from None
    import io

    from . import container

    creds = Credentials(passwords=[passphrase] if isinstance(passphrase, str) else [],
                        prompt=passphrase if callable(passphrase) else None)
    if not creds.passwords and creds.prompt is None:
        raise Tres0rError(f"{path} ist mit einer Passphrase geschützt.")
    out = io.BytesIO()
    try:
        container.decrypt_stream(io.BytesIO(data), out, creds)
    except WrongPassword:
        raise WrongPassword(f"Falsche Passphrase für {path}.") from None
    return out.getvalue().decode("utf-8")


@dataclass
class KeyFile:
    identities: list[X25519PrivateKey] = field(default_factory=list)
    signing_keys: list[Ed25519PrivateKey] = field(default_factory=list)


def _parse_key_text(text: str, source: str) -> KeyFile:
    found = KeyFile()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.upper().startswith(SIGN_SECRET_PREFIX):
            found.signing_keys.append(parse_signing_key(line))
        else:
            found.identities.append(parse_identity(line))
    if not found.identities and not found.signing_keys:
        raise KeyFormatError(f"{source} enthält keinen privaten Schlüssel.")
    return found


def load_key_file(path: str | os.PathLike[str], passphrase: Passphrase = None) -> KeyFile:
    """Identitätsdatei lesen – geschützt (Passphrase bzw. Rückfrage) oder nicht."""
    return _parse_key_text(_read_key_text(path, passphrase), str(path))


def load_identities(path: str | os.PathLike[str], passphrase: Passphrase = None) -> list[X25519PrivateKey]:
    """Alle X25519-Identitäten aus einer Identitätsdatei (ggf. mit ``passphrase``)."""
    found = load_key_file(path, passphrase).identities
    if not found:
        raise KeyFormatError(f"{path} enthält keine X25519-Identität.")
    return found


def load_signing_keys(path: str | os.PathLike[str], passphrase: Passphrase = None) -> list[Ed25519PrivateKey]:
    """Alle Signaturschlüssel aus einer Identitätsdatei (ggf. mit ``passphrase``)."""
    found = load_key_file(path, passphrase).signing_keys
    if not found:
        raise KeyFormatError(f"{path} enthält keinen Signaturschlüssel.")
    return found


def _public_lines(path: str | os.PathLike[str]) -> list[str]:
    text = Path(path).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


def load_recipients(path: str | os.PathLike[str], passphrase: Passphrase = None) -> list[X25519PublicKey]:
    """Empfängerliste (ein Schlüssel pro Zeile) oder eine Identitätsdatei."""
    if is_protected(path) or any(l.upper().startswith(SECRET_PREFIX) for l in _public_lines(path)):
        return [k.public_key() for k in load_identities(path, passphrase)]
    found = [parse_recipient(line) for line in _public_lines(path)]
    if not found:
        raise KeyFormatError(f"{path} enthält keinen Empfänger.")
    return found


def load_verify_keys(path: str | os.PathLike[str], passphrase: Passphrase = None) -> list[Ed25519PublicKey]:
    """Liste von Prüfschlüsseln (tres0r-sig-…) oder eine Identitätsdatei mit Signaturschlüssel."""
    if is_protected(path) or any(l.upper().startswith(SIGN_SECRET_PREFIX) for l in _public_lines(path)):
        return [k.public_key() for k in load_signing_keys(path, passphrase)]
    found = [parse_verify_key(line) for line in _public_lines(path)]
    if not found:
        raise KeyFormatError(f"{path} enthält keinen Prüfschlüssel.")
    return found


# ---------------------------------------------------------------------------
# Wiederherstellungsphrasen
# ---------------------------------------------------------------------------
def generate_recovery(lang: str = "de") -> passgen.Secret:
    """Neue Wiederherstellungsphrase (``lang``: Wortliste "de" oder "en")."""
    return passgen.generate_passphrase(RECOVERY_WORDS, lang=lang, separator="-")


def canonical_secret(text: str | bytes) -> bytes:
    """Kanonische Form für Schlüssel-Slots (FORMAT.md, Abschnitt 5.2):

    NFC -> Kleinschreibung (str.lower) -> NFC -> jedes Zeichen, das weder
    Buchstabe noch Ziffer ist (not str.isalnum), trennt Wörter -> Wörter mit
    "-" verbinden -> UTF-8 (surrogateescape).

    So entsperrt die Phrase auch, wenn sie mit Leerzeichen statt Bindestrichen
    oder in anderer Groß-/Kleinschreibung eingetippt wird.
    """
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    folded = unicodedata.normalize("NFC", unicodedata.normalize("NFC", text).lower())
    spaced = "".join(ch if ch.isalnum() else " " for ch in folded)
    return "-".join(spaced.split()).encode("utf-8", "surrogateescape")


# ---------------------------------------------------------------------------
# Keyfiles (zweiter Faktor)
# ---------------------------------------------------------------------------
KEYFILE_BYTES = 64


def keyfile_secret(path: str | os.PathLike[str]) -> bytes:
    """K = SHA-256("tres0r keyfile" ‖ Dateiinhalt) – beliebige Dateien sind möglich,
    empfohlen ist ein mit ``generate_keyfile`` erzeugtes (512 Bit Zufall)."""
    digest = hashlib.sha256(b"tres0r keyfile")
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.digest()


def keyfile_id(secret: bytes) -> bytes:
    """Kennung im Keyslot: erkennt ein falsches Keyfile, bevor Argon2 läuft.

    ``secret``: Ergebnis von ``keyfile_secret``.
    """
    return hashlib.sha256(b"tres0r keyfile id" + secret).digest()[:16]


def generate_keyfile(path: str | os.PathLike[str]) -> None:
    """Neues Keyfile (64 Byte Zufall, Rechte 0600) an ``path``; überschreibt nie."""
    _write_new(path, rng.random_bytes(KEYFILE_BYTES))


# ---------------------------------------------------------------------------
# Zugangsdaten zum Entsperren
# ---------------------------------------------------------------------------
@dataclass
class Credentials:
    """Alles, womit ein Container entsperrt werden kann.

    ``prompt`` wird nur aufgerufen, wenn Identitäten nicht gereicht haben und
    der Container Passwort- oder Wiederherstellungs-Slots hat.
    """

    passwords: list[str | bytes] = field(default_factory=list)
    identities: list[X25519PrivateKey] = field(default_factory=list)
    prompt: Callable[[], str] | None = None
    keyfiles: list[bytes] = field(default_factory=list)  # K-Werte, siehe keyfile_secret()
    shares: list = field(default_factory=list)  # shamir.Share
    fido2: Callable | None = None  # (rp_id, credential_id, salt) -> 32 Byte, z. B. hwtoken.TokenProvider

    def password_candidates(self) -> list[str | bytes]:
        if not self.passwords and self.prompt is not None:
            self.passwords.append(self.prompt())
        return self.passwords

    @classmethod
    def coerce(cls, value: Credentials | str | bytes | None) -> Credentials:
        if isinstance(value, Credentials):
            return value
        if value is None:
            return cls()
        return cls(passwords=[value])


__all__ = [
    "Credentials",
    "KeyFormatError",
    "KEYFILE_BYTES",
    "generate_identity",
    "generate_signing_key",
    "generate_recovery",
    "generate_keyfile",
    "encode_identity",
    "encode_recipient",
    "encode_signing_key",
    "encode_verify_key",
    "parse_identity",
    "parse_recipient",
    "parse_signing_key",
    "parse_verify_key",
    "load_identities",
    "load_recipients",
    "load_signing_keys",
    "load_verify_keys",
    "write_identity_file",
    "protect_identity_file",
    "is_protected",
    "public_text",
    "keyfile_secret",
    "keyfile_id",
]
