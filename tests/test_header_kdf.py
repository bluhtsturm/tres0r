import unicodedata

import pytest

from tres0r import kdf
from tres0r.errors import FormatError, Tres0rError, UnsupportedVersion, WrongPassword
from tres0r.header import HEADER_LEN, MAGIC, Header
from tres0r.kdf import LEVELS, KdfParams, derive_key, level_of

from conftest import FAST, PASSWORD


# --- Header ---------------------------------------------------------------
def test_header_roundtrip_and_unlock():
    header, dek = Header.create(PASSWORD, FAST)
    raw = header.to_bytes()
    assert len(raw) == HEADER_LEN == 107
    parsed = Header.from_bytes(raw)
    assert parsed == header
    assert parsed.unlock(PASSWORD) == dek


def test_wrong_password():
    header, _ = Header.create(PASSWORD, FAST)
    with pytest.raises(WrongPassword):
        header.unlock("falsch")


@pytest.mark.parametrize("mask", [0x01, 0x80])
def test_every_header_byte_is_protected(mask):
    """Jede Änderung irgendwo im Header muss scheitern – nie still durchgehen."""
    header, _ = Header.create(PASSWORD, FAST)
    raw = header.to_bytes()
    for i in range(len(raw)):
        tampered = bytearray(raw)
        tampered[i] ^= mask
        with pytest.raises(Tres0rError):
            Header.from_bytes(bytes(tampered)).unlock(PASSWORD)


def test_magic_version_and_truncation():
    header, _ = Header.create(PASSWORD, FAST)
    raw = header.to_bytes()
    with pytest.raises(FormatError):
        Header.from_bytes(b"XXXX" + raw[4:])
    with pytest.raises(UnsupportedVersion):
        Header.from_bytes(raw[:4] + bytes([2]) + raw[5:])
    for n in (0, 3, 4, 5, HEADER_LEN - 1):
        with pytest.raises(FormatError):
            Header.from_bytes(raw[:n])
    assert raw.startswith(MAGIC)


def test_hostile_kdf_params_rejected_before_derivation(monkeypatch):
    """1 TiB RAM im Header darf nicht zu einer Argon2-Berechnung führen."""
    header, _ = Header.create(PASSWORD, FAST)
    raw = bytearray(header.to_bytes())
    raw[6:10] = (2**30).to_bytes(4, "big")  # 1 TiB in KiB
    monkeypatch.setattr(kdf, "_derive_cryptography", lambda *a: pytest.fail("KDF lief trotzdem"))
    with pytest.raises(FormatError):
        Header.from_bytes(bytes(raw))


def test_rewrap_keeps_payload_key():
    header, dek = Header.create(PASSWORD, FAST)
    other = KdfParams(memory_kib=16 * 1024, iterations=2, lanes=2)
    new = header.rewrap(dek, "neues-passwort", other)
    assert new.unlock("neues-passwort") == dek
    assert new.payload_key(dek) == header.payload_key(dek)
    assert new.kdf == other and new.salt != header.salt
    with pytest.raises(WrongPassword):
        new.unlock(PASSWORD)


# --- KDF ------------------------------------------------------------------
def test_levels_are_valid_and_ordered():
    costs = []
    for params in LEVELS.values():
        params.validate()
        costs.append(params.memory_kib * params.iterations)
        assert level_of(params) is not None
    assert costs == sorted(costs)
    assert level_of(FAST) is None


@pytest.mark.parametrize(
    "params",
    [
        KdfParams(1024, 1, 1),
        KdfParams(8 * 1024, 0, 1),
        KdfParams(8 * 1024, 1, 0),
        KdfParams(8 * 1024 * 1024, 1, 1),
        KdfParams(8 * 1024, 1000, 1),
    ],
)
def test_param_bounds(params):
    with pytest.raises(FormatError):
        params.validate()


def test_unicode_normalization():
    nfc = unicodedata.normalize("NFC", "Käsebrötchen")
    nfd = unicodedata.normalize("NFD", "Käsebrötchen")
    assert nfc != nfd
    salt = bytes(16)
    assert derive_key(nfc, salt, FAST) == derive_key(nfd, salt, FAST)


def test_empty_password_rejected():
    with pytest.raises(Tres0rError):
        derive_key("", bytes(16), FAST)


def test_backends_agree():
    pytest.importorskip("argon2")
    pw, salt = kdf.encode_password(PASSWORD), bytes(range(16))
    params = KdfParams(memory_kib=8 * 1024, iterations=2, lanes=4)
    assert kdf._derive_cryptography(pw, salt, params) == kdf._derive_argon2_cffi(pw, salt, params)


def test_fallback_to_argon2_cffi(monkeypatch):
    """Distributions-cryptography ohne Argon2 -> argon2-cffi springt ein."""
    pytest.importorskip("argon2")
    from cryptography.exceptions import UnsupportedAlgorithm

    expected = derive_key(PASSWORD, bytes(16), FAST)

    def unsupported(*args):
        raise UnsupportedAlgorithm("kein Argon2 im System-OpenSSL")

    monkeypatch.setattr(kdf, "_derive_cryptography", unsupported)
    assert derive_key(PASSWORD, bytes(16), FAST) == expected


def test_memory_check_gives_clear_error(monkeypatch):
    from tres0r.errors import InsufficientMemory

    monkeypatch.setattr(kdf, "available_memory", lambda: 100 * 1024 * 1024)
    kdf.check_memory(KdfParams(64 * 1024, 1, 1))  # 64 MiB passen
    with pytest.raises(InsufficientMemory, match="1024 MiB"):
        derive_key(PASSWORD, bytes(16), kdf.LEVELS["stark"])
    monkeypatch.setattr(kdf, "available_memory", lambda: None)  # unbekannt -> kein Veto
    kdf.check_memory(KdfParams(4 * 1024 * 1024, 1, 1))


def test_available_memory_is_plausible():
    value = kdf.available_memory()
    assert value is None or value > 16 * 1024 * 1024
