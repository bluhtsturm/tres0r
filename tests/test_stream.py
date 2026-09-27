import io
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from tres0r.errors import IntegrityError
from tres0r.stream import (
    CHUNK_SIZE,
    ENC_CHUNK_SIZE,
    DecryptingReader,
    EncryptingWriter,
    _nonce,
    encrypted_size,
)

KEY = bytes(range(32))
SIZES = [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE, 3 * CHUNK_SIZE + 123]


def encrypt(data, key=KEY, write_size=10_240):
    out = io.BytesIO()
    w = EncryptingWriter(out, key)
    for i in range(0, len(data), write_size):
        w.write(data[i : i + write_size])
    w.finish()
    return out.getvalue()


def decrypt(blob, key=KEY, read_size=-1):
    r = DecryptingReader(io.BytesIO(blob), key)
    if read_size < 0:
        data = r.read()
    else:
        parts = []
        while chunk := r.read(read_size):
            parts.append(chunk)
        data = b"".join(parts)
    r.finish()
    assert r.verified
    return data


def chunks(blob):
    return [blob[i : i + ENC_CHUNK_SIZE] for i in range(0, len(blob), ENC_CHUNK_SIZE)]


@pytest.mark.parametrize("size", SIZES)
def test_roundtrip(size):
    data = os.urandom(size)
    blob = encrypt(data)
    assert len(blob) == encrypted_size(size)
    assert decrypt(blob) == data


@pytest.mark.parametrize("read_size", [1, 7, 4096, CHUNK_SIZE + 5])
def test_roundtrip_small_reads(read_size):
    data = os.urandom(2 * CHUNK_SIZE + 17)
    assert decrypt(encrypt(data), read_size=read_size) == data


def test_write_granularity_does_not_matter():
    data = os.urandom(3 * CHUNK_SIZE + 5)
    assert decrypt(encrypt(data, write_size=1)) == data
    assert decrypt(encrypt(data, write_size=len(data))) == data


def test_wrong_key():
    blob = encrypt(b"geheim")
    with pytest.raises(IntegrityError):
        decrypt(blob, key=bytes(32))


@pytest.mark.parametrize("size", [0, 5, CHUNK_SIZE, 3 * CHUNK_SIZE + 123])
def test_every_truncation_is_detected(size):
    blob = encrypt(os.urandom(size))
    cut_points = {0, 1, 15, 16, len(blob) - 1}
    cut_points |= {i * ENC_CHUNK_SIZE for i in range(1, len(blob) // ENC_CHUNK_SIZE + 1)}
    cut_points |= {i * ENC_CHUNK_SIZE + 100 for i in range(len(blob) // ENC_CHUNK_SIZE)}
    for cut in sorted(c for c in cut_points if 0 <= c < len(blob)):
        with pytest.raises(IntegrityError):
            decrypt(blob[:cut])


@pytest.mark.parametrize("size", [0, 10, CHUNK_SIZE, 2 * CHUNK_SIZE + 1])
def test_appended_data_is_detected(size):
    blob = encrypt(os.urandom(size))
    for extra in (b"\x00", os.urandom(20), os.urandom(ENC_CHUNK_SIZE)):
        with pytest.raises(IntegrityError):
            decrypt(blob + extra)


def test_bitflip_in_every_chunk():
    blob = bytearray(encrypt(os.urandom(4 * CHUNK_SIZE + 10)))
    for offset in (0, ENC_CHUNK_SIZE + 5, 2 * ENC_CHUNK_SIZE + 1000, len(blob) - 1):
        tampered = bytearray(blob)
        tampered[offset] ^= 0x01
        with pytest.raises(IntegrityError):
            decrypt(bytes(tampered))


def test_reordered_duplicated_dropped_chunks():
    c = chunks(encrypt(os.urandom(4 * CHUNK_SIZE + 10)))  # 5 Chunks
    variants = {
        "vertauscht": [c[1], c[0], *c[2:]],
        "verdoppelt": [c[0], c[0], *c[1:]],
        "mitte fehlt": [c[0], *c[2:]],
        "anfang fehlt": c[1:],
        "letzter doppelt": [*c, c[-1]],
    }
    for name, parts in variants.items():
        with pytest.raises(IntegrityError):
            decrypt(b"".join(parts))


def test_chunks_from_other_stream_are_rejected():
    a = chunks(encrypt(os.urandom(2 * CHUNK_SIZE + 1)))
    b = chunks(encrypt(os.urandom(2 * CHUNK_SIZE + 1), key=bytes(32)))
    with pytest.raises(IntegrityError):
        decrypt(a[0] + b[1] + a[2])


def test_forged_empty_final_chunk_rejected():
    # Selbst mit Schlüssel: ein leerer Abschluss-Chunk nach Daten ist nicht kanonisch.
    aead = ChaCha20Poly1305(KEY)
    blob = aead.encrypt(_nonce(0, False), os.urandom(CHUNK_SIZE), None)
    blob += aead.encrypt(_nonce(1, True), b"", None)
    with pytest.raises(IntegrityError):
        decrypt(blob)


def test_writer_refuses_after_finish():
    w = EncryptingWriter(io.BytesIO(), KEY)
    w.finish()
    with pytest.raises(ValueError):
        w.write(b"x")
