"""Gültig verschlüsselte, aber inhaltlich falsche Segmenttabellen müssen abgelehnt werden."""
import dataclasses
import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from tres0r import container, segments
from tres0r import header2 as h2
from tres0r.errors import FormatError, IntegrityError

from conftest import FAST, PASSWORD


@pytest.fixture
def appended(tmp_path, sample_tree):
    out = container.create(sample_tree, tmp_path / "s.tres0r", PASSWORD, FAST).path
    container.append(out, [sample_tree[1]], PASSWORD)
    with open(out, "rb") as f:
        header = h2.read_header(f)
    dek, _ = header.unlock(PASSWORD)
    with open(out, "rb") as f:
        total = f.seek(0, 2)
        entries, table_start = segments.read_table(f, total, header.header_len, dek, header.stream_nonce)
    return out, header, dek, entries, table_start


def with_table(path, header, dek, table_start, *, entries=None, plain=None):
    """Tabelle ersetzen – gültig verschlüsselt, Inhalt nach Wunsch."""
    raw = path.read_bytes()[:table_start]
    if plain is None:
        trailer = segments.encode_table(dek, header.stream_nonce, entries)
    else:  # Klartext direkt (z. B. falsche Version)
        nonce = bytes(16)
        key = h2._hkdf(dek, nonce, segments._INFO_TABLE)
        ct = ChaCha20Poly1305(key).encrypt(bytes(12), plain, segments._INFO_TABLE + header.stream_nonce)
        trailer = nonce + ct + struct.pack(">I", len(ct)) + segments.MAGIC
    path.write_bytes(raw + trailer)


def test_valid_table_reads(appended):
    out, *_ = appended
    assert container.verify(out, PASSWORD).segments == 2


@pytest.mark.parametrize("change, message", [
    (lambda e: [dataclasses.replace(e[0], offset=16)] + e[1:], "Nutzdatenbeginn"),
    (lambda e: [e[0], dataclasses.replace(e[1], offset=e[0].length - 10)], "Grenzen"),  # überlappt
    (lambda e: [e[0], dataclasses.replace(e[1], length=e[1].length + 50)], "Grenzen"),  # ragt in die Tabelle
    (lambda e: [e[0], dataclasses.replace(e[1], length=8)], "Grenzen"),                 # kürzer als ein Tag
    (lambda e: [e[0], dataclasses.replace(e[1], flags=0x04)], "Eigenschaften"),          # Segment-Flag im Segment
    (lambda e: [e[0], dataclasses.replace(e[1], compression=7)], "Eigenschaften"),
])
def test_bad_entries_rejected(appended, change, message):
    out, header, dek, entries, table_start = appended
    with_table(out, header, dek, table_start, entries=change(entries))
    with pytest.raises(FormatError, match=message):
        container.verify(out, PASSWORD)


@pytest.mark.parametrize("plain, message", [
    (bytes([2]) + struct.pack(">I", 1) + bytes(34), "Version"),
    (bytes([1]) + struct.pack(">I", 0), "Länge"),                                   # null Segmente
    (bytes([1]) + struct.pack(">I", 2) + bytes(34), "Länge"),                        # Anzahl passt nicht
    (bytes([1]) + struct.pack(">I", segments.MAX_SEGMENTS + 1), "Länge"),
])
def test_bad_table_structure_rejected(appended, plain, message):
    out, header, dek, _, table_start = appended
    with_table(out, header, dek, table_start, plain=plain)
    with pytest.raises(FormatError, match=message):
        container.verify(out, PASSWORD)


def test_missing_or_foreign_table(appended, tmp_path):
    out, header, dek, entries, table_start = appended
    out.write_bytes(out.read_bytes()[:header.header_len + 20])  # fast alles weg
    with pytest.raises(FormatError, match="Segmenttabelle fehlt"):
        container.verify(out, PASSWORD)


def test_repair_skips_damaged_candidates(appended):
    out, header, dek, entries, table_start = appended
    good = out.read_bytes()
    # hinter der gültigen Tabelle: ein Stück, das wie eine Tabelle endet, aber keine ist
    out.write_bytes(good + b"\x00" * 40 + struct.pack(">I", 20) + segments.MAGIC)
    with pytest.raises((FormatError, IntegrityError)):
        container.verify(out, PASSWORD)
    assert "gekürzt" in container.repair(out, PASSWORD).action
    assert out.read_bytes() == good


def test_window_seek_modes(tmp_path):
    import io

    window = segments.Window(io.BytesIO(b"0123456789"), 2, 5)
    assert window.seek(0, io.SEEK_END) == 7 and window.read() == b""
    window.seek(-3, io.SEEK_CUR)
    assert window.tell() == 4 and window.read(10) == b"456" and window.peek() == b""
