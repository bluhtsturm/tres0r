import io
import json
import os

import pytest

from tres0r import container, keys, sign
from tres0r import header2 as h2
from tres0r.cli import main
from tres0r.errors import FormatError, Tres0rError, WrongPassword
from tres0r.kdf import LEVELS
from tres0r.keys import Credentials
from tres0r.sign import SignatureError
from tres0r.stream import EncryptingWriter

from conftest import FAST, PASSWORD, snapshot


@pytest.fixture
def signer():
    return keys.generate_signing_key()


@pytest.fixture(autouse=True)
def fast_levels(monkeypatch):
    for name in LEVELS:
        monkeypatch.setitem(LEVELS, name, FAST)


def pack(sources, out, **kw):
    return container.create(sources, out, PASSWORD, FAST, **kw).path


# --- Schlüssel ---------------------------------------------------------------
def test_signing_key_texts(signer):
    public = keys.encode_verify_key(signer.public_key())
    secret = keys.encode_signing_key(signer)
    assert public.startswith("tres0r-sig-") and secret.startswith("TRES0R-SIGN-SECRET-")
    assert keys.parse_verify_key(public).public_bytes_raw() == signer.public_key().public_bytes_raw()
    assert keys.parse_signing_key(secret).private_bytes_raw() == signer.private_bytes_raw()
    with pytest.raises(keys.KeyFormatError):  # Präfixe sind nicht austauschbar
        keys.parse_recipient(public.replace("tres0r-sig-", "tres0r-pub-"))


def test_mixed_identity_file(tmp_path, signer):
    ident = keys.generate_identity()
    path = tmp_path / "beide.key"
    keys.write_identity_file(path, [ident, signer])
    found = keys.load_key_file(path)
    assert len(found.identities) == 1 and len(found.signing_keys) == 1
    assert keys.load_verify_keys(path)[0].public_bytes_raw() == signer.public_key().public_bytes_raw()
    assert keys.load_recipients(path)[0].public_bytes_raw() == ident.public_key().public_bytes_raw()


def test_protected_identity_file(tmp_path):
    ident = keys.generate_identity()
    path = tmp_path / "geschuetzt.key"
    keys.write_identity_file(path, ident, "gute-passphrase", FAST)
    assert keys.is_protected(path) and b"TRES0R-SECRET" not in path.read_bytes()
    if os.name == "posix":
        assert (path.stat().st_mode & 0o777) == 0o600
    [loaded] = keys.load_identities(path, "gute-passphrase")
    assert loaded.private_bytes_raw() == ident.private_bytes_raw()
    with pytest.raises(WrongPassword, match="Passphrase"):
        keys.load_identities(path, "falsch")
    with pytest.raises(Tres0rError, match="geschützt"):
        keys.load_identities(path)
    calls = []
    keys.load_identities(path, lambda: calls.append(1) or "gute-passphrase")
    assert calls == [1]
    # Eine geschützte Identität ist ein normaler Rohdaten-Container
    out = io.BytesIO()
    container.decrypt_stream(io.BytesIO(path.read_bytes()), out, "gute-passphrase")
    assert keys.encode_identity(ident) in out.getvalue().decode()


def test_protect_existing_file(tmp_path, signer):
    path = tmp_path / "alt.key"
    keys.write_identity_file(path, signer)
    keys.protect_identity_file(path, "neue-passphrase", FAST)
    assert keys.is_protected(path)
    assert keys.load_signing_keys(path, "neue-passphrase")[0].private_bytes_raw() == signer.private_bytes_raw()
    with pytest.raises(Tres0rError, match="bereits"):
        keys.protect_identity_file(path, "x", FAST)
    assert sorted(os.listdir(tmp_path)) == ["alt.key"]


# --- Signaturmodul ------------------------------------------------------------
def test_tail_hasher_matches_direct_hash():
    import hashlib

    data = os.urandom(300_000)
    for split in (1, 7, 105, 104, 106, 65536):
        hasher = sign.TailHasher()
        for i in range(0, len(data), split):
            hasher.update(data[i:i + split])
        digest, tail = hasher.finish()
        assert digest == hashlib.sha256(data[:-105]).digest() and tail == data[-105:]


def test_trailer_validation(signer):
    header = h2.HeaderV2(0, 0, h2.FLAG_SIGNED, bytes(16), [])
    tail = sign.trailer(signer, header, bytes(32))
    assert sign.verify(header, bytes(32), tail).public_bytes_raw() == signer.public_key().public_bytes_raw()
    with pytest.raises(SignatureError):
        sign.verify(header, b"\x01" * 32, tail)  # anderer Inhalt
    with pytest.raises(FormatError):
        sign.verify(header, bytes(32), tail[:-1] + b"\x02")  # Kennung
    with pytest.raises(FormatError):
        sign.verify(header, bytes(32), b"\x02" + tail[1:])  # Verfahren
    with pytest.raises(SignatureError):
        sign.verify(header, bytes(32), tail[:50])


# --- Signierte Container ------------------------------------------------------
@pytest.mark.parametrize("compress", [False, True])
def test_signed_container_roundtrip(tmp_path, sample_tree, signer, compress):
    if compress and container.payload.zstd_backend() is None:
        pytest.skip("kein zstd")
    out = pack(sample_tree, tmp_path / "s.tres0r", sign_with=signer, compress=compress)
    expected = keys.encode_verify_key(signer.public_key())
    assert container.inspect(out).signed
    assert len(container.list_contents(out, PASSWORD)) == 10  # Index liegt vor dem Anhang
    result = container.verify(out, PASSWORD, signers=[signer.public_key()])
    assert result.signed and result.signer == expected and result.checked_hashes
    extracted = container.extract(out, tmp_path / "z", PASSWORD)
    assert extracted.signer == expected
    assert snapshot(tmp_path / "z" / "Projekt") == snapshot(sample_tree[0])


def test_required_signer(tmp_path, sample_tree, signer):
    signed = pack(sample_tree, tmp_path / "s.tres0r", sign_with=signer)
    unsigned = pack(sample_tree, tmp_path / "u.tres0r")
    other = keys.generate_signing_key().public_key()
    with pytest.raises(SignatureError, match="anderen Schlüssel"):
        container.verify(signed, PASSWORD, signers=[other])
    with pytest.raises(SignatureError, match="nicht signiert"):
        container.verify(unsigned, PASSWORD, signers=[signer.public_key()])
    assert container.verify(signed, PASSWORD, signers=[other, signer.public_key()]).signer
    assert container.verify(unsigned, PASSWORD).signer is None


def test_only_extract_and_signatures(tmp_path, sample_tree, signer):
    out = pack(sample_tree, tmp_path / "s.tres0r", sign_with=signer)
    fast = container.extract(out, tmp_path / "a", PASSWORD, only=["einzeln.txt"])
    assert fast.signed and fast.signer is None  # Direkteinstieg prüft keine Signatur
    checked = container.extract(out, tmp_path / "b", PASSWORD, only=["einzeln.txt"],
                                signers=[signer.public_key()])
    assert checked.signer and os.listdir(tmp_path / "b") == ["einzeln.txt"]


def test_signature_survives_key_changes(tmp_path, sample_tree, signer):
    out = pack(sample_tree, tmp_path / "s.tres0r", sign_with=signer)
    ident = keys.generate_identity()
    container.add_keys(out, PASSWORD, recipients=[ident.public_key()])
    container.change_password(out, PASSWORD, "neues-passwort")
    container.remove_key(out, Credentials(identities=[ident]), 1)
    assert container.verify(out, "neues-passwort", signers=[signer.public_key()]).signer


def test_signed_raw_stream(signer):
    data = os.urandom(200_000)
    sealed = io.BytesIO()
    container.encrypt_stream(io.BytesIO(data), sealed, PASSWORD, FAST, sign_with=signer)
    out = io.BytesIO()
    result = container.decrypt_stream(io.BytesIO(sealed.getvalue()), out, PASSWORD, signers=[signer.public_key()])
    assert out.getvalue() == data and result.signer == keys.encode_verify_key(signer.public_key())
    with pytest.raises(SignatureError):
        container.decrypt_stream(io.BytesIO(sealed.getvalue()), io.BytesIO(), PASSWORD,
                                 signers=[keys.generate_signing_key().public_key()])


# --- Insider-Angriffe -----------------------------------------------------------
def _reencrypt(path, transform, header_transform=None):
    """Wie ein Mit-Empfänger mit bekanntem DEK: Klartext ändern und korrekt neu verschlüsseln."""
    with container._open(path, PASSWORD) as op:
        access = op.random_access()
        plain = access.pread(0, access.plaintext_size)
        header, dek = op.header, op.dek
    plain = transform(plain)
    if header_transform is not None:
        header = header_transform(header, dek)
    buf = io.BytesIO()
    buf.write(header.to_bytes())
    enc = EncryptingWriter(buf, header.payload_key(dek))
    enc.write(plain)
    enc.finish()
    path.write_bytes(buf.getvalue())


def _flip_in_file_data(plain: bytes, marker: bytes) -> bytes:
    pos = plain.index(marker)
    return plain[:pos] + bytes([plain[pos] ^ 1]) + plain[pos + 1:]


def test_insider_cannot_change_content(tmp_path, sample_tree, signer):
    out = pack(sample_tree, tmp_path / "s.tres0r", sign_with=signer)
    _reencrypt(out, lambda p: _flip_in_file_data(p, b"einzelne Datei"))
    # verify fällt schon über den SHA-256 im Inhaltsverzeichnis …
    with pytest.raises((FormatError, SignatureError)):
        container.verify(out, PASSWORD)
    # … extract prüft keine Index-Hashes – hier greift die Signatur
    dest = tmp_path / "ziel"
    dest.mkdir()
    with pytest.raises(SignatureError):
        container.extract(out, dest, PASSWORD)
    assert os.listdir(dest) == []  # nichts landet vor der Prüfung im Ziel


def test_insider_updating_index_hash_is_still_caught(tmp_path, sample_tree, signer):
    """Gründlicher Angreifer: ändert den Inhalt UND führt den Index-Hash nach.
    Dann bleibt als einziger Schutz die Signatur."""
    import hashlib
    import zlib

    out = pack(sample_tree, tmp_path / "s.tres0r", sign_with=signer)
    original = b"einzelne Datei"
    forged = b"gefaelschte!!!"  # gleiche Länge -> tar-Struktur bleibt gültig

    def forge(plain: bytes) -> bytes:
        plain = plain.replace(original, forged, 1)
        end = len(plain) - sign.TRAILER_LEN
        length = int.from_bytes(plain[end - 16:end - 8], "big")
        blob_start = end - 16 - length
        doc = json.loads(zlib.decompress(plain[blob_start:end - 16]))
        for entry in doc["entries"]:
            if entry["n"] == "einzeln.txt":
                entry["h"] = hashlib.sha256(forged).hexdigest()
        blob = zlib.compress(json.dumps(doc, separators=(",", ":")).encode())
        trailer = blob + len(blob).to_bytes(8, "big") + plain[end - 8:end]
        return plain[:blob_start] + trailer + plain[end:]

    _reencrypt(out, forge)
    with pytest.raises(SignatureError, match="ungültig"):
        container.verify(out, PASSWORD)


def test_insider_stripping_signature_is_caught_by_signer_requirement(tmp_path, sample_tree, signer):
    out = pack(sample_tree, tmp_path / "s.tres0r", sign_with=signer)

    def unsign(header, dek):
        stripped = h2.HeaderV2(header.payload_type, header.compression, header.flags & ~h2.FLAG_SIGNED,
                               header.stream_nonce, header.slots)
        return stripped._sign(dek)

    # Flag löschen UND Anhang abschneiden – sonst sucht der Leser den Index an der falschen Stelle
    _reencrypt(out, lambda p: p[:-sign.TRAILER_LEN], unsign)
    assert container.verify(out, PASSWORD).signer is None  # ohne Anforderung: "unsigniert"
    with pytest.raises(SignatureError, match="nicht signiert"):
        container.verify(out, PASSWORD, signers=[signer.public_key()])


def test_signature_is_bound_to_stream_nonce(tmp_path, sample_tree, signer):
    out = pack(sample_tree, tmp_path / "s.tres0r", sign_with=signer)

    def new_nonce(header, dek):
        moved = h2.HeaderV2(header.payload_type, header.compression, header.flags, bytes(16), header.slots)
        return moved._sign(dek)

    with container._open(out, PASSWORD) as op:
        access = op.random_access()
        plain = access.pread(0, access.plaintext_size)
        header, dek = op.header, op.dek
    moved = new_nonce(header, dek)
    buf = io.BytesIO()
    buf.write(moved.to_bytes())
    enc = EncryptingWriter(buf, moved.payload_key(dek))  # neuer Payload-Schlüssel
    enc.write(plain)
    enc.finish()
    out.write_bytes(buf.getvalue())
    with pytest.raises(SignatureError):
        container.verify(out, PASSWORD)


# --- CLI ------------------------------------------------------------------------
def run_json(capsys, argv):
    capsys.readouterr()
    code = main([*argv, "--json"])
    return code, json.loads(capsys.readouterr().out)


def test_cli_signing_workflow(tmp_path, sample_tree, capsys):
    phrase = tmp_path / "phrase"
    phrase.write_text("eine-lange-schutz-passphrase\n")
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    key = tmp_path / "sign.key"
    code, data = run_json(capsys, ["keygen", "--sign", "-o", str(key), "--passphrase-file", str(phrase), "--offline"])
    assert code == 0 and data["protected"] and data["public_key"].startswith("tres0r-sig-")
    public = data["public_key"]
    code, data = run_json(capsys, ["pubkey", str(key), "--key-passphrase-file", str(phrase)])
    assert data["public_keys"] == [public]

    out = tmp_path / "s.tres0r"
    code, data = run_json(capsys, ["pack", str(sample_tree[1]), "-o", str(out), "--password-file", str(pw),
                                   "--offline", "--sign", str(key), "--key-passphrase-file", str(phrase)])
    assert code == 0 and data["signer"] == public
    code, data = run_json(capsys, ["info", str(out)])
    assert data["signed"]
    code, data = run_json(capsys, ["verify", str(out), "--password-file", str(pw), "--signer", public])
    assert code == 0 and data["signer"] == public
    other = keys.encode_verify_key(keys.generate_signing_key().public_key())
    code, data = run_json(capsys, ["verify", str(out), "--password-file", str(pw), "--signer", other])
    assert code == 3 and data["error"]["type"] == "SignatureError"
    code, data = run_json(capsys, ["unpack", str(out), "-o", str(tmp_path / "z"), "--password-file", str(pw),
                                   "--signers-file", str(key), "--key-passphrase-file", str(phrase)])
    assert code == 0 and data["signer"] == public


def test_cli_protect_and_unprotected_keygen(tmp_path, capsys):
    path = tmp_path / "id.key"
    assert main(["keygen", "-o", str(path), "--unprotected"]) == 0
    assert not keys.is_protected(path)
    phrase = tmp_path / "phrase"
    phrase.write_text("eine-lange-schutz-passphrase\n")
    assert main(["protect", str(path), "--passphrase-file", str(phrase), "--offline"]) == 0
    assert keys.is_protected(path)
    assert main(["protect", str(path), "--passphrase-file", str(phrase), "--offline"]) == 1
    assert main(["pubkey", str(path), "--key-passphrase-file", str(phrase)]) == 0
