"""Testvektoren aus FORMAT.md, dreifach geprüft:

1. tres0r liest sie (jede Zugangsart, verify, Inhalt),
2. der unabhängige Referenz-Leser (tests/reference_decoder.py) liest sie,
3. reproduzierbare Vektoren entstehen byte-genau neu (Schreibpfad).

Dazu: Alle Formatkonstanten aus dem Code müssen wörtlich in FORMAT.md stehen.
"""
import hashlib
import importlib
import io
import json
import sys
from pathlib import Path

import pytest

from tres0r import container, keys, payload, sign
from tres0r import header as v1
from tres0r import header2 as h2
from tres0r import stream as stream_mod

HERE = Path(__file__).resolve().parent
VECTORS = sorted((HERE / "vectors").glob("*.json"))
sys.path.insert(0, str(HERE / "vectors"))
generate = importlib.import_module("generate")
import reference_decoder as ref  # noqa: E402


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def needs_zstd(vector):
    """Überspringen ohne zstd – Header-Kompression (Segment 0) oder "zstd" im Namen
    (z. B. ein angehängtes Segment, dessen Kompression erst in der Tabelle steht)."""
    blob = bytes.fromhex(vector["container_hex"])
    uses_zstd = (blob[4] == 2 and blob[8] == 1) or "zstd" in vector.get("name", "")
    if uses_zstd and payload.zstd_backend() is None:
        pytest.skip("kein zstd")


def credentials(vector: dict) -> dict:
    inputs = vector["inputs"]
    from tres0r import shamir

    keyfile = bytes.fromhex(inputs.get("keyfile_hex", ""))
    return {
        "password": keys.Credentials(passwords=[inputs["password"]]),
        "recovery": keys.Credentials(passwords=[inputs["recovery"]]),
        "identity": keys.Credentials(identities=[keys.parse_identity(inputs["identity"])]),
        "password+keyfile": keys.Credentials(passwords=[inputs["password"]], keyfiles=[
            hashlib.sha256(b"tres0r keyfile" + keyfile).digest()]),
        "shares": keys.Credentials(shares=[shamir.parse_share(t) for t in inputs.get("shares", [])]),
        "password+fido2": keys.Credentials(passwords=[inputs["password"]], fido2=lambda rp, cid, salt: bytes.fromhex(
            inputs["fido2_secret_hex"])),
    }


def test_vectors_exist():
    assert {p.stem for p in VECTORS} >= set(generate.NAMES) - {"v2-tar-zstd-phrase", "v2-roh-zstd-empfaenger"}


@pytest.mark.parametrize("path", VECTORS, ids=lambda p: p.stem)
def test_tres0r_reads_vector(path, tmp_path):
    vector = load(path)
    needs_zstd(vector)
    blob = bytes.fromhex(vector["container_hex"])
    expected = vector["expected"]
    file = tmp_path / "c.tres0r"
    file.write_bytes(blob)

    for how, slot in vector["unlock"].items():
        creds = credentials(vector)[how]
        header = h2.read_header(io.BytesIO(blob))
        if header.version == 2:
            dek, used = header.unlock(creds)
            assert used == slot, how
        else:
            dek = header.unlock(creds.passwords[0])
        assert dek.hex() == expected["dek_hex"], how
        container.verify(file, creds)

    creds = credentials(vector)[next(iter(vector["unlock"]))]
    result = container.verify(file, creds)
    assert result.signer == vector.get("signer")
    if "data_sha256" in expected:
        out = io.BytesIO()
        container.decrypt_stream(io.BytesIO(blob), out, creds)
        assert hashlib.sha256(out.getvalue()).hexdigest() == expected["data_sha256"]
    else:
        got = [{"name": e.name, "kind": e.kind, "size": e.size, "sha256": e.sha256}
               for e in container.list_contents(file, creds)]
        if vector["format_version"] == 1:  # v1 hat keinen Index -> keine Hashes aus list
            got = [dict(g, sha256=None) for g in got]
            want = [dict(e, sha256=None) for e in expected["entries"]]
        else:
            want = expected["entries"]
        assert got == want


@pytest.mark.parametrize("path", VECTORS, ids=lambda p: p.stem)
def test_reference_decoder_reads_vector(path):
    vector = load(path)
    needs_zstd(vector)
    blob = bytes.fromhex(vector["container_hex"])
    inputs = vector["inputs"]
    for how, slot in vector["unlock"].items():
        if how == "identity":
            result = ref.open_container(blob, identities=[ref.decode_identity(inputs["identity"])])
        elif how == "password+keyfile":
            result = ref.open_container(blob, passwords=[inputs["password"]],
                                        keyfiles=[bytes.fromhex(inputs["keyfile_hex"])])
        elif how == "shares":
            result = ref.open_container(blob, shares=inputs["shares"])
        elif how == "password+fido2":
            result = ref.open_container(blob, passwords=[inputs["password"]],
                                        fido2=[bytes.fromhex(inputs["fido2_secret_hex"])])
        else:
            result = ref.open_container(blob, passwords=[inputs[how]])
        assert result["dek"].hex() == vector["expected"]["dek_hex"]
        assert result["slot"] == slot
        signer = vector.get("signer")
        signatures = [seg["signer"] for seg in result["segments"]] if result.get("segments") else [result["signer"]]
        for found in signatures:  # bei Segmenten: jedes einzeln
            assert (found is None) == (signer is None)
            if signer:
                assert keys.encode_verify_key(keys.Ed25519PublicKey.from_public_bytes(found)) == signer
    expected = vector["expected"]
    if "data_sha256" in expected:
        assert hashlib.sha256(result["data"]).hexdigest() == expected["data_sha256"]
    else:
        if result.get("segments"):  # angehängte Segmente: spätere ersetzen frühere
            files = result["files"]
            for seg in result["segments"]:
                assert [e["n"] for e in seg["index"]] == [e["name"] for e in ref.read_tar(seg["data"])]
        else:
            files = {e["name"]: e for e in ref.read_tar(result["data"])}
        for entry in expected["entries"]:
            assert entry["name"] in files
            if entry["kind"] == "datei":
                assert files[entry["name"]]["size"] == entry["size"]
                if entry["sha256"]:
                    assert files[entry["name"]]["sha256"] == entry["sha256"]
        if result["index"] is not None:
            assert [e["n"] for e in result["index"]] == [e["name"] for e in expected["entries"]]


@pytest.mark.parametrize("path", [p for p in VECTORS if load(p)["reproducible"]], ids=lambda p: p.stem)
def test_reproducible_vectors_are_byte_identical(path):
    vector = load(path)
    assert generate.build(vector["name"])["container_hex"] == vector["container_hex"]


def test_reference_decoder_rejects_forged_signature():
    """Klartext unter bekanntem DEK ändern und korrekt neu verschlüsseln: nur die Signatur fällt."""
    vector = load(HERE / "vectors" / "v2-roh-signiert.json")
    blob = bytes.fromhex(vector["container_hex"])
    h = ref.parse_v2(blob)
    dek = bytes.fromhex(vector["expected"]["dek_hex"])
    key = ref.hkdf(dek, h["nonce"], b"tres0r v2 payload key")
    plain = bytearray(ref.decrypt_payload(key, h["payload"]))
    plain[10] ^= 1
    out = io.BytesIO()
    enc = stream_mod.EncryptingWriter(out, key)
    enc.write(bytes(plain))
    enc.finish()
    with pytest.raises(ref.ReferenceError_, match="Signatur"):
        ref.open_container(h["header"] + out.getvalue(), passwords=[vector["inputs"]["password"]])


def test_reference_decoder_rejects_tampering():
    vector = load(HERE / "vectors" / "v2-roh-alle-slots.json")
    blob = bytearray(bytes.fromhex(vector["container_hex"]))
    blob[9] ^= 1  # Flags: vom Header-MAC geschützt
    with pytest.raises(ref.ReferenceError_):
        ref.open_container(bytes(blob), passwords=[vector["inputs"]["password"]])


# --- Spezifikation und Code stimmen überein ---------------------------------
def test_format_md_mentions_all_constants():
    spec = (HERE.parent / "FORMAT.md").read_text(encoding="utf-8")
    constants = [
        h2._INFO_SECRET, h2._INFO_X25519, h2._INFO_MAC, h2._INFO_PAYLOAD, v1._PAYLOAD_INFO,
        h2.MAGIC, payload.INDEX_MAGIC.replace(b"\x01", b"\\x01"),
        sign.MAGIC.replace(b"\x01", b"\\x01"), sign._CONTEXT.rstrip(b"\x00"),
    ]
    for value in constants:
        assert value.decode("ascii") in spec, value
    numbers = {
        "Keyslots gesamt / davon Passwort": f"{h2.MAX_SLOTS} / {h2.MAX_PASSWORD_SLOTS}",
        "Header |": f"{h2.MAX_HEADER_LEN}",
        "Block (lesen)": f"{payload.MAX_READ_BLOCK >> 20} MiB",
        "Chunks zu": f"{stream_mod.CHUNK_SIZE}",
        "S / ": f"{stream_mod.ENC_CHUNK_SIZE}",
    }
    for context, number in numbers.items():
        assert number in spec, (context, number)
    from tres0r import kdf

    assert f"{kdf.MIN_MEMORY_KIB} … {kdf.MAX_MEMORY_KIB}" in spec
    assert f"1 … {kdf.MAX_ITERATIONS}" in spec and f"1 … {kdf.MAX_LANES}" in spec
    assert f"{keys.RECOVERY_WORDS} zufällige Wörter" in spec
    assert "tres0r-pub-" in spec and "TRES0R-SECRET-" in spec
    assert keys.SIGN_PUB_PREFIX in spec and keys.SIGN_SECRET_PREFIX in spec
    assert f"({sign.TRAILER_LEN} B)" in spec
