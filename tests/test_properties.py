"""Property- und Fuzz-Tests (Hypothesis).

Zwei Invarianten stehen im Mittelpunkt:

1. Parser (Header, Blöcke, Index, Schlüsseltexte, Muster) liefern bei beliebigen
   Eingaben entweder ein gültiges Ergebnis oder eine Tres0rError-Unterklasse –
   nie IndexError, struct.error, RecursionError, UnicodeError …
2. Jede Änderung an einem Container – egal an welcher Stelle – führt zum
   Fehlschlag, und dabei bleibt nichts im Zielordner zurück.

Gründlicher Lauf:  HYPOTHESIS_PROFILE=fuzz python -m pytest tests/test_properties.py
"""
import hmac
import io
import json
import os
import zlib

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import assume, given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from tres0r import container, keys, payload, portability  # noqa: E402
from tres0r import header2 as h2  # noqa: E402
from tres0r.errors import FormatError, IntegrityError, Tres0rError  # noqa: E402
from tres0r.exclude import ExcludeRules  # noqa: E402
from tres0r.stream import DecryptingReader, EncryptingWriter  # noqa: E402

from conftest import FAST, PASSWORD  # noqa: E402

KEY = bytes(range(32))


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """Argon2 durch eine schnelle, deterministische Funktion ersetzen.

    Mutierte Header können gültige, aber teure Parameter enthalten (bis 4 GiB) –
    die Semantik des Entsperrens bleibt dabei erhalten.
    """
    def derive(password, salt, params):
        pw = password.encode() if isinstance(password, str) else password
        info = f"{params.memory_kib}/{params.iterations}/{params.lanes}".encode()
        return hmac.new(salt + info, pw, "sha256").digest()

    monkeypatch.setattr(h2, "derive_key", derive)


# --- Mutationen -------------------------------------------------------------
@st.composite
def mutations(draw, data: bytes):
    """Ein bis drei Änderungen: Bit kippen, Byte setzen, einfügen, löschen, kürzen, anhängen."""
    out = bytearray(data)
    for _ in range(draw(st.integers(1, 3))):
        op = draw(st.sampled_from(["flip", "set", "insert", "delete", "truncate", "append"]))
        pos = draw(st.integers(0, max(0, len(out) - 1)))
        if op == "flip" and out:
            out[pos] ^= 1 << draw(st.integers(0, 7))
        elif op == "set" and out:
            out[pos] = draw(st.integers(0, 255))
        elif op == "insert":
            out[pos:pos] = draw(st.binary(min_size=1, max_size=8))
        elif op == "delete" and out:
            del out[pos:pos + draw(st.integers(1, 8))]
        elif op == "truncate":
            del out[pos:]
        elif op == "append":
            out += draw(st.binary(min_size=1, max_size=64))
    return bytes(out)


# --- Header -----------------------------------------------------------------
IDENTITY = keys.X25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
DEK = bytes(range(100, 132))
KEYFILE = bytes(range(32))
FIDO2_H = bytes(range(32, 64))
SHARES: list = []


def _reference_header() -> bytes:
    threshold, shares = h2.threshold_slot(DEK, 2, 3)
    SHARES[:] = shares[:2]
    slots = [h2.password_slot(DEK, PASSWORD, FAST), h2.secret_slot(DEK, "wald-see-berg"),
             h2.x25519_slot(DEK, IDENTITY.public_key()), h2.password_keyfile_slot(DEK, PASSWORD, KEYFILE, FAST),
             threshold, h2.password_fido2_slot(DEK, PASSWORD, FAST, "tres0r.local", b"C" * 40, b"S" * 32, FIDO2_H),
             h2.Slot(77, b"unbekannt")]
    return h2.HeaderV2.create(DEK, slots, flags=h2.FLAG_INDEX, compression=h2.COMPRESS_ZSTD).to_bytes()


HEADER = None


def reference_header():
    global HEADER
    if HEADER is None:
        HEADER = _reference_header()
    return HEADER


@given(st.binary(max_size=600))
def test_header_parser_on_random_bytes(data):
    for candidate in (data, b"TRS0\x02" + data, b"TRS0\x01" + data):
        try:
            h2.read_header(io.BytesIO(candidate))
        except Tres0rError:
            pass


@given(st.data())
def test_mutated_header_never_unlocks(data):
    original = reference_header()
    mutated = data.draw(mutations(original))
    assume(mutated != original)
    creds = keys.Credentials(passwords=[PASSWORD, "wald-see-berg"], identities=[IDENTITY],
                             keyfiles=[KEYFILE], shares=list(SHARES), fido2=lambda rp, cid, salt: FIDO2_H)
    try:
        header = h2.read_header(io.BytesIO(mutated))
        if header.version == 2:
            header.unlock(creds)
        else:
            header.unlock(PASSWORD)
    except Tres0rError:
        return
    # Nur erlaubt, wenn die Änderung hinter dem Header lag (Anhang/Kürzung außerhalb)
    assert mutated[: len(original)] == original


@given(
    slots=st.lists(
        st.one_of(
            st.tuples(st.just("pw"), st.text(min_size=1, max_size=20)),
            st.tuples(st.just("secret"), st.text(min_size=1, max_size=40)),
            st.tuples(st.just("x25519"), st.binary(min_size=32, max_size=32)),
            st.tuples(st.integers(8, 255), st.binary(max_size=100)),  # 1–7 sind vergeben
        ),
        min_size=1, max_size=h2.MAX_SLOTS,
    ),
    payload_type=st.sampled_from([h2.PAYLOAD_TAR, h2.PAYLOAD_RAW]),
    compression=st.sampled_from([h2.COMPRESS_NONE, h2.COMPRESS_ZSTD]),
)
def test_header_roundtrip(slots, payload_type, compression):
    built = []
    for kind, value in slots:
        if kind == "pw":
            built.append(h2.password_slot(DEK, value, FAST))
        elif kind == "secret":
            built.append(h2.secret_slot(DEK, value))
        elif kind == "x25519":
            built.append(h2.x25519_slot(DEK, keys.X25519PrivateKey.from_private_bytes(value).public_key()))
        else:
            built.append(h2.Slot(kind, value))
    assume(sum(s.type == h2.SLOT_PASSWORD for s in built) <= h2.MAX_PASSWORD_SLOTS)
    flags = h2.FLAG_INDEX if payload_type == h2.PAYLOAD_TAR else 0
    header = h2.HeaderV2.create(DEK, built, payload_type=payload_type, compression=compression, flags=flags)
    parsed = h2.read_header(io.BytesIO(header.to_bytes()))
    assert parsed.slots == built and parsed.to_bytes() == header.to_bytes()
    first_pw = next((v for k, v in slots if k == "pw"), None)
    if first_pw is not None:
        dek, index = parsed.unlock(first_pw)
        assert dek == DEK and built[index].type in (h2.SLOT_PASSWORD, h2.SLOT_SECRET)


# --- Stream -----------------------------------------------------------------
@given(st.binary(max_size=200_000), st.integers(1, 70_000))
def test_stream_roundtrip(data, write_size):
    out = io.BytesIO()
    writer = EncryptingWriter(out, KEY)
    for i in range(0, len(data), write_size):
        writer.write(data[i:i + write_size])
    writer.finish()
    reader = DecryptingReader(io.BytesIO(out.getvalue()), KEY)
    assert reader.read() == data
    reader.finish()


@given(st.data(), st.binary(max_size=150_000))
def test_any_stream_mutation_is_detected(data, plain):
    out = io.BytesIO()
    writer = EncryptingWriter(out, KEY)
    writer.write(plain)
    writer.finish()
    original = out.getvalue()
    mutated = data.draw(mutations(original))
    assume(mutated != original)
    with pytest.raises(IntegrityError):
        reader = DecryptingReader(io.BytesIO(mutated), KEY)
        reader.read()
        reader.finish()


# --- Blöcke, Seek-Punkte ----------------------------------------------------
@given(st.binary(max_size=4000))
def test_block_reader_on_random_bytes(data):
    reader = payload.BlockReader(io.BytesIO(data))
    try:
        while reader.read(997):
            pass
    except FormatError:
        pass


@given(
    parts=st.lists(st.binary(max_size=3000), max_size=30),
    marks=st.sets(st.integers(0, 29)),
    compress=st.booleans() if payload.zstd_backend() else st.just(False),
)
def test_payload_marks(parts, marks, compress, monkeypatch):
    monkeypatch.setattr(payload, "FRAME_TARGET", 4096)  # viele Frames erzwingen
    monkeypatch.setattr(payload, "MAX_BLOCK", 1500)  # viele Blöcke erzwingen
    out = io.BytesIO()
    enc = EncryptingWriter(out, KEY)
    writer = payload.PayloadWriter(enc, compress)
    points = []
    for i, part in enumerate(parts):
        if i in marks:
            points.append((writer.tell(), writer.mark()))
        writer.write(part)
    writer.close()
    enc.write_zeros(100)
    enc.finish()
    blob, plain = out.getvalue(), b"".join(parts)

    reader = DecryptingReader(io.BytesIO(blob), KEY)
    blocks, stream = payload.decoded_reader(reader, int(compress))
    assert stream.read() == plain
    access = payload.RandomAccessPayload(io.BytesIO(blob), KEY, 0, len(blob))
    for position, (offset, skip) in points:
        _, stream = payload.decoded_reader(access.open_at(offset), int(compress))
        payload.skip(stream, skip)
        assert stream.read() == plain[position:]


# --- Index ------------------------------------------------------------------
# Namen inkl. einzelner Surrogate U+DC80–U+DCFF: So stellt Python unter Linux
# Dateinamen dar, deren Bytes kein gültiges UTF-8 sind (surrogateescape).
# st.text() allein erzeugt solche Zeichen nie.
# Hohe Surrogate (U+D800–U+DBFF) sind ausgeschlossen: Kein Dateisystem liefert sie
# gefolgt von einem niedrigen Surrogat als zwei Codepunkte (Linux/surrogateescape nur
# U+DC80–U+DCFF, Windows kombiniert UTF-16-Paare) – JSON würde sie zusammenfügen.
names = st.lists(st.one_of(st.characters(exclude_categories=("Cs",)), st.integers(0xDC80, 0xDCFF).map(chr)),
                 max_size=40).map("".join)

entry_strategy = st.builds(
    payload.IndexEntry,
    name=names,
    kind=st.sampled_from(list(payload.KINDS)),
    size=st.integers(0, 2**63),
    mtime=st.integers(-(2**40), 2**40),
    offset=st.integers(0, 2**63),
    skip=st.integers(0, 2**40),
    sha256=st.one_of(st.none(), st.text("0123456789abcdef", min_size=64, max_size=64)),
    link=st.one_of(st.none(), names),
)


def _index_payload(trailer: bytes) -> payload.RandomAccessPayload:
    out = io.BytesIO()
    enc = EncryptingWriter(out, KEY)
    enc.write(b"x" * 10)
    enc.write(trailer)
    enc.finish()
    blob = out.getvalue()
    return payload.RandomAccessPayload(io.BytesIO(blob), KEY, 0, len(blob))


@given(st.lists(entry_strategy, max_size=20))
def test_index_roundtrip(entries):
    blob = payload.index_trailer(payload.encode_index(entries))
    assert payload.read_index(_index_payload(blob)) == entries


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=10),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=3), children, max_size=4),
    max_leaves=20,
)


@given(st.one_of(
    json_values.map(lambda v: {"v": 1, "entries": v}),
    st.lists(st.dictionaries(st.sampled_from("ntsmokhl"), json_values, max_size=8), max_size=5)
    .map(lambda e: {"v": 1, "entries": e}),
    json_values,
))
def test_index_parser_on_arbitrary_json(doc):
    blob = zlib.compress(json.dumps(doc).encode())
    try:
        payload.read_index(_index_payload(payload.index_trailer(blob)))
    except FormatError:
        pass


@given(st.binary(max_size=300))
def test_index_parser_on_random_trailer(data):
    try:
        payload.read_index(_index_payload(data))
    except FormatError:
        pass


def test_deeply_nested_index_json():
    doc = "[" * 200_000 + "]" * 200_000
    blob = zlib.compress(doc.encode())
    with pytest.raises(FormatError):
        payload.read_index(_index_payload(payload.index_trailer(blob)))


# --- Textformate und Muster -------------------------------------------------
@given(st.text(max_size=120))
def test_key_parsers_on_arbitrary_text(text):
    for parse, prefix in ((keys.parse_recipient, keys.PUB_PREFIX), (keys.parse_identity, keys.SECRET_PREFIX)):
        for candidate in (text, prefix + text):
            try:
                parse(candidate)
            except keys.KeyFormatError:
                pass


@given(names)
def test_canonical_secret_is_idempotent(text):
    once = keys.canonical_secret(text)
    assert keys.canonical_secret(once) == once
    assert keys.canonical_secret(text.upper().replace("-", " ")) == keys.canonical_secret(text.upper())


@given(st.lists(st.text(max_size=15), max_size=6), st.text(max_size=30), st.booleans())
def test_exclude_rules_never_crash(patterns, path, is_dir):
    try:
        rules = ExcludeRules(patterns)
    except ValueError:
        return
    rules.matches(path, is_dir)


@given(names.filter(bool))
def test_sanitized_components_are_valid(name):
    assume("/" not in name)
    fixed = portability.sanitize_component(name)
    assert fixed and "/" not in fixed
    assert fixed in (".", "..") or portability.component_problem(fixed) is None


@given(st.lists(st.tuples(names.filter(bool), st.booleans()), max_size=15))
def test_check_names_never_crashes(items):
    portability.check_names(items)


# --- Ganzer Container -------------------------------------------------------
_CONTAINER: dict = {}


def small_container_bytes(tmp_path_factory) -> bytes:
    """Kleiner Container mit zwei Dateien, erzeugt unter dem KDF-Platzhalter –
    so lösen mutierte Argon2-Parameter keine echten 2-GiB-Berechnungen aus."""
    if "bytes" not in _CONTAINER:
        root = tmp_path_factory.mktemp("fuzz")
        src = root / "quelle"
        (src / "sub").mkdir(parents=True)
        (src / "a.txt").write_text("alpha")
        (src / "sub" / "b.bin").write_bytes(bytes(range(256)) * 300)
        out = root / "c.tres0r"
        container.create([src], out, PASSWORD, FAST)
        _CONTAINER["bytes"] = out.read_bytes()
    return _CONTAINER["bytes"]


@given(data=st.data())
def test_mutated_container_always_fails_cleanly(data, tmp_path_factory):
    original = small_container_bytes(tmp_path_factory)
    mutated = data.draw(mutations(original))
    assume(mutated != original)
    work = tmp_path_factory.mktemp("m")
    bad = work / "bad.tres0r"
    bad.write_bytes(mutated)
    with pytest.raises(Tres0rError):
        container.verify(bad, PASSWORD)
    dest = work / "ziel"
    dest.mkdir()
    with pytest.raises(Tres0rError):
        container.extract(bad, dest, PASSWORD)
    assert os.listdir(dest) == []
    assert [n for n in os.listdir(work) if n.startswith(".")] == []


def test_unmutated_container_passes(tmp_path_factory):
    """Gegenprobe: Ohne Änderung muss der Fuzz-Container einwandfrei sein."""
    work = tmp_path_factory.mktemp("ok")
    good = work / "gut.tres0r"
    good.write_bytes(small_container_bytes(tmp_path_factory))
    assert container.verify(good, PASSWORD).files == 2


# --- Signaturen -----------------------------------------------------------------
@given(st.binary(max_size=250), st.binary(min_size=32, max_size=32))
def test_signature_trailer_on_random_bytes(tail, digest):
    from tres0r import sign

    header = h2.HeaderV2(0, 0, h2.FLAG_SIGNED, bytes(16), [])
    try:
        sign.verify(header, digest, tail)
    except Tres0rError:
        return
    pytest.fail("zufällige Bytes als gültige Signatur akzeptiert")


@given(st.binary(max_size=5000), st.lists(st.integers(1, 700), min_size=1, max_size=30))
def test_tail_hasher_any_split(data, splits):
    import hashlib

    from tres0r import sign

    hasher = sign.TailHasher()
    pos, i = 0, 0
    while pos < len(data):
        step = splits[i % len(splits)]
        hasher.update(data[pos:pos + step])
        pos += step
        i += 1
    digest, tail = hasher.finish()
    keep = min(len(data), sign.TRAILER_LEN)
    assert tail == data[len(data) - keep:]
    assert digest == hashlib.sha256(data[: len(data) - keep]).digest()


def test_surrogate_pair_limitation_is_documented():
    """JSON fügt ein hohes + niedriges Surrogat zusammen – für echte Namen unerreichbar (s. oben)."""
    entry = payload.IndexEntry("\ud800\udc00", "f", 0, 0, 0, 0)
    [back] = payload.read_index(_index_payload(payload.index_trailer(payload.encode_index([entry]))))
    assert back.name == "\U00010000"
    lone = payload.IndexEntry("\ud800x\udce9", "f", 0, 0, 0, 0)  # einzeln bleiben sie erhalten
    [back] = payload.read_index(_index_payload(payload.index_trailer(payload.encode_index([lone]))))
    assert back.name == lone.name
