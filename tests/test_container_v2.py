import importlib
import io
import os
import sys
import tarfile

import pytest

from tres0r import container, keys, payload
from tres0r.errors import FormatError, IntegrityError, Tres0rError, WrongPassword
from tres0r.keys import Credentials

from conftest import FAST, PASSWORD, make_tar, snapshot, write_raw_container, write_raw_container_v2


def _has_zstd():
    for module in ("compression.zstd", "zstandard"):
        try:
            importlib.import_module(module)
            return True
        except ImportError:
            pass
    return False


needs_zstd = pytest.mark.skipif(not _has_zstd(), reason="kein zstd")


@pytest.fixture
def ident():
    return keys.generate_identity()


def pack(sources, out, password=PASSWORD, **kw):
    return container.create(sources, out, password, FAST, **kw)


# --- Keyslots beim Anlegen --------------------------------------------------
def test_recipient_only_container(tmp_path, sample_tree, ident):
    out = tmp_path / "r.tres0r"
    result = pack(sample_tree, out, password=None, recipients=[ident.public_key()])
    assert result.slots == ["Empfänger (X25519)"]
    info = container.inspect(out)
    assert info.version == 2 and info.kdf is None and [s.type for s in info.slots] == ["empfaenger"]
    with pytest.raises(WrongPassword):
        container.list_contents(out, PASSWORD)
    container.extract(out, tmp_path / "z", Credentials(identities=[ident]))
    assert snapshot(tmp_path / "z" / "Projekt") == snapshot(sample_tree[0])


def test_needs_at_least_one_key(tmp_path, sample_tree):
    with pytest.raises(Tres0rError, match="Mindestens"):
        pack(sample_tree, tmp_path / "x.tres0r", password=None)
    assert not (tmp_path / "x.tres0r").exists()


def test_all_keys_open_the_same_container(tmp_path, sample_tree, ident):
    phrase = keys.generate_recovery().value
    out = tmp_path / "multi.tres0r"
    pack(sample_tree, out, recipients=[ident.public_key(), keys.generate_identity().public_key()],
         recovery=phrase)
    kinds = [s.type for s in container.inspect(out).slots]
    assert kinds == ["passwort", "wiederherstellung", "empfaenger", "empfaenger"]
    for creds in (PASSWORD, phrase.upper().replace("-", " "), Credentials(identities=[ident])):
        assert container.verify(out, creds).files == 6


# --- Kompression ------------------------------------------------------------
@needs_zstd
def test_compressed_roundtrip(tmp_path, sample_tree):
    (sample_tree[0] / "text.txt").write_text("Zeile\n" * 200_000, encoding="utf-8")
    plain = pack(sample_tree, tmp_path / "p.tres0r")
    packed = pack(sample_tree, tmp_path / "z.tres0r", compress=True)
    assert packed.size < plain.size - 1_000_000
    assert container.inspect(packed.path).compression == "zstd"
    assert container.verify(packed.path, PASSWORD).checked_hashes
    container.extract(packed.path, tmp_path / "raus", PASSWORD)
    assert snapshot(tmp_path / "raus" / "Projekt") == snapshot(sample_tree[0])


# --- Index ------------------------------------------------------------------
def test_list_from_index_matches_archive(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "i.tres0r").path
    fast = container.list_contents(out, PASSWORD)
    with container._open(out, PASSWORD) as op:
        _, _, data = op.stream()
        with tarfile.open(fileobj=data, mode="r|") as tar:
            streamed = [(ti.name, ti.size if ti.isreg() else 0) for ti in tar]
    assert [(e.name, e.size) for e in fast] == streamed
    assert all(e.sha256 for e in fast if e.kind == "datei")


def test_list_reads_only_the_end(tmp_path, sample_tree):
    """Ein beschädigter Chunk in der Mitte stört list nicht – verify findet ihn."""
    out = pack(sample_tree, tmp_path / "i.tres0r").path
    raw = bytearray(out.read_bytes())
    raw[container.inspect(out).header_len + 70_000] ^= 1
    out.write_bytes(bytes(raw))
    assert len(container.list_contents(out, PASSWORD)) == 10
    with pytest.raises(IntegrityError):
        container.verify(out, PASSWORD)


def test_verify_detects_index_mismatch(tmp_path):
    ti = tarfile.TarInfo("a.txt")
    ti.size = 3
    tar = make_tar([(ti, b"abc")])
    wrong = [payload.IndexEntry("a.txt", "f", 3, 0, 0, 0, "0" * 64)]
    bad = tmp_path / "idx.tres0r"
    write_raw_container_v2(bad, tar, index=wrong)
    with pytest.raises(FormatError, match="Prüfsumme"):
        container.verify(bad, PASSWORD)
    renamed = [payload.IndexEntry("b.txt", "f", 3, 0, 0, 0)]
    write_raw_container_v2(bad, tar, index=renamed)
    with pytest.raises(FormatError, match="passt nicht"):
        container.verify(bad, PASSWORD)


# --- Teilweises Entpacken ---------------------------------------------------
@pytest.mark.parametrize("compress", [False, pytest.param(True, marks=needs_zstd)])
def test_extract_only(tmp_path, sample_tree, compress):
    out = pack(sample_tree, tmp_path / "o.tres0r", compress=compress).path
    dest = tmp_path / "ziel"
    result = container.extract(out, dest, PASSWORD, only=["Projekt/Unterordner", "*.txt"])
    got = set(snapshot(dest))
    assert "Projekt/Unterordner/gross.bin" in got and "Projekt/Unterordner/tief/x.dat" in got
    assert "Projekt/notiz.txt" in got and "einzeln.txt" in got
    assert "Projekt/leere-datei" not in got
    assert (dest / "Projekt/Unterordner/gross.bin").read_bytes() == (sample_tree[0] / "Unterordner/gross.bin").read_bytes()
    # Unterordner, gross.bin, tief, x.dat, notiz.txt, Überraschung…txt, einzeln.txt
    assert result.entries == 7


def test_extract_only_no_match(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "o.tres0r").path
    with pytest.raises(Tres0rError, match="Kein Eintrag"):
        container.extract(out, tmp_path / "z", PASSWORD, only=["gibtsnicht/*"])
    assert not (tmp_path / "z").exists() or os.listdir(tmp_path / "z") == []


@pytest.mark.skipif(os.name != "posix", reason="Hardlinks")
def test_extract_only_brings_hardlink_target(tmp_path):
    src = tmp_path / "hl"
    src.mkdir()
    (src / "a.txt").write_text("gemeinsam")
    os.link(src / "a.txt", src / "b.txt")
    out = pack([src], tmp_path / "h.tres0r").path
    container.extract(out, tmp_path / "z", PASSWORD, only=["hl/b.txt"])
    assert (tmp_path / "z/hl/b.txt").read_text() == "gemeinsam"


def test_extract_only_works_for_v1_by_streaming(tmp_path):
    ti1, ti2 = tarfile.TarInfo("x/a.txt"), tarfile.TarInfo("x/b.txt")
    ti1.size = ti2.size = 1
    old = tmp_path / "alt.tres0r"
    write_raw_container(old, make_tar([(ti1, b"1"), (ti2, b"2")]))
    container.extract(old, tmp_path / "z", PASSWORD, only=["x/b.txt"])
    assert snapshot(tmp_path / "z") == {"x": None, "x/b.txt": b"2"}


# --- Keyslots verwalten -----------------------------------------------------
def test_add_and_remove_keys(tmp_path, sample_tree, ident):
    out = pack(sample_tree, tmp_path / "k.tres0r").path
    payload_before = out.read_bytes()[container.inspect(out).header_len:]
    phrase = keys.generate_recovery().value
    new = container.add_keys(out, PASSWORD, recovery=phrase, recipients=[ident.public_key()],
                             password="zweites-passwort", params=FAST)
    assert new == [1, 2, 3]
    info = container.inspect(out)
    assert [s.type for s in info.slots] == ["passwort", "passwort", "wiederherstellung", "empfaenger"]
    assert out.read_bytes()[info.header_len:] == payload_before  # nicht neu verschlüsselt
    for creds in ("zweites-passwort", phrase, Credentials(identities=[ident])):
        container.verify(out, creds)

    removed = container.remove_key(out, Credentials(identities=[ident]), 0)
    assert removed.type == "passwort"
    with pytest.raises(WrongPassword):
        container.verify(out, PASSWORD)
    assert len(container.inspect(out).slots) == 3


def test_cannot_remove_last_key_or_unknown_slot(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "k.tres0r").path
    with pytest.raises(Tres0rError, match="letzte"):
        container.remove_key(out, PASSWORD, 0)
    with pytest.raises(Tres0rError, match="gibt es nicht"):
        container.remove_key(out, PASSWORD, 5)
    with pytest.raises(WrongPassword):
        container.add_keys(out, "falsch", password="x", params=FAST)


def test_change_password_replaces_matching_slot(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "p.tres0r").path
    container.add_keys(out, PASSWORD, password="zwei", params=FAST)
    container.change_password(out, "zwei", "drei")
    for pw, ok in ((PASSWORD, True), ("zwei", False), ("drei", True)):
        if ok:
            container.verify(out, pw)
        else:
            with pytest.raises(WrongPassword):
                container.verify(out, pw)


def test_change_password_needs_password_slot(tmp_path, sample_tree, ident):
    out = pack(sample_tree, tmp_path / "p.tres0r", recipients=[ident.public_key()]).path
    with pytest.raises(Tres0rError, match="Slot 1"):
        container.change_password(out, Credentials(identities=[ident]), "neu")


def test_v1_container_stays_usable(tmp_path):
    ti = tarfile.TarInfo("alt.txt")
    ti.size = 3
    old = tmp_path / "v1.tres0r"
    write_raw_container(old, make_tar([(ti, b"alt")]))
    info = container.inspect(old)
    assert info.version == 1 and info.header_len == 107
    assert [e.name for e in container.list_contents(old, PASSWORD)] == ["alt.txt"]
    container.change_password(old, PASSWORD, "neu")
    container.extract(old, tmp_path / "z", "neu")
    assert (tmp_path / "z/alt.txt").read_bytes() == b"alt"
    with pytest.raises(Tres0rError, match="Formatversion 2"):
        container.add_keys(old, "neu", password="x", params=FAST)


def test_header_manipulation_is_integrity_error(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "m.tres0r").path
    raw = bytearray(out.read_bytes())
    raw[8] = 1  # Kompressions-Flag setzen
    out.write_bytes(bytes(raw))
    with pytest.raises(IntegrityError, match="Header"):
        container.list_contents(out, PASSWORD)


# --- Rohdatenströme ---------------------------------------------------------
@pytest.mark.parametrize("compress", [False, pytest.param(True, marks=needs_zstd)])
def test_raw_stream_roundtrip(compress, ident):
    data = os.urandom(300_000) + b"x" * 500_000
    sealed = io.BytesIO()
    assert container.encrypt_stream(io.BytesIO(data), sealed, PASSWORD, FAST,
                                    recipients=[ident.public_key()], compress=compress).bytes == len(data)
    for creds in (PASSWORD, Credentials(identities=[ident])):
        out = io.BytesIO()
        assert container.decrypt_stream(io.BytesIO(sealed.getvalue()), out, creds).bytes == len(data)
        assert out.getvalue() == data


def test_raw_stream_detects_truncation():
    sealed = io.BytesIO()
    container.encrypt_stream(io.BytesIO(os.urandom(200_000)), sealed, PASSWORD, FAST)
    with pytest.raises(IntegrityError):
        container.decrypt_stream(io.BytesIO(sealed.getvalue()[:-100]), io.BytesIO(), PASSWORD)


def test_raw_container_rejects_file_operations(tmp_path):
    path = tmp_path / "roh.tres0r"
    with container.atomic_output(path) as f:
        container.encrypt_stream(io.BytesIO(b"daten"), f, PASSWORD, FAST)
    assert container.inspect(path).payload_type == "roh"
    assert container.verify(path, PASSWORD).bytes == 5
    for call in (lambda: container.list_contents(path, PASSWORD),
                 lambda: container.extract(path, tmp_path / "z", PASSWORD)):
        with pytest.raises(Tres0rError, match="decrypt"):
            call()


def test_decrypt_tar_container_yields_tar_stream(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "t.tres0r").path
    buf = io.BytesIO()
    with open(out, "rb") as f:
        container.decrypt_stream(f, buf, PASSWORD)
    buf.seek(0)
    with tarfile.open(fileobj=buf, mode="r:") as tar:
        assert "Projekt/notiz.txt" in tar.getnames()


def test_atomic_output_leaves_nothing_on_error(tmp_path):
    target = tmp_path / "ziel.bin"
    with pytest.raises(RuntimeError):
        with container.atomic_output(target) as f:
            f.write(b"halb")
            raise RuntimeError("abbruch")
    assert os.listdir(tmp_path) == []


@pytest.mark.skipif(os.name != "posix" or sys.platform == "darwin",
                    reason="nur Dateisysteme, die beliebige Bytes in Namen erlauben")
def test_non_utf8_filenames_roundtrip(tmp_path):
    src = tmp_path / "quelle"
    src.mkdir()
    raw_name = b"caf\xe9-latin1.txt"
    with open(os.path.join(os.fsencode(src), raw_name), "wb") as f:
        f.write(b"alter Dateiname")
    out = tmp_path / "s.tres0r"
    result = pack([src], out)
    assert [i.kind for i in result.issues] == ["kodierung"]  # Warnung beim Packen
    names = [e.name for e in container.list_contents(out, PASSWORD)]
    assert os.fsdecode(b"quelle/" + raw_name) in names
    container.verify(out, PASSWORD)
    container.extract(out, tmp_path / "raus", PASSWORD)
    assert os.listdir(os.fsencode(tmp_path / "raus" / "quelle")) == [raw_name]  # Bytes identisch


@pytest.mark.parametrize("mtime", ["1e30", "-1e30", "inf", "nan"])
def test_absurd_timestamps_do_not_crash(tmp_path, raw_writer, mtime):
    """Fuzzer-Fund: präparierte PAX-Zeitstempel ließen os.utime bzw. int() abstürzen."""
    import io as _io

    buf = _io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        ti = tarfile.TarInfo("a.txt")
        ti.size = 3
        ti.pax_headers = {"mtime": mtime}
        tar.addfile(ti, _io.BytesIO(b"abc"))
    path = tmp_path / "c.tres0r"
    raw_writer(path, buf.getvalue())
    container.extract(path, tmp_path / "z", PASSWORD)
    assert (tmp_path / "z" / "a.txt").read_bytes() == b"abc"
    assert all(isinstance(e.mtime, int) for e in container.list_contents(path, PASSWORD))
    assert container.salvage(path, tmp_path / "s", PASSWORD).complete
    if container.inspect(path).version == 1:
        container.upgrade(path, PASSWORD, tmp_path / "u.tres0r")
        assert container.verify(tmp_path / "u.tres0r", PASSWORD).files == 1
