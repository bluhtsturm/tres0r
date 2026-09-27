import os
import tarfile
import unicodedata

import pytest

from tres0r import container
from tres0r.errors import (
    Cancelled,
    IntegrityError,
    Tres0rError,
    UnsafeArchive,
    WrongPassword,
)
from tres0r.kdf import LEVELS
from tres0r.stream import ENC_CHUNK_SIZE

from conftest import FAST, PASSWORD, make_tar, snapshot, write_raw_container

posix_only = pytest.mark.skipif(os.name != "posix", reason="nur POSIX")


def pack(sources, out, **kw):
    return container.create(sources, out, PASSWORD, FAST, **kw)


def leftovers(folder):
    return [n for n in os.listdir(folder) if n.startswith(".") and ("tres0r" in n or "partial" in n)]


# --- Roundtrip ------------------------------------------------------------
def test_roundtrip(tmp_path, sample_tree):
    out = tmp_path / "a.tres0r"
    result = pack(sample_tree, out)
    assert result.path == out and out.exists() and result.skipped == []

    dest = tmp_path / "ziel"
    names = container.extract(out, dest, PASSWORD).names
    assert names == ["Projekt", "einzeln.txt"]
    assert snapshot(dest / "Projekt") == snapshot(sample_tree[0])
    assert (dest / "einzeln.txt").read_bytes() == sample_tree[1].read_bytes()
    assert leftovers(dest) == []
    assert leftovers(tmp_path) == []


def test_list_and_inspect(tmp_path, sample_tree):
    out = tmp_path / "a.tres0r"
    pack(sample_tree, out)
    # NFC-normalisiert vergleichen (HFS+ unter macOS speichert Namen als NFD)
    names = {unicodedata.normalize("NFC", e.name) for e in container.list_contents(out, PASSWORD)}
    assert "Projekt/Überraschung ä ö ü ß.txt" in names
    assert "Projekt/leer" in names and "einzeln.txt" in names

    info = container.inspect(out)
    assert info.kdf == FAST and info.level is None and info.size == out.stat().st_size


def test_level_is_recorded(tmp_path, monkeypatch):
    # Echte Stufe, aber Argon2 durch Dummy ersetzt, damit der Test schnell bleibt.
    monkeypatch.setattr("tres0r.header2.derive_key", lambda pw, salt, p: bytes(32))
    src = tmp_path / "x.txt"
    src.write_text("x")
    out = tmp_path / "x.tres0r"
    container.create([src], out, PASSWORD, LEVELS["stark"])
    assert container.inspect(out).level == "stark"


def test_metadata_is_anonymized(tmp_path, sample_tree):
    out = tmp_path / "a.tres0r"
    pack(sample_tree, out)
    with container._open(out, PASSWORD) as op:
        _, _, data = op.stream()
        with tarfile.open(fileobj=data, mode="r|") as tar:
            for ti in tar:
                assert (ti.uid, ti.gid, ti.uname, ti.gname) == (0, 0, "", "")


def test_progress_reaches_total(tmp_path, sample_tree):
    calls = []
    pack(sample_tree, tmp_path / "a.tres0r", progress=lambda d, t: calls.append((d, t)))
    assert calls and calls[-1][0] == calls[-1][1] > 0
    assert all(d <= t for d, t in calls)

    calls.clear()
    container.extract(tmp_path / "a.tres0r", tmp_path / "z", PASSWORD, progress=lambda d, t: calls.append((d, t)))
    assert calls[-1][0] == calls[-1][1]


# --- Eingaben & Konflikte ---------------------------------------------------
def test_output_inside_source_is_excluded(tmp_path, sample_tree):
    root = sample_tree[0]
    out = root / "selbst.tres0r"
    pack([root], out)
    names = {e.name for e in container.list_contents(out, PASSWORD)}
    assert "Projekt/selbst.tres0r" not in names
    assert not any(n.endswith(".partial") for n in names)
    # Auch beim Überschreiben einer vorhandenen Datei
    pack([root], out, overwrite=True)
    names = {e.name for e in container.list_contents(out, PASSWORD)}
    assert "Projekt/selbst.tres0r" not in names


def test_duplicate_names_rejected(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "x.txt").write_text("1")
    (tmp_path / "b" / "x.txt").write_text("2")
    with pytest.raises(Tres0rError, match="heißen"):
        pack([tmp_path / "a" / "x.txt", tmp_path / "b" / "x.txt"], tmp_path / "o.tres0r")


def test_missing_source_and_existing_output(tmp_path):
    with pytest.raises(Tres0rError, match="Nicht gefunden"):
        pack([tmp_path / "gibtsnicht"], tmp_path / "o.tres0r")
    src = tmp_path / "s.txt"
    src.write_text("s")
    (tmp_path / "o.tres0r").write_text("alt")
    with pytest.raises(Tres0rError, match="existiert bereits"):
        pack([src], tmp_path / "o.tres0r")
    assert (tmp_path / "o.tres0r").read_text() == "alt"


def test_extract_conflict_leaves_existing_untouched(tmp_path, sample_tree):
    out = tmp_path / "a.tres0r"
    pack(sample_tree, out)
    dest = tmp_path / "ziel"
    dest.mkdir()
    (dest / "einzeln.txt").write_text("NICHT ÜBERSCHREIBEN")
    with pytest.raises(Tres0rError, match="existiert bereits"):
        container.extract(out, dest, PASSWORD)
    assert (dest / "einzeln.txt").read_text() == "NICHT ÜBERSCHREIBEN"
    assert sorted(os.listdir(dest)) == ["einzeln.txt"]


@posix_only
def test_special_files_are_skipped(tmp_path):
    folder = tmp_path / "mitfifo"
    folder.mkdir()
    (folder / "normal.txt").write_text("ok")
    os.mkfifo(folder / "rohr")
    result = pack([folder], tmp_path / "f.tres0r")
    assert result.skipped == [str(folder / "rohr")]


@posix_only
def test_internal_symlink_roundtrip(tmp_path):
    folder = tmp_path / "links"
    folder.mkdir()
    (folder / "ziel.txt").write_text("ziel")
    os.symlink("ziel.txt", folder / "verweis")
    pack([folder], tmp_path / "l.tres0r")
    container.extract(tmp_path / "l.tres0r", tmp_path / "raus", PASSWORD)
    link = tmp_path / "raus" / "links" / "verweis"
    assert link.is_symlink() and link.read_text() == "ziel"


# --- Abbruch & Aufräumen ----------------------------------------------------
def test_cancel_during_create_leaves_nothing(tmp_path, sample_tree):
    def cancel(done, total):
        if done > 100_000:
            raise Cancelled("stop")

    out = tmp_path / "abbruch.tres0r"
    with pytest.raises(Cancelled):
        pack(sample_tree, out, progress=cancel)
    assert not out.exists()
    assert leftovers(tmp_path) == []


# --- Falsches Passwort & Manipulation ---------------------------------------
@pytest.fixture
def packed(tmp_path, sample_tree):
    out = tmp_path / "a.tres0r"
    pack(sample_tree, out)
    return out


def assert_extract_fails(blob_path, dest, exc):
    dest.mkdir(exist_ok=True)
    before = sorted(os.listdir(dest))
    with pytest.raises(exc):
        container.extract(blob_path, dest, PASSWORD)
    assert sorted(os.listdir(dest)) == before  # nichts angelegt, kein Staging-Rest


def test_wrong_password_extract(packed, tmp_path):
    dest = tmp_path / "ziel"
    dest.mkdir()
    with pytest.raises(WrongPassword):
        container.extract(packed, dest, "falsch")
    assert os.listdir(dest) == []


@pytest.mark.parametrize("where", ["erster Chunk", "mittlerer Chunk", "letztes Byte"])
def test_payload_tampering(packed, tmp_path, where):
    raw = bytearray(packed.read_bytes())
    start = container.inspect(packed).header_len
    offset = {
        "erster Chunk": start + 10,
        "mittlerer Chunk": start + 2 * ENC_CHUNK_SIZE + 500,
        "letztes Byte": len(raw) - 1,
    }[where]
    raw[offset] ^= 0x01
    bad = tmp_path / "bad.tres0r"
    bad.write_bytes(bytes(raw))
    assert_extract_fails(bad, tmp_path / "ziel", IntegrityError)
    with pytest.raises(IntegrityError):
        container.verify(bad, PASSWORD)


@pytest.mark.parametrize("cut", ["ein Byte", "letzter Chunk", "halbe Datei"])
def test_truncation(packed, tmp_path, cut):
    raw = packed.read_bytes()
    payload_len = len(raw) - container.inspect(packed).header_len
    last_chunk = payload_len % ENC_CHUNK_SIZE or ENC_CHUNK_SIZE
    keep = {
        "ein Byte": len(raw) - 1,
        "letzter Chunk": len(raw) - last_chunk,
        "halbe Datei": len(raw) // 2,
    }[cut]
    bad = tmp_path / "bad.tres0r"
    bad.write_bytes(raw[:keep])
    assert_extract_fails(bad, tmp_path / "ziel", IntegrityError)


def test_appended_garbage(packed, tmp_path):
    bad = tmp_path / "bad.tres0r"
    bad.write_bytes(packed.read_bytes() + b"angehaengt")
    assert_extract_fails(bad, tmp_path / "ziel", IntegrityError)


# --- Bösartige Container (Absender kennt das Passwort) ----------------------
def _file(name, data=b"boese"):
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    return ti, data


def _link(name, target, kind=tarfile.SYMTYPE):
    ti = tarfile.TarInfo(name)
    ti.type = kind
    ti.linkname = target
    return ti, None


@pytest.mark.parametrize(
    "members",
    [
        [_file("../ausbruch.txt")],
        [_file("ok/../../ausbruch.txt")],
        [_link("link", "/etc/passwd")],
        [_link("link", "../../draussen")],
        [_link("hard", "/etc/passwd", tarfile.LNKTYPE)],
    ],
    ids=["dotdot", "dotdot-verschachtelt", "symlink-absolut", "symlink-raus", "hardlink-raus"],
)
def test_malicious_archives_are_refused(tmp_path, members, raw_writer):
    bad = tmp_path / "boese.tres0r"
    raw_writer(bad, make_tar(members))
    dest = tmp_path / "sandbox" / "ziel"
    dest.mkdir(parents=True)
    assert_extract_fails(bad, dest, UnsafeArchive)
    assert os.listdir(tmp_path / "sandbox") == ["ziel"]


def test_absolute_paths_stay_inside(tmp_path):
    """Absolute Pfade werden vom data-Filter relativ gemacht, nicht abgelehnt."""
    import uuid

    name = f"/tmp/tres0r-test-{uuid.uuid4().hex}.txt"  # tar-Namen sind immer POSIX-Pfade
    outside = os.path.abspath(name)  # unter Windows z. B. C:\tmp\...
    bad = tmp_path / "abs.tres0r"
    write_raw_container(bad, make_tar([_file(name)]))
    names = container.extract(bad, tmp_path / "z", PASSWORD).names
    assert not os.path.exists(outside)
    assert names and (tmp_path / "z" / names[0]).exists()


def test_setuid_bits_are_stripped(tmp_path, raw_writer):
    ti, data = _file("prog")
    ti.mode = 0o4777
    bad = tmp_path / "suid.tres0r"
    raw_writer(bad, make_tar([(ti, data)]))
    container.extract(bad, tmp_path / "z", PASSWORD)
    if os.name == "posix":
        mode = (tmp_path / "z" / "prog").stat().st_mode
        assert not mode & 0o4000 and not mode & 0o022


# --- Passwort ändern --------------------------------------------------------
def test_change_password(packed, tmp_path):
    payload_before = packed.read_bytes()[container.inspect(packed).header_len:]
    container.change_password(packed, PASSWORD, "ganz-neues-passwort")
    assert packed.read_bytes()[container.inspect(packed).header_len:] == payload_before  # nicht neu verschlüsselt
    with pytest.raises(WrongPassword):
        container.list_contents(packed, PASSWORD)
    container.extract(packed, tmp_path / "neu", "ganz-neues-passwort")
    assert leftovers(tmp_path) == []


def test_change_password_wrong_old(packed, tmp_path):
    before = packed.read_bytes()
    with pytest.raises(WrongPassword):
        container.change_password(packed, "falsch", "egal")
    assert packed.read_bytes() == before
    assert leftovers(tmp_path) == []


def test_change_level(tmp_path, monkeypatch):
    # Dummy-KDF, deren Ergebnis von den Parametern abhängt – so bleibt der Test
    # schnell und prüft trotzdem, dass der Keyslot mit den neuen Parametern entsteht.
    monkeypatch.setattr("tres0r.header2.derive_key", lambda pw, salt, p: bytes([p.iterations]) * 32)
    src = tmp_path / "x.txt"
    src.write_text("x")
    out = tmp_path / "x.tres0r"
    container.create([src], out, PASSWORD, LEVELS["normal"])
    container.change_password(out, PASSWORD, "neu", LEVELS["schnell"])
    assert container.inspect(out).level == "schnell"
    container.extract(out, tmp_path / "z", "neu")
    assert (tmp_path / "z" / "x.txt").read_text() == "x"
