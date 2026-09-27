import io
import os
import tarfile
from collections import namedtuple

import pytest

from tres0r import container
from tres0r.container import _NameGuard
from tres0r.errors import InsufficientSpace, IntegrityError, NameConflict, WrongPassword
from tres0r.exclude import ExcludeRules
from tres0r.padding import padme
from tres0r.stream import ENC_CHUNK_SIZE, TAG_LEN

from conftest import FAST, PASSWORD, make_tar, write_raw_container


def pack(sources, out, **kw):
    return container.create(sources, out, PASSWORD, FAST, **kw)


def names_in(path):
    return {e.name for e in container.list_contents(path, PASSWORD)}


def plaintext_len(path):
    payload = container.inspect(path).payload_size
    chunks = -(-payload // ENC_CHUNK_SIZE)
    return payload - chunks * TAG_LEN


# --- scan & Ausschlüsse -----------------------------------------------------
@pytest.fixture
def messy(tmp_path):
    root = tmp_path / "Projekt"
    (root / "build" / "tief").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "__pycache__").mkdir()
    for rel in ["src/main.py", "src/main.tmp", "build/tief/x.o", "__pycache__/m.pyc",
                ".DS_Store", "notiz.txt", "entwurf.txt"]:
        (root / rel).write_text(rel, encoding="utf-8")
    return root


def test_scan_counts_and_excludes(messy, tmp_path):
    plan = container.scan([messy], exclude=ExcludeRules(["*.tmp", "build/"]))
    arcs = {arc for _, arc, _ in plan.entries}
    assert "Projekt/src/main.tmp" not in arcs and "Projekt/build" not in arcs
    assert "Projekt/src/main.py" in arcs
    assert plan.excluded == 2  # Ordner zählt einmal, nicht sein Inhalt
    assert plan.files == 5 and plan.dirs == 3  # Projekt, src, __pycache__

    out = tmp_path / "p.tres0r"
    result = pack(plan, out)
    assert result.excluded == 2
    assert names_in(out) == arcs


def test_ignore_file_and_junk(messy, tmp_path):
    (messy / ".tres0rignore").write_text("# lokal\n/entwurf.txt\nbuild/\n", encoding="utf-8")
    plan = container.scan([messy], exclude=ExcludeRules.junk())
    arcs = {arc for _, arc, _ in plan.entries}
    assert "Projekt/entwurf.txt" not in arcs and "Projekt/build" not in arcs  # .tres0rignore
    assert "Projekt/.DS_Store" not in arcs and "Projekt/__pycache__" not in arcs  # junk
    assert "Projekt/.tres0rignore" in arcs  # die Datei selbst wird mitgenommen

    plan = container.scan([messy], ignore_files=False)
    assert "Projekt/entwurf.txt" in {arc for _, arc, _ in plan.entries}


def test_explicit_sources_are_never_excluded(messy):
    plan = container.scan([messy / "src" / "main.tmp"], exclude=ExcludeRules(["*.tmp"]))
    assert [arc for _, arc, _ in plan.entries] == ["main.tmp"]


def test_strict_names(tmp_path):
    src = tmp_path / "quelle"
    src.mkdir()
    (src / "CON.txt").write_text("x")
    out = tmp_path / "s.tres0r"
    with pytest.raises(NameConflict):
        pack([src], out, strict_names=True)
    assert not out.exists() and os.listdir(tmp_path) == ["quelle"]

    result = pack([src], out)  # ohne strict: nur Hinweis
    assert [i.path for i in result.issues] == ["quelle/CON.txt"]


# --- Padding ----------------------------------------------------------------
def test_padding_hides_exact_size(tmp_path, sample_tree):
    padded = pack(sample_tree, tmp_path / "mit.tres0r")
    plain = pack(sample_tree, tmp_path / "ohne.tres0r", pad=False)
    p_len = plaintext_len(padded.path)
    assert padme(p_len) == p_len and padded.padding > 0
    assert plaintext_len(plain.path) + padded.padding == p_len
    assert padded.padding / p_len < 0.07
    # Beide lassen sich identisch entpacken und prüfen
    assert names_in(padded.path) == names_in(plain.path)
    container.extract(padded.path, tmp_path / "z", PASSWORD)
    assert (tmp_path / "z" / "einzeln.txt").exists()


def test_padding_is_authenticated(tmp_path, sample_tree):
    """Auch die Padding-Bytes am Ende sind geschützt (letzter Chunk)."""
    out = pack(sample_tree, tmp_path / "p.tres0r").path
    raw = bytearray(out.read_bytes())
    raw[-TAG_LEN - 5] ^= 0x01
    out.write_bytes(bytes(raw))
    with pytest.raises(IntegrityError):
        container.verify(out, PASSWORD)


@pytest.mark.parametrize("pad", [True, False])
def test_estimate_is_upper_bound(tmp_path, sample_tree, pad):
    plan = container.scan(sample_tree)
    result = pack(plan, tmp_path / "e.tres0r", pad=pad)
    estimate = container.estimate_size(plan, pad)
    assert result.size <= estimate < result.size * 1.5 + 50_000


# --- Speicherplatz ----------------------------------------------------------
Usage = namedtuple("Usage", "total used free")


def test_space_check(tmp_path, sample_tree, monkeypatch):
    out = tmp_path / "voll.tres0r"
    pack(sample_tree, tmp_path / "ok.tres0r")
    monkeypatch.setattr(container.shutil, "disk_usage", lambda p: Usage(10**9, 10**9, 1000))
    with pytest.raises(InsufficientSpace, match="Nicht genug Speicherplatz"):
        pack(sample_tree, out)
    assert not out.exists()
    with pytest.raises(InsufficientSpace):
        container.extract(tmp_path / "ok.tres0r", tmp_path / "ziel", PASSWORD)
    assert not (tmp_path / "ziel").exists()  # Abbruch vor dem Anlegen
    with pytest.raises(InsufficientSpace):
        container.change_password(tmp_path / "ok.tres0r", PASSWORD, "neu")

    pack(sample_tree, out, check_space=False)  # abschaltbar
    assert out.exists()


# --- verify -----------------------------------------------------------------
def test_verify(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "v.tres0r").path
    result = container.verify(out, PASSWORD)
    assert result.files == 6 and result.bytes == 300_000 + 65536 + 11 + 16 + 14
    with pytest.raises(WrongPassword):
        container.verify(out, "falsch")
    raw = bytearray(out.read_bytes())
    raw[container.inspect(out).header_len + ENC_CHUNK_SIZE + 3] ^= 0x01
    out.write_bytes(bytes(raw))
    with pytest.raises(IntegrityError):
        container.verify(out, PASSWORD)


# --- Namensschutz beim Entpacken --------------------------------------------
def _file(name, data=b"x"):
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    return ti, data


def _dir(name):
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.DIRTYPE
    ti.mode = 0o755
    return ti, None


def _case_insensitive(folder):
    probe = folder / "tres0r-Probe"
    probe.write_text("x")
    try:
        return (folder / "TRES0R-probe").exists()
    finally:
        probe.unlink()


def test_duplicate_name_aborts_or_renames(tmp_path):
    bad = tmp_path / "dup.tres0r"
    write_raw_container(bad, make_tar([_file("bericht.pdf", b"eins"), _file("bericht.pdf", b"zwei")]))
    dest = tmp_path / "ziel"
    with pytest.raises(NameConflict):
        container.extract(bad, dest, PASSWORD)
    assert os.listdir(dest) == []

    result = container.extract(bad, dest, PASSWORD, rename=True)
    assert (dest / "bericht.pdf").read_bytes() == b"eins"
    assert (dest / "bericht (1).pdf").read_bytes() == b"zwei"
    assert result.renamed == [("bericht.pdf", "bericht (1).pdf")]


def test_renamed_directory_takes_children_along(tmp_path):
    members = [_file("y", b"datei"), _dir("y"), _file("y/kind.txt", b"kind"),
               _dir("m"), _file("m/a.txt", b"a"), _dir("m"), _file("m/b.txt", b"b")]
    bad = tmp_path / "d.tres0r"
    write_raw_container(bad, make_tar(members))
    dest = tmp_path / "ziel"
    result = container.extract(bad, dest, PASSWORD, rename=True)
    assert (dest / "y").read_bytes() == b"datei"
    assert (dest / "y (1)" / "kind.txt").read_bytes() == b"kind"
    assert sorted(os.listdir(dest / "m")) == ["a.txt", "b.txt"]  # gleiche Ordner: zusammengelegt
    assert result.renamed == [("y", "y (1)")]


def test_case_collision_matches_filesystem(tmp_path):
    """Auf case-insensitiven Dateisystemen (Windows/macOS-CI) greift der Schutz,
    unter Linux dürfen beide Dateien nebeneinander existieren."""
    bad = tmp_path / "case.tres0r"
    write_raw_container(bad, make_tar([_file("Datei.txt", b"gross"), _file("datei.txt", b"klein")]))
    dest = tmp_path / "ziel"
    dest.mkdir()
    if _case_insensitive(dest):
        with pytest.raises(NameConflict):
            container.extract(bad, dest, PASSWORD)
        container.extract(bad, dest, PASSWORD, rename=True)
        assert (dest / "datei (1).txt").read_bytes() == b"klein"
    else:
        container.extract(bad, dest, PASSWORD)
        assert (dest / "Datei.txt").read_bytes() == b"gross"
        assert (dest / "datei.txt").read_bytes() == b"klein"


def _guarded_extract(tmp_path, members, *, rename):
    staging = tmp_path / "staging"
    staging.mkdir(parents=True)
    guard = _NameGuard(staging, rename=rename, windows=True)
    with tarfile.open(fileobj=io.BytesIO(make_tar(members)), mode="r") as tar:
        tar.extractall(staging, filter=guard)
    return staging, guard


def test_windows_invalid_names(tmp_path):
    members = [_dir("a:b"), _file("a:b/CON.txt", b"1"), _file("frage?.txt", b"2"), _file("ende.", b"3")]
    with pytest.raises(NameConflict, match="--rename"):
        _guarded_extract(tmp_path / "eins", members, rename=False)

    staging, guard = _guarded_extract(tmp_path / "zwei", members, rename=True)
    assert (staging / "a_b" / "CON_.txt").read_bytes() == b"1"
    assert (staging / "frage_.txt").read_bytes() == b"2"
    assert (staging / "ende_").read_bytes() == b"3"
    assert ("a:b/CON.txt", "a_b/CON_.txt") in guard.renamed


def test_hardlink_follows_renamed_target(tmp_path):
    link = tarfile.TarInfo("verweis")
    link.type = tarfile.LNKTYPE
    link.linkname = "d.txt"
    members = [_file("d.txt", b"alt"), _file("d.txt", b"neu"), (link, None)]
    staging, _ = _guarded_extract(tmp_path, members, rename=True)
    assert (staging / "verweis").read_bytes() == b"neu"  # tar-Semantik: letzter Eintrag gilt
