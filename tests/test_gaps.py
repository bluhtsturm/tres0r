"""Pfade, die die Abdeckungsmessung als ungetestet zeigte."""
import hashlib
import io
import os
import tarfile

import pytest

from tres0r import container, payload, segments
from tres0r.errors import FormatError, IntegrityError, NameConflict, Tres0rError, UnsafeArchive

from conftest import FAST, PASSWORD, make_tar, write_raw_container, write_raw_container_v2


def tree(root, files):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


# --- Zusammenführen angehängter Segmente ----------------------------------------------
def test_append_into_existing_folders(tmp_path):
    first = tree(tmp_path / "a" / "Projekt", {"alt.txt": "1", "Unter/tief.txt": "1", "wird-ordner": "Datei"})
    later = tree(tmp_path / "b" / "Projekt", {"neu.txt": "2", "Unter/tief.txt": "2", "wird-ordner/innen.txt": "O"})
    out = container.create([first], tmp_path / "c.tres0r", PASSWORD, FAST).path
    container.append(out, [later], PASSWORD)
    for how in ("extract", "salvage"):
        dest = tmp_path / how
        if how == "extract":
            container.extract(out, dest, PASSWORD)
        else:
            container.salvage(out, dest, PASSWORD)
        root = dest / "Projekt"
        assert (root / "alt.txt").read_text() == "1"               # aus Segment 0 erhalten
        assert (root / "neu.txt").read_text() == "2"               # aus Segment 1 dazu
        assert (root / "Unter" / "tief.txt").read_text() == "2"    # neuere Fassung im Unterordner
        assert (root / "wird-ordner" / "innen.txt").read_text() == "O"  # Datei durch Ordner ersetzt
    # und umgekehrt: Ordner durch Datei ersetzt
    newer = tree(tmp_path / "c" / "Projekt", {"Unter": "jetzt eine Datei"})
    container.append(out, [newer], PASSWORD)
    container.extract(out, tmp_path / "zwei", PASSWORD)
    assert (tmp_path / "zwei" / "Projekt" / "Unter").read_text() == "jetzt eine Datei"


# --- Inhaltsverzeichnis und Archiv müssen übereinstimmen ----------------------------------
def _members(names):
    out = []
    for name in names:
        ti = tarfile.TarInfo(name)
        ti.size = 1
        out.append((ti, b"x"))
    return out


def _entry(name):
    return payload.IndexEntry(name, "f", 1, 0, 0, 0, hashlib.sha256(b"x").hexdigest())


@pytest.mark.parametrize("archive, index, message", [
    (["a", "b"], ["a"], "mehr Einträge"),
    (["a"], ["a", "b"], "im Archiv"),
])
def test_index_and_archive_must_match(tmp_path, archive, index, message):
    path = tmp_path / "x.tres0r"
    write_raw_container_v2(path, make_tar(_members(archive)), index=[_entry(n) for n in index])
    with pytest.raises(FormatError, match=message):
        container.verify(path, PASSWORD)


# --- Ablehnungen -------------------------------------------------------------------------
def test_refusals(tmp_path, sample_tree):
    out = container.create(sample_tree, tmp_path / "s.tres0r", PASSWORD, FAST).path
    container.append(out, [sample_tree[1]], PASSWORD)
    with pytest.raises(Tres0rError, match="unpack"):
        container.decrypt_stream(io.BytesIO(out.read_bytes()), io.BytesIO(), PASSWORD)
    old = tmp_path / "v1.tres0r"
    write_raw_container(old, make_tar(_members(["a"])))
    with pytest.raises(Tres0rError, match="Formatversion 2"):
        container.append(old, [sample_tree[1]], PASSWORD)
    with pytest.raises(Tres0rError, match="v2-Container"):
        container.repair(old, PASSWORD)
    split = container.create(sample_tree, tmp_path / "t.tres0r", PASSWORD, FAST, split=1 << 20).path
    with pytest.raises(Tres0rError, match="Aufgeteilte"):
        container.repair(split, PASSWORD)
    bad = tmp_path / "con"  # unter Windows reserviert
    bad.mkdir()
    (bad / "aux.txt").write_text("x")
    with pytest.raises(NameConflict):
        container.append(out, [bad], PASSWORD, strict_names=True)


def test_key_changes_wait_for_repair(tmp_path, sample_tree):
    out = container.create(sample_tree, tmp_path / "s.tres0r", PASSWORD, FAST).path
    header_len = container.inspect(out).header_len
    segments.write_journal(out, out.stat().st_size, out.read_bytes()[:header_len])
    with open(out, "ab") as f:
        f.write(os.urandom(1000))
    with pytest.raises(FormatError, match="repair"):
        container.change_password(out, PASSWORD, "neu")
    # Journal mit falscher Header-Länge wird nicht blind angewendet
    segments.write_journal(out, header_len + 10, b"zu kurz")
    with pytest.raises(FormatError, match="Journal passt nicht"):
        container.repair(out, PASSWORD)


def test_repair_gives_up_safely(tmp_path, sample_tree):
    plain = container.create(sample_tree, tmp_path / "p.tres0r", PASSWORD, FAST).path
    with open(plain, "ab") as f:  # Müll hinten, kein Journal, keine Segmente
        f.write(os.urandom(500))
    with pytest.raises(Tres0rError, match="Nichts Sicheres"):
        container.repair(plain, PASSWORD)
    seg = container.create(sample_tree, tmp_path / "s.tres0r", PASSWORD, FAST).path
    container.append(seg, [sample_tree[1]], PASSWORD)
    raw = seg.read_bytes()
    table_len = int.from_bytes(raw[-12:-8], "big") + 16 + 12
    seg.write_bytes(raw[:-table_len] + os.urandom(table_len))  # einzige Tabelle zerstört
    with pytest.raises(IntegrityError, match="salvage"):
        container.repair(seg, PASSWORD)


def test_diff_quick_notices_time(tmp_path, sample_tree):
    out = container.create(sample_tree, tmp_path / "d.tres0r", PASSWORD, FAST).path
    os.utime(sample_tree[1], (2_000_000_000, 2_000_000_000))
    changes = container.diff(out, sample_tree, PASSWORD, quick=True).changes
    assert [(c.name, c.status) for c in changes] == [("einzeln.txt", "geändert")]
    assert "Änderungszeit" in changes[0].detail


@pytest.mark.parametrize("names", [["@/../x"], ["a/../b"], ["ok.txt", "tief/../../raus"], ["@/.."]])
def test_dotdot_names_rejected_cleanly(tmp_path, names, raw_writer):
    """Fuzzer-Fund: '@/..' ließ tarfile mit FileExistsError abbrechen (kein Ausbruch, aber roher Fehler)."""
    path = tmp_path / "x.tres0r"
    raw_writer(path, make_tar(_members(names)))
    dest = tmp_path / "ziel"
    dest.mkdir()
    with pytest.raises(UnsafeArchive, match=r"'\.\.'"):
        container.extract(path, dest, PASSWORD)
    assert os.listdir(dest) == []
    # salvage rettet, was sicher ist, und meldet den Rest – statt abzubrechen
    result = container.salvage(path, tmp_path / "rettung", PASSWORD)
    rescued = sorted(str(p.relative_to(tmp_path / "rettung")) for p in (tmp_path / "rettung").rglob("*")) \
        if (tmp_path / "rettung").exists() else []
    assert rescued == (["ok.txt"] if "ok.txt" in names else [])
    assert any(".." in reason or ".." in name for name, reason in result.damaged)
    assert not (tmp_path / "raus").exists() and not (tmp_path / "x").exists()
