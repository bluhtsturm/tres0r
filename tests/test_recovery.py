import importlib
import os
import tarfile

import pytest

from tres0r import container
from tres0r.errors import IntegrityError, Tres0rError, WrongPassword
from tres0r.stream import ENC_CHUNK_SIZE

from conftest import FAST, PASSWORD, make_tar, snapshot, write_raw_container


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
def v1_container(tmp_path):
    members = []
    for name, data in (("alt/eins.txt", b"eins"), ("alt/zwei.bin", os.urandom(150_000)), ("alt/drei.txt", b"drei")):
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        members.append((ti, data))
    path = tmp_path / "alt.tres0r"
    write_raw_container(path, make_tar(members))
    return path, dict((ti.name, data) for ti, data in members)


# --- upgrade ----------------------------------------------------------------
@pytest.mark.parametrize("compress", [False, pytest.param(True, marks=needs_zstd)])
def test_upgrade_in_place(v1_container, tmp_path, compress):
    path, contents = v1_container
    result = container.upgrade(path, PASSWORD, compress=compress)
    info = container.inspect(path)
    assert result.entries == 3 and info.version == 2 and info.has_index and info.kdf == FAST
    assert info.compression == ("zstd" if compress else None)
    assert container.verify(path, PASSWORD).checked_hashes
    container.extract(path, tmp_path / "z", PASSWORD)
    for name, data in contents.items():
        assert (tmp_path / "z" / name).read_bytes() == data
    assert sorted(os.listdir(tmp_path)) == ["alt.tres0r", "z"]  # keine Temp-Reste


def test_upgrade_to_other_file_keeps_original(v1_container, tmp_path):
    path, _ = v1_container
    before = path.read_bytes()
    container.upgrade(path, PASSWORD, tmp_path / "neu.tres0r")
    assert path.read_bytes() == before
    assert container.inspect(tmp_path / "neu.tres0r").version == 2


def test_upgrade_refuses_v2_wrong_password_and_damage(v1_container, tmp_path, sample_tree):
    path, _ = v1_container
    with pytest.raises(WrongPassword):
        container.upgrade(path, "falsch")
    raw = bytearray(path.read_bytes())
    raw[-50] ^= 1  # Ende des alten Streams
    path.write_bytes(bytes(raw))
    with pytest.raises(IntegrityError):
        container.upgrade(path, PASSWORD)
    assert path.read_bytes() == bytes(raw)  # Original unangetastet
    assert sorted(os.listdir(tmp_path)) == ["alt.tres0r", "quelle"]
    new = container.create(sample_tree, tmp_path / "v2.tres0r", PASSWORD, FAST).path
    with pytest.raises(Tres0rError, match="bereits Formatversion 2"):
        container.upgrade(new, PASSWORD)


# --- salvage ----------------------------------------------------------------
@pytest.fixture
def big_tree(tmp_path):
    root = tmp_path / "quelle" / "Daten"
    root.mkdir(parents=True)
    # > 1 MiB, damit es bei Kompression mehrere zstd-Frames gibt (Schadensgranularität)
    files = {f"datei{i}.bin": os.urandom(150_000) for i in range(8)}
    files["gross.bin"] = os.urandom(400_000)  # alphabetisch zuletzt -> am Ende der Nutzdaten
    for name, data in files.items():
        (root / name).write_bytes(data)
    return root, files


def pack(root, out, **kw):
    return container.create([root], out, PASSWORD, FAST, **kw).path


def flip(path, offset):
    raw = bytearray(path.read_bytes())
    raw[offset] ^= 1
    path.write_bytes(bytes(raw))


def test_salvage_intact_container_recovers_everything(big_tree, tmp_path):
    root, files = big_tree
    out = pack(root, tmp_path / "c.tres0r")
    result = container.salvage(out, tmp_path / "raus", PASSWORD)
    assert result.complete and result.used_index
    assert snapshot(tmp_path / "raus" / "Daten") == {name: data for name, data in files.items()}


@pytest.mark.parametrize("compress", [False, pytest.param(True, marks=needs_zstd)])
def test_salvage_skips_only_damaged_entries(big_tree, tmp_path, compress):
    root, files = big_tree
    out = pack(root, tmp_path / "c.tres0r", compress=compress)
    # Einen Chunk kurz vor dem Ende beschädigen: liegt in "gross.bin" (letzte Datei);
    # die letzten Chunks mit Padding und Inhaltsverzeichnis bleiben heil.
    info = container.inspect(out)
    chunks = -(-info.payload_size // ENC_CHUNK_SIZE)
    flip(out, info.header_len + (chunks - 4) * ENC_CHUNK_SIZE + 100)
    with pytest.raises(IntegrityError):
        container.verify(out, PASSWORD)

    result = container.salvage(out, tmp_path / "raus", PASSWORD)
    damaged = [name for name, _ in result.damaged]
    assert "Daten/gross.bin" in damaged and not result.complete
    got = snapshot(tmp_path / "raus" / "Daten")
    assert "gross.bin" not in got  # keine halbe Datei
    intact = {n: d for n, d in files.items() if f"Daten/{n}" not in damaged}
    assert len(intact) >= 7 and all(got[n] == d for n, d in intact.items())


def test_salvage_truncated_container_falls_back_to_stream(big_tree, tmp_path):
    root, files = big_tree
    out = pack(root, tmp_path / "c.tres0r")
    raw = out.read_bytes()
    out.write_bytes(raw[: int(len(raw) * 0.7)])  # Kopieren abgebrochen: Index weg
    result = container.salvage(out, tmp_path / "raus", PASSWORD)
    assert not result.used_index and any("Inhaltsverzeichnis" in n for n in result.notes)
    got = snapshot(tmp_path / "raus")
    rescued = [n for n in files if f"Daten/{n}" in got]
    assert rescued and all(got[f"Daten/{n}"] == files[n] for n in rescued)
    assert not result.complete


def test_salvage_v1(v1_container, tmp_path):
    path, contents = v1_container
    raw = path.read_bytes()
    path.write_bytes(raw[: 107 + 2 * ENC_CHUNK_SIZE])  # mitten in "zwei.bin"
    result = container.salvage(path, tmp_path / "raus", PASSWORD)
    assert result.recovered == ["alt/eins.txt"]
    assert [name for name, _ in result.damaged][0] == "alt/zwei.bin"
    assert snapshot(tmp_path / "raus") == {"alt": None, "alt/eins.txt": b"eins"}


def test_salvage_needs_readable_header(big_tree, tmp_path):
    root, _ = big_tree
    out = pack(root, tmp_path / "c.tres0r")
    flip(out, 12)  # Stream-Nonce -> Header-MAC falsch
    with pytest.raises(IntegrityError):
        container.salvage(out, tmp_path / "raus", PASSWORD)


# --- CLI --------------------------------------------------------------------
def test_cli_salvage_and_upgrade(v1_container, tmp_path, capsys):
    import json

    from tres0r.cli import main

    path, _ = v1_container
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    assert main(["upgrade", str(path), "--password-file", str(pw)]) == 0
    assert container.inspect(path).version == 2
    capsys.readouterr()
    assert main(["salvage", str(path), "-o", str(tmp_path / "ok"), "--password-file", str(pw), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["complete"] and len(data["recovered"]) == 3  # 3 Dateien (Archiv ohne Ordnereintrag)

    raw = path.read_bytes()
    path.write_bytes(raw[: len(raw) // 2])
    assert main(["salvage", str(path), "-o", str(tmp_path / "teil"), "--password-file", str(pw), "--json"]) == 3
    data = json.loads(capsys.readouterr().out)
    assert not data["complete"] and data["damaged"] and data["ok"]


def test_upgrade_drops_foreign_pax_headers(tmp_path):
    """Fuzzer-Fund: ein PAX-Schlüsselwort aus ungültigem UTF-8 ließ upgrade abstürzen."""
    import io as _io

    buf = _io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        ti = tarfile.TarInfo("a.txt")
        ti.size = 3
        ti.pax_headers = {"SCHILY.xattr.user.test": "wert", "comment": "fremd"}
        tar.addfile(ti, _io.BytesIO(b"abc"))
    raw = buf.getvalue().replace(b"comment=", b"co\xed\xa0\x80nt=")  # gleich lang, ungültiges UTF-8
    path = tmp_path / "v1.tres0r"
    write_raw_container(path, raw)
    result = container.upgrade(path, PASSWORD, tmp_path / "neu.tres0r")
    assert result.entries == 1
    container.extract(tmp_path / "neu.tres0r", tmp_path / "z", PASSWORD)
    assert (tmp_path / "z" / "a.txt").read_bytes() == b"abc"
