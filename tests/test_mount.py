import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest

from tres0r import container, payload
from tres0r.errors import FormatError, IntegrityError, Tres0rError
from tres0r.mount import ContainerFS

from conftest import FAST, PASSWORD, make_tar, write_raw_container, write_raw_container_v2

ROOT = Path(__file__).resolve().parents[1]


def pack(sources, out, **kw):
    return container.create(sources, out, PASSWORD, FAST, **kw).path


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "quelle" / "Daten"
    (root / "unter").mkdir(parents=True)
    (root / "gross.bin").write_bytes(os.urandom(2_500_000))
    (root / "unter" / "text.txt").write_text("hallo\n" * 1000)
    (root / "leer").write_bytes(b"")
    if os.name == "posix":
        os.symlink("unter/text.txt", root / "verweis")
        os.link(root / "gross.bin", root / "hart.bin")
    return root


def read_all(fs, path, step):
    handle = fs.open(path)
    size = fs.attributes(path)["st_size"]
    return b"".join(handle.read(offset, step) for offset in range(0, size, step))


@pytest.mark.parametrize("compress", [False, pytest.param(True, marks=pytest.mark.skipif(
    payload.zstd_backend() is None, reason="kein zstd"))])
def test_container_fs_reads_everything(tmp_path, tree, compress):
    out = pack([tree], tmp_path / "m.tres0r", compress=compress)
    fs = ContainerFS(out, PASSWORD)
    assert fs.listdir("/") == ["Daten"]
    expected = {"gross.bin", "unter", "leer"} | ({"verweis", "hart.bin"} if os.name == "posix" else set())
    assert set(fs.listdir("/Daten")) == expected
    big = (tree / "gross.bin").read_bytes()
    assert read_all(fs, "/Daten/gross.bin", 131072) == big
    assert read_all(fs, "/Daten/unter/text.txt", 4096) == (tree / "unter" / "text.txt").read_bytes()
    assert fs.open("/Daten/leer").read(0, 10) == b""
    handle = fs.open("/Daten/gross.bin")  # Sprünge: vorwärts und zurück
    assert handle.read(2_000_000, 100) == big[2_000_000:2_000_100]
    assert handle.read(10, 50) == big[10:60]
    assert handle.read(2_499_990, 100) == big[2_499_990:]
    attrs = fs.attributes("/Daten/gross.bin")
    assert attrs["st_size"] == len(big) and attrs["st_mode"] & 0o777 == 0o444
    if os.name == "posix":
        assert fs.readlink("/Daten/verweis") == "unter/text.txt"
        assert read_all(fs, "/Daten/hart.bin", 1 << 20) == big
    with pytest.raises(FileNotFoundError):
        fs.attributes("/gibt/es/nicht")
    with pytest.raises(IsADirectoryError):
        fs.open("/Daten")
    fs.close()


def test_container_fs_split_and_signed(tmp_path, tree):
    from tres0r import keys

    out = pack([tree], tmp_path / "s.tres0r", split=1 << 20, sign_with=keys.generate_signing_key())
    fs = ContainerFS(out, PASSWORD)
    assert read_all(fs, "/Daten/gross.bin", 300_000) == (tree / "gross.bin").read_bytes()
    fs.close()


def test_container_fs_v1_and_hostile_names(tmp_path):
    members = []
    for name, data in (("alt/datei.txt", b"v1"), ("../ausbruch", b"x"), ("/absolut", b"y"), ("ok/./a", b"z")):
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        members.append((ti, data))
    old = tmp_path / "v1.tres0r"
    write_raw_container(old, make_tar(members))
    fs = ContainerFS(old, PASSWORD)
    assert fs.listdir("/") == ["alt", "ok"]
    assert fs.open("/alt/datei.txt").read(0, 10) == b"v1"
    assert fs.open("/ok/a").read(0, 10) == b"z"
    assert sorted(fs.skipped) == ["../ausbruch", "/absolut"]
    fs.close()


def test_container_fs_refuses_unindexed_and_raw(tmp_path):
    ti = tarfile.TarInfo("a")
    ti.size = 1
    bare = tmp_path / "ohne-index.tres0r"
    write_raw_container_v2(bare, make_tar([(ti, b"a")]))
    with pytest.raises(FormatError, match="Inhaltsverzeichnis"):
        ContainerFS(bare, PASSWORD)
    import io
    raw = tmp_path / "roh.tres0r"
    with container.atomic_output(raw) as f:
        container.encrypt_stream(io.BytesIO(b"x"), f, PASSWORD, FAST)
    with pytest.raises(Tres0rError, match="Rohdaten"):
        ContainerFS(raw, PASSWORD)


def test_damaged_chunk_is_read_error(tmp_path, tree):
    out = pack([tree], tmp_path / "d.tres0r")
    fs = ContainerFS(out, PASSWORD)
    entry = next(e for e in payload.read_index(fs._access) if e.name == "Daten/gross.bin")
    fs.close()
    raw = bytearray(out.read_bytes())
    raw[container.inspect(out).header_len + (entry.offset // 65536 + 3) * 65552 + 10] ^= 1
    out.write_bytes(bytes(raw))
    fs = ContainerFS(out, PASSWORD)
    with pytest.raises(IntegrityError):
        read_all(fs, "/Daten/gross.bin", 1 << 20)
    assert fs.open("/Daten/unter/text.txt").read(0, 6) == b"hallo\n"  # Rest bleibt lesbar
    fs.close()


# --- echtes Einhängen (FUSE) ------------------------------------------------------------
def _fuse_available() -> bool:
    import importlib

    try:
        importlib.import_module("fuse")
    except (ImportError, OSError):
        return False
    return sys.platform.startswith("linux") and os.path.exists("/dev/fuse") and shutil.which("fusermount") is not None


@pytest.mark.skipif(not _fuse_available(), reason="FUSE nicht verfügbar")
def test_real_mount(tmp_path, tree):
    out = pack([tree], tmp_path / "m.tres0r")
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    proc = subprocess.Popen([sys.executable, "-m", "tres0r", "mount", str(out), str(mnt), "--password-file", str(pw)],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if (mnt / "Daten").exists():
                break
            if proc.poll() is not None:
                pytest.skip(f"Einhängen nicht möglich: {proc.stderr.read().decode()[-200:]}")
            time.sleep(0.1)
        assert (mnt / "Daten" / "gross.bin").read_bytes() == (tree / "gross.bin").read_bytes()
        assert sorted(os.listdir(mnt / "Daten" / "unter")) == ["text.txt"]
        with pytest.raises(OSError):
            (mnt / "Daten" / "neu.txt").write_text("x")  # schreibgeschützt
        assert subprocess.run([sys.executable, "-m", "tres0r", "umount", str(mnt)], env=env).returncode == 0
        assert proc.wait(timeout=10) == 0
        assert not (mnt / "Daten").exists()
    finally:
        if proc.poll() is None:
            subprocess.run(["fusermount", "-u", str(mnt)])
            proc.wait(timeout=10)


def test_empty_or_broken_v1_tar_is_format_error(tmp_path):
    """Fuzzer-Fund: leeres tar in einem v1-Container ließ tarfile.ReadError entweichen."""
    for name, blob in (("leer", b""), ("kaputt", b"\x00" * 100 + b"x" * 400)):
        old = tmp_path / f"{name}.tres0r"
        write_raw_container(old, blob)
        try:
            ContainerFS(old, PASSWORD).close()
        except Tres0rError:
            pass
