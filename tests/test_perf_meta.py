import hashlib
import io
import json
import os
import tarfile
import time

import pytest

from tres0r import container, kdf, payload, workers
from tres0r.cli import main
from tres0r.errors import FormatError, IntegrityError, Tres0rError
from tres0r.kdf import LEVELS, KdfParams

from conftest import FAST, PASSWORD, make_tar, snapshot, write_raw_container_v2

posix_xattrs = pytest.mark.skipif(not hasattr(os, "listxattr"), reason="xattrs nur unter Linux")


def pack(sources, out, **kw):
    return container.create(sources, out, PASSWORD, FAST, **kw).path


def _xattr_supported(path) -> bool:
    try:
        os.setxattr(path, "user.tres0r-probe", b"1")
        os.removexattr(path, "user.tres0r-probe")
        return True
    except OSError:
        return False


# --- Threads ------------------------------------------------------------------
def test_resolve_threads(monkeypatch):
    monkeypatch.setattr(os, "cpu_count", lambda: 32)
    assert workers.resolve_threads(None) == workers.MAX_AUTO_THREADS
    monkeypatch.setattr(os, "cpu_count", lambda: None)
    assert workers.resolve_threads(None) == 1
    assert workers.resolve_threads(3) == 3
    with pytest.raises(ValueError):
        workers.resolve_threads(0)


def test_hash_worker_matches_inline():
    parts = [os.urandom(n) for n in (1, 70_000, 5, 1 << 20, 0, 333)]
    with workers.HashWorker(maxsize=2) as worker:
        a, b = hashlib.sha256(), hashlib.sha256()
        for part in parts:  # zwei Hashes verschränkt: Reihenfolge je Hash muss stimmen
            worker.update(a, part)
            worker.update(b, part[::-1])
        assert worker.hexdigest(a) == hashlib.sha256(b"".join(parts)).hexdigest()
        assert worker.hexdigest(b) == hashlib.sha256(b"".join(p[::-1] for p in parts)).hexdigest()
    worker.close()  # zweimal schließen ist harmlos


@pytest.mark.parametrize("compress", [False, pytest.param(True, marks=pytest.mark.skipif(
    payload.zstd_backend() is None, reason="kein zstd"))])
def test_threads_give_identical_results(tmp_path, sample_tree, compress):
    one = pack(sample_tree, tmp_path / "eins.tres0r", threads=1, compress=compress)
    four = pack(sample_tree, tmp_path / "vier.tres0r", threads=4, compress=compress)
    index = lambda p: [(e.name, e.size, e.sha256) for e in container.list_contents(p, PASSWORD)]  # noqa: E731
    assert index(one) == index(four)
    assert container.verify(four, PASSWORD, threads=4).checked_hashes
    container.extract(four, tmp_path / "z", PASSWORD)
    assert snapshot(tmp_path / "z" / "Projekt") == snapshot(sample_tree[0])


def test_threaded_verify_still_detects_tampering(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "c.tres0r")
    raw = bytearray(out.read_bytes())
    raw[container.inspect(out).header_len + 150_000] ^= 1
    out.write_bytes(bytes(raw))
    with pytest.raises(IntegrityError):
        container.verify(out, PASSWORD, threads=4)


@pytest.mark.skipif(payload.zstd_backend() is None, reason="kein zstd")
def test_multithreaded_zstd_roundtrip():
    data = (os.urandom(3 << 20) + b"komprimierbar " * 400_000)
    compressor = payload.FrameCompressor(level=3, threads=3)
    frame = compressor.compress(data) + compressor.end_frame()
    framed = b"".join(len(frame[i:i + payload.MAX_BLOCK]).to_bytes(4, "big") + frame[i:i + payload.MAX_BLOCK]
                      for i in range(0, len(frame), payload.MAX_BLOCK)) + bytes(4)
    reader = payload.open_decompressor(payload.BlockReader(io.BytesIO(framed)))
    assert reader.read() == data


def test_diff_parallel_hashing(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "d.tres0r")
    assert container.diff(out, sample_tree, PASSWORD, threads=4).identical
    (sample_tree[0] / "notiz.txt").write_text("Hallo Welt?", encoding="utf-8")
    changes = container.diff(out, sample_tree, PASSWORD, threads=4).changes
    assert [(c.name, c.status) for c in changes] == [("Projekt/notiz.txt", "geändert")]


# --- Argon2-Kalibrierung --------------------------------------------------------
def fake_timer(seconds_per_gib):
    calls = []

    def timer(params):
        calls.append(params)
        return params.memory_kib / (1024 * 1024) * seconds_per_gib * params.iterations
    return timer, calls


def test_calibrate_uses_max_memory_and_fills_time(monkeypatch):
    monkeypatch.setattr(kdf, "available_memory", lambda: 64 << 30)
    timer, calls = fake_timer(0.5)  # 1 GiB, 1 Iteration = 0,5 s
    params = kdf.calibrate(2.0, timer=timer)
    assert params == KdfParams(1024 * 1024, 4, 4)
    assert [(c.memory_kib, c.iterations) for c in calls] == [(8192, 1), (1 << 20, 1), (1 << 20, 2)]


def test_calibrate_halves_memory_on_slow_machines(monkeypatch):
    monkeypatch.setattr(kdf, "available_memory", lambda: 64 << 30)
    timer, calls = fake_timer(8.0)  # 1 GiB = 8 s -> 256 MiB = 2 s
    params = kdf.calibrate(2.0, timer=timer)
    assert params.memory_kib == 256 * 1024 and params.iterations == 1
    assert [c.memory_kib for c in calls] == [8192, 1 << 20, 1 << 19, 1 << 18]  # Ziel erreicht: keine 2. Messung


def affine_timer(fixed_per_gib, per_iteration_per_gib):
    """T(t) = A + B·t, beide proportional zum Speicher – wie auf den gemessenen Rechnern."""
    def timer(params):
        gib = params.memory_kib / (1024 * 1024)
        return gib * (fixed_per_gib + per_iteration_per_gib * params.iterations)
    return timer


@pytest.mark.parametrize("fixed, per_iteration", [(0.094, 0.156), (0.23, 0.485), (0.0, 0.3)])
def test_calibrate_hits_target_with_fixed_cost(monkeypatch, fixed, per_iteration):
    """Modelle aus echten Messungen (PC mit DDR5 bzw. DDR4): Ziel auf ±B/2 getroffen."""
    monkeypatch.setattr(kdf, "available_memory", lambda: 64 << 30)
    timer = affine_timer(fixed, per_iteration)
    params = kdf.calibrate(2.0, timer=timer)
    assert params.memory_kib == 1 << 20
    assert abs(timer(params) - 2.0) <= per_iteration / 2 + 1e-9
    # alte Rechnung (nur t = 1) läge deutlich darunter
    old = max(1, round(2.0 / (fixed + per_iteration)))
    assert fixed == 0 or fixed + per_iteration * old < timer(params)


def test_calibrate_falls_back_on_implausible_second_measurement(monkeypatch):
    monkeypatch.setattr(kdf, "available_memory", lambda: 64 << 30)
    params = kdf.calibrate(2.0, timer=lambda p: 0.4 * p.memory_kib / (1 << 20))  # t = 2 nicht langsamer
    assert params.iterations == 5  # vorsichtig: Ziel / T(1)


def test_calibrate_respects_free_memory_and_floor(monkeypatch):
    monkeypatch.setattr(kdf, "available_memory", lambda: 1 << 30)  # 1 GiB frei -> max 256 MiB
    timer, _ = fake_timer(0.1)
    assert kdf.calibrate(1.0, timer=timer).memory_kib == 256 * 1024
    timer, _ = fake_timer(1000.0)  # absurd langsam: nicht unter 64 MiB
    params = kdf.calibrate(1.0, timer=timer)
    assert params.memory_kib == 64 * 1024 and params.iterations == 1
    with pytest.raises(ValueError):
        kdf.calibrate(0)


def test_calibrate_real_machine():
    params = kdf.calibrate(0.2, max_memory_kib=64 * 1024)
    params.validate()
    assert 0.02 < kdf.measure(params) < 2.0


# --- Metadaten: --no-times -------------------------------------------------------
def test_no_times(tmp_path, sample_tree):
    os.utime(sample_tree[1], (1_000_000_000, 1_000_000_000))
    out = pack(sample_tree, tmp_path / "n.tres0r", times=False)
    assert {e.mtime for e in container.list_contents(out, PASSWORD)} == {0}
    with container._open(out, PASSWORD) as op:  # auch im tar selbst steht 0
        _, _, data = op.stream()
        with tarfile.open(fileobj=data, mode="r|") as tar:
            assert {ti.mtime for ti in tar} == {0}
    before = time.time()
    container.extract(out, tmp_path / "z", PASSWORD)
    assert (tmp_path / "z" / "einzeln.txt").stat().st_mtime >= before - 2  # jetzt, nicht 1970
    quick = container.diff(out, sample_tree, PASSWORD, quick=True)
    assert quick.identical and quick.hashed > 0  # ohne Zeiten hasht --quick doch
    assert container.diff(out, sample_tree, PASSWORD, times=True).identical


# --- Metadaten: xattrs / ACLs ------------------------------------------------------
@posix_xattrs
def test_xattrs_and_acls_roundtrip(tmp_path):
    src = tmp_path / "quelle"
    src.mkdir()
    if not _xattr_supported(src):
        pytest.skip("Dateisystem ohne user-xattrs")
    (src / "datei.txt").write_text("inhalt")
    os.setxattr(src / "datei.txt", "user.kommentar", "grün".encode())
    os.setxattr(src / "datei.txt", "user.binaer", bytes(range(256)))
    os.setxattr(src, "user.ordner", b"ja")
    acl = bytes.fromhex("02000000" "0100060000000000" "0400040000000000" "1000040000000000" "2000040000000000")
    try:
        os.setxattr(src / "datei.txt", "system.posix_acl_access", acl)
        has_acl = True
    except OSError:
        has_acl = False

    out = pack([src], tmp_path / "x.tres0r", xattrs=True, acls=True)
    full = tmp_path / "voll"
    result = container.extract(out, full, PASSWORD, xattrs=True, acls=True)
    assert not result.warnings
    assert os.getxattr(full / "quelle" / "datei.txt", "user.kommentar") == "grün".encode()
    assert os.getxattr(full / "quelle" / "datei.txt", "user.binaer") == bytes(range(256))
    assert os.getxattr(full / "quelle", "user.ordner") == b"ja"
    if has_acl:
        assert "system.posix_acl_access" in os.listxattr(full / "quelle" / "datei.txt")

    plain = tmp_path / "ohne"
    container.extract(out, plain, PASSWORD)  # ohne Schalter: nichts wiederherstellen
    assert "user.kommentar" not in os.listxattr(plain / "quelle" / "datei.txt")
    only_user = tmp_path / "nur-user"
    container.extract(out, only_user, PASSWORD, xattrs=True)
    assert "system.posix_acl_access" not in os.listxattr(only_user / "quelle" / "datei.txt")

    without = pack([src], tmp_path / "ohne.tres0r")  # ohne --xattrs nichts gesichert
    container.extract(without, tmp_path / "w", PASSWORD, xattrs=True)
    assert "user.kommentar" not in os.listxattr(tmp_path / "w" / "quelle" / "datei.txt")


@posix_xattrs
def test_dangerous_xattrs_are_never_restored(tmp_path):
    """Präparierter Container: security.capability (Rechteausweitung!) und trusted.*."""
    if not _xattr_supported(tmp_path):
        pytest.skip("Dateisystem ohne user-xattrs")
    ti = tarfile.TarInfo("prog")
    ti.size = 2
    ti.pax_headers = {
        "SCHILY.xattr.security.capability": "\x01\x00\x00\x02\xff\xff\xff\xff",
        "SCHILY.xattr.trusted.boese": "x",
        "SCHILY.xattr.user.harmlos": "ok",
    }
    bad = tmp_path / "boese.tres0r"
    write_raw_container_v2(bad, make_tar([(ti, b"#!")]))
    result = container.extract(bad, tmp_path / "z", PASSWORD, xattrs=True, acls=True)
    names = os.listxattr(tmp_path / "z" / "prog")
    assert "user.harmlos" in names
    assert not any(n.startswith(("security.", "trusted.")) for n in names)
    assert not result.warnings


def test_xattrs_require_linux(tmp_path, sample_tree, monkeypatch):
    monkeypatch.delattr(os, "listxattr", raising=False)
    with pytest.raises(Tres0rError, match="nur unter Linux"):
        pack(sample_tree, tmp_path / "x.tres0r", xattrs=True)


# --- CLI ------------------------------------------------------------------------------
@pytest.fixture
def fast_levels(monkeypatch):
    for name in LEVELS:
        monkeypatch.setitem(LEVELS, name, FAST)
    monkeypatch.setattr(kdf, "calibrate", lambda target, **kw: KdfParams(16 * 1024, 2, 1))


def test_cli_auto_level_threads_and_metadata(tmp_path, sample_tree, capsys, fast_levels):
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    out = tmp_path / "a.tres0r"
    assert main(["pack", *map(str, sample_tree), "-o", str(out), "-l", "auto", "--kdf-time", "0.5",
                 "--password-file", str(pw), "--offline", "--threads", "3", "--no-times"]) == 0
    err = capsys.readouterr().err
    assert "Kalibriere" in err and "16 MiB, t=2" in err
    capsys.readouterr()
    assert main(["info", str(out), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["kdf"] == {"algorithm": "argon2id", "memory_kib": 16 * 1024, "iterations": 2, "lanes": 1}
    assert data["level"] is None  # benutzerdefiniert
    assert main(["verify", str(out), "--password-file", str(pw), "--threads", "2"]) == 0
    assert main(["verify", str(out), "--password-file", str(pw), "--threads", "0"]) == 1


def test_cli_bench_throughput(tmp_path, capsys, fast_levels):
    assert main(["bench", "--throughput", "--size", "4", "--dir", str(tmp_path), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    operations = {r["operation"] for r in data["throughput"]}
    assert {"pack", "verify"} <= operations
    assert any(r["level"] == "auto" for r in data["levels"])
    assert os.listdir(tmp_path) == []  # Testdaten aufgeräumt


def test_format_error_types_unchanged():
    assert issubclass(FormatError, Tres0rError)
