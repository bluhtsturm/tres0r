import io
import os
import tarfile

import pytest

from tres0r.header import Header
from tres0r.kdf import KdfParams
from tres0r.stream import EncryptingWriter

@pytest.fixture(autouse=True)
def _simulated_cores(monkeypatch):
    """TRES0R_TEST_CPUS=4 täuscht mehrere Kerne vor – dann laufen alle Tests auch mit
    den Mehrkern-Pfaden (Hintergrund-Dekodierer, Hash-Worker, zstd-Worker)."""
    cpus = os.environ.get("TRES0R_TEST_CPUS")
    if cpus:
        monkeypatch.setattr(os, "cpu_count", lambda: int(cpus))


@pytest.fixture(autouse=True)
def _no_leaked_threads():
    """Nach jedem Test darf kein Hintergrund-Thread von tres0r mehr laufen."""
    import threading
    import time

    yield
    deadline = time.monotonic() + 2
    while True:
        leaked = [t.name for t in threading.enumerate() if t.name in ("tres0r-prefetch", "tres0r-hash")]
        if not leaked or time.monotonic() > deadline:
            break
        time.sleep(0.05)
    assert not leaked, f"hängende Threads: {leaked}"


# Minimal zulässige Kosten – echte Stufen würden die Tests minutenlang machen.
FAST = KdfParams(memory_kib=8 * 1024, iterations=1, lanes=1)
PASSWORD = "korrekt-pferd-batterie-heftklammer"


@pytest.fixture
def fast():
    return FAST


@pytest.fixture
def sample_tree(tmp_path):
    """Ordner mit Unterordnern, Umlauten, leerer Datei, leerem Ordner und
    genug Daten für mehrere Chunks."""
    root = tmp_path / "quelle" / "Projekt"
    (root / "Unterordner" / "tief").mkdir(parents=True)
    (root / "leer").mkdir()
    (root / "notiz.txt").write_text("Hallo Welt\n", encoding="utf-8")
    (root / "Überraschung ä ö ü ß.txt").write_text("Umlaute im Namen", encoding="utf-8")
    (root / "leere-datei").write_bytes(b"")
    (root / "Unterordner" / "gross.bin").write_bytes(os.urandom(300_000))  # ~4,6 Chunks
    (root / "Unterordner" / "tief" / "x.dat").write_bytes(b"\x00" * 65536)
    single = tmp_path / "quelle" / "einzeln.txt"
    single.write_text("einzelne Datei", encoding="utf-8")
    return [root, single]


def snapshot(path):
    """{relativer Pfad: Inhalt | None für Ordner} für Vergleiche."""
    result = {}
    for dirpath, dirnames, filenames in os.walk(path):
        rel = os.path.relpath(dirpath, path)
        for d in dirnames:
            result[os.path.normpath(os.path.join(rel, d))] = None
        for f in filenames:
            with open(os.path.join(dirpath, f), "rb") as fh:
                result[os.path.normpath(os.path.join(rel, f))] = fh.read()
    return result


def write_raw_container(path, tar_bytes, password=PASSWORD, params=FAST):
    """Beliebige tar-Daten korrekt verschlüsselt ablegen – simuliert einen
    Container, den ein böswilliger Absender mit bekanntem Passwort baut."""
    header, dek = Header.create(password, params)
    with open(path, "wb") as f:
        f.write(header.to_bytes())
        writer = EncryptingWriter(f, header.payload_key(dek))
        writer.write(tar_bytes)
        writer.finish()


def make_tar(members):
    """members: Liste von (TarInfo, bytes|None)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for ti, data in members:
            tar.addfile(ti, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def write_raw_container_v2(path, tar_bytes, password=PASSWORD, params=FAST, index=None):
    """Wie write_raw_container, aber Formatversion 2 (optional mit eigenem Index)."""
    from tres0r import container, payload
    from tres0r import header2 as h2

    dek = os.urandom(32)
    header = h2.HeaderV2.create(dek, [h2.password_slot(dek, password, params)],
                                flags=h2.FLAG_INDEX if index is not None else 0)
    with open(path, "wb") as f:
        f.write(header.to_bytes())
        enc = EncryptingWriter(f, header.payload_key(dek))
        writer = payload.PayloadWriter(enc, False)
        writer.write(tar_bytes)
        writer.close()
        trailer = payload.index_trailer(payload.encode_index(index)) if index is not None else b""
        container._finish_payload(enc, trailer, True)


@pytest.fixture(params=["v1", "v2"])
def raw_writer(request):
    return write_raw_container if request.param == "v1" else write_raw_container_v2


# --- Hypothesis-Profile -----------------------------------------------------
# Standard: schnell genug für jeden Testlauf. Gründlich:
#     HYPOTHESIS_PROFILE=fuzz python -m pytest tests/test_properties.py
try:
    from hypothesis import HealthCheck, settings

    _common = dict(deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture,
                                                         HealthCheck.too_slow])
    settings.register_profile("default", max_examples=60, **_common)
    settings.register_profile("fuzz", max_examples=5000, **_common)
    settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))
except ImportError:  # Hypothesis ist optional (Extra "dev")
    pass
