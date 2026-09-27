import io
import json
import os
import subprocess
import sys
import tarfile
import threading
from pathlib import Path

import pytest

from tres0r import container, keys
from tres0r.cli import main, render_progress
from tres0r.errors import Cancelled, IntegrityError, WrongPassword
from tres0r.exclude import ExcludeRules
from tres0r.kdf import LEVELS
from tres0r.progress import UNIT_ENTRIES, CancelToken, Monitor, ProgressEvent, Tracker

from conftest import FAST, PASSWORD, make_tar, snapshot, write_raw_container

ROOT = Path(__file__).resolve().parents[1]


def pack(sources, out, **kw):
    return container.create(sources, out, PASSWORD, FAST, **kw).path


# --- Tracker (mit künstlicher Uhr) ---------------------------------------------
class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def test_tracker_throttles_and_computes_rate_eta():
    events, clock = [], Clock()
    monitor = Monitor(events.append, interval=0.5)
    t = Tracker(monitor, "packen", total=1000, clock=clock)
    assert events[-1].done == 0 and events[-1].phase == "packen"  # Startereignis
    clock.now += 0.1
    t(100)  # gedrosselt
    assert len(events) == 1
    clock.now += 0.9  # 1 s nach Start: Datei wechselt -> Meldung
    t.item("a.bin")
    assert (events[-1].done, events[-1].item) == (100, "a.bin") and len(events) == 2
    t(50)  # im selben Zeitfenster -> gedrosselt
    assert len(events) == 2
    clock.now += 0.5  # 1,5 s nach Start
    t(50)
    last = events[-1]
    assert last.done == 200 and last.item == "a.bin"
    assert last.rate == pytest.approx(200 / 1.5) and last.eta == pytest.approx(800 / (200 / 1.5))
    t.finish()
    assert events[-1].finished and events[-1].done == 1000 and events[-1].eta is None


def test_tracker_unknown_total_and_legacy():
    events = []
    t = Tracker(Monitor(events.append, interval=0), "entpacken", total=None)
    t(10)
    assert events[-1].total is None and events[-1].fraction is None
    calls = []
    legacy = Tracker(lambda d, total: calls.append((d, total)), "packen", total=50)
    legacy(30)
    legacy(40)  # wird auf total begrenzt
    legacy.finish()
    assert calls == [(30, 50), (50, 50), (50, 50)]
    silent = Tracker(lambda d, total: calls.append("x"), "durchsuchen", total=None)
    silent(5)  # alte Callbacks bekommen nichts ohne bekannte Gesamtgröße
    assert calls[-1] == (50, 50)


def test_cancel_token_is_threadsafe_and_checked():
    token = CancelToken()
    t = Tracker(Monitor(cancel=token), "packen", total=10)
    t(1)
    threading.Thread(target=token.cancel).start()
    token._event.wait(1)
    with pytest.raises(Cancelled):
        t(1)
    with pytest.raises(Cancelled):
        Tracker(Monitor(cancel=token), "packen")  # schon vor dem Start abgebrochen


# --- Ereignisse aus echten Vorgängen --------------------------------------------
def test_create_and_extract_emit_phases_and_items(tmp_path, sample_tree):
    events = []
    monitor = Monitor(events.append, interval=0)
    plan = container.scan(sample_tree, progress=monitor)
    out = pack(plan, tmp_path / "c.tres0r", progress=monitor)
    phases = [e.phase for e in events]
    assert phases[0] == "durchsuchen" and "schlüssel" in phases and phases[-1] == "packen"
    items = {e.item for e in events if e.phase == "packen"}
    assert "Projekt/Unterordner/gross.bin" in items
    assert events[-1].finished and events[-1].done == events[-1].total == plan.total_bytes

    events.clear()
    container.extract(out, tmp_path / "z", PASSWORD, progress=monitor)
    unpack = [e for e in events if e.phase == "entpacken"]
    assert unpack[-1].finished and "einzeln.txt" in {e.item for e in unpack}

    events.clear()
    container.extract(out, tmp_path / "t", PASSWORD, progress=monitor, only=["*.txt"])
    only = [e for e in events if e.phase == "entpacken"]
    assert only[-1].unit == UNIT_ENTRIES and only[-1].finished


def _cancel_after(phase, count=1):
    token = CancelToken()
    seen = []

    def on_event(event):
        if event.phase == phase and event.item:
            seen.append(event.item)
            if len(seen) >= count:
                token.cancel()
    return Monitor(on_event, cancel=token, interval=0)


def test_cancel_during_create_cleans_up(tmp_path, sample_tree):
    out = tmp_path / "c.tres0r"
    with pytest.raises(Cancelled):
        pack(sample_tree, out, progress=_cancel_after("packen", 2))
    assert not out.exists() and [n for n in os.listdir(tmp_path) if n.startswith(".")] == []


def test_cancel_during_extract_and_verify(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "c.tres0r")
    dest = tmp_path / "ziel"
    dest.mkdir()
    with pytest.raises(Cancelled):
        container.extract(out, dest, PASSWORD, progress=_cancel_after("entpacken", 2))
    assert os.listdir(dest) == []
    with pytest.raises(Cancelled):
        container.verify(out, PASSWORD, progress=_cancel_after("prüfen"))


def test_cancel_during_key_change_keeps_container(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "c.tres0r")
    before = out.read_bytes()
    token = CancelToken()
    monitor = Monitor(lambda e: token.cancel() if e.phase == "kopieren" else None, cancel=token, interval=0)
    with pytest.raises(Cancelled):
        container.add_keys(out, PASSWORD, recipients=[keys.generate_identity().public_key()], progress=monitor)
    assert out.read_bytes() == before


def test_render_progress():
    ev = ProgressEvent("packen", 450, 1000, item="Projekt/Unterordner/sehr-lange-datei.bin", rate=120 * 2**20, eta=12)
    line = render_progress(ev, 100)
    assert line.startswith("Verschlüsseln:  45 %") and "120.0 MiB/s" in line and "noch 0:12" in line
    assert "sehr-lange-datei.bin" in line
    assert len(render_progress(ev, 40)) <= 39
    assert "Einträge" in render_progress(ProgressEvent("durchsuchen", 12, None, unit=UNIT_ENTRIES), 80)
    assert render_progress(ProgressEvent("entpacken", 5 * 2**20, None), 80) == "Entschlüsseln: 5.0 MiB"


# --- diff -----------------------------------------------------------------------
@pytest.fixture
def packed_tree(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "d.tres0r")
    return out, sample_tree


def test_diff_identical(packed_tree):
    out, sources = packed_tree
    result = container.diff(out, sources, PASSWORD)
    assert result.identical and result.unchanged == 10 and result.hashed == 6


def test_diff_detects_all_kinds(packed_tree):
    out, sources = packed_tree
    root = sources[0]
    notiz = root / "notiz.txt"
    stat = notiz.stat()
    notiz.write_text("Hallo Welt?", encoding="utf-8")  # gleiche Länge, anderer Inhalt
    os.utime(notiz, (stat.st_atime, stat.st_mtime))
    (root / "leere-datei").write_bytes(b"jetzt nicht mehr leer")
    (root / "neu.txt").write_text("neu")
    (root / "Unterordner" / "tief" / "x.dat").unlink()
    (root / "leer").rmdir()
    (root / "leer").write_text("war ein Ordner")
    result = container.diff(out, sources, PASSWORD)
    changes = {c.name: c.status for c in result.changes}
    assert changes == {
        "Projekt/notiz.txt": "geändert",
        "Projekt/leere-datei": "geändert",
        "Projekt/neu.txt": "neu",
        "Projekt/Unterordner/tief/x.dat": "entfernt",
        "Projekt/leer": "typ",
    }
    # --quick sieht die gleich große Änderung mit gleicher Zeit nicht (wie rsync)
    quick = {c.name for c in container.diff(out, sources, PASSWORD, quick=True).changes}
    assert "Projekt/notiz.txt" not in quick and "Projekt/leere-datei" in quick


def test_diff_times_and_excludes(tmp_path, sample_tree):
    (sample_tree[0] / "wegwerf.tmp").write_text("x")
    out = pack(sample_tree, tmp_path / "e.tres0r", exclude=ExcludeRules(["*.tmp"]))
    assert not container.diff(out, sample_tree, PASSWORD, exclude=ExcludeRules(["*.tmp"])).changes
    assert [c.status for c in container.diff(out, sample_tree, PASSWORD).changes] == ["neu"]
    os.utime(sample_tree[1], (1_000_000_000, 1_000_000_000))
    assert container.diff(out, sample_tree, PASSWORD, exclude=ExcludeRules(["*.tmp"])).identical
    timed = container.diff(out, sample_tree, PASSWORD, exclude=ExcludeRules(["*.tmp"]), times=True)
    assert [(c.name, c.status) for c in timed.changes] == [("einzeln.txt", "zeit")]


@pytest.mark.skipif(os.name != "posix", reason="Symlinks/Hardlinks")
def test_diff_links(tmp_path):
    src = tmp_path / "links"
    src.mkdir()
    (src / "a.txt").write_text("a")
    os.link(src / "a.txt", src / "hart.txt")
    os.symlink("a.txt", src / "weich")
    out = pack([src], tmp_path / "l.tres0r")
    assert container.diff(out, [src], PASSWORD).identical
    (src / "weich").unlink()
    os.symlink("anderswo", src / "weich")
    assert [(c.name, c.status) for c in container.diff(out, [src], PASSWORD).changes] == [("links/weich", "link")]


def test_diff_v1_container(tmp_path):
    src = tmp_path / "alt"
    src.mkdir()
    (src / "a.txt").write_bytes(b"inhalt")
    ti = tarfile.TarInfo("alt/a.txt")
    ti.size = 6
    ti.mtime = int((src / "a.txt").stat().st_mtime)
    d = tarfile.TarInfo("alt")
    d.type = tarfile.DIRTYPE
    path = tmp_path / "v1.tres0r"
    write_raw_container(path, make_tar([(d, None), (ti, b"inhalt")]))
    assert container.diff(path, [src], PASSWORD).identical
    (src / "a.txt").write_bytes(b"INHALT")
    assert [c.status for c in container.diff(path, [src], PASSWORD).changes] == ["geändert"]


def test_cli_diff_exit_codes(packed_tree, tmp_path, capsys):
    out, sources = packed_tree
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    base = ["diff", str(out), *map(str, sources), "--password-file", str(pw)]
    assert main(base) == 0
    (sources[0] / "neu.txt").write_text("neu")
    capsys.readouterr()
    assert main([*base, "--json"]) == 4
    data = json.loads(capsys.readouterr().out)
    assert not data["identical"] and data["changes"] == [{"name": "Projekt/neu.txt", "status": "neu", "detail": ""}]


# --- Entpacken aus Datenströmen -------------------------------------------------
def test_extract_stream(tmp_path, sample_tree):
    signer = keys.generate_signing_key()
    out = pack(sample_tree, tmp_path / "s.tres0r", sign_with=signer)
    with open(out, "rb") as f:
        result = container.extract_stream(f, tmp_path / "z", PASSWORD, signers=[signer.public_key()])
    assert result.signer and snapshot(tmp_path / "z" / "Projekt") == snapshot(sample_tree[0])
    with open(out, "rb") as f:
        only = container.extract_stream(f, tmp_path / "o", PASSWORD, only=["einzeln.txt"])
    assert only.names == ["einzeln.txt"]
    with open(out, "rb") as f, pytest.raises(WrongPassword):
        container.extract_stream(f, tmp_path / "w", "falsch")


def test_extract_stream_damaged_leaves_nothing(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "s.tres0r")
    data = out.read_bytes()
    dest = tmp_path / "ziel"
    dest.mkdir()
    with pytest.raises(IntegrityError):
        container.extract_stream(io.BytesIO(data[:-300]), dest, PASSWORD)
    assert os.listdir(dest) == []


def test_cli_unpack_from_real_pipe(tmp_path, sample_tree):
    out = pack(sample_tree, tmp_path / "p.tres0r")
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    run = subprocess.run([sys.executable, "-m", "tres0r", "unpack", "-", "-o", str(tmp_path / "z"),
                          "--password-file", str(pw)], input=out.read_bytes(), capture_output=True,
                         env=env, timeout=120)
    assert run.returncode == 0, run.stderr.decode()
    assert snapshot(tmp_path / "z" / "Projekt") == snapshot(sample_tree[0])
    broken = subprocess.run([sys.executable, "-m", "tres0r", "unpack", "-", "-o", str(tmp_path / "k"),
                             "--password-file", str(pw)], input=out.read_bytes()[:-500], capture_output=True,
                            env=env, timeout=120)
    assert broken.returncode == 3 and not (tmp_path / "k").exists() or os.listdir(tmp_path / "k") == []


@pytest.fixture(autouse=True)
def fast_levels(monkeypatch):
    for name in LEVELS:
        monkeypatch.setitem(LEVELS, name, FAST)
