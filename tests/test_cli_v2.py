import importlib
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from tres0r import cli, keys
from tres0r.cli import main
from tres0r.errors import Cancelled
from tres0r.kdf import LEVELS

from conftest import FAST, PASSWORD

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def fast_levels(monkeypatch):
    for name in LEVELS:
        monkeypatch.setitem(LEVELS, name, FAST)


@pytest.fixture
def pwfile(tmp_path):
    f = tmp_path / "pw.txt"
    f.write_text(PASSWORD + "\n", encoding="utf-8")
    return str(f)


@pytest.fixture
def identity(tmp_path, capsys):
    path = tmp_path / "ich.key"
    assert main(["keygen", "-o", str(path), "--unprotected"]) == 0
    public = capsys.readouterr().out.strip()
    assert public.startswith("tres0r-pub-")
    return str(path), public


def run_json(capsys, argv):
    capsys.readouterr()  # Ausgaben vorheriger Befehle verwerfen
    code = main([*argv, "--json"])
    captured = capsys.readouterr()
    return code, json.loads(captured.out)


def _has_zstd():
    for module in ("compression.zstd", "zstandard"):
        try:
            importlib.import_module(module)
            return True
        except ImportError:
            pass
    return False


# --- Schlüssel --------------------------------------------------------------
def test_keygen_and_pubkey(identity, capsys):
    path, public = identity
    code, data = run_json(capsys, ["pubkey", path])
    assert code == 0 and data["public_keys"] == [public]
    assert main(["keygen", "-o", path, "--unprotected"]) == 1  # nie überschreiben
    assert "nicht überschrieben" in capsys.readouterr().err


def test_recipient_only_roundtrip(tmp_path, sample_tree, identity, capsys):
    key_path, public = identity
    out = tmp_path / "r.tres0r"
    assert main(["pack", str(sample_tree[1]), "-o", str(out), "-r", public, "--no-password"]) == 0
    code, data = run_json(capsys, ["info", str(out)])
    assert data["format_version"] == 2 and [s["type"] for s in data["slots"]] == ["empfaenger"]
    assert data["kdf"] is None
    code, data = run_json(capsys, ["unpack", str(out), "-o", str(tmp_path / "z"), "-i", key_path])
    assert code == 0 and data["names"] == ["einzeln.txt"]


def test_no_password_needs_other_key(tmp_path, sample_tree, capsys):
    assert main(["pack", str(sample_tree[1]), "-o", str(tmp_path / "x.tres0r"), "--no-password"]) == 1
    assert "mindestens einen Empfänger" in capsys.readouterr().err


def test_recovery_phrase_opens_container(tmp_path, sample_tree, pwfile, capsys):
    out = tmp_path / "rec.tres0r"
    code, data = run_json(capsys, ["pack", str(sample_tree[1]), "-o", str(out), "--password-file", pwfile,
                                   "--offline", "--recovery", "--wordlist", "en"])
    assert code == 0 and data["slots"][0].startswith("Passwort") and data["slots"][1] == "Wiederherstellung"
    phrase_file = tmp_path / "phrase"
    phrase_file.write_text(data["recovery"].replace("-", " ") + "\n")
    code, data = run_json(capsys, ["verify", str(out), "--password-file", str(phrase_file)])
    assert code == 0 and data["checked_hashes"]


def test_keys_management(tmp_path, sample_tree, pwfile, identity, capsys):
    key_path, public = identity
    out = tmp_path / "k.tres0r"
    main(["pack", str(sample_tree[1]), "-o", str(out), "--password-file", pwfile, "--offline"])
    second = tmp_path / "zweites"
    second.write_text("ein-zweites-langes-passwort\n")
    base = [str(out), "--password-file", pwfile]
    assert main(["keys", "add-password", *base, "--new-password-file", str(second), "--offline"]) == 0
    assert main(["keys", "add-recipient", *base, "-r", public]) == 0
    code, data = run_json(capsys, ["keys", "add-recovery", *base])
    assert code == 0 and data["added"] == [3] and len(data["recovery"].split("-")) == 20
    code, data = run_json(capsys, ["keys", "list", str(out)])
    assert data["command"] == "keys list"
    assert [s["type"] for s in data["slots"]] == ["passwort", "passwort", "empfaenger", "wiederherstellung"]

    code, data = run_json(capsys, ["keys", "remove", str(out), "0", "-i", key_path])
    assert code == 0 and data["removed"] == {"index": 0, "type": "passwort"}
    assert main(["verify", str(out), "--password-file", pwfile]) == 2
    assert main(["verify", str(out), "--password-file", str(second)]) == 0


def test_passwd_v2(tmp_path, sample_tree, pwfile, capsys):
    out = tmp_path / "p.tres0r"
    main(["pack", str(sample_tree[1]), "-o", str(out), "--password-file", pwfile, "--offline"])
    new = tmp_path / "neu"
    new.write_text("brandneues-langes-passwort\n")
    code, data = run_json(capsys, ["passwd", str(out), "--password-file", pwfile, "--new-password-file", str(new),
                                   "--offline", "-l", "stark"])
    assert code == 0 and data["level"] == "stark"
    assert main(["verify", str(out), "--password-file", str(new)]) == 0


@pytest.mark.skipif(not _has_zstd(), reason="kein zstd")
def test_pack_compressed_and_only(tmp_path, sample_tree, pwfile, capsys):
    out = tmp_path / "z.tres0r"
    assert main(["pack", *map(str, sample_tree), "-o", str(out), "-z", "--password-file", pwfile, "--offline"]) == 0
    code, data = run_json(capsys, ["info", str(out)])
    assert data["compression"] == "zstd" and data["has_index"]
    code, data = run_json(capsys, ["unpack", str(out), "-o", str(tmp_path / "t"), "--password-file", pwfile,
                                   "--only", "Projekt/Unterordner/tief"])
    assert code == 0 and (tmp_path / "t/Projekt/Unterordner/tief/x.dat").exists()
    assert not (tmp_path / "t/Projekt/notiz.txt").exists()


# --- Datenströme ------------------------------------------------------------
def test_encrypt_decrypt_files(tmp_path, identity, capsys):
    key_path, public = identity
    src = tmp_path / "daten.bin"
    src.write_bytes(os.urandom(250_000))
    sealed, back = tmp_path / "daten.tres0r", tmp_path / "zurueck.bin"
    assert main(["encrypt", str(src), "-o", str(sealed), "-r", public, "--no-password"]) == 0
    code, data = run_json(capsys, ["info", str(sealed)])
    assert data["payload_type"] == "roh" and not data["has_index"]
    assert main(["decrypt", str(sealed), "-o", str(back), "-i", key_path]) == 0
    assert back.read_bytes() == src.read_bytes()
    assert main(["decrypt", str(sealed), "-o", str(back), "-i", key_path]) == 1  # existiert schon
    assert main(["list", str(sealed), "-i", key_path]) == 1  # Rohdaten haben keine Liste


def test_json_and_stdout_exclude_each_other(tmp_path, capsys):
    code, data = run_json(capsys, ["encrypt", "-o", "-", "--no-password", "-r",
                                   keys.encode_recipient(keys.generate_identity().public_key())])
    assert code == 1 and "stdout" in data["error"]["message"]


def _run(args, stdin=None, cwd=None):
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    return subprocess.run([sys.executable, "-m", "tres0r", *args], input=stdin, capture_output=True,
                          cwd=cwd, env=env, timeout=120)


def test_real_pipes(tmp_path, identity):
    key_path, public = identity
    data = os.urandom(400_000)
    sealed = _run(["encrypt", "-o", "-", "-r", public, "--no-password", "-l", "schnell"], stdin=data)
    assert sealed.returncode == 0, sealed.stderr.decode()
    plain = _run(["decrypt", "-", "-i", key_path], stdin=sealed.stdout)
    assert plain.returncode == 0 and plain.stdout == data

    broken = _run(["decrypt", "-", "-i", key_path], stdin=sealed.stdout[:-500])
    assert broken.returncode == 3  # Abschneiden fällt auf – Exit-Code prüfen!


def test_decrypt_tar_container_to_tar(tmp_path, sample_tree, pwfile):
    out = tmp_path / "t.tres0r"
    main(["pack", *map(str, sample_tree), "-o", str(out), "--password-file", pwfile, "--offline"])
    tar_path = tmp_path / "archiv.tar"
    assert main(["decrypt", str(out), "-o", str(tar_path), "--password-file", pwfile]) == 0
    with tarfile.open(tar_path) as tar:
        assert "Projekt/notiz.txt" in tar.getnames()


# --- Bestätigung der Wiederherstellungsphrase -------------------------------
def test_confirm_recovery(monkeypatch, capsys):
    phrase = "-".join(f"wort{i}" for i in range(1, 21))
    monkeypatch.setattr(cli, "_ask", lambda prompt: "")

    class FixedRandom:
        def sample(self, population, k):
            return [2, 9, 16][:k]

    monkeypatch.setattr(cli._random, "SystemRandom", FixedRandom)
    answers = iter(["wort3", "falsch", "wort17", "wort3", "wort10", "WORT17"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    cli._confirm_recovery(phrase)
    err = capsys.readouterr().err
    assert "Bestätigt" in err and "noch 2 Versuch" in err and " 1 wort1" in err

    answers = iter(["x"] * 9)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    with pytest.raises(Cancelled):
        cli._confirm_recovery(phrase)
