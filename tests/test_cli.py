import re
from pathlib import Path

import pytest

from tres0r.cli import main
from tres0r.kdf import LEVELS

from conftest import FAST


@pytest.fixture(autouse=True)
def fast_levels(monkeypatch):
    # Stufe "schnell" für die Tests auf Minimalkosten setzen.
    monkeypatch.setitem(LEVELS, "schnell", FAST)


@pytest.fixture
def pwfile(tmp_path):
    f = tmp_path / "pw.txt"
    f.write_text("Ein-langes-Test-Passwort-42\n", encoding="utf-8")
    return str(f)


def test_pack_info_list_unpack(tmp_path, sample_tree, pwfile, capsys):
    out = tmp_path / "c.tres0r"
    args = ["pack", *map(str, sample_tree), "-o", str(out), "-l", "schnell", "--password-file", pwfile, "--offline"]
    assert main(args) == 0 and out.exists()

    assert main(args) == 1  # existiert schon
    assert "existiert bereits" in capsys.readouterr().err

    assert main(["info", str(out)]) == 0
    assert "schnell" in capsys.readouterr().out

    assert main(["list", str(out), "--password-file", pwfile]) == 0
    assert "Projekt/notiz.txt" in capsys.readouterr().out

    dest = tmp_path / "ziel"
    assert main(["unpack", str(out), "-o", str(dest), "--password-file", pwfile]) == 0
    assert (dest / "einzeln.txt").read_text(encoding="utf-8") == "einzelne Datei"


def test_version_matches_pyproject(capsys):
    """Beim Versionssprung müssen pyproject.toml und tres0r.__version__ zusammen geändert
    werden – der Release-Workflow prüft nur den Tag gegen pyproject.toml."""
    pyproject = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE).group(1)
    with pytest.raises(SystemExit) as stop:
        main(["--version"])
    assert stop.value.code == 0 and capsys.readouterr().out.strip() == f"tres0r {version}"


def test_wrong_password_exit_code(tmp_path, sample_tree, pwfile, capsys):
    out = tmp_path / "c.tres0r"
    main(["pack", str(sample_tree[1]), "-o", str(out), "-l", "schnell", "--password-file", pwfile, "--offline"])
    wrong = tmp_path / "falsch.txt"
    wrong.write_text("falsch\n")
    assert main(["unpack", str(out), "-o", str(tmp_path / "z"), "--password-file", str(wrong)]) == 2
    assert "Falsches Passwort" in capsys.readouterr().err


def test_pack_with_generated_passphrase(tmp_path, sample_tree, capsys):
    out = tmp_path / "gen.tres0r"
    assert main(["pack", str(sample_tree[1]), "-o", str(out), "-l", "schnell", "-g", "passphrase", "-w", "10", "-y"]) == 0
    err = capsys.readouterr().err
    lines = [l.strip() for l in err.splitlines()]
    passphrase = lines[lines.index("Generierte Passphrase:") + 1]
    assert len(passphrase.split("-")) == 10

    pw = tmp_path / "gen-pw.txt"
    pw.write_text(passphrase + "\n", encoding="utf-8")
    assert main(["unpack", str(out), "-o", str(tmp_path / "z"), "--password-file", str(pw)]) == 0


def test_passwd(tmp_path, sample_tree, pwfile):
    out = tmp_path / "c.tres0r"
    main(["pack", str(sample_tree[1]), "-o", str(out), "-l", "schnell", "--password-file", pwfile, "--offline"])
    new = tmp_path / "neu.txt"
    new.write_text("Noch-ein-langes-Passwort-7\n")
    assert main(["passwd", str(out), "--password-file", pwfile, "--new-password-file", str(new), "--offline"]) == 0
    assert main(["list", str(out), "--password-file", pwfile]) == 2
    assert main(["list", str(out), "--password-file", str(new)]) == 0


def test_genpass(capsys):
    assert main(["genpass", "-c", "3"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 3 and all(len(l.split("-")) == 8 for l in lines)

    assert main(["genpass", "passwort", "-n", "32", "--no-symbols"]) == 0
    pw = capsys.readouterr().out.strip()
    assert len(pw) == 32 and pw.isalnum()

    assert main(["genpass", "-w", "3"]) == 1  # unter Minimum
    with pytest.raises(SystemExit):  # Fund: -c 0 endete mit IndexError-Traceback
        main(["genpass", "-c", "0"])

    assert main(["genpass", "--wordlist", "en", "--digit"]) == 0
    parts = capsys.readouterr().out.strip().split("-")
    assert len(parts) == 9 and parts[-1].isdigit()


def test_checkpass(tmp_path, capsys):
    weak = tmp_path / "w.txt"
    weak.write_text("hallo\n")
    assert main(["checkpass", "--password-file", str(weak), "--offline"]) == 1
    assert "kürzer als 12" in capsys.readouterr().out

    good = tmp_path / "g.txt"
    good.write_text("Zug-Tanne-Kaffee-Laterne-7\n")
    assert main(["checkpass", "--password-file", str(good), "--offline"]) == 0


def test_not_a_container(tmp_path, capsys):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"irgendwas")
    assert main(["info", str(junk)]) == 3
    assert "Keine tres0r-Datei" in capsys.readouterr().err


# --- Hilfe und Erfolgsmeldungen (Wünsche nach dem Test unter macOS: „für doofe“, eindeutiger Erfolg) --
def test_help_for_beginners(capsys):
    """Nur "tres0r" endete mit "error: the following arguments are required: BEFEHL" (englisch, Exit 2
    – der heißt bei tres0r „falsches Passwort“); "tres0r help" gab es nicht; die Hilfe war halb
    englisch ("usage:", "show this help message and exit")."""
    assert main([]) == 1
    out = capsys.readouterr().out
    assert out.startswith("Aufruf: tres0r") and "pack" in out and "tres0r help BEFEHL" in out
    for argv, expected in ((["help"], "Aufruf: tres0r [-h]"), (["help", "pack"], "Aufruf: tres0r pack"),
                           (["pack", "-h"], "Aufruf: tres0r pack")):
        with pytest.raises(SystemExit) as stop:
            main(argv)
        out = capsys.readouterr().out
        assert stop.value.code == 0 and out.startswith(expected), argv
        assert not re.search(r"usage:|positional arguments|show this help|^options:", out, re.M), argv
    with pytest.raises(SystemExit) as stop:
        main(["pack"])
    err = capsys.readouterr().err
    assert stop.value.code == 1 and "Fehler: Es fehlt: PFAD" in err and "Hilfe: tres0r pack -h" in err
    with pytest.raises(SystemExit) as stop:
        main(["help", "gibtsnicht"])
    assert stop.value.code == 1 and "Fehler:" in capsys.readouterr().err


def test_pack_and_unpack_say_they_succeeded(tmp_path, sample_tree, pwfile, capsys):
    """Erfolg eindeutig wie in TUI und GUI – ohne ✓: Windows-Konsolen schreiben umgeleitet cp1252."""
    out = tmp_path / "c.tres0r"
    assert main(["pack", *map(str, sample_tree), "-o", str(out), "-l", "schnell", "--password-file", pwfile,
                 "--offline"]) == 0
    printed = capsys.readouterr()
    assert printed.out.startswith(f"Erfolgreich gepackt: {out}  (") and "✓" not in printed.out + printed.err
    dest = tmp_path / "ziel"
    assert main(["unpack", str(out), "-o", str(dest), "--password-file", pwfile]) == 0
    printed = capsys.readouterr()
    assert "Erfolgreich entpackt: " in printed.err and f"nach {dest}" in printed.err
    assert "Erfolgreich" not in printed.out  # stdout bleibt die Liste der Namen

