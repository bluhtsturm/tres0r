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
