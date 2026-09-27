import json

import pytest

from tres0r import cli, container
from tres0r.cli import main
from tres0r.errors import Cancelled
from tres0r.kdf import LEVELS
from tres0r.passgen import Secret

from conftest import FAST, PASSWORD, make_tar, write_raw_container


@pytest.fixture(autouse=True)
def fast_levels(monkeypatch):
    monkeypatch.setitem(LEVELS, "schnell", FAST)


@pytest.fixture
def pwfile(tmp_path):
    f = tmp_path / "pw.txt"
    f.write_text(PASSWORD + "\n", encoding="utf-8")
    return str(f)


@pytest.fixture
def packed(tmp_path, sample_tree, pwfile):
    out = tmp_path / "c.tres0r"
    assert main(["pack", *map(str, sample_tree), "-o", str(out), "-l", "schnell",
                 "--password-file", pwfile, "--offline"]) == 0
    return out


def run_json(capsys, argv):
    code = main([*argv, "--json"])
    captured = capsys.readouterr()
    return code, json.loads(captured.out), captured.err


# --- JSON -------------------------------------------------------------------
def test_json_info_list_verify(packed, pwfile, capsys):
    capsys.readouterr()
    code, data, err = run_json(capsys, ["info", str(packed)])
    assert code == 0 and data["ok"] and data["command"] == "info" and err == ""
    assert data["level"] == "schnell" and data["kdf"]["memory_kib"] == FAST.memory_kib

    code, data, _ = run_json(capsys, ["list", str(packed), "--password-file", pwfile])
    entry = next(e for e in data["entries"] if e["name"] == "einzeln.txt")
    assert (entry["size"], entry["kind"], len(entry["sha256"])) == (14, "datei", 64)

    code, data, _ = run_json(capsys, ["verify", str(packed), "--password-file", pwfile])
    assert code == 0 and data["files"] == 6


def test_json_errors_and_exit_codes(packed, tmp_path, capsys):
    wrong = tmp_path / "falsch"
    wrong.write_text("falsch\n")
    code, data, _ = run_json(capsys, ["verify", str(packed), "--password-file", str(wrong)])
    assert code == 2 and not data["ok"] and data["error"]["type"] == "WrongPassword"

    raw = bytearray(packed.read_bytes())
    raw[container.inspect(packed).header_len + 20] ^= 0x01
    packed.write_bytes(bytes(raw))
    pw = tmp_path / "pw2"
    pw.write_text(PASSWORD + "\n")
    code, data, _ = run_json(capsys, ["verify", str(packed), "--password-file", str(pw)])
    assert code == 3 and data["error"]["type"] == "IntegrityError"


def test_json_pack_with_generated_passphrase(tmp_path, sample_tree, capsys):
    out = tmp_path / "g.tres0r"
    code, data, err = run_json(capsys, ["pack", str(sample_tree[1]), "-o", str(out), "-l", "schnell",
                                        "-g", "passphrase"])
    assert code == 0 and err == ""
    secret = data["generated"]["value"]
    assert len(secret.split("-")) == 8 and data["padding"] >= 0 and data["size"] == out.stat().st_size

    pw = tmp_path / "gen"
    pw.write_text(secret + "\n")
    code, data, _ = run_json(capsys, ["unpack", str(out), "-o", str(tmp_path / "z"), "--password-file", str(pw)])
    assert code == 0 and data["names"] == ["einzeln.txt"] and data["renamed"] == []


def test_json_genpass_checkpass(tmp_path, capsys):
    code, data, _ = run_json(capsys, ["genpass", "-c", "3", "--wordlist", "en"])
    assert code == 0 and len(data["secrets"]) == 3 and data["entropy_bits"] > 100
    weak = tmp_path / "w"
    weak.write_text("hallo\n")
    code, data, _ = run_json(capsys, ["checkpass", "--password-file", str(weak), "--offline"])
    assert code == 1 and data["ok"] and not data["passed"] and len(data["problems"]) == 2


# --- pack-Optionen ----------------------------------------------------------
def test_pack_exclude_and_verify(tmp_path, sample_tree, pwfile, capsys):
    out = tmp_path / "x.tres0r"
    assert main(["pack", str(sample_tree[0]), "-o", str(out), "-l", "schnell", "--password-file", pwfile,
                 "--offline", "-x", "*.bin", "-x", "leer/", "--verify"]) == 0
    captured = capsys.readouterr()
    assert "2 ausgeschlossen" in captured.err and "Prüfung erfolgreich" in captured.out
    code, data, _ = run_json(capsys, ["list", str(out), "--password-file", pwfile])
    names = {e["name"] for e in data["entries"]}
    assert "Projekt/Unterordner/gross.bin" not in names and "Projekt/leer" not in names
    assert "Projekt/notiz.txt" in names


def test_pack_no_pad_is_smaller(tmp_path, sample_tree, pwfile, capsys):
    base = ["-l", "schnell", "--password-file", pwfile, "--offline"]
    main(["pack", str(sample_tree[0]), "-o", str(tmp_path / "a.tres0r"), *base])
    main(["pack", str(sample_tree[0]), "-o", str(tmp_path / "b.tres0r"), "--no-pad", *base])
    assert (tmp_path / "b.tres0r").stat().st_size < (tmp_path / "a.tres0r").stat().st_size


def test_pack_name_warnings_and_strict(tmp_path, pwfile, capsys):
    src = tmp_path / "quelle"
    src.mkdir()
    (src / "aux.txt").write_text("x")
    (src / "was?.txt").write_text("y")
    base = ["pack", str(src), "-l", "schnell", "--password-file", pwfile, "--offline"]
    assert main([*base, "-o", str(tmp_path / "s.tres0r"), "--strict-names"]) == 1
    assert not (tmp_path / "s.tres0r").exists()
    capsys.readouterr()

    code, data, _ = run_json(capsys, [*base, "-o", str(tmp_path / "w.tres0r")])
    assert code == 0 and {i["path"] for i in data["name_issues"]} == {"quelle/aux.txt", "quelle/was?.txt"}


def test_unpack_rename(tmp_path, capsys):
    bad = tmp_path / "dup.tres0r"
    import tarfile

    ti1, ti2 = tarfile.TarInfo("a.txt"), tarfile.TarInfo("a.txt")
    ti1.size = ti2.size = 1
    write_raw_container(bad, make_tar([(ti1, b"1"), (ti2, b"2")]))
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    args = ["unpack", str(bad), "--password-file", str(pw)]
    assert main([*args, "-o", str(tmp_path / "eins")]) == 1
    assert "--rename" in capsys.readouterr().err
    code, data, _ = run_json(capsys, [*args, "-o", str(tmp_path / "zwei"), "--rename"])
    assert code == 0 and data["renamed"] == [{"from": "a.txt", "to": "a (1).txt"}]


# --- Abtipp-Bestätigung -----------------------------------------------------
@pytest.fixture
def secret():
    return Secret("wald-see-berg-tal-fluss-dorf-feld-hain", "passphrase", 103.4)


def _script(monkeypatch, typed):
    typed = iter(typed)
    shown = []
    monkeypatch.setattr(cli, "_ask", lambda prompt: shown.append(prompt) or "")
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(typed))
    return shown


def test_confirm_by_typing_accepts(monkeypatch, secret, capsys):
    shown = _script(monkeypatch, ["falsch", "", secret.value])
    cli._confirm_by_typing(secret)
    assert len(shown) == 2  # leere Eingabe hat das Geheimnis erneut angezeigt
    err = capsys.readouterr().err
    assert err.count(secret.value) == 2 and "Bestätigt" in err


def test_confirm_by_typing_gives_up(monkeypatch, secret):
    _script(monkeypatch, ["a", "b", "c"])
    with pytest.raises(Cancelled, match="nichts wurde verschlüsselt"):
        cli._confirm_by_typing(secret)
