import json
import os

import pytest

from tres0r import container, keys, shamir
from tres0r import header2 as h2
from tres0r.cli import main
from tres0r.errors import Tres0rError, WrongPassword
from tres0r.kdf import LEVELS
from tres0r.keys import Credentials

from conftest import FAST, PASSWORD, snapshot


@pytest.fixture(autouse=True)
def fast_levels(monkeypatch):
    for name in LEVELS:
        monkeypatch.setitem(LEVELS, name, FAST)


@pytest.fixture
def keyfile(tmp_path):
    path = tmp_path / "zweiter.key"
    keys.generate_keyfile(path)
    return path


def pack(sources, out, **kw):
    return container.create(sources, out, PASSWORD, FAST, **kw)


# --- Keyfile ---------------------------------------------------------------------
def test_generate_keyfile(tmp_path, keyfile):
    assert keyfile.stat().st_size == keys.KEYFILE_BYTES
    if os.name == "posix":
        assert (keyfile.stat().st_mode & 0o777) == 0o600
    with pytest.raises(Tres0rError, match="nicht überschrieben"):
        keys.generate_keyfile(keyfile)
    other = tmp_path / "foto.jpg"  # beliebige Dateien gehen auch
    other.write_bytes(os.urandom(300_000))
    assert keys.keyfile_secret(other) != keys.keyfile_secret(keyfile)


def test_password_and_keyfile_both_required(tmp_path, sample_tree, keyfile, monkeypatch):
    k = keys.keyfile_secret(keyfile)
    out = pack(sample_tree, tmp_path / "k.tres0r", keyfile=k).path
    assert [s.type for s in container.inspect(out).slots] == ["passwort+keyfile"]
    assert "Passwort + Keyfile" in container.inspect(out).slots[0].description
    assert container.verify(out, Credentials(passwords=[PASSWORD], keyfiles=[k])).files == 6
    with pytest.raises(WrongPassword, match="Keyfile"):
        container.verify(out, PASSWORD)  # Passwort allein reicht nicht
    wrong = tmp_path / "falsch.key"
    keys.generate_keyfile(wrong)
    # Falsches Keyfile fällt über die Kennung auf – Argon2 läuft gar nicht erst
    monkeypatch.setattr(h2, "derive_key", lambda *a: pytest.fail("Argon2 trotz falschem Keyfile"))
    with pytest.raises(WrongPassword, match="Keyfile"):
        container.verify(out, Credentials(passwords=[PASSWORD], keyfiles=[keys.keyfile_secret(wrong)]))


def test_wrong_password_with_right_keyfile(tmp_path, sample_tree, keyfile):
    k = keys.keyfile_secret(keyfile)
    out = pack(sample_tree, tmp_path / "k.tres0r", keyfile=k).path
    with pytest.raises(WrongPassword):
        container.verify(out, Credentials(passwords=["falsch"], keyfiles=[k]))


def test_keyfile_needs_password(tmp_path, sample_tree, keyfile):
    ident = keys.generate_identity()
    with pytest.raises(Tres0rError, match="zweite Faktor"):
        container.create(sample_tree, tmp_path / "x.tres0r", None, FAST, recipients=[ident.public_key()],
                         keyfile=keys.keyfile_secret(keyfile))


def test_change_password_keeps_keyfile(tmp_path, sample_tree, keyfile):
    k = keys.keyfile_secret(keyfile)
    out = pack(sample_tree, tmp_path / "k.tres0r", keyfile=k).path
    container.change_password(out, Credentials(passwords=[PASSWORD], keyfiles=[k]), "neues-passwort")
    assert container.inspect(out).slots[0].type == "passwort+keyfile"
    container.verify(out, Credentials(passwords=["neues-passwort"], keyfiles=[k]))
    with pytest.raises(WrongPassword):
        container.verify(out, "neues-passwort")


def test_add_password_with_keyfile(tmp_path, sample_tree, keyfile):
    out = pack(sample_tree, tmp_path / "k.tres0r").path
    k = keys.keyfile_secret(keyfile)
    container.add_keys(out, PASSWORD, password="zweites", params=FAST, keyfile=k)
    assert [s.type for s in container.inspect(out).slots] == ["passwort", "passwort+keyfile"]
    container.verify(out, Credentials(passwords=["zweites"], keyfiles=[k]))
    with pytest.raises(WrongPassword):
        container.verify(out, "zweites")


# --- Shamir ------------------------------------------------------------------------
def test_share_text_tolerance_and_typos():
    share = shamir.split(os.urandom(32), 2, 3)[0]
    text = share.text()
    spaced = text[:12] + " ".join(text[12:][i:i + 4] for i in range(0, len(text) - 12, 4))
    assert shamir.parse_share(spaced) == share
    assert shamir.parse_share(text.upper()) == share
    for bad in (text[:-1] + ("a" if text[-1] != "a" else "b"), text[:40], "tres0r-pub-" + text[12:]):
        with pytest.raises(keys.KeyFormatError):
            shamir.parse_share(bad)
    with pytest.raises(ValueError):
        shamir.split(os.urandom(32), 1, 3)
    with pytest.raises(ValueError):
        shamir.split(os.urandom(32), 3, 2)


def test_conflicting_or_mixed_shares():
    a = shamir.split(os.urandom(32), 2, 3)
    b = shamir.split(os.urandom(32), 2, 3)
    with pytest.raises(Tres0rError, match="verschiedenen Sätzen"):
        shamir.combine([a[0], b[1]])
    forged = shamir.Share(a[0].set_id, 2, 3, 1, os.urandom(32))
    with pytest.raises(Tres0rError, match="zwei verschiedenen Fassungen"):
        shamir.combine([a[0], forged, a[1]])
    assert shamir.combine([a[2], a[2], a[0]]) == shamir.combine(a[:2])  # Duplikate stören nicht


def test_threshold_container(tmp_path, sample_tree):
    result = pack(sample_tree, tmp_path / "s.tres0r", threshold=(2, 3))
    out, shares = result.path, result.shares
    assert len(shares) == 3 and [s.type for s in container.inspect(out).slots] == ["passwort", "schwellwert"]
    no_prompt = lambda: pytest.fail("Passwortabfrage trotz Anteilen")  # noqa: E731
    for pair in ([shares[0], shares[2]], [shares[1], shares[0]]):
        creds = Credentials(shares=[shamir.parse_share(s.text()) for s in pair], prompt=no_prompt)
        assert container.verify(out, creds).files == 6
    with pytest.raises(WrongPassword, match="1 von 2"):
        container.verify(out, Credentials(shares=[shares[0]]))
    stranger = shamir.split(os.urandom(32), 2, 3)
    foreign = [shamir.Share(shares[0].set_id, 2, 3, s.x, s.y) for s in stranger[:2]]  # gleiche ID, falsche Werte
    with pytest.raises(WrongPassword, match="passen nicht"):
        container.verify(out, Credentials(shares=foreign))


def test_threshold_only_and_add_remove(tmp_path, sample_tree):
    result = container.create(sample_tree, tmp_path / "t.tres0r", None, FAST, threshold=(3, 5))
    creds = Credentials(shares=result.shares[1:4])
    container.extract(result.path, tmp_path / "z", creds)
    assert snapshot(tmp_path / "z" / "Projekt") == snapshot(sample_tree[0])
    index, more = container.add_threshold(result.path, creds, 2, 2)
    assert index == 1 and container.verify(result.path, Credentials(shares=more)).files == 6
    container.remove_key(result.path, Credentials(shares=more), 0)
    with pytest.raises(WrongPassword):
        container.verify(result.path, creds)


def test_threshold_raw_stream(tmp_path):
    import io

    sealed = io.BytesIO()
    result = container.encrypt_stream(io.BytesIO(b"geheim" * 1000), sealed, None, threshold=(2, 2))
    out = io.BytesIO()
    container.decrypt_stream(io.BytesIO(sealed.getvalue()), out, Credentials(shares=result.shares))
    assert out.getvalue() == b"geheim" * 1000


# --- CLI ----------------------------------------------------------------------------
def run_json(capsys, argv):
    capsys.readouterr()
    code = main([*argv, "--json"])
    return code, json.loads(capsys.readouterr().out)


def test_cli_keyfile_workflow(tmp_path, sample_tree, capsys):
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    kf = tmp_path / "zweiter.key"
    assert main(["keyfile", "-o", str(kf)]) == 0
    out = tmp_path / "k.tres0r"
    assert main(["pack", str(sample_tree[1]), "-o", str(out), "--password-file", str(pw), "--offline",
                 "--keyfile", str(kf)]) == 0
    code, data = run_json(capsys, ["verify", str(out), "--password-file", str(pw)])
    assert code == 2 and "Keyfile" in data["error"]["message"]
    code, data = run_json(capsys, ["verify", str(out), "--password-file", str(pw), "--keyfile", str(kf)])
    assert code == 0


def test_cli_pack_verify_with_second_factor_and_shares(tmp_path, sample_tree, capsys):
    """Fund: 'pack --keyfile … --verify' schrieb den Container, meldete dann aber
    "Fehler" mit Exit-Code 2 – die Prüfung bekam das Keyfile nicht. Mit
    --no-password --shares wurde die Prüfung übersprungen, obwohl Anteile vorlagen."""
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    kf = tmp_path / "zweiter.key"
    keys.generate_keyfile(kf)
    code, data = run_json(capsys, ["pack", str(sample_tree[1]), "-o", str(tmp_path / "k.tres0r"),
                                   "--password-file", str(pw), "--offline", "--keyfile", str(kf), "--verify"])
    assert code == 0 and data["verified"] is True
    code, data = run_json(capsys, ["pack", str(sample_tree[1]), "-o", str(tmp_path / "s.tres0r"),
                                   "--no-password", "--shares", "2/3", "--verify"])
    assert code == 0 and data["verified"] is True and not data.get("warnings")


def test_cli_shares_workflow(tmp_path, sample_tree, capsys):
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    out = tmp_path / "s.tres0r"
    folder = tmp_path / "anteile"
    assert main(["pack", str(sample_tree[1]), "-o", str(out), "--password-file", str(pw), "--offline",
                 "--shares", "2/3", "--shares-dir", str(folder)]) == 0
    files = sorted(folder.iterdir())
    assert [f.name for f in files] == ["anteil-1-von-3.txt", "anteil-2-von-3.txt", "anteil-3-von-3.txt"]
    if os.name == "posix":
        assert all((f.stat().st_mode & 0o777) == 0o600 for f in files)
    code, data = run_json(capsys, ["unpack", str(out), "-o", str(tmp_path / "z"),
                                   "--shares-file", str(files[0]), "--shares-file", str(files[2])])
    assert code == 0 and data["names"] == ["einzeln.txt"]
    code, data = run_json(capsys, ["verify", str(out), "--shares-file", str(files[1]), "--password-file", str(pw)])
    assert code == 0  # ein Anteil reicht nicht – das Passwort springt ein
    code, data = run_json(capsys, ["keys", "add-shares", str(out), "2/2", "--password-file", str(pw)])
    assert code == 0 and len(data["shares"]) == 2
    texts = [s["text"] for s in data["shares"]]
    code, data = run_json(capsys, ["verify", str(out), "--share", texts[0], "--share", texts[1]])
    assert code == 0
    assert main(["pack", str(sample_tree[1]), "-o", str(tmp_path / "x"), "--shares", "1/3",
                 "--password-file", str(pw), "--offline"]) == 1
