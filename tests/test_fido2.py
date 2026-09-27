import json

import pytest

pytest.importorskip("fido2")

from soft_token import SoftToken  # noqa: E402

from tres0r import container, hwtoken  # noqa: E402
from tres0r import header2 as h2  # noqa: E402
from tres0r.cli import main  # noqa: E402
from tres0r.errors import FormatError, Tres0rError, WrongPassword  # noqa: E402
from tres0r.kdf import LEVELS  # noqa: E402
from tres0r.keys import Credentials  # noqa: E402

from conftest import FAST, PASSWORD  # noqa: E402


@pytest.fixture(autouse=True)
def fast_levels(monkeypatch):
    for name in LEVELS:
        monkeypatch.setitem(LEVELS, name, FAST)


def with_token(*tokens, password=PASSWORD):
    return Credentials(passwords=[password], fido2=hwtoken.TokenProvider(list(tokens)))


def pack(tmp_path, sample_tree, token, **kw):
    return container.create(sample_tree, tmp_path / "f.tres0r", PASSWORD, FAST,
                            fido2=hwtoken.TokenProvider([token]), **kw).path


def test_slot_format_and_validation():
    dek = bytes(32)
    slot = h2.password_fido2_slot(dek, "pw", FAST, "tres0r.local", b"\x01" * 70, b"\x02" * 32, b"\x03" * 32)
    assert slot.fido2 == ("tres0r.local", b"\x01" * 70, b"\x02" * 32)
    assert "FIDO2" in slot.describe()
    slot.validate()
    head = slot.body[:26 + 32]
    for body in (head + bytes([0]) + b"\x00\x01x" + bytes(48),              # leere RP-ID
                 head + bytes([1]) + b"r" + b"\x00\x00" + bytes(48),         # leere Credential-ID
                 head + bytes([1]) + b"r" + b"\x00\x05ab" + bytes(48),       # Länge passt nicht
                 head[:20]):
        with pytest.raises(FormatError):
            h2.Slot(h2.SLOT_FIDO2, body).validate()


def test_token_and_password_both_required(tmp_path, sample_tree):
    token = SoftToken()
    out = pack(tmp_path, sample_tree, token)
    assert token.touches == 2  # Registrierung + erstes Geheimnis
    assert [s.type for s in container.inspect(out).slots] == ["passwort+fido2"]
    assert container.verify(out, with_token(token)).files == 6
    assert token.touches == 3
    with pytest.raises(WrongPassword, match="--fido2"):
        container.verify(out, PASSWORD)
    with pytest.raises(WrongPassword):
        container.verify(out, with_token(token, password="falsch"))


def test_foreign_or_refused_token(tmp_path, sample_tree):
    token = SoftToken()
    out = pack(tmp_path, sample_tree, token)
    stranger = SoftToken()
    with pytest.raises(WrongPassword, match="passt nicht"):
        container.verify(out, with_token(stranger))
    assert stranger.touches == 0  # fremde Tokens werden ohne Berührung übersprungen
    token.deny_touch = True
    with pytest.raises(WrongPassword, match="Berührung"):
        container.verify(out, with_token(token))
    with pytest.raises(WrongPassword, match="Kein FIDO2-Token"):
        container.verify(out, with_token())


def test_several_plugged_tokens(tmp_path, sample_tree):
    token = SoftToken()
    out = pack(tmp_path, sample_tree, token)
    assert container.verify(out, with_token(SoftToken(), SoftToken(), token)).files == 6


def test_passwd_keeps_token_without_extra_touch(tmp_path, sample_tree):
    token = SoftToken()
    out = pack(tmp_path, sample_tree, token)
    before = token.touches
    container.change_password(out, with_token(token), "neues-passwort")
    assert token.touches == before + 1  # nur das Entsperren
    assert container.inspect(out).slots[0].type == "passwort+fido2"
    container.verify(out, with_token(token, password="neues-passwort"))


def test_backup_token_and_mixed_slots(tmp_path, sample_tree):
    main_token, backup = SoftToken(), SoftToken()
    out = pack(tmp_path, sample_tree, main_token)
    container.add_keys(out, with_token(main_token), password="ersatz", params=FAST,
                       fido2=hwtoken.TokenProvider([backup]))
    assert container.verify(out, with_token(backup, password="ersatz")).files == 6
    container.add_keys(out, with_token(main_token), password="nur-passwort", params=FAST)
    touches = main_token.touches
    container.verify(out, "nur-passwort")
    assert main_token.touches == touches  # reiner Passwort-Slot: keine Berührung


def test_conflicts(tmp_path, sample_tree):
    from tres0r import keys

    provider = hwtoken.TokenProvider([SoftToken()])
    with pytest.raises(Tres0rError, match="zweite Faktor"):
        container.create(sample_tree, tmp_path / "x", None, FAST, fido2=provider,
                         recipients=[keys.generate_identity().public_key()])
    with pytest.raises(Tres0rError, match="entweder"):
        container.create(sample_tree, tmp_path / "y", PASSWORD, FAST, fido2=provider, keyfile=bytes(32))


def test_cli_fido2(tmp_path, sample_tree, capsys, monkeypatch):
    token = SoftToken()
    monkeypatch.setattr(hwtoken, "devices", lambda: [token])
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    out = tmp_path / "c.tres0r"
    assert main(["pack", str(sample_tree[1]), "-o", str(out), "--password-file", str(pw), "--offline", "--fido2"]) == 0
    assert "berühren" in capsys.readouterr().err
    assert main(["verify", str(out), "--password-file", str(pw), "--fido2", "--json"]) == 0
    capsys.readouterr()
    assert main(["verify", str(out), "--password-file", str(pw), "--json"]) == 2
    assert "--fido2" in json.loads(capsys.readouterr().out)["error"]["message"]
    assert main(["fido2", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["tokens"]) == 1
    monkeypatch.setattr(hwtoken, "devices", lambda: [])
    assert main(["verify", str(out), "--password-file", str(pw), "--fido2"]) == 2


# --- Token mit PIN ------------------------------------------------------------------
def test_pin_asked_once_at_enrollment_not_at_unlock(tmp_path, sample_tree):
    token = SoftToken(pin="4711")
    asked = []
    provider = hwtoken.TokenProvider([token], pin=lambda: asked.append(1) or "4711")
    out = container.create(sample_tree, tmp_path / "p.tres0r", PASSWORD, FAST, fido2=provider).path
    assert len(asked) == 1
    unlock = Credentials(passwords=[PASSWORD], fido2=hwtoken.TokenProvider([token], pin=lambda: asked.append(1)))
    assert container.verify(out, unlock).files == 6
    assert len(asked) == 1  # Entsperren nur mit Berührung


def test_wrong_or_missing_pin(tmp_path, sample_tree):
    token = SoftToken(pin="4711")
    with pytest.raises(WrongPassword, match="Falsche PIN"):
        container.create(sample_tree, tmp_path / "a", PASSWORD, FAST,
                         fido2=hwtoken.TokenProvider([token], pin=lambda: "0000"))
    assert token.pin_retries == 7 and not (tmp_path / "a").exists()
    with pytest.raises(Tres0rError, match="verlangt seine PIN"):
        container.create(sample_tree, tmp_path / "b", PASSWORD, FAST, fido2=hwtoken.TokenProvider([token]))
    token.pin_retries = 0
    with pytest.raises(WrongPassword, match="gesperrt"):
        container.create(sample_tree, tmp_path / "c", PASSWORD, FAST,
                         fido2=hwtoken.TokenProvider([token], pin=lambda: "4711"))


def test_token_that_allows_enrollment_without_pin(tmp_path, sample_tree):
    token = SoftToken(pin="4711", make_cred_uv_not_required=True)
    provider = hwtoken.TokenProvider([token], pin=lambda: pytest.fail("PIN nicht nötig"))
    container.create(sample_tree, tmp_path / "n.tres0r", PASSWORD, FAST, fido2=provider)
    assert token.pin_prompts_seen == 0


def test_cli_asks_token_pin(tmp_path, sample_tree, monkeypatch, capsys):
    token = SoftToken(pin="4711")
    monkeypatch.setattr(hwtoken, "devices", lambda: [token])
    prompts = []
    monkeypatch.setattr("getpass.getpass", lambda prompt="": prompts.append(prompt) or "4711")
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    out = tmp_path / "c.tres0r"
    assert main(["pack", str(sample_tree[1]), "-o", str(out), "--password-file", str(pw), "--offline", "--fido2"]) == 0
    assert any("PIN des FIDO2-Tokens" in p for p in prompts)
    assert main(["verify", str(out), "--password-file", str(pw), "--fido2"]) == 0
