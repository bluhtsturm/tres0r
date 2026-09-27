import io
import os
import secrets

import pytest

from tres0r import header2 as h2
from tres0r import kdf, keys
from tres0r.errors import FormatError, IntegrityError, Tres0rError, WrongPassword
from tres0r.kdf import KdfParams
from tres0r.keys import Credentials

from conftest import FAST, PASSWORD


# --- Schlüsselformate -------------------------------------------------------
def test_recipient_and_identity_roundtrip():
    ident = keys.generate_identity()
    pub_text = keys.encode_recipient(ident.public_key())
    sec_text = keys.encode_identity(ident)
    assert pub_text.startswith("tres0r-pub-") and sec_text.startswith("TRES0R-SECRET-")
    assert keys.parse_recipient(pub_text).public_bytes_raw() == ident.public_key().public_bytes_raw()
    assert keys.parse_recipient(pub_text.upper()).public_bytes_raw() == ident.public_key().public_bytes_raw()
    assert keys.parse_identity(sec_text).private_bytes_raw() == ident.private_bytes_raw()


@pytest.mark.parametrize("mangle", [
    lambda t: t[:-1] + ("a" if t[-1] != "a" else "b"),  # Tippfehler -> Prüfsumme
    lambda t: t[:-4],  # zu kurz
    lambda t: t.replace("tres0r-pub-", "age1"),  # falsches Präfix
    lambda t: t[:20] + "!" + t[21:],  # ungültiges Zeichen
])
def test_recipient_typos_are_detected(mangle):
    text = keys.encode_recipient(keys.generate_identity().public_key())
    with pytest.raises(keys.KeyFormatError):
        keys.parse_recipient(mangle(text))


def test_secret_key_is_not_a_recipient():
    ident = keys.generate_identity()
    with pytest.raises(keys.KeyFormatError):
        keys.parse_recipient(keys.encode_identity(ident))


def test_identity_file(tmp_path):
    ident = keys.generate_identity()
    path = tmp_path / "ich.key"
    keys.write_identity_file(path, ident)
    if os.name == "posix":
        assert (path.stat().st_mode & 0o777) == 0o600
    text = path.read_text(encoding="utf-8")
    assert keys.encode_recipient(ident.public_key()) in text  # als Kommentar
    [loaded] = keys.load_identities(path)
    assert loaded.private_bytes_raw() == ident.private_bytes_raw()
    with pytest.raises(Tres0rError, match="nicht überschrieben"):
        keys.write_identity_file(path, keys.generate_identity())
    # Empfängerliste darf auch eine Identitätsdatei sein
    [pub] = keys.load_recipients(path)
    assert pub.public_bytes_raw() == ident.public_key().public_bytes_raw()


def test_recipients_file(tmp_path):
    a, b = keys.generate_identity(), keys.generate_identity()
    f = tmp_path / "empfaenger.txt"
    f.write_text(f"# Team\n{keys.encode_recipient(a.public_key())}\n\n{keys.encode_recipient(b.public_key())}\n")
    assert len(keys.load_recipients(f)) == 2
    f.write_text("# leer\n")
    with pytest.raises(keys.KeyFormatError):
        keys.load_recipients(f)


def test_recovery_phrase_and_canonical_form():
    phrase = keys.generate_recovery("de")
    assert len(phrase.value.split("-")) == keys.RECOVERY_WORDS and phrase.entropy_bits > 250
    canon = keys.canonical_secret(phrase.value)
    assert keys.canonical_secret(phrase.value.replace("-", "  ").upper()) == canon
    assert keys.canonical_secret(" " + phrase.value.replace("-", " - ") + "\n") == canon


def test_english_recovery_phrase_has_exactly_20_words(monkeypatch):
    """CI-Fund: "t-shirt" aus der EFF-Liste machte 21 "Wörter" (Anzeige, Wortabfrage)."""
    from tres0r import pwgen
    # Zufall so lenken, dass ein Wort mit Bindestrich gewählt würde, wenn es in der Auswahl wäre
    monkeypatch.setattr(pwgen.secrets, "choice", lambda seq: next((w for w in seq if "-" in w), seq[0]))
    phrase = keys.generate_recovery("en")
    assert len(phrase.value.split("-")) == keys.RECOVERY_WORDS


def test_credentials_prompt_is_lazy():
    calls = []
    creds = Credentials(prompt=lambda: calls.append(1) or "x")
    assert calls == []
    assert creds.password_candidates() == ["x"] and creds.password_candidates() == ["x"]
    assert calls == [1]
    assert Credentials.coerce("pw").passwords == ["pw"]
    assert Credentials.coerce(None).passwords == []


# --- Header v2 --------------------------------------------------------------
@pytest.fixture
def setup():
    dek = secrets.token_bytes(32)
    ident = keys.generate_identity()
    phrase = keys.generate_recovery().value
    slots = [h2.password_slot(dek, PASSWORD, FAST), h2.secret_slot(dek, phrase),
             h2.x25519_slot(dek, ident.public_key())]
    header = h2.HeaderV2.create(dek, slots, flags=h2.FLAG_INDEX)
    return dek, ident, phrase, header


def reparse(raw):
    return h2.read_header(io.BytesIO(raw))


def test_all_slot_types_unlock(setup):
    dek, ident, phrase, header = setup
    parsed = reparse(header.to_bytes())
    assert parsed.unlock(PASSWORD) == (dek, 0)
    assert parsed.unlock(phrase.replace("-", " ")) == (dek, 1)
    assert parsed.unlock(Credentials(identities=[ident])) == (dek, 2)
    assert parsed.payload_key(dek) == header.payload_key(dek)


def test_wrong_credentials(setup):
    _, _, _, header = setup
    with pytest.raises(WrongPassword):
        header.unlock("falsch")
    with pytest.raises(WrongPassword):
        header.unlock(Credentials(identities=[keys.generate_identity()]))


def test_identity_does_not_trigger_prompt(setup):
    dek, ident, _, header = setup
    creds = Credentials(identities=[ident], prompt=lambda: pytest.fail("Passwortabfrage unnötig"))
    assert header.unlock(creds) == (dek, 2)


def test_every_header_byte_is_protected(setup):
    _, ident, _, header = setup
    raw = header.to_bytes()
    for i in range(len(raw)):
        for mask in (0x01, 0x80):
            tampered = bytearray(raw)
            tampered[i] ^= mask
            with pytest.raises(Tres0rError):
                reparse(bytes(tampered)).unlock(Credentials(passwords=[PASSWORD], identities=[ident]))


def test_swapped_slot_fails_mac():
    """Ein Slot aus einem anderen Container entsperrt, aber die MAC passt nicht."""
    dek_a, dek_b = secrets.token_bytes(32), secrets.token_bytes(32)
    a = h2.HeaderV2.create(dek_a, [h2.password_slot(dek_a, PASSWORD, FAST)])
    b = h2.HeaderV2.create(dek_b, [h2.password_slot(dek_b, "anderes", FAST)])
    forged = h2.HeaderV2(b.payload_type, b.compression, b.flags, b.stream_nonce, a.slots)
    forged.raw = forged._unsigned() + b.mac
    forged.mac = b.mac
    with pytest.raises(IntegrityError):
        reparse(forged.raw).unlock(PASSWORD)


def test_unknown_slot_types_are_skipped_and_kept(setup):
    dek, _, _, header = setup
    future = h2.Slot(200, b"zukunftsmusik")
    extended = header.with_slots(dek, header.slots + [future])
    parsed = reparse(extended.to_bytes())
    assert parsed.unlock(PASSWORD) == (dek, 0)
    assert parsed.slots[-1] == future
    assert "unbekannter Typ 200" in parsed.slots[-1].describe()
    # Nur unbekannte Slots -> sauberer Fehler statt Absturz
    only_future = h2.HeaderV2.create(dek, [future])
    with pytest.raises(WrongPassword):
        reparse(only_future.to_bytes()).unlock(PASSWORD)


def test_slot_limits():
    dek = secrets.token_bytes(32)
    ident = keys.generate_identity()
    with pytest.raises(Tres0rError):
        h2.HeaderV2.create(dek, [])
    with pytest.raises(Tres0rError):
        h2.HeaderV2.create(dek, [h2.x25519_slot(dek, ident.public_key())] * (h2.MAX_SLOTS + 1))
    pw = h2.password_slot(dek, PASSWORD, FAST)
    with pytest.raises(Tres0rError):
        h2.HeaderV2.create(dek, [pw] * (h2.MAX_PASSWORD_SLOTS + 1))


def test_hostile_kdf_params_rejected_before_derivation(monkeypatch):
    dek = secrets.token_bytes(32)
    raw = bytearray(h2.HeaderV2.create(dek, [h2.password_slot(dek, PASSWORD, FAST)]).to_bytes())
    # Argon2-Speicher im Slot (nach Fixteil 27 + Slotkopf 3 + KDF-ID 1) auf 1 TiB setzen
    raw[31:35] = (2**30).to_bytes(4, "big")
    monkeypatch.setattr(kdf, "_derive_cryptography", lambda *a: pytest.fail("KDF lief trotzdem"))
    with pytest.raises(FormatError):
        reparse(bytes(raw))


def test_header_field_validation(setup):
    _, _, _, header = setup
    raw = header.to_bytes()
    for offset, value in [(7, 9), (8, 9), (9, 0x80), (26, 0), (26, 17)]:
        bad = bytearray(raw)
        bad[offset] = value
        with pytest.raises(FormatError):
            reparse(bytes(bad))
    with pytest.raises(FormatError):
        reparse(raw[:-1])  # Länge passt nicht mehr


def test_v1_headers_still_parse():
    from tres0r import header as v1

    header, dek = v1.Header.create(PASSWORD, FAST)
    parsed = h2.read_header(io.BytesIO(header.to_bytes()))
    assert parsed.version == 1 and parsed.unlock(PASSWORD) == dek


def test_levels_describe_in_slots(monkeypatch):
    monkeypatch.setattr(h2, "derive_key", lambda pw, salt, p: bytes(32))
    dek = secrets.token_bytes(32)
    slot = h2.password_slot(dek, PASSWORD, kdf.LEVELS["stark"])
    assert "Stufe stark" in slot.describe() and slot.kdf == kdf.LEVELS["stark"]
    assert KdfParams(8 * 1024, 1, 1) == FAST


def test_only_canonical_encoding_is_accepted():
    """Das letzte Base32-Zeichen trägt 2 Füllbits – Änderungen daran müssen auffallen."""
    for _ in range(64):
        ident = keys.generate_identity()
        for text, parse in ((keys.encode_recipient(ident.public_key()), keys.parse_recipient),
                            (keys.encode_identity(ident), keys.parse_identity)):
            last = text[-1].upper()
            for replacement in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567":
                if replacement == last:
                    continue
                with pytest.raises(keys.KeyFormatError):
                    parse(text[:-1] + replacement)
