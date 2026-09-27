import hashlib
import inspect
import math
import string
import unicodedata
import urllib.error

import pytest

from tres0r import passgen, pwgen
from tres0r.errors import HibpUnavailable


# --- Vertragstest: genutzte pwgen-Schnittstelle -----------------------------
def test_pwgen_contract():
    """Schlägt fehl, wenn eine neue pwgen.py-Version die genutzte API ändert."""
    for const in ("MIN_PW_LENGTH", "MAX_PW_LENGTH", "DEFAULT_PW_LENGTH", "MIN_WORDS",
                  "MAX_WORDS", "DEFAULT_WORDS", "AMBIGUOUS_CHARS", "WORDLIST_FILES"):
        assert hasattr(pwgen, const), const
    expected = {
        "build_alphabet": ["use_symbols", "exclude_ambiguous"],
        "generate_password": ["length", "classes"],
        "generate_passphrase": ["words", "count", "separator", "capitalize", "append_digit"],
        "load_wordlist": ["lang"],
        "check_password_pwned": ["password"],
        "http_get": ["url", "headers"],
    }
    for name, params in expected.items():
        assert list(inspect.signature(getattr(pwgen, name)).parameters) == params, name


# --- Wortlisten -------------------------------------------------------------
@pytest.mark.parametrize("lang", passgen.LANGUAGES)
def test_wordlists(lang):
    words = passgen.load_wordlist(lang)
    assert len(words) == 7776 == len(set(words))
    assert all(w and w == unicodedata.normalize("NFC", w) and not any(c.isspace() for c in w) for w in words)


def test_unknown_wordlist():
    with pytest.raises(ValueError):
        passgen.load_wordlist("fr")


def test_custom_wordlist_file_dice_and_plain(tmp_path):
    f = tmp_path / "liste.txt"
    f.write_text("# Kommentar\n11111\talpha\nbeta\n11113 alpha\n\ngamma\n", encoding="utf-8")
    assert passgen.load_wordlist_file(f) == ("alpha", "beta", "gamma")


# --- Passphrasen ------------------------------------------------------------
def test_passphrase_defaults():
    secret = passgen.generate_passphrase()
    words = secret.value.split("-")
    assert len(words) == passgen.DEFAULT_WORDS
    assert set(words) <= set(passgen.load_wordlist("de"))
    assert secret.entropy_bits == pytest.approx(8 * math.log2(7776))
    assert secret.strong_enough


@pytest.mark.parametrize("n", [passgen.PASSPHRASE_MIN_WORDS - 1, passgen.PASSPHRASE_MAX_WORDS + 1])
def test_passphrase_bounds(n):
    with pytest.raises(ValueError):
        passgen.generate_passphrase(n)


def test_passphrase_digit_and_capitalize():
    secret = passgen.generate_passphrase(8, wordlist=["eins", "zwei"], separator=" ",
                                         capitalize=True, append_digit=True)
    parts = secret.value.split(" ")
    assert len(parts) == 9 and parts[-1].isdigit()
    assert all(w in ("Eins", "Zwei") for w in parts[:-1])
    assert secret.entropy_bits == pytest.approx(8 + math.log2(10))
    assert not secret.strong_enough


def test_empty_separator_rejected():
    with pytest.raises(ValueError):
        passgen.generate_passphrase(8, separator="")


# --- Passwörter -------------------------------------------------------------
@pytest.mark.parametrize("length", [8, 20, 128])
def test_password_contains_every_class(length):
    for _ in range(50):
        pw = passgen.generate_password(length).value
        assert len(pw) == length
        for cls in (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation):
            assert any(ch in cls for ch in pw)


@pytest.mark.parametrize("length", [passgen.PASSWORD_MIN_LEN - 1, passgen.PASSWORD_MAX_LEN + 1])
def test_password_bounds(length):
    with pytest.raises(ValueError):
        passgen.generate_password(length)


def test_password_options():
    pw = passgen.generate_password(64, symbols=False, exclude_ambiguous=True).value
    assert pw.isalnum() and not set(pw) & passgen.AMBIGUOUS


def test_password_entropy_is_exact():
    # 2 Zeichen, Klassen {a,b} und {1}: gültig sind a1, 1a, b1, 1b -> 4 -> 2 Bit
    assert passgen._password_entropy(2, [2, 1]) == pytest.approx(2.0)
    # Knapp unter pwgens Näherung Länge × log2(Zeichenvorrat), nie darüber
    exact = passgen.generate_password(20).entropy_bits
    naive = 20 * math.log2(94)
    assert naive - 1 < exact < naive


def test_secret_repr_hides_value():
    secret = passgen.generate_password()
    assert secret.value not in repr(secret)


# --- HIBP (ohne Netzwerk, pwgen.http_get wird ersetzt) ----------------------
class FakeHttp:
    def __init__(self, body="", error=None):
        self.body, self.error, self.calls = body, error, []

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        if self.error:
            raise self.error
        return 200, self.body


def _sha1(pw):
    return hashlib.sha1(pw.encode()).hexdigest().upper()


def test_hibp_k_anonymity_and_padding(monkeypatch):
    pw = "passwort123"
    fake = FakeHttp(f"00000000000000000000000000000000000:0\r\n{_sha1(pw)[5:]}:4711\r\n")
    monkeypatch.setattr(pwgen, "http_get", fake)
    assert passgen.hibp_count(pw) == 4711
    url, headers = fake.calls[0]
    assert url.endswith("/range/" + _sha1(pw)[:5])
    assert _sha1(pw)[5:] not in url  # nur das Präfix verlässt den Rechner
    assert headers.get("Add-Padding") == "true"


def test_hibp_uses_nfc(monkeypatch):
    fake = FakeHttp("")
    monkeypatch.setattr(pwgen, "http_get", fake)
    passgen.hibp_count(unicodedata.normalize("NFD", "Käse"))
    assert fake.calls[0][0].endswith(_sha1(unicodedata.normalize("NFC", "Käse"))[:5])


def test_hibp_offline(monkeypatch):
    monkeypatch.setattr(pwgen, "http_get", FakeHttp(error=urllib.error.URLError("kein Netz")))
    with pytest.raises(HibpUnavailable):
        passgen.hibp_count("x")
    check = passgen.check_password("ein-langes-passwort-2026", online=True)
    assert check.pwned is None and check.hibp_error and check.ok


def test_check_password(monkeypatch):
    weak = passgen.check_password("hallo")
    assert len(weak.warnings) == 2 and not weak.ok and weak.pwned is None

    pw = "Sommer2026!Sommer"
    monkeypatch.setattr(pwgen, "http_get", FakeHttp(f"{_sha1(pw)[5:]}:1234\n"))
    check = passgen.check_password(pw, online=True)
    assert check.pwned == 1234
    assert any("1.234-mal" in w for w in check.warnings)

    monkeypatch.setattr(pwgen, "http_get", FakeHttp(""))
    good = passgen.check_password("Zug-Tanne-Kaffee-Laterne-7", online=True)
    assert good.ok and good.pwned == 0
