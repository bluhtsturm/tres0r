"""Anbindung von pwgen an tres0r.

``tres0r/pwgen.py`` ist eine **unveränderte** Kopie von pwgen.py. Dieses Modul
ist nur die dünne Schicht darüber und ergänzt, was tres0r zusätzlich braucht:

* strukturierte Rückgaben (``Secret``, ``PasswordCheck``) statt Terminal-Ausgabe
* Eingabeprüfung vor dem Aufruf, damit pwgen-Fehlertexte nie auftauchen
* exakte Entropie für Passwörter (pwgen rechnet ``Länge × log2(Zeichenvorrat)``;
  durch "jede Klasse mindestens einmal" liegt der echte Wert minimal darunter)
* NFC-Normalisierung, passend zur Schlüsselableitung in ``kdf.py``
* Netzwerkfehler der HIBP-Abfrage als ``HibpUnavailable``

Aktualisieren: pwgen.py einfach ersetzen. Der Vertragstest in
``tests/test_passgen.py`` meldet, falls sich eine genutzte Schnittstelle ändert.
"""
from __future__ import annotations

import math
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from itertools import combinations
from pathlib import Path
from typing import Sequence

from . import pwgen
from .errors import HibpUnavailable

PASSWORD_MIN_LEN = pwgen.MIN_PW_LENGTH
PASSWORD_MAX_LEN = pwgen.MAX_PW_LENGTH
DEFAULT_PASSWORD_LEN = pwgen.DEFAULT_PW_LENGTH
PASSPHRASE_MIN_WORDS = pwgen.MIN_WORDS
PASSPHRASE_MAX_WORDS = pwgen.MAX_WORDS
DEFAULT_WORDS = pwgen.DEFAULT_WORDS
DEFAULT_SEPARATOR = "-"
LANGUAGES = tuple(pwgen.WORDLIST_FILES)
AMBIGUOUS = frozenset(pwgen.AMBIGUOUS_CHARS)

# Ab dieser Entropie gilt ein generiertes Geheimnis als ausreichend für einen
# Container, der auch Offline-Angriffen mit viel Rechenleistung standhalten soll.
RECOMMENDED_BITS = 80


@dataclass(frozen=True)
class Secret:
    value: str
    kind: str  # "passwort" | "passphrase"
    entropy_bits: float

    @property
    def strong_enough(self) -> bool:
        return self.entropy_bits >= RECOMMENDED_BITS

    def __repr__(self) -> str:  # Geheimnis nicht versehentlich in Logs/Tracebacks
        return f"Secret(kind={self.kind!r}, entropy_bits={self.entropy_bits:.1f}, value=***)"


@dataclass
class PasswordCheck:
    length: int
    classes: int
    pwned: int | None = None  # None = nicht geprüft / nicht erreichbar
    hibp_error: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.warnings


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


# ---------------------------------------------------------------------------
# Wortlisten
# ---------------------------------------------------------------------------
@lru_cache(maxsize=None)
def load_wordlist(lang: str = "de") -> tuple[str, ...]:
    """Mitgelieferte Diceware-Liste über pwgen laden (je 7776 Wörter)."""
    if lang not in LANGUAGES:
        raise ValueError(f"Unbekannte Wortliste {lang!r} (möglich: {', '.join(LANGUAGES)}).")
    return tuple(dict.fromkeys(_nfc(w) for w in pwgen.load_wordlist(lang)))


def load_wordlist_file(path: str | Path) -> tuple[str, ...]:
    """Eigene Liste laden – gleiches Format wie pwgen ('würfel<TAB>wort' oder nur 'wort')."""
    words = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.append(_nfc(line.split()[-1]))
    return tuple(dict.fromkeys(words))


# ---------------------------------------------------------------------------
# Generatoren
# ---------------------------------------------------------------------------
def _password_entropy(length: int, class_sizes: Sequence[int]) -> float:
    """Exakte Entropie bei "jede Klasse mindestens einmal" (Inklusion-Exklusion)."""
    total = sum(class_sizes)
    count = 0
    for k in range(len(class_sizes) + 1):
        for missing in combinations(class_sizes, k):
            count += (-1) ** k * (total - sum(missing)) ** length
    return math.log2(count)


def generate_password(
    length: int = DEFAULT_PASSWORD_LEN,
    *,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> Secret:
    """Wie pwgen: Klein-, Großbuchstaben und Ziffern immer, Sonderzeichen optional.

    ``length``: Zeichen; ``symbols``: Sonderzeichen verwenden; ``exclude_ambiguous``: Verwechselbares (0/O, 1/l/I) weglassen.
    """
    if not PASSWORD_MIN_LEN <= length <= PASSWORD_MAX_LEN:
        raise ValueError(f"Passwortlänge muss zwischen {PASSWORD_MIN_LEN} und {PASSWORD_MAX_LEN} liegen.")
    classes = pwgen.build_alphabet(symbols, exclude_ambiguous)
    value = pwgen.generate_password(length, classes)
    return Secret(value, "passwort", _password_entropy(length, [len(c) for c in classes]))


def generate_passphrase(
    words: int = DEFAULT_WORDS,
    *,
    lang: str = "de",
    separator: str = DEFAULT_SEPARATOR,
    capitalize: bool = False,
    append_digit: bool = False,
    wordlist: Sequence[str] | None = None,
) -> Secret:
    """Passphrase aus ``words`` Wörtern der Liste ``lang`` (oder ``wordlist``), getrennt durch ``separator``; optional ``capitalize``/``append_digit``."""
    if not PASSPHRASE_MIN_WORDS <= words <= PASSPHRASE_MAX_WORDS:
        raise ValueError(
            f"Wortanzahl muss zwischen {PASSPHRASE_MIN_WORDS} und {PASSPHRASE_MAX_WORDS} liegen."
        )
    if not separator:
        raise ValueError("Trennzeichen darf nicht leer sein (sonst sind Wortgrenzen mehrdeutig).")
    pool = tuple(dict.fromkeys(wordlist)) if wordlist is not None else load_wordlist(lang)
    if len(pool) < 2:
        raise ValueError("Wortliste ist zu klein.")
    value = pwgen.generate_passphrase(pool, words, separator, capitalize, append_digit)
    # Großschreibung bringt keine Entropie; die Ziffer zählt log2(10) ≈ 3,3 Bit.
    bits = words * math.log2(len(pool)) + (math.log2(10) if append_digit else 0.0)
    return Secret(value, "passphrase", bits)


# ---------------------------------------------------------------------------
# Prüfung
# ---------------------------------------------------------------------------
def hibp_count(password: str) -> int:
    """Treffer in der Pwned-Passwords-Datenbank (k-Anonymität, siehe pwgen)."""
    try:
        return pwgen.check_password_pwned(_nfc(password))
    except OSError as e:  # URLError, HTTPError, Timeout
        raise HibpUnavailable(f"HIBP nicht erreichbar: {e}") from None


def check_password(password: str, *, online: bool = False) -> PasswordCheck:
    """Selbst gewähltes Passwort prüfen.

    Bewusst ohne Entropie-Schätzung: Heuristiken wie "Länge × Zeichenvorrat"
    überschätzen menschlich gewählte Passwörter massiv ("Sommer2026!" wirkt
    nach 72 Bit, ist aber in Sekunden geraten). Stattdessen harte Kriterien
    plus – nur wenn ``online`` – der Abgleich mit echten Datenlecks.
    """
    pw = _nfc(password)
    classes = sum(
        (
            any(ch.islower() for ch in pw),
            any(ch.isupper() for ch in pw),
            any(ch.isdigit() for ch in pw),
            any(not ch.isalnum() for ch in pw),
        )
    )
    check = PasswordCheck(length=len(pw), classes=classes)
    if len(pw) < 12:
        check.warnings.append("Passwort ist kürzer als 12 Zeichen")
    if classes == 1 and len(pw) < 20:
        check.warnings.append("Passwort nutzt nur eine Zeichenart (z. B. nur Kleinbuchstaben)")
    if online:
        try:
            check.pwned = hibp_count(pw)
        except HibpUnavailable as e:
            check.hibp_error = str(e)
        else:
            if check.pwned:
                check.warnings.append(
                    f"Passwort taucht {check.pwned:,}-mal in bekannten Datenlecks auf".replace(",", ".")
                )
    return check


__all__ = [
    "Secret", "PasswordCheck", "generate_password", "generate_passphrase", "check_password", "hibp_count",
    "load_wordlist", "load_wordlist_file", "LANGUAGES", "AMBIGUOUS", "RECOMMENDED_BITS", "DEFAULT_SEPARATOR",
    "PASSWORD_MIN_LEN", "PASSWORD_MAX_LEN", "DEFAULT_PASSWORD_LEN", "PASSPHRASE_MIN_WORDS", "PASSPHRASE_MAX_WORDS",
    "DEFAULT_WORDS",
]
