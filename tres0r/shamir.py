"""Schwellwert-Wiederherstellung: Shamirs Secret Sharing über GF(2⁸).

Ein 32-Byte-Geheimnis S wird in n Anteile zerlegt; beliebige k davon genügen,
um S zurückzugewinnen, k−1 verraten darüber informationstheoretisch nichts.
Jedes Byte von S ist der konstante Term eines eigenen Polynoms vom Grad k−1
mit zufälligen übrigen Koeffizienten; Anteil i ist die Auswertung aller
Polynome an der Stelle x = i (1 … n). Rechnen in GF(2⁸) mit dem
AES-Polynom x⁸+x⁴+x³+x+1 (0x11B), Addition = XOR.

Textform eines Anteils (Base32 ohne Padding, klein, 4 Byte Prüfsumme):

    tres0r-teil-<76 Zeichen>   =  set_id(8) ‖ k ‖ n ‖ x ‖ y(32) ‖ check(4)

``set_id`` verbindet die Anteile eines Satzes mit genau einem Keyslot.
Leerzeichen und Bindestriche im Anteil werden beim Einlesen ignoriert.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import rng
from .errors import Tres0rError, WrongPassword
from .keys import KeyFormatError, _b32decode, _b32encode

PREFIX = "tres0r-teil-"
SECRET_LEN = 32
MAX_SHARES = 32

# --- GF(2⁸) -------------------------------------------------------------------
_EXP = [0] * 510
_LOG = [0] * 256
_value = 1
for _i in range(255):
    _EXP[_i] = _EXP[_i + 255] = _value
    _LOG[_value] = _i
    _value ^= (_value << 1) ^ (0x11B if _value & 0x80 else 0)  # · 3 = · (x + 1)
    _value &= 0xFF
del _i, _value


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("Division durch 0 in GF(2⁸)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


# --- Anteile ------------------------------------------------------------------
@dataclass(frozen=True)
class Share:
    set_id: bytes  # 8 Byte
    k: int
    n: int
    x: int
    y: bytes  # 32 Byte

    def _raw(self) -> bytes:
        return self.set_id + bytes([self.k, self.n, self.x]) + self.y

    def text(self) -> str:
        raw = self._raw()
        return PREFIX + _b32encode(raw + _check(raw)).lower()

    @property
    def label(self) -> str:
        return f"Teil {self.x} von {self.n} (je {self.k} nötig)"


def _check(raw: bytes) -> bytes:
    return hashlib.sha256(b"tres0r share " + raw).digest()[:4]


def parse_share(text: str) -> Share:
    """Anteil ``tres0r-teil-…`` aus ``text`` lesen (Prüfsumme, kanonische Schreibweise)."""
    text = text.strip()
    if not text.lower().startswith(PREFIX):
        raise KeyFormatError(f"Anteil muss mit '{PREFIX}' beginnen.")
    body = "".join(ch for ch in text[len(PREFIX):] if ch not in " \t-")
    data = _b32decode(body)
    if len(data) != 8 + 3 + SECRET_LEN + 4:
        raise KeyFormatError("Anteil hat die falsche Länge.")
    if _b32encode(data) != body.upper():
        raise KeyFormatError("Ungültige Schreibweise – Tippfehler im Anteil?")
    raw, check = data[:-4], data[-4:]
    if _check(raw) != check:
        raise KeyFormatError("Prüfsumme stimmt nicht – Tippfehler im Anteil?")
    k, n, x = raw[8], raw[9], raw[10]
    if not (2 <= k <= n <= MAX_SHARES and 1 <= x <= n):
        raise KeyFormatError("Anteil enthält unzulässige Werte.")
    return Share(raw[:8], k, n, x, raw[11:])


def split(secret: bytes, k: int, n: int, set_id: bytes | None = None) -> list[Share]:
    """Geheimnis in n Anteile zerlegen, von denen k genügen.

    ``secret``: 32 Byte; ``k``/``n``: nötige/alle Anteile; ``set_id``: 8 Byte (sonst zufällig).
    """
    if len(secret) != SECRET_LEN:
        raise ValueError("Geheimnis muss 32 Byte lang sein.")
    if not 2 <= k <= n <= MAX_SHARES:
        raise ValueError(f"Es gilt 2 ≤ k ≤ n ≤ {MAX_SHARES} (k = nötige, n = alle Anteile).")
    set_id = set_id or rng.random_bytes(8)
    coefficients = [rng.random_bytes(k - 1) for _ in range(SECRET_LEN)]  # je Byte: a1 … a(k−1)
    shares = []
    for x in range(1, n + 1):
        y = bytearray(SECRET_LEN)
        for j in range(SECRET_LEN):
            value = 0
            for a in reversed(coefficients[j]):  # Horner: ((a(k−1)·x + …) + a1)·x + s
                value = gf_mul(value, x) ^ a
            y[j] = gf_mul(value, x) ^ secret[j]
        shares.append(Share(set_id, k, n, x, bytes(y)))
    return shares


def combine(shares: list[Share]) -> bytes:
    """Geheimnis aus mindestens k Anteilen desselben Satzes (Lagrange an x = 0).

    ``shares``: mindestens k Anteile desselben Satzes; zu wenige -> ``WrongPassword``.
    """
    if not shares:
        raise WrongPassword("Keine Anteile angegeben.")
    first = shares[0]
    if any((s.set_id, s.k, s.n) != (first.set_id, first.k, first.n) for s in shares):
        raise Tres0rError("Anteile stammen aus verschiedenen Sätzen.")
    distinct: dict[int, Share] = {}
    for share in shares:
        if share.x in distinct and distinct[share.x].y != share.y:
            raise Tres0rError(f"Anteil {share.x} liegt in zwei verschiedenen Fassungen vor.")
        distinct[share.x] = share
    if len(distinct) < first.k:
        raise WrongPassword(f"{len(distinct)} von {first.k} nötigen Anteilen vorhanden.")
    use = list(distinct.values())[: first.k]
    secret = bytearray(SECRET_LEN)
    for i, share_i in enumerate(use):
        weight = 1  # L_i(0) = Π x_j / (x_j ⊕ x_i)
        for j, share_j in enumerate(use):
            if i != j:
                weight = gf_mul(weight, gf_div(share_j.x, share_j.x ^ share_i.x))
        for b in range(SECRET_LEN):
            secret[b] ^= gf_mul(share_i.y[b], weight)
    return bytes(secret)


__all__ = [
    "Share",
    "split",
    "combine",
    "parse_share",
    "PREFIX",
    "SECRET_LEN",
    "MAX_SHARES",
]
