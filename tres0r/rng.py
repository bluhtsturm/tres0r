"""Einzige Zufallsquelle für alles, was tres0r verschlüsselt.

Alle Salts, Nonces, Datenschlüssel und ephemeren X25519-Schlüssel kommen von
hier – direkt aus dem CSPRNG des Betriebssystems (``secrets``). Die Bündelung
hat zwei Gründe: Man sieht auf einen Blick, woher Zufall stammt (Audit), und
die Testvektoren (tests/vectors) können ihn gezielt durch eine feste Folge
ersetzen, um byte-genau reproduzierbare Container zu erzeugen.

Wichtig: Aufrufer verwenden ``rng.random_bytes(...)`` über das Modul, nie
``from .rng import random_bytes`` – sonst greift das Ersetzen in Tests nicht.
(Passwort-/Passphrasen-Erzeugung läuft über pwgen und dessen ``secrets``-Aufrufe.)
"""
from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)


def x25519_private_key() -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(random_bytes(32))
