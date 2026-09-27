"""Gemeinsame Hilfen für die atheris-Harnesses.

Erlaubt sind nur Tres0rError-Unterklassen – jede andere Exception (IndexError,
RecursionError, UnicodeError …) gilt als Fund und wird von atheris gemeldet.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

PHRASE = "fuzz-phrase"  # Schlüssel-Slot: HKDF statt Argon2 -> schnell


def fast_kdf():
    """Argon2 durch eine schnelle Funktion ersetzen (mutierte Parameter bis 4 GiB)."""
    import hmac

    from tres0r import header, header2

    def derive(password, salt, params):
        pw = password.encode("utf-8", "surrogateescape") if isinstance(password, str) else password
        return hmac.new(salt + str(params).encode(), pw, "sha256").digest()

    header.derive_key = derive  # v1
    header2.derive_key = derive
