"""Fehlerklassen von tres0r.

Alle erwartbaren Fehler erben von Tres0rError, damit Frontends (CLI, TUI, GUI)
sie gesammelt abfangen und als verständliche Meldung anzeigen können.
"""


class Tres0rError(Exception):
    """Basisklasse für alle erwarteten Fehler."""


class FormatError(Tres0rError):
    """Keine tres0r-Datei oder Header strukturell ungültig."""


class UnsupportedVersion(FormatError):
    """Formatversion wird von dieser Programmversion nicht unterstützt."""


class WrongPassword(Tres0rError):
    """Falsches Passwort – oder der Header wurde manipuliert.

    Beides ist kryptografisch nicht unterscheidbar: Der komplette Header ist
    als Associated Data an den verschlüsselten Datenschlüssel gebunden.
    """


class IntegrityError(Tres0rError):
    """Nutzdaten beschädigt, manipuliert, abgeschnitten oder verlängert."""


class UnsafeArchive(Tres0rError):
    """Archivinhalt würde außerhalb des Zielordners schreiben o. Ä."""


class Cancelled(Tres0rError):
    """Vorgang wurde abgebrochen (Nutzer oder Progress-Callback)."""


class HibpUnavailable(Tres0rError):
    """Have-I-Been-Pwned-Abfrage nicht möglich (offline, Timeout, …)."""


class NameConflict(Tres0rError):
    """Namen würden beim Entpacken kollidieren oder sind auf diesem System ungültig."""


class InsufficientSpace(Tres0rError):
    """Auf dem Zieldatenträger ist voraussichtlich nicht genug Platz."""


class InsufficientMemory(Tres0rError):
    """Die Schlüsselableitung bräuchte mehr Arbeitsspeicher als verfügbar."""


class SignatureError(IntegrityError):
    """Signatur fehlt, ist ungültig oder stammt nicht vom erwarteten Schlüssel."""


class KeyFormatError(Tres0rError, ValueError):
    """Schlüssel- oder Anteiltext ist ungültig (Tippfehler, falsches Präfix, falsche Länge)."""


__all__ = [
    "Tres0rError", "FormatError", "UnsupportedVersion", "WrongPassword", "IntegrityError", "SignatureError",
    "UnsafeArchive", "Cancelled", "HibpUnavailable", "NameConflict", "InsufficientSpace", "InsufficientMemory",
    "KeyFormatError",
]
