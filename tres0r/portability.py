"""Portabilität von Pfadnamen zwischen Linux, Windows und macOS.

Unter Linux ist fast jeder Dateiname erlaubt. Beim Entpacken woanders drohen:

* Windows: reservierte Namen (CON, NUL, COM1 …, auch "con.txt"), verbotene
  Zeichen (< > : " \\ | ? * und Steuerzeichen), Punkt/Leerzeichen am Ende
  (werden stillschweigend entfernt), sehr lange Pfade.
* Windows und macOS: Groß-/Kleinschreibung wird standardmäßig ignoriert –
  "Datei.txt" und "datei.txt" landen in derselben Datei.
* macOS: Unicode-Normalisierung wird ignoriert – "ä" als ein Zeichen (NFC) und
  als "a" + Umlautpunkte (NFD) sind derselbe Name.

Beide Kollisionsarten führen ohne Gegenmaßnahme zu stillem Datenverlust:
die zweite Datei überschreibt die erste.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Iterable

WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{c}" for c in "123456789\u00b9\u00b2\u00b3"}
    | {f"LPT{c}" for c in "123456789\u00b9\u00b2\u00b3"}
)
WINDOWS_INVALID_CHARS = frozenset('<>:"\\|?*') | frozenset(chr(i) for i in range(32))
# Relativer Pfad im Container; der Zielordner kommt beim Entpacken noch dazu.
LONG_PATH_WARNING = 200

KIND_RESERVED = "reserviert"
KIND_CHARS = "zeichen"
KIND_TRAILING = "ende"
KIND_LONG = "lang"
KIND_COLLISION = "kollision"
KIND_ENCODING = "kodierung"


def _escaped_bytes(name: str) -> bool:
    """Enthält der Name Bytes, die kein gültiges UTF-8 waren (surrogateescape)?"""
    return any(0xDC80 <= ord(ch) <= 0xDCFF for ch in name)


@dataclass(frozen=True)
class Issue:
    path: str
    kind: str
    detail: str
    other: str | None = None

    def to_dict(self) -> dict:
        data = {"path": self.path, "kind": self.kind, "detail": self.detail}
        if self.other is not None:
            data["other"] = self.other
        return data


def collision_key(path: str) -> str:
    """Schlüssel, unter dem Windows/macOS zwei Namen als gleich betrachten.

    Bewusst lower() statt casefold(): casefold macht aus "ß" ein "ss", NTFS
    unterscheidet "Straße" und "Strasse" aber sehr wohl.
    """
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", path).lower())


def component_problem(name: str) -> tuple[str, str] | None:
    """Warum ist dieser einzelne Namensbestandteil unter Windows ungültig?"""
    if _escaped_bytes(name):
        return KIND_ENCODING, "kein gültiges UTF-8 – wird auf anderen Systemen anders dargestellt"
    bad = sorted({ch for ch in name if ch in WINDOWS_INVALID_CHARS})
    if bad:
        shown = " ".join(repr(ch)[1:-1] for ch in bad)
        return KIND_CHARS, f"unter Windows verbotene Zeichen: {shown}"
    if name.partition(".")[0].rstrip(" ").upper() in WINDOWS_RESERVED:
        return KIND_RESERVED, "unter Windows reservierter Gerätename"
    if name.endswith((".", " ")) and name not in (".", ".."):
        return KIND_TRAILING, "Punkt/Leerzeichen am Ende wird unter Windows entfernt"
    return None


def sanitize_component(name: str) -> str:
    """Namensbestandteil so ändern, dass Windows ihn akzeptiert."""
    # Ungültige UTF-8-Bytes als Latin-1 deuten (typisch für alte Namen: b"caf\xe9" -> "café")
    name = "".join(chr(ord(ch) - 0xDC00) if 0xDC80 <= ord(ch) <= 0xDCFF else ch for ch in name)
    name = "".join("_" if ch in WINDOWS_INVALID_CHARS else ch for ch in name)
    if name.endswith((".", " ")):
        name = name.rstrip(". ") + "_"
    if name.partition(".")[0].rstrip(" ").upper() in WINDOWS_RESERVED:
        stem, dot, rest = name.partition(".")
        name = f"{stem}_{dot}{rest}"
    return name or "_"


def check_names(items: Iterable[tuple[str, bool]]) -> list[Issue]:
    """Alle Portabilitätsprobleme von Container-Pfaden.

    ``items`` sind Paare (Pfad im Container wie "a/b/c", ist_ordner). Zwei
    Ordner, die nur in der Schreibweise abweichen, gelten nicht als Kollision –
    sie werden unter Windows/macOS lediglich zusammengelegt. Kollidierende
    Dateien darin fallen trotzdem auf, weil deren volle Pfade kollidieren.
    """
    issues: list[Issue] = []
    reported: set[str] = set()
    by_key: dict[str, tuple[str, bool]] = {}
    for path, is_dir in items:
        parts = path.split("/")
        for i, part in enumerate(parts):
            prefix = "/".join(parts[: i + 1])
            if prefix in reported:
                continue  # Ordner nur einmal melden, nicht bei jeder Datei darin
            problem = component_problem(part)
            if problem:
                reported.add(prefix)
                issues.append(Issue(prefix, problem[0], problem[1]))
        if len(path) > LONG_PATH_WARNING:
            issues.append(Issue(path, KIND_LONG, f"Pfad mit {len(path)} Zeichen – unter Windows evtl. zu lang"))
        key = collision_key(path)
        first = by_key.get(key)
        if first is None:
            by_key[key] = (path, is_dir)
        elif first[0] != path and not (is_dir and first[1]):
            issues.append(
                Issue(path, KIND_COLLISION, "kollidiert unter Windows/macOS (Groß-/Kleinschreibung "
                      "oder Unicode-Form)", other=first[0])
            )
    return issues


def numbered_variant(name: str, n: int) -> str:
    """'bericht.pdf' -> 'bericht (n).pdf', Ordner/ohne Endung -> 'name (n)'."""
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem:  # keine Endung oder versteckte Datei wie ".bashrc"
        return f"{name} ({n})"
    return f"{stem} ({n}).{ext}"
