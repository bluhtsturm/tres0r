"""Ausschlussmuster für das Packen.

Syntax (an .gitignore angelehnt, bewusst kleiner):

    *.tmp          ohne "/": passt auf den Namen in jeder Tiefe
    build/         "/" am Ende: nur Ordner (samt Inhalt)
    docs/entwurf   mit "/": passt auf den Pfad relativ zur Wurzel
    /notizen.txt   führender "/": nur direkt in der Wurzel
    # Kommentar    Kommentare und Leerzeilen werden ignoriert

Groß-/Kleinschreibung wird auf allen Systemen gleich behandelt (unterschieden),
damit ein Container unabhängig vom packenden Rechner denselben Inhalt hat.
Negationen ("!muster") werden nicht unterstützt und abgelehnt statt still
ignoriert.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Iterable

IGNORE_FILE = ".tres0rignore"

# Typischer Datenmüll von Betriebssystemen und Office-Programmen.
JUNK_PATTERNS = (
    ".DS_Store",
    "._*",
    ".Spotlight-V100/",
    ".Trashes/",
    ".Trash-*/",
    "Thumbs.db",
    "ehthumbs.db",
    "desktop.ini",
    "$RECYCLE.BIN/",
    "__pycache__/",
    "~$*",
    ".~lock.*#",
)


@dataclass(frozen=True)
class _Pattern:
    glob: str
    anchored: bool
    dir_only: bool

    def matches(self, relpath: str, is_dir: bool) -> bool:
        if self.dir_only and not is_dir:
            return False
        if self.anchored:
            return fnmatchcase(relpath, self.glob)
        return fnmatchcase(relpath.rpartition("/")[2], self.glob)


def _parse(pattern: str) -> _Pattern | None:
    pattern = pattern.strip()
    if not pattern or pattern.startswith("#"):
        return None
    if pattern.startswith("!"):
        raise ValueError(f"Negierte Muster werden nicht unterstützt: {pattern!r}")
    dir_only = pattern.endswith("/")
    pattern = pattern.rstrip("/")
    anchored = "/" in pattern
    pattern = pattern.lstrip("/")
    if not pattern:
        raise ValueError("Leeres Muster.")
    return _Pattern(pattern, anchored, dir_only)


class ExcludeRules:
    """Menge von Mustern; ``matches`` bekommt Pfade mit "/" als Trenner."""

    def __init__(self, patterns: Iterable[str] = ()) -> None:
        self._patterns = tuple(p for p in (_parse(x) for x in patterns) if p)

    def __bool__(self) -> bool:
        return bool(self._patterns)

    def __add__(self, other: ExcludeRules) -> ExcludeRules:
        combined = ExcludeRules()
        combined._patterns = self._patterns + other._patterns
        return combined

    def matches(self, relpath: str, is_dir: bool) -> bool:
        return any(p.matches(relpath, is_dir) for p in self._patterns)

    @classmethod
    def from_file(cls, path: str | Path) -> ExcludeRules:
        return cls(Path(path).read_text(encoding="utf-8").splitlines())

    @classmethod
    def junk(cls) -> ExcludeRules:
        return cls(JUNK_PATTERNS)
