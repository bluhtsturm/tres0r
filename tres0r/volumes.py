"""Aufgeteilte Container (--split): backup.tres0r.001, .002, …

Die Aufteilung ist reine Byte-Ebene: Die Teile aneinandergehängt ergeben exakt
den normalen Container (``cat backup.tres0r.* | tres0r unpack -`` funktioniert).
Beim Lesen sieht ein ``VolumeReader`` wie eine einzige seekbare Datei aus;
beim Schreiben entstehen zuerst Temporärteile, die erst nach vollständigem
Erfolg umbenannt werden. Fehlende oder abgeschnittene Teile fallen spätestens
beim Abschluss-Chunk auf (Integritätsfehler), eine Lücke in der Nummerierung
schon beim Öffnen.
"""
from __future__ import annotations

import io
import os
import re
import tempfile
from pathlib import Path

from .errors import FormatError, Tres0rError

MIN_PART = 1 << 20  # 1 MiB – der Header muss ganz in Teil 1 passen
_SUFFIX = re.compile(r"\.(\d{3,})$")
_UNITS = {"": 1, "b": 1, "k": 1 << 10, "kib": 1 << 10, "m": 1 << 20, "mib": 1 << 20,
          "g": 1 << 30, "gib": 1 << 30, "t": 1 << 40, "tib": 1 << 40,
          "kb": 10**3, "mb": 10**6, "gb": 10**9, "tb": 10**12}


def parse_size(text: str) -> int:
    """'4G', '700M', '2GiB', '650MB', '1048576' -> Byte (K/M/G = 1024er, KB/MB/GB = 1000er)."""
    match = re.fullmatch(r"\s*(\d+(?:[.,]\d+)?)\s*([a-zA-Z]*)\s*", text)
    if not match or match.group(2).lower() not in _UNITS:
        raise Tres0rError(f"Unverständliche Größe '{text}' (z. B. 4G, 700M, 650MB).")
    size = int(float(match.group(1).replace(",", ".")) * _UNITS[match.group(2).lower()])
    if size < MIN_PART:
        raise Tres0rError("Teile müssen mindestens 1 MiB groß sein.")
    return size


def part_name(base: Path, number: int) -> Path:
    return base.with_name(f"{base.name}.{number:03d}")


def base_of(path: Path) -> Path | None:
    """Basis eines Teilesatzes, falls ``path`` einer ist (x.tres0r.001 oder x.tres0r mit .001)."""
    match = _SUFFIX.search(path.name)
    if match and not path.is_dir():
        return path.with_name(path.name[: match.start()])
    if not os.path.lexists(path) and os.path.lexists(part_name(path, 1)):
        return path
    return None


def parts_of(base: Path) -> list[Path]:
    """Alle Teile in Reihenfolge; Lücken sind ein Fehler."""
    pattern = re.compile(re.escape(base.name) + r"\.(\d{3,})$")
    numbers = sorted(int(m.group(1)) for p in (base.parent if str(base.parent) else Path(".")).iterdir()
                     if (m := pattern.fullmatch(p.name)))
    if not numbers or numbers[0] != 1:
        raise FormatError(f"Teil 1 ({part_name(base, 1).name}) fehlt.")
    for expected, number in enumerate(numbers, start=1):
        if number != expected:
            raise FormatError(f"Teil {expected} ({part_name(base, expected).name}) fehlt.")
    return [part_name(base, n) for n in numbers]


class VolumeReader(io.RawIOBase):
    """Mehrere Dateien als eine lesbare, seekbare Datei."""

    def __init__(self, paths: list[Path]) -> None:
        self._files = [open(p, "rb") for p in paths]
        self._sizes = [os.fstat(f.fileno()).st_size for f in self._files]
        self._starts = [sum(self._sizes[:i]) for i in range(len(self._sizes))]
        self.size = sum(self._sizes)
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._pos, io.SEEK_END: self.size}[whence]
        self._pos = max(0, base + offset)
        return self._pos

    def readinto(self, buffer) -> int:
        view = memoryview(buffer)
        done = 0
        while done < len(view) and self._pos < self.size:
            index = max(i for i, start in enumerate(self._starts) if start <= self._pos)
            f = self._files[index]
            f.seek(self._pos - self._starts[index])
            chunk = f.read(min(len(view) - done, self._starts[index] + self._sizes[index] - self._pos))
            if not chunk:
                break
            view[done:done + len(chunk)] = chunk
            done += len(chunk)
            self._pos += len(chunk)
        return done

    def close(self) -> None:
        for f in self._files:
            f.close()
        super().close()


def open_read(path: str | os.PathLike[str]) -> tuple:
    """Container zum Lesen öffnen – einzelne Datei oder Teilesatz: (Datei, Gesamtgröße)."""
    path = Path(path)
    base = base_of(path)
    if base is None:
        f = open(path, "rb")
        return f, os.fstat(f.fileno()).st_size
    reader = VolumeReader(parts_of(base))
    return io.BufferedReader(reader, buffer_size=1 << 16), reader.size


def exists(path: str | os.PathLike[str]) -> bool:
    path = Path(path)
    return os.path.lexists(path) or os.path.lexists(part_name(path, 1))


def is_part_of(candidate: Path, output: Path) -> bool:
    """Gehört ``candidate`` zur Ausgabe (Teil oder Temporärdatei)? – damit ein Container
    nicht sich selbst einpackt, wenn er in einem Quellordner liegt."""
    if candidate.parent.resolve() != (output.parent if str(output.parent) else Path(".")).resolve():
        return False
    name = candidate.name
    return (re.fullmatch(re.escape(output.name) + r"\.\d{3,}", name) is not None
            or (name.startswith(f".{output.name}.") and name.endswith(".partial")))


def display_name(path: str | os.PathLike[str]) -> str:
    base = base_of(Path(path))
    if base is None:
        return Path(path).name
    return f"{base.name}.001…{len(parts_of(base)):03d}"


def part_size_of(path: str | os.PathLike[str]) -> int | None:
    """Teilgröße eines vorhandenen Satzes (für Umschreiben in gleicher Aufteilung)."""
    base = base_of(Path(path))
    if base is None:
        return None
    parts = parts_of(base)
    return os.path.getsize(parts[0]) if len(parts) > 1 else max(MIN_PART, os.path.getsize(parts[0]))


class VolumeWriter(io.RawIOBase):
    """Schreibt fortlaufend in Temporärteile; commit() benennt alle atomar einzeln um."""

    def __init__(self, base: Path, part_size: int) -> None:
        self.base, self.part_size = base, part_size
        self._parent = base.parent if str(base.parent) else Path(".")
        self._temps: list[Path] = []
        self._current = None
        self._written = 0

    def writable(self) -> bool:
        return True

    def _next(self) -> None:
        if self._current is not None:
            self._current.flush()
            os.fsync(self._current.fileno())
            self._current.close()
        number = len(self._temps) + 1
        fd, name = tempfile.mkstemp(dir=self._parent, prefix=f".{part_name(self.base, number).name}.",
                                    suffix=".partial")
        self._temps.append(Path(name))
        self._current = os.fdopen(fd, "wb")
        self._written = 0

    def write(self, data) -> int:
        view = memoryview(data)
        total = len(view)
        while len(view):
            if self._current is None or self._written >= self.part_size:
                self._next()
            take = min(len(view), self.part_size - self._written)
            self._current.write(view[:take])
            self._written += take
            view = view[take:]
        return total

    def commit(self, overwrite: bool) -> list[Path]:
        if self._current is None:
            self._next()  # leerer Inhalt: trotzdem ein Teil
        self._current.flush()
        os.fsync(self._current.fileno())
        self._current.close()
        finals = [part_name(self.base, i) for i in range(1, len(self._temps) + 1)]
        if not overwrite:
            existing = [p for p in finals if os.path.lexists(p)]
            if existing:
                raise Tres0rError(f"{existing[0]} existiert bereits.")
        stale = []
        if overwrite and os.path.lexists(part_name(self.base, 1)):
            try:
                stale = [p for p in parts_of(self.base) if p not in finals]
            except FormatError:
                stale = []
        for temp, final in zip(self._temps, finals):
            os.replace(temp, final)
        for old in stale:  # alter Satz hatte mehr Teile
            old.unlink(missing_ok=True)
        self._temps = []
        return finals

    def abort(self) -> None:
        if self._current is not None and not self._current.closed:
            self._current.close()
        for temp in self._temps:
            temp.unlink(missing_ok=True)
        self._temps = []

    @property
    def temp_paths(self) -> list[Path]:
        return list(self._temps)
