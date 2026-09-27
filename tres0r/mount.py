"""Container schreibgeschützt einhängen (FUSE).

``ContainerFS`` ist die eigentliche Logik und ohne FUSE testbar: Baum aus dem
Inhaltsverzeichnis, Attribute, Lesen beliebiger Bereiche. ``mount()`` hängt sie
über fusepy ein (Linux mit libfuse2, macOS mit macFUSE; Extra ``tres0r[mount]``).

Lesen: Jede geöffnete Datei hat einen eigenen Dekodier-Datenstrom ab ihrem
Einstiegspunkt (Abschnitt 8 in FORMAT.md). Fortlaufendes Lesen (cat, cp,
Mediaplayer) ist dadurch effizient; ein Sprung zurück beginnt am Dateianfang neu.
Jeder gelesene Chunk ist authentifiziert, das Abschneiden des Containers fällt
schon beim Einhängen auf (Inhaltsverzeichnis am Ende). Eine Signatur lässt sich
bei Einzelzugriffen nicht prüfen – dafür ``verify`` vorher (``mount --verify``).

Nicht angezeigt werden präparierte Namen (absolut, "..", leer). Dateirechte
kennt das Inhaltsverzeichnis nicht: Dateien erscheinen als 0444, Ordner als 0555.
"""
from __future__ import annotations

import errno
import os
import stat
import tarfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import header2 as v2
from . import payload, segments, sign, volumes
from .container import INTERRUPTED, Unlock, _index_kind, _interrupted, _safe_mtime, _unlock
from .errors import FormatError, Tres0rError
from .header2 import read_header


@dataclass
class Node:
    kind: str  # "d" | "f" | "l"
    size: int = 0
    mtime: int = 0
    entry: payload.IndexEntry | None = None  # Datei: woher lesen
    segment: int = 0  # in welchem Segment (angehängte Container)
    link: str | None = None  # Symlink-Ziel
    children: dict[str, Node] = field(default_factory=dict)


def _clean(name: str) -> str | None:
    """Pfad im Container -> "a/b/c" oder None, wenn unsicher/ungültig."""
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or name.startswith("/") or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


class ContainerFS:
    """Schreibgeschützte Sicht auf einen entsperrten Container."""

    def __init__(self, container: str | os.PathLike[str], credentials: Unlock) -> None:
        self._file, total = volumes.open_read(container)
        try:
            self.header = read_header(self._file)
            if _interrupted(Path(container), self.header, self._file, total):
                raise FormatError(INTERRUPTED)
            dek, _ = _unlock(self.header, credentials)
            if self.header.version == 2 and self.header.payload_type == v2.PAYLOAD_RAW:
                raise Tres0rError("Rohdaten-Container enthalten keine Dateien.")
            # je Segment: (wahlfreier Zugriff, Kompression, signiert, mit Index)
            if self.header.version == 2 and self.header.segmented:
                table, _ = segments.read_table(self._file, total, self.header.header_len, dek,
                                               self.header.stream_nonce)
                self._segments = [
                    (payload.RandomAccessPayload(self._file, v2.payload_key_for(dek, e.nonce),
                                                 self.header.header_len + e.offset, e.length),
                     e.compression, bool(e.flags & v2.FLAG_SIGNED), bool(e.flags & v2.FLAG_INDEX))
                    for e in table]
            else:
                v2_header = self.header.version == 2
                self._segments = [(payload.RandomAccessPayload(
                    self._file, self.header.payload_key(dek), self.header.header_len, total - self.header.header_len),
                    self.header.compression if v2_header else 0, v2_header and self.header.signed,
                    v2_header and self.header.has_index)]
            self._access = self._segments[0][0]
            self._lock = threading.Lock()  # eine Datei, viele Leser
            self.mounted_at = int(time.time())
            self.skipped: list[str] = []
            self.root = Node("d", mtime=self.mounted_at)
            for number in range(len(self._segments)):  # spätere Segmente ersetzen frühere Einträge
                for entry in self._load_entries(number):
                    self._add(entry, number)
        except BaseException:
            self._file.close()
            raise

    # -- Aufbau ------------------------------------------------------------
    def _load_entries(self, number: int = 0) -> list[payload.IndexEntry]:
        access, _, signed, indexed = self._segments[number]
        if self.header.version == 2:
            if not indexed:
                raise FormatError("Container ohne Inhaltsverzeichnis lassen sich nicht einhängen.")
            return payload.read_index(access, sign.TRAILER_LEN if signed else 0)
        # v1: Klartext ist direkt der tar-Stream -> Einstiegspunkte beim Durchlesen sammeln
        entries = []
        try:
            with tarfile.open(fileobj=self._access.open_at(0), mode="r|") as tar:
                for ti in tar:
                    entry = payload.IndexEntry(ti.name, _index_kind(ti), ti.size if ti.isreg() else 0,
                                               _safe_mtime(ti.mtime), ti.offset, 0,
                                               link=ti.linkname if (ti.issym() or ti.islnk()) else None)
                    entries.append(entry)
        except tarfile.TarError as e:
            raise FormatError(f"Archiv im Container ist defekt: {e}") from None
        return entries

    def _add(self, entry: payload.IndexEntry, segment: int = 0) -> None:
        clean = _clean(entry.name)
        if clean is None:
            self.skipped.append(entry.name)
            return
        *dirs, leaf = clean.split("/")
        node = self.root
        for part in dirs:
            child = node.children.get(part)
            if child is None:
                child = node.children[part] = Node("d", mtime=self.mounted_at)
            if child.kind != "d":
                self.skipped.append(entry.name)
                return
            node = child
        mtime = entry.mtime or self.mounted_at
        if entry.kind == "d":
            existing = node.children.get(leaf)
            if existing is None or existing.kind != "d":
                node.children[leaf] = Node("d", mtime=mtime)
            else:
                existing.mtime = mtime
        elif entry.kind == "f":
            node.children[leaf] = Node("f", entry.size, mtime, entry, segment=segment)
        elif entry.kind == "l":
            node.children[leaf] = Node("l", len(entry.link or ""), mtime, link=entry.link or "")
        elif entry.kind == "h":
            target = self.lookup("/" + (_clean(entry.link or "") or ""), missing_ok=True)
            if target is None or target.kind != "f":
                self.skipped.append(entry.name)
                return
            node.children[leaf] = Node("f", target.size, mtime, target.entry, segment=target.segment)
        else:
            self.skipped.append(entry.name)

    # -- Abfragen ----------------------------------------------------------
    def lookup(self, path: str, missing_ok: bool = False) -> Node | None:
        node = self.root
        for part in [p for p in path.split("/") if p]:
            if node.kind != "d" or part not in node.children:
                if missing_ok:
                    return None
                raise FileNotFoundError(path)
            node = node.children[part]
        return node

    def attributes(self, path: str) -> dict:
        node = self.lookup(path)
        mode = {"d": stat.S_IFDIR | 0o555, "f": stat.S_IFREG | 0o444, "l": stat.S_IFLNK | 0o777}[node.kind]
        return {"st_mode": mode, "st_nlink": 2 if node.kind == "d" else 1, "st_size": node.size,
                "st_mtime": node.mtime, "st_ctime": node.mtime, "st_atime": node.mtime,
                "st_uid": os.getuid() if hasattr(os, "getuid") else 0,
                "st_gid": os.getgid() if hasattr(os, "getgid") else 0}

    def listdir(self, path: str) -> list[str]:
        node = self.lookup(path)
        if node.kind != "d":
            raise NotADirectoryError(path)
        return sorted(node.children)

    def readlink(self, path: str) -> str:
        node = self.lookup(path)
        if node.kind != "l":
            raise OSError(errno.EINVAL, "kein Symlink")
        return node.link

    def open(self, path: str) -> _Reader:
        node = self.lookup(path)
        if node.kind != "f":
            raise IsADirectoryError(path)
        return _Reader(self, node)

    def close(self) -> None:
        self._file.close()

    # -- intern: Dekodier-Datenstrom ab einem Eintrag -------------------------
    def _member_stream(self, entry: payload.IndexEntry, segment: int = 0):
        access, compression, _, _ = self._segments[segment]
        if self.header.version == 2:
            _, data = payload.decoded_reader(access.open_at(entry.offset), compression)
            payload.skip(data, entry.skip)
        else:
            data = access.open_at(entry.offset)
        try:
            tar = tarfile.open(fileobj=data, mode="r|")
            member = tar.next()
        except tarfile.TarError as e:
            raise FormatError(f"Archiv im Container ist defekt: {e}") from None
        if member is None or member.name != entry.name or not member.isreg():
            raise FormatError("Inhaltsverzeichnis zeigt auf den falschen Eintrag.")
        return tar.extractfile(member)


class _Reader:
    """Leser für eine geöffnete Datei; merkt sich die Position für Folgelesevorgänge."""

    def __init__(self, fs: ContainerFS, node: Node) -> None:
        self._fs, self._node = fs, node
        self._source = None
        self._pos = 0

    def read(self, offset: int, size: int) -> bytes:
        if offset >= self._node.size or size <= 0:
            return b""
        size = min(size, self._node.size - offset)
        with self._fs._lock:
            try:
                return self._read(offset, size)
            except tarfile.TarError as e:
                self._source = None
                raise FormatError(f"Archiv im Container ist defekt: {e}") from None

    def _read(self, offset: int, size: int) -> bytes:
        if self._source is None or offset < self._pos:
            self._source = self._fs._member_stream(self._node.entry, self._node.segment)
            self._pos = 0
        while self._pos < offset:  # vorwärts springen
            skipped = self._source.read(min(offset - self._pos, 1 << 20))
            if not skipped:
                raise FormatError("Datei im Container ist kürzer als angegeben.")
            self._pos += len(skipped)
        data = self._source.read(size)
        self._pos += len(data)
        return data


# ---------------------------------------------------------------------------
# FUSE-Adapter
# ---------------------------------------------------------------------------
def mount(container: str | os.PathLike[str], mountpoint: str | os.PathLike[str], credentials: Unlock,
          *, foreground: bool = True, allow_other: bool = False) -> None:
    """Container einhängen; kehrt erst nach dem Aushängen zurück (Strg+C oder
    ``fusermount -u``). Braucht fusepy und libfuse (Linux) bzw. macFUSE (macOS).

    ``mountpoint``: leerer Ordner; ``foreground``: blockiert bis zum Aushängen; ``allow_other``: auch andere Benutzer dürfen lesen (FUSE-Option).
    """
    try:
        from fuse import FUSE, FuseOSError, Operations
    except (ImportError, OSError) as e:
        raise Tres0rError(f"Einhängen braucht fusepy und libfuse/macFUSE ({e}). "
                          "Installieren: pip install 'tres0r[mount]' und z. B. apt install libfuse2t64") from None
    if not Path(mountpoint).is_dir():
        raise Tres0rError(f"Einhängepunkt {mountpoint} ist kein Ordner.")
    fs = ContainerFS(container, credentials)

    def guarded(fn):
        def call(*args):
            try:
                return fn(*args)
            except (FileNotFoundError, KeyError):
                raise FuseOSError(errno.ENOENT) from None
            except NotADirectoryError:
                raise FuseOSError(errno.ENOTDIR) from None
            except IsADirectoryError:
                raise FuseOSError(errno.EISDIR) from None
            except Tres0rError:  # beschädigter Chunk o. Ä. beim Lesen
                raise FuseOSError(errno.EIO) from None
        return call

    class Adapter(Operations):
        def __init__(self) -> None:
            self._handles: dict[int, _Reader] = {}
            self._next = 1

        @guarded
        def getattr(self, path, fh=None):
            return fs.attributes(path)

        @guarded
        def readdir(self, path, fh):
            return [".", "..", *fs.listdir(path)]

        @guarded
        def readlink(self, path):
            return fs.readlink(path)

        @guarded
        def open(self, path, flags):
            if flags & (os.O_WRONLY | os.O_RDWR):
                raise FuseOSError(errno.EROFS)
            handle, self._next = self._next, self._next + 1
            self._handles[handle] = fs.open(path)
            return handle

        @guarded
        def read(self, path, size, offset, fh):
            return self._handles[fh].read(offset, size)

        def release(self, path, fh):
            self._handles.pop(fh, None)
            return 0

        def statfs(self, path):
            return {"f_bsize": 65536, "f_blocks": 0, "f_bavail": 0, "f_bfree": 0, "f_namemax": 255}

    try:
        FUSE(Adapter(), os.fspath(mountpoint), foreground=foreground, ro=True, nothreads=True,
             allow_other=allow_other, fsname="tres0r", subtype="tres0r")
    finally:
        fs.close()


def unmount(mountpoint: str | os.PathLike[str]) -> None:
    """Eingehängten Container unter ``mountpoint`` aushängen (fusermount bzw. umount)."""
    import shutil
    import subprocess
    import sys

    command = ["umount", os.fspath(mountpoint)] if sys.platform == "darwin" else None
    if command is None:
        tool = shutil.which("fusermount3") or shutil.which("fusermount")
        if tool is None:
            raise Tres0rError("fusermount nicht gefunden.")
        command = [tool, "-u", os.fspath(mountpoint)]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise Tres0rError(f"Aushängen fehlgeschlagen: {result.stderr.strip() or result.returncode}")


__all__ = ["ContainerFS", "Node", "mount", "unmount"]
