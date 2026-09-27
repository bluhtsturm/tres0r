"""Container anlegen, entpacken, prüfen, Schlüssel verwalten.

Geschrieben wird Formatversion 2 (header2.py, payload.py), gelesen werden
Version 1 und 2.

Aufbau v2:  [Header mit Keyslots + MAC][verschlüsselter Stream]
            Stream = Blöcke(tar bzw. Rohdaten, optional zstd) + Padding + Index

Es entsteht nie eine Klartext-Zwischendatei; Dateinamen und Metadaten liegen
ausschließlich verschlüsselt vor.

Diese Schicht macht keine Terminal-Ein-/Ausgabe. Frontends bekommen
Fortschritt über ``progress=`` – eine Funktion ``(erledigt, gesamt)`` oder einen
``progress.Monitor`` mit Ereignissen (Phase, Datei, Durchsatz, Restzeit) und
Abbruch-Token. Jeder Abbruch (auch eine Exception im Callback) räumt auf. Zugangsdaten sind ein Passwort (str) oder ``keys.Credentials``
(Passwörter, X25519-Identitäten, optional eine Rückfrage-Funktion).

Typischer Ablauf in einem Frontend:

    plan = scan(pfade, exclude=regeln, output=ziel)   # schnell, ohne Passwort
    ... plan.issues / plan.files / estimate_size(plan) anzeigen ...
    create(plan, ziel, passwort, LEVELS["normal"], recipients=[...])
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import tarfile
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from . import header as v1
from . import header2 as v2
from . import payload, portability, rng, segments, sign, volumes, workers
from .errors import (
    FormatError,
    InsufficientSpace,
    IntegrityError,
    NameConflict,
    Tres0rError,
    UnsafeArchive,
    WrongPassword,
)
from .exclude import IGNORE_FILE, ExcludeRules
from .header2 import read_header
from .kdf import DEFAULT_LEVEL, LEVELS, KdfParams, level_of
from .keys import Credentials, encode_verify_key, keyfile_id
from .padding import padme
from .progress import UNIT_ENTRIES, Progress
from .progress import tracker as _tracker
from .stream import DecryptingReader, EncryptingWriter, encrypted_size

if not hasattr(tarfile, "data_filter"):  # pragma: no cover
    raise ImportError("tres0r benötigt tarfile-Filter (Python 3.10.12+, 3.11.4+ oder 3.12+).")

SUFFIX = ".tres0r"
SPACE_MARGIN = 1 << 20  # Reserve bei der Speicherplatzprüfung
# Beim Packen kopiert tarfile Dateien standardmäßig in 16-KiB-Portionen; jede läuft
# durch alle Schichten (Hash, Blöcke, Verschlüsselung). 1 MiB spart ~98 % der Aufrufe.
# (Nur beim Schreiben: im Lese-Stream-Modus kopiert tarfile seinen Puffer bei jedem
# kleinen read um – ein großer Puffer macht das Lesen dort langsamer, gemessen.)
TAR_BUFSIZE = 1 << 20
Unlock = Credentials | str | bytes | None
AnyHeader = v1.Header | v2.HeaderV2


# ---------------------------------------------------------------------------
# Datentypen
# ---------------------------------------------------------------------------
@dataclass
class Plan:
    """Ergebnis von scan(): was in den Container käme."""

    entries: list[tuple[Path, str, os.stat_result]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # FIFOs, Sockets, Geräte
    excluded: int = 0  # durch Muster ausgeschlossene Einträge (Ordner zählen einmal)
    issues: list[portability.Issue] = field(default_factory=list)

    @property
    def files(self) -> int:
        return sum(1 for _, _, st in self.entries if stat.S_ISREG(st.st_mode))

    @property
    def dirs(self) -> int:
        return sum(1 for _, _, st in self.entries if stat.S_ISDIR(st.st_mode))

    @property
    def total_bytes(self) -> int:
        return sum(st.st_size for _, _, st in self.entries if stat.S_ISREG(st.st_mode))


@dataclass
class CreateResult:
    path: Path
    entries: int
    size: int
    padding: int = 0
    skipped: list[str] = field(default_factory=list)
    excluded: int = 0
    issues: list[portability.Issue] = field(default_factory=list)
    slots: list[str] = field(default_factory=list)
    shares: list = field(default_factory=list)  # shamir.Share – nur jetzt verfügbar, nicht speichern!


@dataclass
class ExtractResult:
    names: list[str]  # oberste Einträge im Zielordner
    entries: int
    renamed: list[tuple[str, str]] = field(default_factory=list)  # (im Container, auf Platte)
    signed: bool = False
    signer: str | None = None  # geprüfter Prüfschlüssel (tres0r-sig-…); None = nicht geprüft/unsigniert
    warnings: list[str] = field(default_factory=list)  # z. B. nicht setzbare ACLs


@dataclass
class VerifyResult:
    entries: int
    files: int
    bytes: int
    checked_hashes: bool = False
    segments: int = 1
    signed: bool = False
    signer: str | None = None


@dataclass
class EncryptResult:
    bytes: int
    shares: list = field(default_factory=list)


@dataclass
class DecryptResult:
    bytes: int
    signed: bool = False
    signer: str | None = None


@dataclass
class SlotInfo:
    index: int
    type: str  # "passwort" | "wiederherstellung" | "empfaenger" | "unbekannt"
    description: str
    level: str | None = None


@dataclass
class ContainerInfo:
    path: Path
    kdf: KdfParams | None  # erster Passwort-Slot (für Anzeige/RAM-Bedarf)
    level: str | None
    size: int
    version: int = 1
    header_len: int = v1.HEADER_LEN
    payload_type: str = "tar"
    compression: str | None = None
    has_index: bool = False
    slots: list[SlotInfo] = field(default_factory=list)
    signed: bool = False
    volumes: int = 1  # Anzahl Teile (--split)
    segmented: bool = False  # hat angehängte Segmente
    interrupted: bool = False  # ein Anhängen wurde unterbrochen ('repair')

    @property
    def payload_size(self) -> int:
        return max(0, self.size - self.header_len)


@dataclass
class Entry:
    name: str
    size: int
    kind: str  # "datei" | "ordner" | "link" | "sonstiges"
    mtime: int | None = None
    sha256: str | None = None
    segment: int = 0  # 0 = ursprünglicher Inhalt, ab 1 angehängt


_SLOT_KIND = {v2.SLOT_PASSWORD: "passwort", v2.SLOT_SECRET: "wiederherstellung",
              v2.SLOT_X25519: "empfaenger", v2.SLOT_PASSWORD_KEYFILE: "passwort+keyfile",
              v2.SLOT_THRESHOLD: "schwellwert", v2.SLOT_FIDO2: "passwort+fido2"}


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------
def format_size(n: int) -> str:
    """Bytezahl menschenlesbar (``1536`` -> ``"1.5 KiB"``)."""
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


def _fsync_dir(path: Path) -> None:
    """Verzeichniseintrag nach os.replace() dauerhaft machen (nur POSIX)."""
    if os.name != "posix":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _existing_ancestor(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    while not path.exists() and path.parent != path:
        path = path.parent
    return path


def check_free_space(directory: str | os.PathLike[str], needed: int, purpose: str) -> None:
    """InsufficientSpace, wenn ``needed`` Byte (+ Reserve) nicht frei sind.

    Netzlaufwerke oder Dateisysteme mit Kompression melden mitunter
    unzuverlässige Werte – Frontends sollten die Prüfung abschaltbar machen.

    ``directory``: Ordner auf dem Zieldatenträger; ``needed``: Byte; ``purpose``: Text für die Fehlermeldung ("für …").
    """
    try:
        free = shutil.disk_usage(_existing_ancestor(Path(directory))).free
    except OSError:
        return
    if needed + SPACE_MARGIN > free:
        raise InsufficientSpace(
            f"Nicht genug Speicherplatz für {purpose}: benötigt ca. {format_size(needed)}, "
            f"frei {format_size(free)}."
        )


class _Excluder:
    """Erkennt die Ausgabedatei, falls sie innerhalb einer Quelle liegt."""

    def __init__(self, paths: Sequence[Path]) -> None:
        self._stats = []
        self._names = set()
        for p in paths:
            try:
                st = os.stat(p)
            except OSError:
                continue
            self._names.add(os.path.normcase(os.path.realpath(p)))
            if st.st_ino:  # auf manchen Windows-Dateisystemen 0 -> nicht vergleichbar
                self._stats.append(st)

    def __call__(self, path: Path, st: os.stat_result) -> bool:
        if st.st_ino and any(os.path.samestat(st, other) for other in self._stats):
            return True
        return os.path.normcase(os.path.realpath(path)) in self._names


def _anonymize(ti: tarfile.TarInfo) -> tarfile.TarInfo:
    # Benutzer-/Gruppennamen und IDs verraten sonst, wer den Container gebaut hat.
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    return ti


def _mtime_ok(value) -> bool:
    """Lässt sich der Zeitstempel auf dieser Plattform setzen? (endlich, in time_t)"""
    try:
        time.gmtime(int(value))  # ValueError: nan · OverflowError: inf/zu groß · OSError: Plattform
        return True
    except (ValueError, OverflowError, OSError):
        return False


def _safe_mtime(value) -> int:
    """Zeitstempel als int; nicht darstellbare (präparierte) Werte werden zu 0."""
    return int(value) if _mtime_ok(value) else 0


def _kind(ti: tarfile.TarInfo) -> str:
    if ti.isdir():
        return "ordner"
    if ti.issym() or ti.islnk():
        return "link"
    if ti.isreg():
        return "datei"
    return "sonstiges"


# ---------------------------------------------------------------------------
# Auswahl
# ---------------------------------------------------------------------------
def plan_sources(sources: Sequence[str | os.PathLike[str]]) -> list[tuple[Path, str]]:
    """Quellen prüfen und ihre Namen im Container bestimmen (ohne Durchlaufen)."""
    if not sources:
        raise Tres0rError("Keine Dateien ausgewählt.")
    planned: list[tuple[Path, str]] = []
    seen: dict[str, Path] = {}
    for raw in sources:
        path = Path(raw)
        if not os.path.lexists(path):
            raise Tres0rError(f"Nicht gefunden: {path}")
        name = path.name or Path(os.path.realpath(path)).name
        if not name:
            raise Tres0rError(f"Kann für {path} keinen Namen im Container bestimmen.")
        if name in seen:
            raise Tres0rError(
                f"Zwei Quellen heißen '{name}' ({seen[name]} und {path}). "
                "Bitte umbenennen oder einen gemeinsamen Ordner auswählen."
            )
        seen[name] = path
        planned.append((path, name))
    return planned


def scan(
    sources: Sequence[str | os.PathLike[str]],
    *,
    exclude: ExcludeRules | None = None,
    ignore_files: bool = True,
    output: str | os.PathLike[str] | None = None,
    progress: Progress = None,
) -> Plan:
    """Quellen durchlaufen und festlegen, was in den Container kommt.

    * ``exclude`` passt auf Pfade, wie ``tres0r list`` sie zeigt ("Projekt/build").
    * Eine ``.tres0rignore`` direkt in einem Quellordner gilt relativ zu diesem.
    * Explizit angegebene Quellen werden nie ausgeschlossen.
    """
    rules = exclude or ExcludeRules()
    excluder = _Excluder([Path(output)] if output is not None else [])
    plan = Plan()
    counter = _tracker(progress, "durchsuchen", None, UNIT_ENTRIES)

    for root, arcname in plan_sources(sources):
        root_st = os.lstat(root)
        local = ExcludeRules()
        if ignore_files and stat.S_ISDIR(root_st.st_mode) and (root / IGNORE_FILE).is_file():
            local = ExcludeRules.from_file(root / IGNORE_FILE)

        # Iterativ statt rekursiv: keine Grenze bei tiefen Verzeichnisbäumen.
        stack: list[tuple[Path, str, str, os.stat_result]] = [(root, arcname, "", root_st)]
        while stack:
            path, arc, rel, st = stack.pop()
            if excluder(path, st):
                continue
            mode = st.st_mode
            is_dir = stat.S_ISDIR(mode)
            if rel and (rules.matches(arc, is_dir) or local.matches(rel, is_dir)):
                plan.excluded += 1
                continue
            if counter is not None:
                counter(1)
                counter.item(arc)
            if stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                plan.entries.append((path, arc, st))
            elif is_dir:
                plan.entries.append((path, arc, st))
                with os.scandir(path) as it:
                    children = sorted(it, key=lambda e: e.name)
                for child in reversed(children):  # reversed -> pop() liefert sortiert
                    stack.append(
                        (
                            Path(child.path),
                            f"{arc}/{child.name}",
                            f"{rel}/{child.name}" if rel else child.name,
                            child.stat(follow_symlinks=False),
                        )
                    )
            else:
                plan.skipped.append(str(path))

    plan.issues = portability.check_names(
        (arc, stat.S_ISDIR(st.st_mode)) for _, arc, st in plan.entries
    )
    if counter is not None:
        counter.finish()
    return plan


def estimate_size(plan: Plan, pad: bool = True) -> int:
    """Obere Schätzung der Containergröße in Byte (ohne Kompression gerechnet)."""
    tar_bytes = 2 * 512  # Archivende
    index_bytes = 64
    for _, arc, st in plan.entries:
        tar_bytes += 3 * 512  # Header + ggf. PAX-Erweiterung (Unicode, lange Namen)
        index_bytes += 200 + len(json.dumps(arc))  # so, wie der Index den Namen speichert
        if stat.S_ISREG(st.st_mode):
            tar_bytes += -(-st.st_size // 512) * 512
    tar_bytes = -(-tar_bytes // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
    blocks = 4 * (len(plan.entries) + tar_bytes // payload.MAX_BLOCK + 2)
    plain = tar_bytes + blocks + index_bytes + 16
    if pad:
        plain = padme(plain)
    return 2048 + encrypted_size(plain)  # 2048: großzügig für den Header


def _make_slots(
    dek: bytes,
    password: str | bytes | None,
    params: KdfParams | None,
    recipients: Sequence[X25519PublicKey],
    recovery: str | None,
    keyfile: bytes | None = None,
    threshold: tuple[int, int] | None = None,
    fido2=None,
) -> tuple[list[v2.Slot], list]:
    """Keyslots für einen neuen Container; gibt (Slots, Shamir-Anteile) zurück."""
    if password is None and not recipients and not recovery and not threshold:
        raise Tres0rError("Mindestens ein Passwort, eine Wiederherstellungsphrase, ein Schwellwert "
                          "oder ein Empfänger ist nötig.")
    if (keyfile is not None or fido2 is not None) and password is None:
        raise Tres0rError("Keyfile und FIDO2-Token sind der zweite Faktor zu einem Passwort – "
                          "bitte auch ein Passwort setzen.")
    if keyfile is not None and fido2 is not None:
        raise Tres0rError("Bitte entweder ein Keyfile oder einen FIDO2-Token als zweiten Faktor.")
    slots, shares = [], []
    if password is not None:
        params = params or LEVELS[DEFAULT_LEVEL]
        if fido2 is not None:  # zwei Berührungen: Registrierung und erstes Geheimnis
            slots.append(v2.password_fido2_slot(dek, password, params, *fido2.enroll()))
        elif keyfile is not None:
            slots.append(v2.password_keyfile_slot(dek, password, keyfile, params))
        else:
            slots.append(v2.password_slot(dek, password, params))
    if recovery:
        slots.append(v2.secret_slot(dek, recovery))
    if threshold:
        slot, shares = v2.threshold_slot(dek, *threshold)
        slots.append(slot)
    slots.extend(v2.x25519_slot(dek, r) for r in recipients)
    return slots, shares


class _HashingReader:
    """Liest eine Quelldatei, hasht mit (ggf. im Hintergrund-Thread) und meldet Fortschritt."""

    def __init__(self, src: BinaryIO, digest, on_bytes: Callable[[int], None] | None,
                 hasher: workers.InlineHasher | None = None) -> None:
        self._src, self._digest, self._on_bytes = src, digest, on_bytes
        self._hasher = hasher or workers.InlineHasher()

    def read(self, size: int = -1) -> bytes:
        data = self._src.read(size)
        if data:
            self._hasher.update(self._digest, data)
        if self._on_bytes and data:
            self._on_bytes(len(data))
        return data


XATTR_PREFIX = "SCHILY.xattr."  # PAX-Konvention von star/GNU tar/bsdtar
ACL_NAMES = ("system.posix_acl_access", "system.posix_acl_default")


def _wanted_xattr(name: str, xattrs: bool, acls: bool) -> bool:
    """Nur user.* (xattrs) und POSIX-ACLs (acls) – nie security.*/trusted.*:
    Letztere könnten z. B. Datei-Capabilities (Rechteausweitung) setzen."""
    return (xattrs and name.startswith("user.")) or (acls and name in ACL_NAMES)


def _read_xattrs(path: Path, is_link: bool, xattrs: bool, acls: bool) -> dict[str, str]:
    if is_link:
        return {}  # Linux erlaubt user.* nicht an Symlinks
    found = {}
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError:  # Dateisystem ohne xattr-Unterstützung
        return {}
    for name in names:
        if _wanted_xattr(name, xattrs, acls):
            try:
                value = os.getxattr(path, name, follow_symlinks=False)
            except OSError:
                continue
            found[XATTR_PREFIX + name] = value.decode("utf-8", "surrogateescape")  # binär-sicher
    return found


def _require_xattr_support() -> None:
    if not hasattr(os, "listxattr"):
        raise Tres0rError("Erweiterte Attribute/ACLs werden nur unter Linux unterstützt.")


def _index_kind(ti: tarfile.TarInfo) -> str:
    if ti.isreg():
        return "f"
    if ti.isdir():
        return "d"
    if ti.issym():
        return "l"
    if ti.islnk():
        return "h"
    return "o"


def _write_tar_payload(out: BinaryIO, key: bytes, header, entries, *, compress: bool, pad: bool,
                       sign_with: Ed25519PrivateKey | None, progress: Progress, times: bool, xattrs: bool,
                       acls: bool, threads: int) -> tuple[list[payload.IndexEntry], int]:
    """Einen vollständigen tar-Nutzdatenstrom schreiben (Container oder angehängtes Segment):
    Blöcke, Inhaltsverzeichnis, Padding, ggf. Signatur. ``header`` liefert Nonce,
    Kompression und Flags für die Signatur."""
    total = sum(st.st_size for _, _, st in entries if stat.S_ISREG(st.st_mode))
    enc = EncryptingWriter(out, key)
    if sign_with is not None:
        enc.digest = hashlib.sha256()
    writer = payload.PayloadWriter(enc, compress, threads=threads)
    on_bytes = _tracker(progress, "packen", total)
    index: list[payload.IndexEntry] = []
    with workers.hasher(threads) as hasher, \
            tarfile.open(fileobj=writer, mode="w", format=tarfile.PAX_FORMAT, copybufsize=TAR_BUFSIZE) as tar:
        for path, arcname, st in entries:
            if on_bytes is not None:
                on_bytes.item(arcname)
            ti = _anonymize(tar.gettarinfo(os.fspath(path), arcname=arcname))
            if not times:
                ti.mtime = 0
            if xattrs or acls:
                ti.pax_headers.update(_read_xattrs(path, stat.S_ISLNK(st.st_mode), xattrs, acls))
            offset, skip = writer.mark()
            entry = payload.IndexEntry(
                name=ti.name, kind=_index_kind(ti), size=ti.size if ti.isreg() else 0,
                mtime=_safe_mtime(ti.mtime), offset=offset, skip=skip,
                link=ti.linkname if (ti.issym() or ti.islnk()) else None,
            )
            if ti.isreg():
                digest = hashlib.sha256()
                with open(path, "rb") as src:
                    tar.addfile(ti, _HashingReader(src, digest, on_bytes, hasher))
                entry.sha256 = hasher.hexdigest(digest)
            else:
                tar.addfile(ti)
            index.append(entry)
    writer.close()
    padding = _finish_payload(enc, payload.index_trailer(payload.encode_index(index)), pad, sign_with, header)
    if on_bytes is not None:
        on_bytes.finish()
    return index, padding


def _finish_payload(enc: EncryptingWriter, trailer: bytes, pad: bool,
                    signer: Ed25519PrivateKey | None = None, header=None) -> int:
    """Padding, Inhaltsverzeichnis und ggf. Signaturanhang schreiben, Stream abschließen.

    Beim Signieren muss ``enc.digest`` seit dem ersten Byte mitlaufen.
    """
    extra = sign.TRAILER_LEN if signer is not None else 0
    base = enc.plain_bytes + len(trailer) + extra
    padding = padme(base) - base if pad else 0
    enc.write_zeros(padding)
    enc.write(trailer)
    if signer is not None:
        enc.write(sign.trailer(signer, header, enc.digest.digest()))
    enc.finish()
    return padding


# ---------------------------------------------------------------------------
# Anlegen
# ---------------------------------------------------------------------------
def create(
    sources: Sequence[str | os.PathLike[str]] | Plan,
    output: str | os.PathLike[str],
    password: str | bytes | None,
    params: KdfParams | None = None,
    *,
    recipients: Sequence[X25519PublicKey] = (),
    recovery: str | None = None,
    keyfile: bytes | None = None,
    threshold: tuple[int, int] | None = None,
    fido2=None,
    compress: bool = False,
    sign_with: Ed25519PrivateKey | None = None,
    overwrite: bool = False,
    progress: Progress | None = None,
    exclude: ExcludeRules | None = None,
    pad: bool = True,
    strict_names: bool = False,
    check_space: bool = True,
    times: bool = True,
    xattrs: bool = False,
    acls: bool = False,
    threads: int | None = None,
    split: int | None = None,
) -> CreateResult:
    """Dateien/Ordner in einen neuen verschlüsselten Container packen (Format v2).

    ``sources`` ist eine Pfadliste oder ein vorab erstellter ``Plan``. Keyslots:
    ``password`` (Argon2id mit ``params``), ``recovery`` (generierte Phrase,
    siehe keys.generate_recovery) und beliebig viele X25519-``recipients``.

    Metadaten: ``times=False`` speichert keine Änderungszeiten (0 = "unbekannt";
    beim Entpacken gilt dann die aktuelle Zeit). ``xattrs``/``acls`` übernehmen
    user.*-Attribute bzw. POSIX-ACLs (nur Linux). ``threads``: SHA-256 im
    Hintergrund und zstd-Worker (None = automatisch, 1 = aus).
    Geschrieben wird in eine temporäre Datei im Zielordner, die erst nach
    vollständigem Erfolg per atomarem os.replace() umbenannt wird.
    """
    if params is not None:
        params.validate()
    output = Path(output)
    plan = sources if isinstance(sources, Plan) else scan(sources, exclude=exclude, output=output)
    if strict_names and plan.issues:
        raise NameConflict(
            f"{len(plan.issues)} Name(n) sind nicht auf allen Systemen gültig, z. B. "
            f"{plan.issues[0].path}: {plan.issues[0].detail}."
        )
    if volumes.exists(output) and not overwrite:
        raise Tres0rError(f"{output} existiert bereits.")
    parent = output.parent if str(output.parent) else Path(".")
    if not parent.is_dir():
        raise Tres0rError(f"Zielordner {parent} existiert nicht.")
    if compress:
        payload._require_zstd()
    if xattrs or acls:
        _require_xattr_support()
    threads = workers.resolve_threads(threads)
    if check_space:
        check_free_space(parent, estimate_size(plan, pad), "den Container")

    with atomic_output(output, overwrite=overwrite, split=split) as f:
        excluder = _Excluder([output])
        entries = [e for e in plan.entries
                   if not excluder(e[0], e[2]) and not volumes.is_part_of(e[0], output)]
        dek = rng.random_bytes(32)
        kdf_phase = _tracker(progress, "schlüssel")
        slots, shares = _make_slots(dek, password, params, recipients, recovery, keyfile,
                                    threshold, fido2)  # langsam: Argon2id (und ggf. Token-Berührungen)
        if kdf_phase is not None:
            kdf_phase.finish()
        header = v2.HeaderV2.create(
            dek, slots, payload_type=v2.PAYLOAD_TAR,
            compression=v2.COMPRESS_ZSTD if compress else v2.COMPRESS_NONE,
            flags=v2.FLAG_INDEX | (v2.FLAG_SIGNED if sign_with is not None else 0),
        )
        f.write(header.to_bytes())
        index, padding = _write_tar_payload(
            f, header.payload_key(dek), header, entries, compress=compress, pad=pad, sign_with=sign_with,
            progress=progress, times=times, xattrs=xattrs, acls=acls, threads=threads)
    return CreateResult(
        path=output,
        entries=len(entries),
        size=volumes.open_read(output)[1],
        padding=padding,
        skipped=list(plan.skipped),
        excluded=plan.excluded,
        issues=list(plan.issues),
        slots=[s.describe() for s in header.slots],
        shares=shares,
    )


# ---------------------------------------------------------------------------
# Öffnen
# ---------------------------------------------------------------------------
@dataclass
class _Opened:
    f: BinaryIO
    header: AnyHeader
    dek: bytes
    slot: int
    payload_size: int | None  # None = Pipe (Größe unbekannt, kein wahlfreier Zugriff)

    @property
    def key(self) -> bytes:
        return self.header.payload_key(self.dek)

    tracker = None
    notes = ()  # Hinweise (nur salvage), bewusst kein Dataclass-Feld

    @property
    def indexed(self) -> bool:
        """Inhaltsverzeichnis nutzbar? (Nur bei seekbaren Dateien, nicht bei Pipes.)"""
        return self.header.version == 2 and self.header.has_index and self.payload_size is not None

    def item(self, name: str) -> None:
        if self.tracker is not None:
            self.tracker.item(name)

    def done(self) -> None:
        if self.tracker is not None:
            self.tracker.finish()

    def random_access(self) -> payload.RandomAccessPayload:
        return payload.RandomAccessPayload(self.f, self.key, self.header.header_len, self.payload_size)

    @property
    def signed(self) -> bool:
        return self.header.version == 2 and self.header.signed

    def read_index(self) -> list[payload.IndexEntry] | None:
        if not self.indexed:
            return None
        return payload.read_index(self.random_access(), sign.TRAILER_LEN if self.signed else 0)

    def check_signature(self, signers=None) -> str | None:
        """Nach vollständigem Lesen über stream(): Signatur prüfen, ggf. Unterzeichner verlangen."""
        key = None
        if self.signed:
            digest, tail = self.hasher.finish()
            key = sign.verify(self.header, digest, tail)
        sign.require(key, signers)
        return encode_verify_key(key) if key is not None else None

    def stream(self, progress: Progress = None, phase: str = "lesen", prefetch: bool | None = None
               ) -> tuple[DecryptingReader, payload.BlockReader | None, BinaryIO]:
        """Sequentieller Leser ab Nutzdatenbeginn: (Entschlüsseler, Blockleser, Datenstrom).

        Bei Dateien wird an den Nutzdatenbeginn gesprungen; bei Pipes (payload_size
        None) steht der Leser bereits dort. ``self.tracker`` zählt mit.
        """
        if self.payload_size is not None:
            self.f.seek(self.header.header_len)
        self.hasher = sign.TailHasher() if self.signed else None
        self.tracker = _tracker(progress, phase, self.payload_size)
        reader = DecryptingReader(self.f, self.key, self.tracker, self.hasher)
        if self.header.version == 1:
            return reader, None, reader  # v1: tar-Stream direkt, danach Nullbytes
        blocks, data = payload.decoded_reader(reader, self.header.compression)
        if prefetch is None:  # Standard: automatisch nach Kernzahl
            prefetch = workers.resolve_threads(None) > 1
        if prefetch and self.header.compression:  # unkomprimiert gäbe es nichts zu überlappen
            data = payload.Prefetcher(data)
            blocks.before_drain.append(data.close)
            self._prefetchers.append(data)
        return reader, blocks, data

    @property
    def _prefetchers(self) -> list:
        if "_prefetch_list" not in self.__dict__:
            self.__dict__["_prefetch_list"] = []
        return self.__dict__["_prefetch_list"]

    def close(self) -> None:
        """Hintergrund-Leser anhalten (bei jedem Ende, auch nach Fehlern)."""
        for prefetcher in self._prefetchers:
            prefetcher.close()


def _unlock(header: AnyHeader, credentials: Unlock) -> tuple[bytes, int]:
    if header.version == 2:
        return header.unlock(credentials)
    creds = Credentials.coerce(credentials)
    candidates = creds.password_candidates()
    if not candidates:
        raise WrongPassword("Dieser Container (Format v1) braucht ein Passwort.")
    error: Exception | None = None
    for candidate in candidates:
        try:
            return header.unlock(candidate), 0
        except WrongPassword as e:
            error = e
    raise error


@dataclass
class _SegmentView:
    """Sieht für die Lesepfade aus wie ein v2-Header – für ein einzelnes Segment."""

    number: int
    payload_type: int
    compression: int
    flags: int
    stream_nonce: bytes
    header_len: int  # absoluter Beginn des Segments in der Datei
    version: int = 2

    @property
    def has_index(self) -> bool:
        return bool(self.flags & v2.FLAG_INDEX)

    @property
    def signed(self) -> bool:
        return bool(self.flags & v2.FLAG_SIGNED)

    def payload_key(self, dek: bytes) -> bytes:
        return v2.payload_key_for(dek, self.stream_nonce)


INTERRUPTED = "Ein Anhängen an diesen Container wurde unterbrochen – 'tres0r repair' stellt einen gültigen Stand her."


def _interrupted(path: Path, header: AnyHeader, f, total: int) -> bool:
    """Liegt ein Journal vor und ist der Container nicht im fertigen Zustand?"""
    if segments.read_journal(volumes.base_of(path) or path) is None:
        return False
    if header.version != 2 or not header.segmented:
        return True
    f.seek(max(0, total - len(segments.MAGIC)))
    return f.read(len(segments.MAGIC)) != segments.MAGIC


def _segment_ops(f, header, dek: bytes, slot: int, total: int) -> list[_Opened]:
    table, _ = segments.read_table(f, total, header.header_len, dek, header.stream_nonce)
    ops = []
    for number, e in enumerate(table):
        start = header.header_len + e.offset
        view = _SegmentView(number, header.payload_type, e.compression, e.flags, e.nonce, start)
        ops.append(_Opened(segments.Window(f, start, e.length), view, dek, slot, e.length))
    return ops


def _find_first_segment_end(f, header, dek: bytes, total: int) -> int | None:
    """Ende von Segment 0 ohne Tabelle finden (nur für salvage): Chunks der Reihe nach
    prüfen; der erste, der nicht als gewöhnlicher Chunk passt, muss der Abschluss-Chunk
    sein – dessen Länge ergibt sich aus der einzigen, die sich mit Abschluss-Flag
    authentifizieren lässt."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    from .stream import ENC_CHUNK_SIZE, TAG_LEN, _nonce

    aead = ChaCha20Poly1305(header.payload_key(dek))
    counter, position = 0, header.header_len
    while position < total:
        f.seek(position)
        data = f.read(min(ENC_CHUNK_SIZE, total - position))
        if len(data) == ENC_CHUNK_SIZE:
            try:
                aead.decrypt(_nonce(counter, False), data, None)
                counter, position = counter + 1, position + ENC_CHUNK_SIZE
                continue
            except InvalidTag:
                pass
        for length in range(len(data), TAG_LEN - 1, -1):
            try:
                aead.decrypt(_nonce(counter, True), data[:length], None)
                return position + length
            except InvalidTag:
                continue
        return None
    return None


@contextmanager
def _open_segments(path: Path, credentials: Unlock, progress: Progress = None,
                   tolerant: bool = False) -> Iterator[list[_Opened]]:
    """Container öffnen: je Segment ein _Opened (ohne angehängte Segmente genau eines).

    ``tolerant`` (salvage): Ist die Segmenttabelle unlesbar, gibt es nur Segment 0
    bis zum Dateiende; ``notes`` am ersten Eintrag sagt warum."""
    f, total = volumes.open_read(path)
    with f:
        header = read_header(f)
        if _interrupted(path, header, f, total) and not tolerant:
            raise FormatError(INTERRUPTED)
        dek, slot = _unlock_tracked(header, credentials, progress)
        if header.version == 2 and header.segmented:
            try:
                ops = _segment_ops(f, header, dek, slot, total)
            except (FormatError, IntegrityError) as e:
                if not tolerant:
                    raise
                view = _SegmentView(0, header.payload_type, header.compression,
                                    header.flags & segments.SEGMENT_FLAGS, header.stream_nonce, header.header_len)
                end = _find_first_segment_end(f, header, dek, total)
                length = (end if end is not None else total) - header.header_len
                op = _Opened(segments.Window(f, header.header_len, length), view, dek, slot, length)
                op.notes = [f"Segmenttabelle nicht lesbar ({_reason(e)}) – rette nur den ursprünglichen Inhalt."]
                ops = [op]
            try:
                yield ops
            finally:
                for op in ops:
                    op.close()
        else:
            op = _Opened(f, header, dek, slot, total - header.header_len)
            try:
                yield [op]
            finally:
                op.close()


def _unlock_tracked(header: AnyHeader, credentials: Unlock, progress: Progress) -> tuple[bytes, int]:
    phase = _tracker(progress, "schlüssel")
    result = _unlock(header, credentials)  # langsam: Argon2id (nur Passwort-Slots)
    if phase is not None:
        phase.finish()
    return result


@contextmanager
def _open(path: Path, credentials: Unlock, progress: Progress = None) -> Iterator[_Opened]:
    f, total = volumes.open_read(path)  # einzelne Datei oder Teilesatz
    with f:
        header = read_header(f)
        dek, slot = _unlock_tracked(header, credentials, progress)
        op = _Opened(f, header, dek, slot, total - header.header_len)
        try:
            yield op
        finally:
            op.close()


def _finish(reader: DecryptingReader, blocks: payload.BlockReader | None) -> None:
    if blocks is not None:
        blocks.drain()
    reader.finish()


# ---------------------------------------------------------------------------
# Lesen
# ---------------------------------------------------------------------------
def inspect(container: str | os.PathLike[str]) -> ContainerInfo:
    """Header-Informationen lesen – ohne Passwort. Bei v2 sind die Angaben erst
    nach dem Entsperren durch die Header-MAC bestätigt."""
    path = Path(container)
    f, size = volumes.open_read(path)
    with f:
        header = read_header(f)
    base = volumes.base_of(path)
    parts = len(volumes.parts_of(base)) if base is not None else 1
    interrupted = segments.read_journal(base or path) is not None
    if header.version == 1:
        level = level_of(header.kdf)
        return ContainerInfo(path=path, kdf=header.kdf, level=level, size=size,
                             slots=[SlotInfo(0, "passwort", "Passwort", level)], volumes=parts)
    slots = []
    for i, slot in enumerate(header.slots):
        level = level_of(slot.kdf) if slot.kdf else None
        slots.append(SlotInfo(i, _SLOT_KIND.get(slot.type, "unbekannt"), slot.describe(), level))
    first_pw = next((s.kdf for s in header.slots if s.type == v2.SLOT_PASSWORD), None)
    return ContainerInfo(
        path=path, kdf=first_pw, level=level_of(first_pw) if first_pw else None, size=size,
        version=2, header_len=header.header_len,
        payload_type="tar" if header.payload_type == v2.PAYLOAD_TAR else "roh",
        compression="zstd" if header.compression == v2.COMPRESS_ZSTD else None,
        has_index=header.has_index, slots=slots, signed=header.signed, volumes=parts,
        segmented=header.segmented, interrupted=interrupted,
    )


def _entry_from_index(e: payload.IndexEntry) -> Entry:
    return Entry(name=e.name, size=e.size, kind=payload.KINDS[e.kind], mtime=e.mtime, sha256=e.sha256)


def list_contents(
    container: str | os.PathLike[str], credentials: Unlock, *, progress: Progress | None = None
) -> list[Entry]:
    """Inhaltsverzeichnis. Bei v2 aus dem Index – dafür werden nur die letzten
    Chunks entschlüsselt. Vollständig prüft ``verify``."""
    path = Path(container)
    with _open_segments(path, credentials, progress) as ops:
        if len(ops) == 1:
            return _list_op(ops[0], progress)
        newest: dict[str, Entry] = {}
        for op in ops:
            for entry in _list_op(op, progress):
                entry.segment = op.header.number
                newest.pop(entry.name, None)  # neuere Fassung ersetzt ältere
                newest[entry.name] = entry
        return list(newest.values())


def _list_op(op: _Opened, progress: Progress) -> list[Entry]:
    if op.header.version == 2 and op.header.payload_type == v2.PAYLOAD_RAW:
        raise Tres0rError("Rohdaten-Container haben kein Inhaltsverzeichnis – 'decrypt' verwenden.")
    index = op.read_index()
    if index is not None:
        return [_entry_from_index(e) for e in index]
    entries: list[Entry] = []
    reader, blocks, data = op.stream(progress, "lesen")
    try:
        with tarfile.open(fileobj=data, mode="r|") as tar:
            for ti in tar:
                op.item(ti.name)
                entries.append(Entry(name=ti.name, size=ti.size, kind=_kind(ti), mtime=_safe_mtime(ti.mtime)))
    except tarfile.TarError as e:
        raise FormatError(f"Archiv im Container ist defekt: {e}") from None
    _finish(reader, blocks)
    op.done()
    return entries


def verify(
    container: str | os.PathLike[str],
    credentials: Unlock,
    *,
    progress: Progress | None = None,
    signers: Sequence[Ed25519PublicKey] | None = None,
    threads: int | None = None,
) -> VerifyResult:
    """Container vollständig prüfen, ohne etwas zu schreiben.

    Authentifiziert jeden Chunk inkl. Padding und Index. Bei v2 mit Index wird
    zusätzlich jeder tar-Eintrag mit dem Inhaltsverzeichnis abgeglichen
    (Name, Typ, Größe, SHA-256). Ist der Container signiert, wird die Signatur
    geprüft; ``signers`` verlangt zusätzlich einen dieser Unterzeichner.
    Ohne Exception ist der Container intakt.
    """
    path = Path(container)
    with _open_segments(path, credentials, progress) as ops, \
            workers.hasher(workers.resolve_threads(threads)) as hasher:
        use_threads = workers.resolve_threads(threads) > 1
        results = [_verify_op(op, progress, signers, hasher, use_threads) for op in ops]
    if len(results) == 1:
        return results[0]
    seen = sorted({r.signer for r in results if r.signer})
    return VerifyResult(entries=sum(r.entries for r in results), files=sum(r.files for r in results),
                        bytes=sum(r.bytes for r in results),
                        checked_hashes=all(r.checked_hashes for r in results),
                        signed=all(r.signed for r in results), signer=", ".join(seen) or None,
                        segments=len(results))


def _verify_op(op: _Opened, progress: Progress, signers, hasher, prefetch: bool | None = None) -> VerifyResult:
    count = files = total = 0
    index = op.read_index()
    reader, blocks, data = op.stream(progress, "prüfen", prefetch=prefetch)
    if op.header.version == 2 and op.header.payload_type == v2.PAYLOAD_RAW:
        while chunk := data.read(1 << 20):
            total += len(chunk)
        _finish(reader, blocks)
        signer = op.check_signature(signers)
        op.done()
        return VerifyResult(entries=1, files=1, bytes=total, signed=op.signed, signer=signer)
    try:
        with tarfile.open(fileobj=data, mode="r|") as tar:
            for ti in tar:
                op.item(ti.name)
                expected = None
                if index is not None:
                    if count >= len(index):
                        raise FormatError("Archiv enthält mehr Einträge als das Inhaltsverzeichnis.")
                    expected = index[count]
                    if (expected.name, expected.kind) != (ti.name, _index_kind(ti)) or (
                        ti.isreg() and expected.size != ti.size
                    ):
                        raise FormatError(f"Inhaltsverzeichnis passt nicht zum Archiv bei '{ti.name}'.")
                if ti.isreg():
                    digest = hashlib.sha256()
                    source = tar.extractfile(ti)
                    while chunk := source.read(1 << 20):
                        hasher.update(digest, chunk)  # auf zweitem Kern parallel zur Entschlüsselung
                    if expected is not None and expected.sha256 != hasher.hexdigest(digest):
                        raise FormatError(f"Prüfsumme von '{ti.name}' passt nicht zum Inhaltsverzeichnis.")
                    files += 1
                    total += ti.size
                count += 1
    except tarfile.TarError as e:
        raise FormatError(f"Archiv im Container ist defekt: {e}") from None
    if index is not None and count != len(index):
        raise FormatError("Inhaltsverzeichnis enthält Einträge, die im Archiv fehlen.")
    _finish(reader, blocks)
    signer = op.check_signature(signers)
    signed = op.signed
    op.done()
    return VerifyResult(entries=count, files=files, bytes=total, checked_hashes=index is not None,
                        signed=signed, signer=signer)


# ---------------------------------------------------------------------------
# Entpacken
# ---------------------------------------------------------------------------
def _matches(name: str, patterns: Sequence[str]) -> bool:
    """Treffer, wenn der Pfad oder einer seiner Ordner auf ein Muster passt."""
    parts = name.split("/")
    prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    return any(fnmatchcase(p, pat.rstrip("/")) for pat in patterns for p in prefixes)


def _select(index: list[payload.IndexEntry], patterns: Sequence[str]) -> list[int]:
    chosen = {i for i, e in enumerate(index) if _matches(e.name, patterns)}
    # Hardlinks brauchen ihr Ziel (den letzten gleichnamigen Eintrag davor)
    for i in sorted(chosen):
        if index[i].kind == "h":
            target = next((j for j in range(i - 1, -1, -1) if index[j].name == index[i].link), None)
            if target is None:
                raise FormatError(f"Ziel des Hardlinks '{index[i].name}' fehlt.")
            chosen.add(target)
    return sorted(chosen)


def _runs(positions: list[int]) -> list[list[int]]:
    runs: list[list[int]] = []
    for pos in positions:
        if runs and runs[-1][-1] == pos - 1:
            runs[-1].append(pos)
        else:
            runs.append([pos])
    return runs


def _extract_indexed(op: _Opened, index: list[payload.IndexEntry], positions: list[int],
                     staging: Path, guard, counter=None) -> None:
    """Nur ausgewählte Einträge: pro zusammenhängendem Lauf direkt einsteigen."""
    access = op.random_access()
    for run in _runs(positions):
        first = index[run[0]]
        _, data = payload.decoded_reader(access.open_at(first.offset), op.header.compression)
        payload.skip(data, first.skip)
        with tarfile.open(fileobj=data, mode="r|") as tar:

            def members(tar=tar, run=run):
                for pos in run:
                    ti = tar.next()
                    if ti is None or ti.name != index[pos].name:
                        raise FormatError("Inhaltsverzeichnis zeigt auf den falschen Eintrag.")
                    if counter is not None:
                        counter.item(ti.name)
                        counter(1)
                    yield ti

            tar.extractall(staging, members=members(), filter=guard)


def extract(
    container: str | os.PathLike[str],
    dest: str | os.PathLike[str],
    credentials: Unlock,
    *,
    progress: Progress = None,
    rename: bool = False,
    check_space: bool = True,
    only: Sequence[str] | None = None,
    signers: Sequence[Ed25519PublicKey] | None = None,
    xattrs: bool = False,
    acls: bool = False,
) -> ExtractResult:
    """Container in ``dest`` entpacken.

    Entpackt wird zunächst in einen versteckten Staging-Ordner innerhalb von
    ``dest``; erst danach werden die Einträge an ihren Platz verschoben. Bei
    jedem Fehler bleibt ``dest`` unverändert.

    ``only``: Muster (fnmatch) für Pfade; ein passender Ordner bringt seinen
    Inhalt mit. Bei v2 springt tres0r über den Index direkt zu den Einträgen
    und prüft dabei nur die gelesenen Chunks (plus den Abschluss) – für eine
    Vollprüfung ``verify`` verwenden. Ohne ``only`` wird immer alles geprüft.

    Namenskollisionen und (unter Windows) ungültige Namen führen zum Abbruch
    (NameConflict) oder mit ``rename=True`` zum Umbenennen.

    Signatur: Beim vollständigen Lesen wird sie geprüft, bevor irgendetwas im
    Zielordner landet. ``signers`` verlangt einen dieser Unterzeichner – dann
    wird auch mit ``only`` alles gelesen, weil nur so geprüft werden kann.
    """
    with _open_segments(Path(container), credentials, progress) as ops:
        if len(ops) == 1:
            return _extract_opened(ops[0], Path(dest), progress=progress, rename=rename, check_space=check_space,
                                   only=only, signers=signers, xattrs=xattrs, acls=acls)
        return _extract_segments(ops, Path(dest), progress=progress, rename=rename, check_space=check_space,
                                 only=only, signers=signers, xattrs=xattrs, acls=acls)


def _merge_tree(src: Path, dst: Path) -> None:
    """src in dst einsortieren; bei gleichem Namen gewinnt src (das neuere Segment)."""
    for item in os.scandir(src):
        target = dst / item.name
        if item.is_dir(follow_symlinks=False) and target.is_dir() and not target.is_symlink():
            _merge_tree(Path(item.path), target)
            continue
        if os.path.lexists(target):
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink()
        os.replace(item.path, target)


def _extract_segments(ops: list[_Opened], dest: Path, *, progress: Progress, rename: bool, check_space: bool,
                      only, signers, xattrs: bool, acls: bool) -> ExtractResult:
    if check_space:
        check_free_space(dest, sum(op.payload_size or 0 for op in ops), "das Entpacken")
    dest.mkdir(parents=True, exist_ok=True)
    merged = Path(tempfile.mkdtemp(prefix=".tres0r-", dir=dest))
    result = ExtractResult(names=[], entries=0, renamed=[], signed=True)
    seen = set()
    try:
        for op in ops:
            part = Path(tempfile.mkdtemp(prefix=".tres0r-segment-", dir=dest))
            try:
                one = _extract_opened(op, part, progress=progress, rename=rename, check_space=False, only=only,
                                      signers=signers, xattrs=xattrs, acls=acls, require_match=False)
                _merge_tree(part, merged)
            finally:
                shutil.rmtree(part, ignore_errors=True)
            result.entries += one.entries
            result.renamed += one.renamed
            result.warnings += one.warnings
            result.signed = result.signed and one.signed
            if one.signer:
                seen.add(one.signer)
        if only and result.entries == 0:
            raise Tres0rError("Kein Eintrag passt zu: " + ", ".join(only))
        names = sorted(os.listdir(merged))
        conflicts = [n for n in names if os.path.lexists(dest / n)]
        if conflicts:
            raise Tres0rError("Im Zielordner existiert bereits: " + ", ".join(conflicts))
        for name in names:
            os.replace(merged / name, dest / name)
    finally:
        shutil.rmtree(merged, ignore_errors=True)
    result.names = names
    result.signer = ", ".join(sorted(seen)) or None
    return result


def extract_stream(
    src: BinaryIO,
    dest: str | os.PathLike[str],
    credentials: Unlock,
    *,
    progress: Progress = None,
    rename: bool = False,
    only: Sequence[str] | None = None,
    signers: Sequence[Ed25519PublicKey] | None = None,
    xattrs: bool = False,
    acls: bool = False,
) -> ExtractResult:
    """Container aus einem Datenstrom (Pipe, stdin) entpacken – mit denselben
    Schutzmechanismen wie ``extract``: Staging-Ordner, Namensschutz, data-Filter,
    Signaturprüfung vor dem Verschieben. Ohne wahlfreien Zugriff: kein
    Inhaltsverzeichnis, keine Speicherplatzprüfung, ``only`` filtert beim Lesen.
    """
    header = read_header(src)
    if header.version == 2 and header.segmented:
        raise Tres0rError("Container mit angehängten Segmenten lassen sich nicht aus einer Pipe entpacken "
                          "(die Segmenttabelle steht am Ende) – bitte als Datei übergeben.")
    dek, slot = _unlock_tracked(header, credentials, progress)
    op = _Opened(src, header, dek, slot, None)
    try:
        return _extract_opened(op, Path(dest), progress=progress, rename=rename, check_space=False,
                               only=only, signers=signers, xattrs=xattrs, acls=acls)
    finally:
        op.close()


def _apply_xattrs(staging: Path, collected: list[tuple[str, dict[str, bytes]]]) -> list[str]:
    """Erweiterte Attribute im Staging-Ordner setzen; Fehlschläge werden gemeldet, nicht fatal."""
    warnings = []
    for name, attributes in collected:
        target = staging / name
        for key, value in attributes.items():
            try:
                os.setxattr(target, key, value, follow_symlinks=False)
            except OSError as e:
                warnings.append(f"{name}: {key} nicht gesetzt ({e.strerror or e})")
    return warnings


def _extract_opened(op: _Opened, dest: Path, *, progress: Progress, rename: bool, check_space: bool,
                    only: Sequence[str] | None, signers, xattrs: bool = False, acls: bool = False,
                    require_match: bool = True) -> ExtractResult:
    if xattrs or acls:
        _require_xattr_support()
    signer = None
    if op.header.version == 2 and op.header.payload_type == v2.PAYLOAD_RAW:
        raise Tres0rError("Rohdaten-Container enthalten keine Dateien – 'decrypt' verwenden.")
    index = op.read_index()
    positions = _select(index, only) if (index is not None and only) else None
    if positions == [] and require_match:
        raise Tres0rError("Kein Eintrag passt zu: " + ", ".join(only))
    if signers:
        positions = None  # Signaturprüfung braucht den ganzen Stream
    if check_space:
        if index is not None:
            chosen = positions if positions is not None else range(len(index))
            needed = sum(index[i].size for i in chosen)
        else:
            needed = op.payload_size or 0
        check_free_space(dest, needed, "das Entpacken")

    dest.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".tres0r-", dir=dest))
    guard = _NameGuard(staging, rename=rename, windows=os.name == "nt", xattrs=xattrs, acls=acls)
    warnings: list[str] = []
    try:
        try:
            if positions is not None:
                counter = _tracker(progress, "entpacken", len(positions), UNIT_ENTRIES)
                _extract_indexed(op, index, positions, staging, guard, counter)
                if counter is not None:
                    counter.finish()
            else:
                reader, blocks, data = op.stream(progress, "entpacken")
                guard.on_member = op.item
                with tarfile.open(fileobj=data, mode="r|") as tar:
                    tar.errorlevel = max(tar.errorlevel, 1)
                    members = tar if not only else (ti for ti in tar if _matches(ti.name, only))
                    # "data"-Filter (im Guard): keine absoluten Pfade, kein "..", keine
                    # Links nach außen, keine Gerätedateien, keine setuid-Bits.
                    tar.extractall(staging, members=members, filter=guard)
                _finish(reader, blocks)
                signer = op.check_signature(signers)  # vor dem Verschieben in den Zielordner
                op.done()
        except tarfile.FilterError as e:
            raise UnsafeArchive(f"Unsicherer Archivinhalt abgelehnt: {e}") from None
        except tarfile.TarError as e:
            raise FormatError(f"Archiv im Container ist defekt: {e}") from None
        if only and guard.count == 0 and require_match:
            raise Tres0rError("Kein Eintrag passt zu: " + ", ".join(only))
        warnings = _apply_xattrs(staging, guard.xattrs)

        names = sorted(os.listdir(staging))
        conflicts = [n for n in names if os.path.lexists(dest / n)]
        if conflicts:
            raise Tres0rError("Im Zielordner existiert bereits: " + ", ".join(conflicts))
        for name in names:
            os.replace(staging / name, dest / name)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return ExtractResult(names=names, entries=guard.count, renamed=guard.renamed, signed=op.signed, signer=signer,
                         warnings=warnings)


# ---------------------------------------------------------------------------
# Rohdatenströme (stdin/stdout, Pipes)
# ---------------------------------------------------------------------------
def encrypt_stream(
    src: BinaryIO,
    out: BinaryIO,
    password: str | bytes | None,
    params: KdfParams | None = None,
    *,
    recipients: Sequence[X25519PublicKey] = (),
    recovery: str | None = None,
    compress: bool = False,
    pad: bool = True,
    sign_with: Ed25519PrivateKey | None = None,
    progress: Progress = None,
    total: int | None = None,
    threads: int | None = None,
    keyfile: bytes | None = None,
    threshold: tuple[int, int] | None = None,
    fido2=None,
) -> EncryptResult:
    """Beliebigen Datenstrom verschlüsseln (Nutzdatentyp "roh"). Gibt die
    Anzahl gelesener Bytes zurück. ``out`` bekommt den Container unmittelbar –
    für Dateien mit atomic_output() kombinieren. ``total``: erwartete Größe
    (für Fortschritt/Restzeit), falls bekannt."""
    if compress:
        payload._require_zstd()
    dek = rng.random_bytes(32)
    slots, shares = _make_slots(dek, password, params, recipients, recovery, keyfile, threshold, fido2)
    header = v2.HeaderV2.create(
        dek, slots, payload_type=v2.PAYLOAD_RAW,
        compression=v2.COMPRESS_ZSTD if compress else v2.COMPRESS_NONE,
        flags=v2.FLAG_SIGNED if sign_with is not None else 0,
    )
    out.write(header.to_bytes())
    enc = EncryptingWriter(out, header.payload_key(dek))
    if sign_with is not None:
        enc.digest = hashlib.sha256()
    writer = payload.PayloadWriter(enc, compress, threads=workers.resolve_threads(threads))
    counter = _tracker(progress, "verschlüsseln", total)
    read = 0
    while data := src.read(1 << 20):
        writer.write(data)
        read += len(data)
        if counter is not None:
            counter(len(data))
    writer.close()
    _finish_payload(enc, b"", pad, sign_with, header)
    out.flush()
    if counter is not None:
        counter.finish()
    return EncryptResult(bytes=read, shares=shares)


def decrypt_stream(src: BinaryIO, out: BinaryIO, credentials: Unlock, *,
                   signers: Sequence[Ed25519PublicKey] | None = None,
                   progress: Progress = None, total: int | None = None) -> DecryptResult:
    """Nutzdaten eines Containers ausgeben (roh; bei tar-Containern den tar-Stream).

    Achtung bei Pipes: Die Daten fließen, bevor Abschluss und Signatur geprüft
    sind. Erst ein Rücklauf ohne Exception (Exit-Code 0) bestätigt beides.
    """
    header = read_header(src)
    if header.version == 2 and header.segmented:
        raise Tres0rError("Container mit angehängten Segmenten: bitte 'unpack' verwenden.")
    dek, _ = _unlock_tracked(header, credentials, progress)
    signed = header.version == 2 and header.signed
    hasher = sign.TailHasher() if signed else None
    counter = _tracker(progress, "entschlüsseln", None if total is None else total - header.header_len)
    reader = DecryptingReader(src, header.payload_key(dek), counter, hasher)
    if header.version == 1:
        blocks, data = None, reader
    else:
        blocks, data = payload.decoded_reader(reader, header.compression)
    total = 0
    while chunk := data.read(1 << 20):
        out.write(chunk)
        total += len(chunk)
    _finish(reader, blocks)
    key = sign.verify(header, *hasher.finish()) if signed else None
    sign.require(key, signers)
    out.flush()
    if counter is not None:
        counter.finish()
    return DecryptResult(bytes=total, signed=signed, signer=encode_verify_key(key) if key else None)


@contextmanager
def atomic_output(path: str | os.PathLike[str], *, overwrite: bool = False,
                  split: int | None = None) -> Iterator[BinaryIO]:
    """Datei (oder mit ``split`` einen Teilesatz) erst nach Erfolg an ihren Platz
    bringen; bei Fehlern bleiben keine Reste. Beim Überschreiben verschwinden auch
    Teile, die ein früherer, anders aufgeteilter Container hinterlassen hat."""
    path = Path(path)
    if volumes.exists(path) and not overwrite:
        raise Tres0rError(f"{path} existiert bereits.")
    parent = path.parent if str(path.parent) else Path(".")
    if split:
        writer = volumes.VolumeWriter(path, split)
        try:
            yield writer
            writer.commit(overwrite)
            if overwrite and os.path.lexists(path):
                path.unlink()  # vorher eine einzelne Datei gleichen Namens
            _fsync_dir(parent)
        except BaseException:
            writer.abort()
            raise
        return
    fd, tmp_name = tempfile.mkstemp(dir=parent, prefix=f".{path.name}.", suffix=".partial")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            yield f
            f.flush()
            os.fsync(f.fileno())
        stale = volumes.parts_of(path) if overwrite and os.path.lexists(volumes.part_name(path, 1)) else []
        os.replace(tmp, path)
        for old in stale:  # vorher ein Teilesatz gleichen Namens
            old.unlink(missing_ok=True)
        _fsync_dir(parent)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# Passwort und Keyslots ändern
# ---------------------------------------------------------------------------
def _rewrite_header(path: Path, old_header_len: int, new_header: bytes, check_space: bool,
                    progress: Progress = None) -> None:
    """Neuen Header + unveränderte Nutzdaten in eine neue Datei, dann atomar ersetzen.

    Segmenttabellen zählen ab Nutzdatenbeginn und bleiben daher gültig, auch wenn
    sich die Header-Länge ändert.

    Kein Überschreiben in place: Ein Absturz mittendrin könnte sonst den
    Container unbrauchbar machen (und v2-Header ändern ihre Länge).
    """
    parent = path.parent if str(path.parent) else Path(".")
    if segments.read_journal(volumes.base_of(path) or path) is not None:
        raise FormatError(INTERRUPTED)
    source, total = volumes.open_read(path)
    source.close()
    if check_space:
        check_free_space(parent, total, "die geänderte Kopie")
    counter = _tracker(progress, "kopieren", total - old_header_len)
    base = volumes.base_of(path) or path
    with atomic_output(base, overwrite=True, split=volumes.part_size_of(path)) as dst:
        src, _ = volumes.open_read(path)
        with src:  # vor dem Ersetzen schließen (Windows!)
            dst.write(new_header)
            src.seek(old_header_len)
            while chunk := src.read(1 << 20):
                dst.write(chunk)
                if counter is not None:
                    counter(len(chunk))
    if counter is not None:
        counter.finish()


def _v2_for_keys(path: Path, credentials: Unlock) -> tuple[v2.HeaderV2, bytes, int]:
    f, _ = volumes.open_read(path)
    with f:
        header = read_header(f)
    if header.version != 2:
        raise Tres0rError("Mehrere Schlüssel gibt es erst ab Formatversion 2 (dieser Container: v1).")
    dek, used = header.unlock(credentials)
    return header, dek, used


def change_password(
    container: str | os.PathLike[str],
    old_password: Unlock,
    new_password: str | bytes,
    params: KdfParams | None = None,
    *,
    check_space: bool = True,
    progress: Progress = None,
) -> None:
    """Das Passwort ändern, mit dem entsperrt wurde – ohne Neuverschlüsselung.

    Bei v2 wird genau der Passwort-Slot ersetzt, der zum alten Passwort passt;
    ohne ``params`` behält er seine Stufe.

    ``old_password``: Zugangsdaten zum Entsperren (wie ``credentials``); ``new_password``: das neue Passwort. Ein zweiter Faktor (Keyfile, FIDO2) bleibt.
    """
    path = Path(container)
    f, _ = volumes.open_read(path)
    with f:
        header = read_header(f)
    if header.version == 1:
        dek, _ = _unlock(header, old_password)
        _rewrite_header(path, header.header_len, header.rewrap(dek, new_password, params).to_bytes(), check_space,
                        progress)
        return
    dek, used = header.unlock(old_password)
    slot = header.slots[used]
    if slot.type not in (v2.SLOT_PASSWORD, v2.SLOT_PASSWORD_KEYFILE, v2.SLOT_FIDO2):
        raise Tres0rError(
            f"Entsperrt wurde über Slot {used} ({slot.describe()}) – zum Ändern mit dem Passwort entsperren "
            "oder 'keys add-password' verwenden."
        )
    slots = list(header.slots)
    if slot.type == v2.SLOT_FIDO2:  # gleicher Token, gleiches Geheimnis (aus dem Entsperren, ohne Berührung)
        rp_id, credential_id, hmac_salt = slot.fido2
        value = Credentials.coerce(old_password).fido2(rp_id, credential_id, hmac_salt)
        slots[used] = v2.password_fido2_slot(dek, new_password, params or slot.kdf, rp_id, credential_id,
                                             hmac_salt, value)
    elif slot.type == v2.SLOT_PASSWORD_KEYFILE:  # zweiter Faktor bleibt derselbe
        keyfile = next(k for k in Credentials.coerce(old_password).keyfiles
                       if keyfile_id(k) == slot.keyfile_id)
        slots[used] = v2.password_keyfile_slot(dek, new_password, keyfile, params or slot.kdf)
    else:
        slots[used] = v2.password_slot(dek, new_password, params or slot.kdf)
    _rewrite_header(path, header.header_len, header.with_slots(dek, slots).to_bytes(), check_space, progress)


def add_keys(
    container: str | os.PathLike[str],
    credentials: Unlock,
    *,
    password: str | bytes | None = None,
    params: KdfParams | None = None,
    recovery: str | None = None,
    recipients: Sequence[X25519PublicKey] = (),
    keyfile: bytes | None = None,
    fido2=None,
    check_space: bool = True,
    progress: Progress = None,
) -> list[int]:
    """Weitere Keyslots hinzufügen. Gibt die Nummern der neuen Slots zurück."""
    path = Path(container)
    header, dek, _ = _v2_for_keys(path, credentials)
    new, _ = _make_slots(dek, password, params, recipients, recovery, keyfile, None, fido2)
    slots = header.slots + new
    _rewrite_header(path, header.header_len, header.with_slots(dek, slots).to_bytes(), check_space, progress)
    return list(range(len(header.slots), len(slots)))


def add_threshold(
    container: str | os.PathLike[str],
    credentials: Unlock,
    k: int,
    n: int,
    *,
    check_space: bool = True,
    progress: Progress = None,
) -> tuple[int, list]:
    """Schwellwert-Slot hinzufügen: k von n Anteilen öffnen den Container.
    Gibt (Slotnummer, Anteile) zurück – die Anteile gibt es nur jetzt."""
    path = Path(container)
    header, dek, _ = _v2_for_keys(path, credentials)
    slot, shares = v2.threshold_slot(dek, k, n)
    slots = header.slots + [slot]
    _rewrite_header(path, header.header_len, header.with_slots(dek, slots).to_bytes(), check_space, progress)
    return len(slots) - 1, shares


def remove_key(
    container: str | os.PathLike[str],
    credentials: Unlock,
    slot_index: int,
    *,
    check_space: bool = True,
    progress: Progress = None,
) -> SlotInfo:
    """Keyslot entfernen. Der letzte Slot lässt sich nicht entfernen.

    ``slot_index``: Nummer des Slots wie in ``inspect().slots``.
    """
    path = Path(container)
    header, dek, _ = _v2_for_keys(path, credentials)
    if not 0 <= slot_index < len(header.slots):
        raise Tres0rError(f"Slot {slot_index} gibt es nicht (vorhanden: 0–{len(header.slots) - 1}).")
    if len(header.slots) == 1:
        raise Tres0rError("Der letzte Keyslot kann nicht entfernt werden – der Container wäre unlesbar.")
    removed = header.slots[slot_index]
    slots = [s for i, s in enumerate(header.slots) if i != slot_index]
    _rewrite_header(path, header.header_len, header.with_slots(dek, slots).to_bytes(), check_space, progress)
    return SlotInfo(slot_index, _SLOT_KIND.get(removed.type, "unbekannt"), removed.describe())


# ---------------------------------------------------------------------------
# Namensschutz beim Entpacken
# ---------------------------------------------------------------------------
class _NameGuard:
    """tar-Filter fürs Entpacken: data_filter + Schutz vor stillem Überschreiben.

    Kollisionen werden am Dateisystem selbst erkannt: Der Staging-Ordner ist
    anfangs leer – existiert ein Zielpfad schon, obwohl der Name neu ist, hat
    das Dateisystem zwei Namen zusammengelegt (Groß-/Kleinschreibung unter
    Windows/macOS, Unicode-Form unter macOS). Unter Windows werden zusätzlich
    dort ungültige Namen erkannt.
    """

    def __init__(self, root: Path, *, rename: bool, windows: bool, xattrs: bool = False, acls: bool = False) -> None:
        self.root = root
        self.rename = rename
        self.windows = windows
        self.want_xattrs, self.want_acls = xattrs, acls
        self.xattrs: list[tuple[str, dict[str, bytes]]] = []  # (Pfad im Staging, Attribute)
        self.now = time.time()
        self.mapping: dict[str, str] = {}  # Pfad im Container -> Pfad auf Platte
        self.renamed: list[tuple[str, str]] = []
        self.count = 0
        # Neuere Python-Versionen rufen den Filter für Ordner ein zweites Mal auf
        # (beim abschließenden Setzen von Zeitstempeln/Rechten) – nur einmal zählen.
        # Die Objekte selbst werden gehalten, damit ihre id() nicht neu vergeben wird.
        self._seen: dict[int, tarfile.TarInfo] = {}
        self.on_member: Callable[[str], None] | None = None  # Fortschritt: aktueller Eintrag

    def _mapped(self, name: str) -> str:
        parts = name.split("/")
        out: list[str] = []
        for i, part in enumerate(parts):
            prefix = "/".join(parts[: i + 1])
            out = self.mapping[prefix].split("/") if prefix in self.mapping else out + [part]
        return "/".join(out)

    def _target(self, name: str) -> str:
        return os.path.join(self.root, *name.split("/"))

    def __call__(self, member: tarfile.TarInfo, dest_path: str) -> tarfile.TarInfo:
        first_call = id(member) not in self._seen
        self._seen[id(member)] = member
        if first_call and self.on_member is not None:
            self.on_member(member.name)
        original = member.name.lstrip("/" + os.sep)  # wie data_filter
        if ".." in original.replace(os.sep, "/").split("/") or (
                member.islnk() and ".." in member.linkname.replace(os.sep, "/").split("/")):
            # tres0r schreibt so etwas nie. data_filter ließe "a/../b" zu (bleibt im Ziel),
            # tarfile scheitert dann aber mit rohen OSErrors beim Anlegen der Ordner.
            raise UnsafeArchive(f"Eintrag '{original}' enthält '..' – abgelehnt.")
        inherited = name = self._mapped(original)  # Umbenennungen übergeordneter Ordner

        # 1. Bekannte Umbenennungen und (unter Windows) Namensbereinigung VOR dem
        #    Sicherheitsfilter anwenden: data_filter löst Pfade per realpath auf und
        #    scheitert sonst an umbenannten Ordnern bzw. deutet "a:b" als Laufwerk.
        #    Beides ist unbedenklich – es entstehen weder ".." noch Pfadtrenner.
        if self.windows:
            parts = name.split("/")
            problems = [portability.component_problem(p) for p in parts]
            if any(problems):
                if not self.rename:
                    detail = next(p for p in problems if p)[1]
                    raise NameConflict(f"'{original}': {detail}. Mit --rename wird umbenannt.")
                name = "/".join(portability.sanitize_component(p) if pr else p
                                for p, pr in zip(parts, problems))
        changes: dict[str, str] = {}
        if name != member.name:
            changes["name"] = name
        if member.islnk():  # Hardlink-Ziel wurde evtl. umbenannt
            linkname = self._mapped(member.linkname)
            if linkname != member.linkname:
                changes["linkname"] = linkname
        if changes:
            member = member.replace(**changes, deep=False)

        # 2. Sicherheitsprüfung (Traversal, Links nach außen, Gerätedateien, Rechte).
        member = tarfile.data_filter(member, dest_path)
        name = member.name
        if not _mtime_ok(member.mtime):
            # os.utime würde mit OverflowError/ValueError abbrechen – tarfile fängt nur OSError.
            member = member.replace(mtime=0, deep=False)
        if member.mtime == 0:
            # 0 = "Zeit nicht gespeichert" (pack --no-times): wie eine neu angelegte Datei
            member = member.replace(mtime=self.now, deep=False)

        # 3. Kollisionen am Dateisystem erkennen.
        target = self._target(name)
        if os.path.lexists(target):
            both_dirs = member.isdir() and os.path.isdir(target) and not os.path.islink(target)
            if not both_dirs:  # zwei Ordner gleichen Namens werden zusammengelegt
                if not self.rename:
                    raise NameConflict(
                        f"'{original}' würde eine bereits entpackte Datei überschreiben "
                        "(Groß-/Kleinschreibung oder Unicode-Form). Mit --rename wird umbenannt."
                    )
                parent, _, last = name.rpartition("/")
                n = 1
                while True:
                    candidate = (parent + "/" if parent else "") + portability.numbered_variant(last, n)
                    if not os.path.lexists(self._target(candidate)):
                        break
                    n += 1
                name = candidate
                member = member.replace(name=name, deep=False)

        if name != inherited:  # nur melden, wo die Umbenennung entsteht, nicht für jedes Kind
            self.mapping[original] = name
            self.renamed.append((original, name))
        if first_call:
            self.count += 1
            if (self.want_xattrs or self.want_acls) and not member.issym():
                attributes = {
                    key[len(XATTR_PREFIX):]: value.encode("utf-8", "surrogateescape")
                    for key, value in member.pax_headers.items()
                    if key.startswith(XATTR_PREFIX)
                    and _wanted_xattr(key[len(XATTR_PREFIX):], self.want_xattrs, self.want_acls)
                }
                if attributes:
                    self.xattrs.append((name, attributes))
        return member


# ---------------------------------------------------------------------------
# Umwandeln (v1 -> v2)
# ---------------------------------------------------------------------------
@dataclass
class UpgradeResult:
    path: Path
    entries: int
    size: int


def upgrade(
    container: str | os.PathLike[str],
    credentials: Unlock,
    output: str | os.PathLike[str] | None = None,
    *,
    compress: bool = False,
    pad: bool = True,
    progress: Progress = None,
    check_space: bool = True,
    threads: int | None = None,
    split: int | None = None,
) -> UpgradeResult:
    """Container der Formatversion 1 in Version 2 umwandeln.

    Läuft als Stream – es entsteht nie Klartext auf der Platte. Passwort und
    Stufe bleiben gleich; neu sind Inhaltsverzeichnis, Header-MAC und optional
    Kompression. Der alte Stream wird vollständig authentifiziert, bevor der neue
    Container an seinen Platz kommt; ohne ``output`` wird atomar ersetzt.
    """
    path = Path(container)
    target = Path(output) if output is not None else (volumes.base_of(path) or path)
    f, total_size = volumes.open_read(path)
    with f:
        header = read_header(f)
    if header.version != 1:
        raise Tres0rError(f"{path} hat bereits Formatversion {header.version}.")
    creds = Credentials.coerce(credentials)
    dek = password = None
    for candidate in creds.password_candidates():
        try:
            dek, password = header.unlock(candidate), candidate
            break
        except WrongPassword:
            continue
    if dek is None:
        raise WrongPassword("Falsches Passwort.")
    if compress:
        payload._require_zstd()
    parent = target.parent if str(target.parent) else Path(".")
    if check_space:
        check_free_space(parent, int(total_size * 1.05) + 65536, "den umgewandelten Container")

    payload_size = total_size - header.header_len
    entries = 0
    split = split if split is not None else (volumes.part_size_of(path) if output is None else None)
    with atomic_output(target, overwrite=output is None, split=split) as out:
        f, _ = volumes.open_read(path)
        with f:  # vor dem Ersetzen schließen (Windows!)
            f.seek(header.header_len)
            counter = _tracker(progress, "umwandeln", payload_size)
            reader = DecryptingReader(f, header.payload_key(dek), counter)
            new_dek = rng.random_bytes(32)
            new_header = v2.HeaderV2.create(
                new_dek, [v2.password_slot(new_dek, password, header.kdf)], payload_type=v2.PAYLOAD_TAR,
                compression=v2.COMPRESS_ZSTD if compress else v2.COMPRESS_NONE, flags=v2.FLAG_INDEX,
            )
            out.write(new_header.to_bytes())
            enc = EncryptingWriter(out, new_header.payload_key(new_dek))
            threads = workers.resolve_threads(threads)
            writer = payload.PayloadWriter(enc, compress, threads=threads)
            hasher = workers.hasher(threads)
            index: list[payload.IndexEntry] = []
            try:
                with tarfile.open(fileobj=reader, mode="r|") as src, \
                        tarfile.open(fileobj=writer, mode="w", format=tarfile.PAX_FORMAT, copybufsize=TAR_BUFSIZE) as dst:
                    for ti in src:
                        if counter is not None:
                            counter.item(ti.name)
                        ti = _anonymize(ti)
                        # Nur Standardfelder übernehmen: fremde PAX-Erweiterungen (beliebige
                        # Schlüsselwörter, Kodierungen) nicht ungeprüft weiterreichen – tarfile
                        # erzeugt die nötigen Einträge (lange/Unicode-Namen, Größe) selbst neu.
                        ti.pax_headers = {}
                        if not _mtime_ok(ti.mtime):  # präparierter Zeitstempel (inf, nan, 1e30 …)
                            ti.mtime = 0
                        offset, skip = writer.mark()
                        entry = payload.IndexEntry(
                            name=ti.name, kind=_index_kind(ti), size=ti.size if ti.isreg() else 0,
                            mtime=_safe_mtime(ti.mtime), offset=offset, skip=skip,
                            link=ti.linkname if (ti.issym() or ti.islnk()) else None,
                        )
                        try:
                            if ti.isreg():
                                digest = hashlib.sha256()
                                dst.addfile(ti, _HashingReader(src.extractfile(ti), digest, None, hasher))
                                entry.sha256 = hasher.hexdigest(digest)
                            else:
                                dst.addfile(ti)
                        except (ValueError, UnicodeError) as e:  # nicht darstellbare Felder
                            raise FormatError(f"Eintrag '{ti.name}' lässt sich nicht übernehmen: {e}") from None
                        index.append(entry)
            except tarfile.TarError as e:
                raise FormatError(f"Archiv im Container ist defekt: {e}") from None
            finally:
                hasher.close()
            writer.close()
            reader.finish()  # alter Container vollständig geprüft, bevor der neue gilt
            _finish_payload(enc, payload.index_trailer(payload.encode_index(index)), pad)
            entries = len(index)
            if counter is not None:
                counter.finish()
    return UpgradeResult(path=target, entries=entries, size=volumes.open_read(target)[1])


# ---------------------------------------------------------------------------
# Retten aus beschädigten Containern
# ---------------------------------------------------------------------------
@dataclass
class SalvageResult:
    recovered: list[str] = field(default_factory=list)  # vollständig und geprüft gerettet
    damaged: list[tuple[str, str]] = field(default_factory=list)  # (Eintrag, Grund)
    names: list[str] = field(default_factory=list)  # oberste Einträge im Zielordner
    used_index: bool = False
    notes: list[str] = field(default_factory=list)
    renamed: list[tuple[str, str]] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.damaged


_SALVAGE_ERRORS = (IntegrityError, FormatError, UnsafeArchive, tarfile.TarError, OSError, KeyError)


def _discard(guard: _NameGuard, name: str) -> None:
    """Halb geschriebene Datei eines gescheiterten Eintrags entfernen."""
    target = guard._target(guard._mapped(name.lstrip("/" + os.sep)))
    if os.path.islink(target) or os.path.isfile(target):
        os.unlink(target)


def _salvage_indexed(op: _Opened, index: list[payload.IndexEntry], staging: Path, guard: _NameGuard,
                     result: SalvageResult, counter=None) -> None:
    access = op.random_access()
    for entry in index:
        if counter is not None:
            counter.item(entry.name)
            counter(1)
        try:
            _, data = payload.decoded_reader(access.open_at(entry.offset), op.header.compression)
            payload.skip(data, entry.skip)
            with tarfile.open(fileobj=data, mode="r|") as tar:
                ti = tar.next()
                if ti is None or ti.name != entry.name:
                    raise FormatError("Inhaltsverzeichnis zeigt auf den falschen Eintrag.")
                tar.extractall(staging, members=[ti], filter=guard)
            if entry.kind == "f" and entry.sha256:
                target = guard._target(guard._mapped(entry.name.lstrip("/" + os.sep)))
                digest = hashlib.sha256()
                with open(target, "rb") as f:
                    while chunk := f.read(1 << 20):
                        digest.update(chunk)
                if digest.hexdigest() != entry.sha256:
                    raise FormatError("Prüfsumme stimmt nicht.")
            result.recovered.append(entry.name)
        except NameConflict:
            raise  # kein Schaden, sondern eine Entscheidung (--rename)
        except _SALVAGE_ERRORS as e:
            _discard(guard, entry.name)
            result.damaged.append((entry.name, _reason(e)))


def _salvage_stream(op: _Opened, staging: Path, guard: _NameGuard, result: SalvageResult,
                    progress: Progress = None) -> None:
    reader, blocks, data = op.stream(progress, "retten")
    guard.on_member = op.item
    current: str | None = None

    def members(tar):
        nonlocal current
        for ti in tar:
            current = ti.name
            yield ti
            result.recovered.append(ti.name)  # vollständig, sobald der nächste angefordert wird
            current = None

    try:
        with tarfile.open(fileobj=data, mode="r|") as tar:
            tar.extractall(staging, members=members(tar), filter=guard)
    except NameConflict:
        raise
    except _SALVAGE_ERRORS as e:
        if current is not None:
            _discard(guard, current)
            result.damaged.append((current, _reason(e)))
        result.damaged.append(("(alles ab dieser Stelle)", _reason(e)))
        return
    try:
        _finish(reader, blocks)
    except _SALVAGE_ERRORS as e:
        result.notes.append(f"Alle Dateien gerettet, aber das Containerende ist beschädigt: {_reason(e)}")


def _reason(error: BaseException) -> str:
    return str(error) or type(error).__name__


def salvage(
    container: str | os.PathLike[str],
    dest: str | os.PathLike[str],
    credentials: Unlock,
    *,
    rename: bool = False,
    progress: Progress = None,
) -> SalvageResult:
    """Aus einem beschädigten Container retten, was intakt ist.

    Voraussetzung: Der Header ist lesbar und lässt sich entsperren.

    * Mit lesbarem Inhaltsverzeichnis (v2): jeder Eintrag einzeln über seinen
      Einstiegspunkt. Ein beschädigter Chunk kostet nur die Einträge, die ihn
      berühren; jede gerettete Datei wird per SHA-256 gegengeprüft.
    * Sonst (v1, abgeschnittener Container): der Reihe nach bis zur ersten
      beschädigten Stelle; die Datei, in der sie liegt, wird verworfen.

    Gerettet wird nur, was vollständig und authentisch ist. Wie bei extract
    landet alles erst am Ende im Zielordner.
    """
    path, dest = Path(container), Path(dest)
    result = SalvageResult()
    with _open_segments(path, credentials, progress, tolerant=True) as ops:
        if ops[0].header.version == 2 and ops[0].header.payload_type == v2.PAYLOAD_RAW:
            raise Tres0rError("Rohdaten-Container enthalten keine Dateien – 'decrypt' verwenden.")
        result.notes += list(ops[0].notes)
        dest.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".tres0r-", dir=dest))
        try:
            for op in ops:
                if len(ops) == 1:
                    _salvage_op(op, staging, rename, result, progress)
                    continue
                part = Path(tempfile.mkdtemp(prefix=".tres0r-segment-", dir=dest))
                try:
                    _salvage_op(op, part, rename, result, progress)
                    _merge_tree(part, staging)  # neuere Segmente gewinnen
                finally:
                    shutil.rmtree(part, ignore_errors=True)
            names = sorted(os.listdir(staging))
            conflicts = [n for n in names if os.path.lexists(dest / n)]
            if conflicts:
                raise Tres0rError("Im Zielordner existiert bereits: " + ", ".join(conflicts))
            for name in names:
                os.replace(staging / name, dest / name)
            result.names = names
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    return result


def _salvage_op(op: _Opened, staging: Path, rename: bool, result: SalvageResult, progress: Progress) -> None:
    """Ein Segment retten (bzw. den ganzen Container ohne Segmente)."""
    label = f"Segment {op.header.number}: " if isinstance(op.header, _SegmentView) and op.header.number else ""
    index = None
    if op.indexed:
        try:
            index = op.read_index()
        except (IntegrityError, FormatError) as e:
            result.notes.append(f"{label}Inhaltsverzeichnis nicht lesbar ({_reason(e)}) – rette der Reihe nach.")
    if op.signed:
        note = "Container ist signiert – beim Retten wird die Signatur nicht geprüft."
        if note not in result.notes:
            result.notes.append(note)
    guard = _NameGuard(staging, rename=rename, windows=os.name == "nt")
    if index is not None:
        result.used_index = True
        counter = _tracker(progress, "retten", len(index), UNIT_ENTRIES)
        _salvage_indexed(op, index, staging, guard, result, counter)
        if counter is not None:
            counter.finish()
    else:
        _salvage_stream(op, staging, guard, result, progress)
    result.renamed += guard.renamed


# ---------------------------------------------------------------------------
# Vergleichen (Container <-> Ordner)
# ---------------------------------------------------------------------------
DIFF_NEW, DIFF_REMOVED, DIFF_CHANGED, DIFF_TYPE, DIFF_LINK, DIFF_TIME = (
    "neu", "entfernt", "geändert", "typ", "link", "zeit")
_KIND_WORDS = {"f": "Datei", "d": "Ordner", "l": "Symlink", "o": "sonstiges"}


@dataclass
class DiffEntry:
    name: str
    status: str  # neu | entfernt | geändert | typ | link | zeit
    detail: str = ""


@dataclass
class DiffResult:
    changes: list[DiffEntry] = field(default_factory=list)
    unchanged: int = 0
    hashed: int = 0  # lokal per SHA-256 verglichene Dateien
    quick: bool = False

    @property
    def identical(self) -> bool:
        return not self.changes


def _manifest(op: _Opened, progress: Progress) -> dict[str, payload.IndexEntry]:
    """Inhalt des Containers als {Name: Eintrag} – aus dem Index oder (v1) per Durchlesen."""
    index = op.read_index()
    if index is None:
        index = []
        reader, blocks, data = op.stream(progress, "lesen")
        try:
            with tarfile.open(fileobj=data, mode="r|") as tar:
                for ti in tar:
                    op.item(ti.name)
                    entry = payload.IndexEntry(ti.name, _index_kind(ti), ti.size if ti.isreg() else 0,
                                               _safe_mtime(ti.mtime), 0, 0,
                                               link=ti.linkname if (ti.issym() or ti.islnk()) else None)
                    if ti.isreg():
                        digest = hashlib.sha256()
                        source = tar.extractfile(ti)
                        while chunk := source.read(1 << 20):
                            digest.update(chunk)
                        entry.sha256 = digest.hexdigest()
                    index.append(entry)
        except tarfile.TarError as e:
            raise FormatError(f"Archiv im Container ist defekt: {e}") from None
        _finish(reader, blocks)
        op.done()
    result: dict[str, payload.IndexEntry] = {}
    for entry in index:
        if entry.kind == "h":  # Hardlink: Inhalt des Ziels übernehmen
            target = result.get(entry.link or "")
            entry = payload.IndexEntry(entry.name, "f", target.size if target else 0, entry.mtime, 0, 0,
                                       target.sha256 if target else None)
        result[entry.name] = entry
    return result


def _local_kind(st: os.stat_result) -> str:
    if stat.S_ISLNK(st.st_mode):
        return "l"
    if stat.S_ISDIR(st.st_mode):
        return "d"
    return "f" if stat.S_ISREG(st.st_mode) else "o"


def diff(
    container: str | os.PathLike[str],
    sources: Sequence[str | os.PathLike[str]],
    credentials: Unlock,
    *,
    exclude: ExcludeRules | None = None,
    ignore_files: bool = True,
    quick: bool = False,
    times: bool = False,
    progress: Progress = None,
    threads: int | None = None,
) -> DiffResult:
    """Container mit Ordnern/Dateien vergleichen – Aufruf wie bei ``create``.

    Die Pfade werden genau wie beim Packen ermittelt (gleiche Namen, gleiche
    Ausschlüsse), sodass "Projekt/a.txt" im Container auf "Projekt/a.txt" lokal
    trifft. Dateien gleicher Größe werden per SHA-256 verglichen; ``quick``
    begnügt sich wie rsync mit Größe und Änderungszeit. Reine Zeitunterschiede
    meldet ``times``. Container ohne Zeitstempel (pack --no-times): ``quick``
    hasht dann doch, ``times`` meldet nichts. ``threads``: Dateien parallel hashen.
    """
    plan = scan(sources, exclude=exclude, ignore_files=ignore_files)
    local = {arc: (path, st) for path, arc, st in plan.entries}
    with _open_segments(Path(container), credentials, progress) as ops:
        if ops[0].header.version == 2 and ops[0].header.payload_type == v2.PAYLOAD_RAW:
            raise Tres0rError("Rohdaten-Container enthalten keine Dateien.")
        remote = {}
        for op in ops:  # neuere Segmente überschreiben ältere
            remote.update(_manifest(op, progress))

    result = DiffResult(quick=quick)
    to_hash: list[tuple[str, Path, payload.IndexEntry, os.stat_result]] = []
    for name in sorted(set(local) | set(remote)):
        if name not in remote:
            result.changes.append(DiffEntry(name, DIFF_NEW))
            continue
        if name not in local:
            result.changes.append(DiffEntry(name, DIFF_REMOVED))
            continue
        entry, (path, st) = remote[name], local[name]
        kind = _local_kind(st)
        if kind != entry.kind:
            result.changes.append(DiffEntry(name, DIFF_TYPE, f"{_KIND_WORDS.get(entry.kind, entry.kind)} → "
                                                             f"{_KIND_WORDS.get(kind, kind)}"))
        elif kind == "l":
            target = os.readlink(path)
            if target != entry.link:
                result.changes.append(DiffEntry(name, DIFF_LINK, f"{entry.link} → {target}"))
            else:
                result.unchanged += 1
        elif kind == "f":
            if st.st_size != entry.size:
                result.changes.append(DiffEntry(name, DIFF_CHANGED,
                                                f"{format_size(entry.size)} → {format_size(st.st_size)}"))
            elif quick and entry.mtime != 0:
                if int(st.st_mtime) != entry.mtime:
                    result.changes.append(DiffEntry(name, DIFF_CHANGED, "Änderungszeit weicht ab (Inhalt ungeprüft)"))
                else:
                    result.unchanged += 1
            else:
                to_hash.append((name, path, entry, st))
        else:
            result.unchanged += 1

    counter = _tracker(progress, "vergleichen", sum(st.st_size for *_, st in to_hash))

    def file_hash(item) -> str:
        name, path, _, _ = item
        if counter is not None:
            counter.item(name)
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(1 << 20):
                digest.update(chunk)  # hashlib gibt den GIL frei -> echte Parallelität
                if counter is not None:
                    counter(len(chunk))
        return digest.hexdigest()

    pool_size = min(workers.resolve_threads(threads), len(to_hash))
    if pool_size > 1:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(pool_size, thread_name_prefix="tres0r-diff") as pool:
            digests = list(pool.map(file_hash, to_hash))
    else:
        digests = [file_hash(item) for item in to_hash]
    for (name, _path, entry, st), digest in zip(to_hash, digests):
        result.hashed += 1
        if entry.sha256 is None or digest != entry.sha256:
            result.changes.append(DiffEntry(name, DIFF_CHANGED, "Inhalt geändert (gleiche Größe)"))
        elif times and entry.mtime != 0 and int(st.st_mtime) != entry.mtime:
            result.changes.append(DiffEntry(name, DIFF_TIME, "nur die Änderungszeit weicht ab"))
        else:
            result.unchanged += 1
    if counter is not None:
        counter.finish()
    result.changes.sort(key=lambda c: c.name)
    return result



# ---------------------------------------------------------------------------
# Anhängen (Segmente) und Reparatur
# ---------------------------------------------------------------------------
@dataclass
class AppendResult:
    path: Path
    segment: int  # Nummer des neuen Segments
    entries: int
    size: int  # neue Gesamtgröße
    added: int  # Bytes, die hinzugekommen sind
    skipped: list[tuple[str, str]] = field(default_factory=list)
    excluded: int = 0
    issues: list[portability.Issue] = field(default_factory=list)


def append(
    container: str | os.PathLike[str],
    sources: Sequence[str | os.PathLike[str]] | Plan,
    credentials: Unlock,
    *,
    exclude: ExcludeRules | None = None,
    ignore_files: bool = True,
    compress: bool = False,
    sign_with: Ed25519PrivateKey | None = None,
    pad: bool = True,
    progress: Progress = None,
    strict_names: bool = False,
    check_space: bool = True,
    times: bool = True,
    xattrs: bool = False,
    acls: bool = False,
    threads: int | None = None,
) -> AppendResult:
    """Dateien als neues Segment an einen v2-Container anhängen – an Ort und Stelle.

    Nur die neuen Daten werden verschlüsselt und geschrieben; der Bestand bleibt
    unberührt. Gleiche Namen: die neue Fassung gilt (list/unpack/mount/diff).
    Absturzsicher über ein Journal neben dem Container; bei einer Exception
    (auch Abbruch) wird die Datei sofort auf den alten Stand gekürzt.
    """
    path = Path(container)
    if volumes.base_of(path) is not None:
        raise Tres0rError("Anhängen an aufgeteilte Container wird nicht unterstützt.")
    if compress:
        payload._require_zstd()
    if xattrs or acls:
        _require_xattr_support()
    threads = workers.resolve_threads(threads)
    plan = sources if isinstance(sources, Plan) else scan(
        sources, exclude=exclude, ignore_files=ignore_files, output=path, progress=progress)
    if strict_names and plan.issues:
        raise NameConflict(f"{len(plan.issues)} Name(n) sind nicht auf allen Systemen gültig, z. B. "
                           f"{plan.issues[0].path}: {plan.issues[0].detail}.")
    excluder = _Excluder([path])
    journal = segments.journal_path(path)
    entries = [e for e in plan.entries if not excluder(e[0], e[2]) and e[0] != journal]
    parent = path.parent if str(path.parent) else Path(".")

    with open(path, "r+b") as f:
        header = read_header(f)
        if header.version != 2:
            raise Tres0rError("Anhängen gibt es ab Formatversion 2 – vorher 'tres0r upgrade'.")
        if header.payload_type != v2.PAYLOAD_TAR:
            raise Tres0rError("An Rohdaten-Container lässt sich nichts anhängen.")
        size_before = f.seek(0, io.SEEK_END)
        if _interrupted(path, header, f, size_before):
            raise FormatError(INTERRUPTED)
        dek, _ = _unlock_tracked(header, credentials, progress)
        if header.segmented:
            table, _ = segments.read_table(f, size_before, header.header_len, dek, header.stream_nonce)
        else:
            table = [segments.SegmentEntry(0, size_before - header.header_len, header.stream_nonce,
                                           header.compression, header.flags & segments.SEGMENT_FLAGS)]
        if len(table) >= segments.MAX_SEGMENTS:
            raise Tres0rError(f"Höchstens {segments.MAX_SEGMENTS} Segmente pro Container.")
        if check_space:
            check_free_space(parent, estimate_size(plan, pad) + 65536, "das Anhängen")

        nonce = rng.random_bytes(16)
        compression = v2.COMPRESS_ZSTD if compress else v2.COMPRESS_NONE
        flags = v2.FLAG_INDEX | (v2.FLAG_SIGNED if sign_with is not None else 0)
        view = _SegmentView(len(table), v2.PAYLOAD_TAR, compression, flags, nonce, size_before)

        segments.write_journal(path, size_before, None if header.segmented else header.to_bytes())
        _fsync_dir(parent)
        try:
            f.seek(size_before)
            _write_tar_payload(f, view.payload_key(dek), view, entries, compress=compress, pad=pad,
                               sign_with=sign_with, progress=progress, times=times, xattrs=xattrs, acls=acls,
                               threads=threads)
            segment_end = f.tell()
            table.append(segments.SegmentEntry(size_before - header.header_len, segment_end - size_before,
                                               nonce, compression, flags))
            f.write(segments.encode_table(dek, header.stream_nonce, table))
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            f.flush()
            f.truncate(size_before)  # sofort zurück auf den alten Stand
            os.fsync(f.fileno())
            journal.unlink(missing_ok=True)
            raise
        # Abschluss: alte Tabelle entwerten (gegen Abschneiden) bzw. Header umstellen
        if header.segmented:
            f.seek(size_before - len(segments.MAGIC))
            f.write(bytes(len(segments.MAGIC)))
        else:
            flagged = header.with_flags(dek, header.flags | v2.FLAG_SEGMENTS).to_bytes()
            if len(flagged) != header.header_len:
                raise Tres0rError("Interner Fehler: Header-Länge würde sich ändern.")
            f.seek(0)
            f.write(flagged)
        f.flush()
        os.fsync(f.fileno())
        size_after = f.seek(0, io.SEEK_END)
    journal.unlink(missing_ok=True)
    _fsync_dir(parent)
    return AppendResult(path=path, segment=len(table) - 1, entries=len(entries), size=size_after,
                        added=size_after - size_before, skipped=list(plan.skipped), excluded=plan.excluded,
                        issues=list(plan.issues))


@dataclass
class RepairResult:
    action: str
    size: int


def repair(container: str | os.PathLike[str], credentials: Unlock) -> RepairResult:
    """Nach einem unterbrochenen Anhängen einen gültigen Stand herstellen.

    * Tabelle am Ende gültig: Anhängen war fertig geschrieben – abschließen.
    * Sonst mit Journal: auf den Stand davor zurücksetzen.
    * Sonst: auf die letzte gültige Segmenttabelle kürzen.
    """
    path = Path(container)
    if volumes.base_of(path) is not None:
        raise Tres0rError("Aufgeteilte Container haben keine angehängten Segmente.")
    journal = segments.read_journal(path)
    with open(path, "r+b") as f:
        header = read_header(f)
        if header.version != 2 or header.payload_type != v2.PAYLOAD_TAR:
            raise Tres0rError("Nur v2-Container mit Dateien können angehängte Segmente haben.")
        total = f.seek(0, io.SEEK_END)
        dek, _ = _unlock(header, credentials)
        try:
            segments.read_table(f, total, header.header_len, dek, header.stream_nonce)
            complete = True
        except (FormatError, IntegrityError):
            complete = False
        if complete and header.segmented:
            action = "Container ist in Ordnung."
        elif complete:
            f.seek(0)
            f.write(header.with_flags(dek, header.flags | v2.FLAG_SEGMENTS).to_bytes())
            action = "Unterbrochenes Anhängen abgeschlossen."
        elif journal is not None and header.header_len <= journal["size"] <= total:
            f.truncate(journal["size"])
            if journal.get("header"):
                original = bytes.fromhex(journal["header"])
                if len(original) != header.header_len:
                    raise FormatError("Journal passt nicht zu diesem Container.")
                f.seek(0)
                f.write(original)
            action = "Auf den Stand vor dem Anhängen zurückgesetzt."
        elif header.segmented:
            found = segments.find_last_table(f, total, header.header_len, dek, header.stream_nonce)
            if found is None:
                raise IntegrityError("Keine gültige Segmenttabelle gefunden – 'tres0r salvage' rettet, was lesbar ist.")
            f.truncate(found[1])
            action = "Auf den letzten gültigen Stand gekürzt."
        else:
            raise Tres0rError("Nichts Sicheres zu reparieren – 'verify' bzw. 'salvage' verwenden.")
        f.flush()
        os.fsync(f.fileno())
        size = f.seek(0, io.SEEK_END)
    segments.journal_path(path).unlink(missing_ok=True)
    return RepairResult(action=action, size=size)
