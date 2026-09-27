"""Schlüsselableitung (Argon2id) und Sicherheitsstufen.

Die Stufen unterscheiden sich ausschließlich in den Kosten der
Schlüsselableitung – also darin, wie teuer jeder einzelne Rateversuch für
einen Angreifer ist. Der Cipher (ChaCha20-Poly1305) ist in allen Stufen
identisch; eine "schwächere Verschlüsselung" gibt es bewusst nicht.
"""
from __future__ import annotations

import os
import sys
import time
import unicodedata
from dataclasses import dataclass

from .errors import FormatError, InsufficientMemory, Tres0rError

KDF_ARGON2ID = 1
KEY_LEN = 32
SALT_LEN = 16

# Grenzen für Parameter aus fremden Headern. Ohne sie könnte eine präparierte
# Datei z. B. 1 TiB RAM oder Millionen Iterationen anfordern (DoS beim Öffnen).
MIN_MEMORY_KIB = 8 * 1024  # 8 MiB
MAX_MEMORY_KIB = 4 * 1024 * 1024  # 4 GiB
MAX_ITERATIONS = 64
MAX_LANES = 16


@dataclass(frozen=True)
class KdfParams:
    memory_kib: int
    iterations: int
    lanes: int

    def validate(self) -> None:
        if not MIN_MEMORY_KIB <= self.memory_kib <= MAX_MEMORY_KIB:
            raise FormatError(
                f"Argon2id-Speicher {self.memory_kib} KiB außerhalb des "
                f"erlaubten Bereichs ({MIN_MEMORY_KIB}–{MAX_MEMORY_KIB} KiB)."
            )
        if not 1 <= self.iterations <= MAX_ITERATIONS:
            raise FormatError(f"Argon2id-Iterationen {self.iterations} außerhalb 1–{MAX_ITERATIONS}.")
        if not 1 <= self.lanes <= MAX_LANES:
            raise FormatError(f"Argon2id-Parallelität {self.lanes} außerhalb 1–{MAX_LANES}.")

    @property
    def memory_mib(self) -> float:
        return self.memory_kib / 1024

    def describe(self) -> str:
        return f"Argon2id, {self.memory_mib:g} MiB, t={self.iterations}, p={self.lanes}"


# Reihenfolge = Anzeige-Reihenfolge in den Frontends.
LEVELS: dict[str, KdfParams] = {
    "schnell": KdfParams(memory_kib=64 * 1024, iterations=3, lanes=4),  # RFC 9106, 2. Empfehlung
    "normal": KdfParams(memory_kib=256 * 1024, iterations=4, lanes=4),
    "stark": KdfParams(memory_kib=1024 * 1024, iterations=4, lanes=4),
}
DEFAULT_LEVEL = "normal"

LEVEL_HINTS: dict[str, str] = {
    "schnell": "Öffnen in Sekundenbruchteilen, geringer RAM-Bedarf",
    "normal": "Guter Kompromiss für die meisten Rechner",
    "stark": "Maximaler Schutz gegen Passwort-Raten, braucht 1 GiB RAM beim Öffnen",
}


def level_of(params: KdfParams) -> str | None:
    """Name der Stufe zu gegebenen Parametern oder None (benutzerdefiniert)."""
    for name, level_params in LEVELS.items():
        if level_params == params:
            return name
    return None


def encode_password(password: str | bytes) -> bytes:
    """Passwort plattformunabhängig in Bytes umwandeln.

    NFC-Normalisierung sorgt dafür, dass "ä" als ein Codepunkt oder als
    "a" + Kombinationszeichen denselben Schlüssel ergibt – sonst kann ein auf
    Linux verschlüsselter Container auf macOS unter Umständen nicht mehr
    geöffnet werden.
    """
    if isinstance(password, str):
        # surrogateescape: ungültige Eingabebytes ergeben deterministisch dieselben Bytes
        password = unicodedata.normalize("NFC", password).encode("utf-8", "surrogateescape")
    if not password:
        raise Tres0rError("Leeres Passwort ist nicht erlaubt.")
    return bytes(password)


def _derive_cryptography(password: bytes, salt: bytes, params: KdfParams) -> bytes:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id  # ab cryptography 44

    kdf = Argon2id(
        salt=salt,
        length=KEY_LEN,
        iterations=params.iterations,
        lanes=params.lanes,
        memory_cost=params.memory_kib,
    )
    return kdf.derive(password)


def _derive_argon2_cffi(password: bytes, salt: bytes, params: KdfParams) -> bytes:
    from argon2.low_level import Type, hash_secret_raw

    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=params.iterations,
        memory_cost=params.memory_kib,
        parallelism=params.lanes,
        hash_len=KEY_LEN,
        type=Type.ID,
        version=19,
    )


AUTO_MAX_MEMORY_KIB = 1024 * 1024  # 1 GiB – wie "stark"; muss auch auf dem Zielrechner passen
AUTO_MIN_MEMORY_KIB = 64 * 1024  # 64 MiB – wie "schnell"


def measure(params: KdfParams) -> float:
    """Dauer einer Schlüsselableitung mit diesen Parametern in Sekunden."""
    start = time.perf_counter()
    derive_key("kalibrierung", bytes(SALT_LEN), params)
    return time.perf_counter() - start


def calibrate(
    target_seconds: float = 2.0,
    *,
    max_memory_kib: int = AUTO_MAX_MEMORY_KIB,
    lanes: int = 4,
    timer=measure,
) -> KdfParams:
    """Argon2id-Parameter für eine Zielzeit auf diesem Rechner ("-l auto").

    Speicher zuerst, weil er gegen Grafikkarten-Angriffe am meisten hilft: so
    viel wie möglich, aber höchstens ``max_memory_kib`` (Standard 1 GiB) und ein
    Viertel des freien Arbeitsspeichers – der Rechner, der den Container später
    öffnet, braucht genauso viel. Ist schon eine Iteration zu langsam, wird der
    Speicher halbiert (nicht unter 64 MiB). Die Iterationen füllen dann die
    Zielzeit auf.

    Die Dauer folgt T(t) ≈ A + B·t: A ist ein fester Anteil (vor allem das
    Bereitstellen des Speichers), B der Anteil je Iteration. Gemessen werden
    t = 1 und t = 2 (nach einem kleinen Aufwärmlauf), daraus t = (Ziel − A) / B.
    Nur mit t = 1 zu rechnen zählt A bei jeder Iteration mit und verfehlt das
    Ziel nach unten (gemessen: 1,3 statt 2 s). Kostet etwa T(1) + T(2) Messzeit.

    ``target_seconds``: Zielzeit; ``max_memory_kib``: Speichergrenze; ``lanes``: Parallelität (p); ``timer``: Messfunktion (für Tests).
    """
    if target_seconds <= 0:
        raise ValueError("Zielzeit muss positiv sein.")
    cap = max(MIN_MEMORY_KIB, min(max_memory_kib, MAX_MEMORY_KIB))
    available = available_memory()
    if available is not None:
        cap = max(MIN_MEMORY_KIB, min(cap, available // 1024 // 4))
    memory = 1 << (cap.bit_length() - 1)  # auf eine Zweierpotenz in KiB abrunden
    floor = min(AUTO_MIN_MEMORY_KIB, memory)
    timer(KdfParams(8 * 1024, 1, 1))  # Aufwärmen (Bibliothek laden usw.), zählt nicht
    while True:
        one = timer(KdfParams(memory, 1, lanes))
        if one <= target_seconds or memory <= floor:
            break
        memory = max(floor, memory // 2)
    if one >= target_seconds:
        iterations = 1
    else:
        per_iteration = timer(KdfParams(memory, 2, lanes)) - one
        if per_iteration < 0.25 * one:  # zweite Messung unplausibel (Rauschen): vorsichtig rechnen
            per_iteration = one
        fixed = max(0.0, one - per_iteration)
        iterations = round((target_seconds - fixed) / max(per_iteration, 1e-6))
    iterations = max(1, min(MAX_ITERATIONS, iterations))
    return KdfParams(memory_kib=memory, iterations=iterations, lanes=lanes)


def available_memory() -> int | None:
    """Verfügbarer Arbeitsspeicher in Byte (best effort, None = unbekannt).

    Linux: MemAvailable aus /proc/meminfo, Windows: GlobalMemoryStatusEx,
    macOS/sonst: physischer Speicher insgesamt (verfügbar ist dort nicht
    ohne Weiteres ermittelbar).
    """
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/meminfo", encoding="ascii") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) * 1024
        elif os.name == "nt":
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            status = MemoryStatus()
            status.dwLength = ctypes.sizeof(MemoryStatus)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullAvailPhys)
        else:
            return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (OSError, ValueError, AttributeError):
        pass
    return None


def check_memory(params: KdfParams) -> None:
    """Klare Meldung statt OOM-Killer – z. B. bei präparierten Containern, die
    zulässige, aber auf diesem Rechner zu hohe Argon2-Parameter verlangen."""
    needed = params.memory_kib * 1024
    available = available_memory()
    if available is not None and needed > available:
        raise InsufficientMemory(
            f"Die Schlüsselableitung braucht {params.memory_mib:g} MiB Arbeitsspeicher, "
            f"verfügbar sind etwa {available // (1024 * 1024)} MiB. "
            "Anwendungen schließen oder auf einem Rechner mit mehr Speicher öffnen."
        )


def derive_key(password: str | bytes, salt: bytes, params: KdfParams) -> bytes:
    """32-Byte-Schlüssel aus Passwort ableiten.

    Bevorzugt cryptography (>= 44). Fällt auf argon2-cffi zurück, falls
    cryptography gegen ein System-OpenSSL ohne Argon2 gebaut wurde (manche
    Distributionspakete). Beide Backends liefern identische Ergebnisse.
    """
    params.validate()
    if len(salt) != SALT_LEN:
        raise FormatError("Salt hat falsche Länge.")
    pw = encode_password(password)
    check_memory(params)

    try:
        from cryptography.exceptions import UnsupportedAlgorithm
    except ImportError:  # pragma: no cover - cryptography ist Pflichtabhängigkeit
        UnsupportedAlgorithm = RuntimeError  # type: ignore[assignment,misc]

    try:
        try:
            return _derive_cryptography(pw, salt, params)
        except (ImportError, UnsupportedAlgorithm):
            pass
        try:
            return _derive_argon2_cffi(pw, salt, params)
        except ImportError:
            raise Tres0rError(
                "Kein Argon2id verfügbar: cryptography >= 44 (mit OpenSSL >= 3.2) "
                "oder argon2-cffi installieren."
            ) from None
    except MemoryError:
        raise InsufficientMemory(
            f"Nicht genug Arbeitsspeicher für die Schlüsselableitung ({params.memory_mib:g} MiB)."
        ) from None
