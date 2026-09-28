"""tres0r – Dateien, Ordner und Datenströme verschlüsseln.

Stabile öffentliche API (1.x, siehe API.md): alles, was hier in ``__all__`` steht,
sowie die Module ``tres0r.keys``, ``tres0r.shamir``, ``tres0r.progress``,
``tres0r.errors``, ``tres0r.passgen``, ``tres0r.hwtoken`` (FIDO2, Extra ``fido2``)
und ``tres0r.mount`` (FUSE, Extra ``mount``) mit ihrem jeweiligen ``__all__``.
Alle anderen Module und alle Namen mit ``_`` sind intern und können sich ändern.

    from tres0r import create, extract, verify, list_contents, Credentials

    result = create(["Projekt"], "Projekt.tres0r", "passwort")
    extract("Projekt.tres0r", "ziel", Credentials(passwords=["passwort"]))
"""
__version__ = "1.2.0"

from . import errors, hwtoken, keys, passgen, progress, shamir
from .container import (
    SUFFIX,
    AppendResult,
    ContainerInfo,
    CreateResult,
    DecryptResult,
    DiffEntry,
    DiffResult,
    EncryptResult,
    Entry,
    ExtractResult,
    Plan,
    RepairResult,
    SalvageResult,
    SlotInfo,
    UpgradeResult,
    VerifyResult,
    add_keys,
    add_threshold,
    append,
    atomic_output,
    change_password,
    check_credentials,
    check_free_space,
    create,
    decrypt_stream,
    diff,
    encrypt_stream,
    estimate_size,
    extract,
    extract_stream,
    format_size,
    inspect,
    list_contents,
    plan_sources,
    remove_key,
    repair,
    salvage,
    scan,
    upgrade,
    verify,
)
from .errors import (
    Cancelled,
    FormatError,
    HibpUnavailable,
    InsufficientMemory,
    InsufficientSpace,
    IntegrityError,
    KeyFormatError,
    NameConflict,
    SignatureError,
    Tres0rError,
    UnsafeArchive,
    UnsupportedVersion,
    WrongPassword,
)
from .exclude import ExcludeRules
from .kdf import DEFAULT_LEVEL, LEVEL_HINTS, LEVELS, KdfParams, calibrate
from .keys import Credentials
from .progress import CancelToken, Monitor, ProgressEvent

__all__ = [
    "__version__",
    # Module
    "errors", "hwtoken", "keys", "passgen", "progress", "shamir",
    # Container anlegen, lesen, prüfen
    "SUFFIX", "scan", "plan_sources", "estimate_size", "check_free_space", "format_size", "atomic_output",
    "create", "append", "inspect", "list_contents", "verify", "extract", "extract_stream", "diff",
    "encrypt_stream", "decrypt_stream", "salvage", "repair", "upgrade",
    # Schlüsselverwaltung
    "add_keys", "add_threshold", "remove_key", "change_password", "check_credentials",
    # Ergebnisse
    "Plan", "ContainerInfo", "SlotInfo", "CreateResult", "AppendResult", "Entry", "VerifyResult",
    "ExtractResult", "EncryptResult", "DecryptResult", "DiffEntry", "DiffResult", "SalvageResult",
    "RepairResult", "UpgradeResult",
    # Zugangsdaten, Stufen, Auswahl, Fortschritt
    "Credentials", "KdfParams", "LEVELS", "LEVEL_HINTS", "DEFAULT_LEVEL", "calibrate", "ExcludeRules",
    "ProgressEvent", "Monitor", "CancelToken",
    # Fehler
    "Tres0rError", "FormatError", "UnsupportedVersion", "WrongPassword", "IntegrityError", "SignatureError",
    "UnsafeArchive", "Cancelled", "HibpUnavailable", "NameConflict", "InsufficientSpace",
    "InsufficientMemory", "KeyFormatError",
]
