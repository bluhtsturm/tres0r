"""Kommandozeile für tres0r (nur Standardbibliothek).

Container (Dateien und Ordner):
    tres0r pack PFAD... [-o DATEI] [-l STUFE] [-g passphrase|passwort] [-r EMPFÄNGER] [--recovery] [-z]
    tres0r unpack CONTAINER [-o ORDNER] [--only MUSTER] [--rename] [-i IDENTITÄT]
    tres0r verify | list | info CONTAINER
    tres0r salvage CONTAINER -o ORDNER        tres0r upgrade CONTAINER [-o NEU]
    tres0r diff CONTAINER PFAD...             tres0r unpack - < CONTAINER
    tres0r mount CONTAINER ORDNER             tres0r umount ORDNER
    tres0r append CONTAINER PFAD...           tres0r repair CONTAINER
Datenströme (Pipes, Backups):
    tres0r encrypt [EINGABE|-] -o AUSGABE|-      tres0r decrypt CONTAINER|- [-o AUSGABE|-]
Schlüssel:
    tres0r keygen -o DATEI [--sign]     tres0r pubkey IDENTITÄT     tres0r protect IDENTITÄT
    tres0r keys list|add-password|add-recovery|add-shares|add-recipient|remove CONTAINER …
    tres0r keyfile -o DATEI
    tres0r passwd CONTAINER [-l STUFE]
Passwörter (pwgen):
    tres0r genpass | checkpass | bench

Jeder Befehl versteht --json: stdout enthält dann genau ein JSON-Objekt,
Statusmeldungen und Fortschritt entfallen.

Exit-Codes: 0 OK · 1 Fehler/Abbruch · 2 falsches Passwort/kein passender Schlüssel ·
            3 Container beschädigt, manipuliert oder unsicher · 4 Unterschiede (diff) · 130 Strg+C

Passwörter werden nie als Argument angenommen (Shell-History, Prozessliste),
sondern per getpass abgefragt oder aus einer Datei gelesen.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets as _random
import shutil
import sys
import time
import unicodedata
from pathlib import Path

from . import __version__, container, hwtoken, keys, passgen, portability, pwgen, shamir, volumes
from .errors import (
    Cancelled,
    FormatError,
    IntegrityError,
    NameConflict,
    Tres0rError,
    UnsafeArchive,
    WrongPassword,
)
from .exclude import ExcludeRules
from .progress import UNIT_ENTRIES, Monitor, ProgressEvent
from . import kdf
from .kdf import DEFAULT_LEVEL, LEVEL_HINTS, LEVELS, derive_key

KINDS = ("passphrase", "passwort")
EXIT_OK, EXIT_ERROR, EXIT_WRONG_PASSWORD, EXIT_DAMAGED, EXIT_DIFFERENT, EXIT_INTERRUPTED = 0, 1, 2, 3, 4, 130
fmt = container.format_size


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------
def _eprint(*args: object, end: str = "\n") -> None:
    print(*args, file=sys.stderr, end=end, flush=True)


class _Terminal:
    """Rückfragen – auch wenn stdin Nutzdaten liefert (encrypt aus einer Pipe).

    getpass liest ohnehin vom Terminal. Für normale Eingaben wird in diesem Fall
    /dev/tty verwendet (nur POSIX); ohne Terminal gilt die Sitzung als
    nicht-interaktiv.
    """

    stdin_is_data = False

    @classmethod
    def _dev_tty(cls):
        if not cls.stdin_is_data or os.name != "posix":
            return None
        try:
            return open("/dev/tty", encoding="utf-8")
        except OSError:
            return None

    @classmethod
    def interactive(cls) -> bool:
        if sys.stdin.isatty() and not cls.stdin_is_data:
            return True
        tty = cls._dev_tty()
        if tty is None:
            return False
        tty.close()
        return True

    @classmethod
    def ask(cls, prompt: str) -> str:
        _eprint(prompt, end="")
        if not cls.stdin_is_data:
            return input()
        tty = cls._dev_tty()
        if tty is None:
            raise EOFError
        with tty:
            line = tty.readline()
        if not line:
            raise EOFError
        return line.rstrip("\n")


def _ask(prompt: str) -> str:
    return _Terminal.ask(prompt)


def _confirm(question: str) -> bool:
    if not _Terminal.interactive():
        return False
    try:
        answer = _ask(f"{question} [j/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in {"j", "ja", "y", "yes"}


_PHASE_LABELS = {
    "durchsuchen": "Durchsuche", "packen": "Verschlüsseln", "entpacken": "Entschlüsseln",
    "prüfen": "Prüfen", "lesen": "Lesen", "vergleichen": "Vergleichen", "umwandeln": "Umwandeln",
    "retten": "Retten", "verschlüsseln": "Verschlüsseln", "entschlüsseln": "Entschlüsseln",
    "kopieren": "Kopieren",
}


def _duration(seconds: float) -> str:
    seconds = int(seconds + 0.5)
    hours, rest = divmod(seconds, 3600)
    return f"{hours}:{rest // 60:02d}:{rest % 60:02d}" if hours else f"{rest // 60}:{rest % 60:02d}"


def render_progress(event: ProgressEvent, width: int) -> str:
    """Eine Zeile wie "Verschlüsseln:  45 % · 120.3 MiB/s · noch 0:12 · Projekt/gross.bin"."""
    label = _PHASE_LABELS.get(event.phase, event.phase.capitalize())
    entries = event.unit == UNIT_ENTRIES
    parts = []
    if event.fraction is not None and event.total:
        parts.append(f"{int(event.fraction * 100):3d} %")
    else:
        parts.append(f"{event.done} Einträge" if entries else fmt(event.done))
    if event.rate and not entries:
        parts.append(f"{fmt(int(event.rate))}/s")
    if event.eta is not None and event.eta >= 1:
        parts.append(f"noch {_duration(event.eta)}")
    line = f"{label}: " + " · ".join(parts)
    if event.item and not event.finished:
        room = width - len(line) - 4
        if room >= 8:
            item = event.item if len(event.item) <= room else "…" + event.item[-(room - 1):]
            line += " · " + item
    return line[: max(10, width - 1)]


class _ProgressLine(Monitor):
    """Fortschritt als überschriebene Zeile auf stderr (nur im Terminal)."""

    def __init__(self, label: str) -> None:
        super().__init__(self._show, interval=0.1)
        self.label = label
        self.enabled = sys.stderr.isatty()
        self._shown = False

    def _show(self, event: ProgressEvent) -> None:
        if not self.enabled or event.phase == "schlüssel":
            return
        width = shutil.get_terminal_size().columns
        line = render_progress(event, width)
        sys.stderr.write("\r\x1b[K" + line if os.name == "posix" else "\r" + line.ljust(width - 1))
        sys.stderr.flush()
        self._shown = True
        if event.finished:
            sys.stderr.write("\n")
            sys.stderr.flush()
            self._shown = False

    def end(self) -> None:
        if self.enabled and self._shown:
            sys.stderr.write("\n")
            sys.stderr.flush()
        self._shown = False


class Ui:
    """Bündelt alle Ausgaben eines Befehls.

    Menschenlesbar: Ergebnisse auf stdout, Status/Warnungen/Fortschritt auf
    stderr. JSON-Modus: Befehle legen ihr Ergebnis in ``data`` ab, main()
    gibt am Ende genau ein Objekt aus.
    """

    def __init__(self, json_mode: bool) -> None:
        self.json = json_mode
        self.data: dict = {}
        self.warnings: list[str] = []
        self._progress: _ProgressLine | None = None

    def out(self, text: object = "") -> None:
        if not self.json:
            print(text, flush=True)

    def status(self, text: str = "") -> None:
        if not self.json:
            _eprint(text)

    def warn(self, text: str) -> None:
        self.warnings.append(text)
        if not self.json:
            _eprint(f"Warnung: {text}")

    def progress(self, label: str) -> _ProgressLine | None:
        self.end_progress()
        if self.json:
            return None
        self._progress = _ProgressLine(label)
        return self._progress

    def end_progress(self) -> None:
        if self._progress:
            self._progress.end()
            self._progress = None


# ---------------------------------------------------------------------------
# Zugangsdaten
# ---------------------------------------------------------------------------
def _read_password_file(spec: str) -> str:
    """Erste Zeile aus Datei lesen; '-' liest eine Zeile von stdin."""
    text = sys.stdin.readline() if spec == "-" else Path(spec).read_text(encoding="utf-8")
    lines = text.splitlines()
    password = lines[0] if lines else ""
    if not password:
        raise Tres0rError("Passwortdatei ist leer.")
    return password


def _existing_password(path_or_none: str | None, prompt: str = "Passwort: ") -> str:
    if path_or_none:
        return _read_password_file(path_or_none)
    return getpass.getpass(prompt)


def _params(args: argparse.Namespace, ui: Ui):
    """Argon2-Parameter aus -l; "auto" kalibriert auf --kdf-time Sekunden."""
    if args.level is None:
        return None
    if args.level != "auto":
        return LEVELS[args.level]
    ui.status(f"Kalibriere Argon2id auf ca. {args.kdf_time:g} s ...")
    params = kdf.calibrate(args.kdf_time)
    ui.status(f"  -> {params.describe()} (der öffnende Rechner braucht {params.memory_mib:g} MiB RAM)")
    return params


def _level_text(args: argparse.Namespace, params) -> str:
    return f"Stufe {args.level} ({params.describe()})"


def _key_passphrase(args: argparse.Namespace, path: str):
    """Passphrase für eine geschützte Schlüsseldatei: aus --key-passphrase-file oder Rückfrage."""
    if getattr(args, "key_passphrase_file", None):
        return _read_password_file(args.key_passphrase_file)
    return lambda: getpass.getpass(f"Passphrase für {path}: ")


def _credentials(args: argparse.Namespace, info: container.ContainerInfo | None = None) -> keys.Credentials:
    """Entsperr-Daten aus --password-file / -i; Passwort sonst erst bei Bedarf abfragen."""
    identities = [k for path in (args.identity or [])
                  for k in keys.load_identities(path, _key_passphrase(args, path))]
    keyfiles = [keys.keyfile_secret(path) for path in (getattr(args, "keyfile", None) or [])]
    shares = [shamir.parse_share(text) for text in (getattr(args, "share", None) or [])]
    for path in getattr(args, "shares_file", None) or []:
        shares += [shamir.parse_share(line) for line in Path(path).read_text(encoding="utf-8").splitlines()
                   if line.strip() and not line.strip().startswith("#")]
    fido2 = _fido2_provider() if getattr(args, "fido2", False) else None
    if args.password_file:
        return keys.Credentials(passwords=[_read_password_file(args.password_file)], identities=identities,
                                keyfiles=keyfiles, shares=shares, fido2=fido2)
    has_recovery = info is not None and any(s.type == "wiederherstellung" for s in info.slots)
    prompt = "Passwort oder Wiederherstellungsphrase: " if has_recovery else "Passwort: "
    return keys.Credentials(identities=identities, prompt=lambda: getpass.getpass(prompt),
                            keyfiles=keyfiles, shares=shares, fido2=fido2)


def _unlock_status(ui: Ui, info: container.ContainerInfo, args: argparse.Namespace) -> None:
    if info.kdf is not None:
        ui.status(f"Entsperre {info.path.name} (per Passwort: {info.kdf.describe()}) ...")
    else:
        ui.status(f"Entsperre {info.path.name} ...")


# ---------------------------------------------------------------------------
# Neue Geheimnisse
# ---------------------------------------------------------------------------
def _generate(kind: str, args: argparse.Namespace) -> passgen.Secret:
    if kind == "passwort":
        return passgen.generate_password(
            args.length, symbols=not args.no_symbols, exclude_ambiguous=args.no_ambiguous
        )
    return passgen.generate_passphrase(
        args.words,
        lang=args.wordlist,
        separator=args.sep,
        capitalize=args.capitalize,
        append_digit=args.digit,
    )


def _secret_lines(secret: passgen.Secret) -> list[str]:
    label = "Generierte Passphrase" if secret.kind == "passphrase" else "Generiertes Passwort"
    lines = ["", f"  {label}:", f"      {secret.value}", f"  Entropie: ca. {secret.entropy_bits:.0f} Bit"]
    if not secret.strong_enough:
        lines.append(f"  Hinweis: unter {passgen.RECOMMENDED_BITS} Bit - für einen Container eher knapp.")
    return lines + [""]


def _recovery_lines(phrase: str) -> list[str]:
    words = phrase.split("-")
    width = max(len(w) for w in words)
    rows = [
        "   ".join(f"{i + 1:>2} {words[i]:<{width}}" for i in range(r, len(words), 5)).rstrip()
        for r in range(5)
    ]
    return ["", "  Wiederherstellungsphrase (20 Wörter, Reihenfolge zählt):", ""] + \
           [f"  {row}" for row in rows] + ["", "  Offline aufbewahren - sie öffnet den Container ohne Passwort.", ""]


def _screen_rows(lines: list[str]) -> int:
    """Belegte Bildschirmzeilen inkl. Umbruch langer Zeilen (lange Passphrasen!)."""
    columns = max(1, shutil.get_terminal_size().columns)
    return sum(max(1, -(-len(line) // columns)) for line in lines)


def _show_then_hide(lines: list[str]) -> None:
    """Anzeigen, nach Enter per ANSI vom Bildschirm entfernen (nicht aus dem Scrollback)."""
    prompt = "Notiere das Geheimnis und drücke Enter ... "
    for line in lines:
        _eprint(line)
    _ask(prompt)
    if os.name == "posix" and sys.stderr.isatty():
        sys.stderr.write(f"\x1b[{_screen_rows(lines + [prompt])}A\x1b[J")
        sys.stderr.flush()


def _confirm_by_typing(secret: passgen.Secret, attempts: int = 3) -> None:
    """Geheimnis zeigen, ausblenden und zur Kontrolle abtippen lassen.

    Wer es einmal korrekt aus seinen Notizen eintippt, hat es wirklich
    festgehalten – der beste Schutz gegen selbstverschuldeten Datenverlust.
    """
    expected = unicodedata.normalize("NFC", secret.value)
    wrong, show = 0, True
    while wrong < attempts:
        if show:
            _show_then_hide(_secret_lines(secret))
            show = False
        typed = getpass.getpass("Zur Kontrolle eingeben (leer = nochmal anzeigen): ")
        if not typed:
            show = True
            continue
        if unicodedata.normalize("NFC", typed.strip()) == expected:
            _eprint("Bestätigt.")
            return
        wrong += 1
        if wrong < attempts:
            _eprint(f"Stimmt nicht überein - noch {attempts - wrong} Versuch(e).")
    raise Cancelled("Abgebrochen - das Geheimnis wurde nicht bestätigt, nichts wurde verschlüsselt.")


def _confirm_recovery(phrase: str, checks: int = 3, attempts: int = 3) -> None:
    """Phrase zeigen und drei zufällig gewählte Wörter abfragen."""
    words = phrase.split("-")
    wrong, show = 0, True
    while wrong < attempts:
        if show:
            _show_then_hide(_recovery_lines(phrase))
            show = False
        positions = sorted(_random.SystemRandom().sample(range(len(words)), checks))
        answers = []
        for pos in positions:
            answers.append(getpass.getpass(f"Wort Nr. {pos + 1} (leer = nochmal anzeigen): ").strip().lower())
            if not answers[-1]:
                break
        if not answers[-1]:
            show = True
            continue
        if all(a == words[p] for a, p in zip(answers, positions)):
            _eprint("Bestätigt.")
            return
        wrong += 1
        if wrong < attempts:
            _eprint(f"Mindestens ein Wort stimmt nicht - noch {attempts - wrong} Versuch(e).")
    raise Cancelled("Abgebrochen - die Wiederherstellungsphrase wurde nicht bestätigt.")


def _report_check(check: passgen.PasswordCheck, ui: Ui) -> bool:
    """Prüfergebnis ausgeben. True, wenn es Warnungen gibt."""
    if check.hibp_error:
        ui.status(f"Hinweis: {check.hibp_error} - Datenleck-Prüfung übersprungen.")
    elif check.pwned == 0:
        ui.status("HIBP: in keinem bekannten Datenleck gefunden.")
    for warning in check.warnings:
        ui.warn(f"{warning}.")
    if check.warnings:
        ui.status("Tipp: Mit --generate passphrase erzeugt tres0r eine sichere Passphrase.")
    return bool(check.warnings)


def _new_password(args: argparse.Namespace, ui: Ui, file_attr: str = "password_file",
                  noun: tuple[str, str] = ("Neues Passwort", "Passwort")) -> str:
    password_file = getattr(args, file_attr)
    if args.generate and password_file:
        raise Tres0rError("--generate und eine Passwortdatei schließen sich aus.")

    if password_file:
        password = _read_password_file(password_file)
        _report_check(passgen.check_password(password, online=not args.offline), ui)
        return password

    if args.generate:
        secret = _generate(args.generate, args)
        if ui.json:
            # Skriptbetrieb: Das Geheimnis steht im JSON – Ausgabe nicht loggen!
            ui.data["generated"] = {"kind": secret.kind, "value": secret.value,
                                    "entropy_bits": round(secret.entropy_bits, 1)}
        elif _Terminal.interactive() and not args.yes:
            _confirm_by_typing(secret)
        else:
            for line in _secret_lines(secret):
                _eprint(line)
        return secret.value

    for _ in range(3):
        first = getpass.getpass(f"{noun[0]}: ")
        if not first:
            _eprint(f"Leeres {noun[1]} ist nicht erlaubt." if noun[1] == "Passwort" else f"Leere {noun[1]} ist nicht erlaubt.")
            continue
        if getpass.getpass(f"{noun[1]} wiederholen: ") != first:
            _eprint("Die Eingaben stimmen nicht überein.")
            continue
        check = passgen.check_password(first, online=not args.offline)
        if _report_check(check, ui) and not _confirm("Trotzdem verwenden?"):
            raise Cancelled("Abgebrochen.")
        return first
    raise Tres0rError("Zu viele Fehlversuche.")


def _new_recovery(args: argparse.Namespace, ui: Ui) -> str:
    phrase = keys.generate_recovery(args.wordlist).value
    if ui.json:
        ui.data["recovery"] = phrase  # Skriptbetrieb – Ausgabe nicht loggen!
    elif _Terminal.interactive() and not args.yes:
        _confirm_recovery(phrase)
    else:
        for line in _recovery_lines(phrase):
            _eprint(line)
    return phrase


def _fido2_provider() -> hwtoken.TokenProvider:
    return hwtoken.TokenProvider(notify=_eprint, pin=lambda: getpass.getpass("PIN des FIDO2-Tokens: "))


def _parse_threshold(text: str | None) -> tuple[int, int] | None:
    if not text:
        return None
    try:
        k, n = (int(part) for part in text.split("/"))
    except ValueError:
        raise Tres0rError("--shares erwartet K/N, z. B. 2/3 (2 von 3 Anteilen öffnen).") from None
    if not 2 <= k <= n <= shamir.MAX_SHARES:
        raise Tres0rError(f"Für --shares gilt 2 ≤ K ≤ N ≤ {shamir.MAX_SHARES}.")
    return k, n


def _deliver_shares(ui: Ui, shares: list, directory: str | None, yes: bool) -> None:
    """Anteile ausgeben: JSON, als Dateien oder einmalig auf dem Bildschirm."""
    if not shares:
        return
    if ui.json:
        ui.data["shares"] = [{"label": sh.label, "text": sh.text()} for sh in shares]  # nicht loggen!
        return
    if directory:
        folder = Path(directory)
        folder.mkdir(parents=True, exist_ok=True)
        for share in shares:
            keys._write_new(folder / f"anteil-{share.x}-von-{share.n}.txt",
                            f"# tres0r – {share.label}\n# An genau eine Person/einen Ort geben.\n{share.text()}\n".encode())
        ui.status(f"{len(shares)} Anteile in {folder}/ abgelegt (Rechte 0600) – jetzt einzeln verteilen, "
                  "dann die Dateien dort löschen.")
        return
    lines = ["", f"  Schwellwert-Anteile: je {shares[0].k} von {shares[0].n} öffnen den Container.",
             "  Jeden Anteil an eine andere Person/einen anderen Ort geben:", ""]
    lines += [f"  {share.label}:\n    {share.text()}" for share in shares] + [""]
    if _Terminal.interactive() and not yes:
        _show_then_hide("\n".join(lines).split("\n"))
    else:
        for line in lines:
            _eprint(line)


def _recipients(args: argparse.Namespace) -> list:
    found = [keys.parse_recipient(text) for text in (args.recipient or [])]
    for path in args.recipients_file or []:
        found.extend(keys.load_recipients(path, _key_passphrase(args, path)))
    return found


def _signing_key(args: argparse.Namespace):
    if not getattr(args, "sign", None):
        return None
    found = keys.load_signing_keys(args.sign, _key_passphrase(args, args.sign))
    if len(found) > 1:
        raise Tres0rError(f"{args.sign} enthält mehrere Signaturschlüssel – bitte eine Datei mit genau einem.")
    return found[0]


def _signers(args: argparse.Namespace) -> list:
    found = [keys.parse_verify_key(text) for text in (args.signer or [])]
    for path in args.signers_file or []:
        found.extend(keys.load_verify_keys(path, _key_passphrase(args, path)))
    return found


def _report_signature(ui: Ui, signed: bool, signer: str | None, required: bool) -> None:
    if signer:
        hint = "" if required else " (prüfe, ob das der erwartete Schlüssel ist, oder nutze --signer)"
        ui.status(f"Signatur gültig: {signer}{hint}")
    elif signed:
        ui.status("Container ist signiert, die Signatur wurde hier nicht geprüft ('verify' prüft sie).")
    ui.data.update(signed=signed, signer=signer)


def _key_setup(args: argparse.Namespace, ui: Ui) -> dict:
    """Keyslots für pack/encrypt: Passwort (außer --no-password), Empfänger, Phrase."""
    recipients = _recipients(args)
    signing_key = _signing_key(args)
    threshold = _parse_threshold(args.shares)
    if args.no_password and not recipients and not args.recovery and not threshold:
        raise Tres0rError("--no-password braucht mindestens einen Empfänger (-r/-R), --recovery oder --shares.")
    keyfile = keys.keyfile_secret(args.keyfile) if args.keyfile else None
    if keyfile is not None and args.no_password:
        raise Tres0rError("--keyfile ist der zweite Faktor zu einem Passwort und passt nicht zu --no-password.")
    if args.fido2 and (args.no_password or keyfile is not None):
        raise Tres0rError("--fido2 ist der zweite Faktor zu einem Passwort – nicht mit --no-password oder --keyfile.")
    fido2 = _fido2_provider() if args.fido2 else None
    if fido2 is not None:
        fido2.devices  # früh melden, wenn kein Token steckt
    password = None if args.no_password else _new_password(args, ui)
    recovery = _new_recovery(args, ui) if args.recovery else None
    parts = [] if password is None else [
        "Passwort + FIDO2-Token" if fido2 else "Passwort + Keyfile" if keyfile else "Passwort"]
    parts += [f"Schwellwert {threshold[0]} von {threshold[1]}"] if threshold else []
    parts += ["Wiederherstellungsphrase"] if recovery else []
    parts += [f"{len(recipients)} Empfänger"] if recipients else []
    ui.status("Keyslots: " + ", ".join(parts))
    if signing_key is not None:
        ui.status(f"Signiert mit {keys.public_text(signing_key)}")
    return {"password": password, "recipients": recipients, "recovery": recovery, "sign_with": signing_key,
            "keyfile": keyfile, "threshold": threshold, "fido2": fido2}


# ---------------------------------------------------------------------------
# Befehle: Container
# ---------------------------------------------------------------------------
def _exclude_rules(args: argparse.Namespace) -> ExcludeRules:
    rules = ExcludeRules(args.exclude or [])
    for path in args.exclude_from or []:
        rules = rules + ExcludeRules.from_file(path)
    if args.exclude_junk:
        rules = rules + ExcludeRules.junk()
    return rules


def _report_issues(ui: Ui, issues: list[portability.Issue], limit: int = 10) -> None:
    if not issues:
        return
    ui.warn(f"{len(issues)} Name(n) sind nicht auf allen Systemen gültig:")
    for issue in issues[:limit]:
        other = f" (mit {issue.other})" if issue.other else ""
        ui.status(f"  {issue.path} - {issue.detail}{other}")
    if len(issues) > limit:
        ui.status(f"  ... und {len(issues) - limit} weitere")
    ui.status("  Beim Entpacken unter Windows/macOS hilft 'tres0r unpack --rename'.")


def cmd_pack(args: argparse.Namespace, ui: Ui) -> int:
    planned = container.plan_sources(args.files)  # Pfadfehler vor allem anderen
    if args.output:
        output = Path(args.output)
    elif len(planned) == 1:
        output = Path(planned[0][1] + container.SUFFIX)
    else:
        raise Tres0rError("Bei mehreren Quellen bitte -o/--output angeben.")
    if volumes.exists(output) and not args.force:
        raise Tres0rError(f"{output} existiert bereits (--force zum Überschreiben).")
    if args.compress:
        container.payload._require_zstd()
    split = volumes.parse_size(args.split) if args.split else None

    plan = container.scan(args.files, exclude=_exclude_rules(args),
                          ignore_files=not args.no_ignore_file, output=output)
    pad = not args.no_pad
    estimate = container.estimate_size(plan, pad)
    excluded = f", {plan.excluded} ausgeschlossen" if plan.excluded else ""
    ui.status(f"{plan.files} Dateien, {plan.dirs} Ordner, {fmt(plan.total_bytes)}{excluded}"
              f" -> Container höchstens ca. {fmt(estimate)}")
    for skipped in plan.skipped:
        ui.warn(f"Übersprungen (FIFO/Socket/Gerätedatei): {skipped}")
    _report_issues(ui, plan.issues)
    if args.strict_names and plan.issues:
        raise NameConflict("Abbruch wegen --strict-names (Details siehe oben).")
    if not args.no_space_check:
        container.check_free_space(output.parent if str(output.parent) else Path("."), estimate, "den Container")

    setup = _key_setup(args, ui)
    params = _params(args, ui) if setup["password"] is not None else None
    if setup["password"] is not None:
        ui.status(f"Leite Schlüssel ab - {_level_text(args, params)} ...")
    try:
        result = container.create(plan, output, setup["password"], params, recipients=setup["recipients"],
                                  recovery=setup["recovery"], compress=args.compress, sign_with=setup["sign_with"],
                                  keyfile=setup["keyfile"], threshold=setup["threshold"], fido2=setup["fido2"],
                                  overwrite=args.force, times=not args.no_times, xattrs=args.xattrs,
                                  acls=args.acls, threads=args.threads, split=split,
                                  progress=ui.progress("Verschlüsseln"), pad=pad,
                                  check_space=not args.no_space_check)
    finally:
        ui.end_progress()
    level = f", Stufe {args.level}" if setup["password"] is not None else ""
    shown = volumes.display_name(result.path) if split else str(result.path)
    ui.out(f"{shown}  ({fmt(result.size)}, {result.entries} Einträge{level})")
    _deliver_shares(ui, result.shares, args.shares_dir, args.yes)
    ui.data.update(path=str(result.path), size=result.size, entries=result.entries,
                   level=args.level if setup["password"] is not None else None, compressed=args.compress,
                   padding=result.padding, excluded=result.excluded, skipped=result.skipped,
                   slots=result.slots, name_issues=[i.to_dict() for i in result.issues],
                   signer=keys.public_text(setup["sign_with"]) if setup["sign_with"] else None)

    if args.verify:
        ui.status("Prüfe den geschriebenen Container ...")
        creds = keys.Credentials(passwords=[p for p in (setup["password"], setup["recovery"]) if p])
        if not creds.passwords:
            ui.warn("--verify übersprungen: ohne Passwort lässt sich nur mit einer Identität prüfen.")
        else:
            try:
                check = container.verify(output, creds, progress=ui.progress("Prüfen"))
            finally:
                ui.end_progress()
            ui.out(f"Prüfung erfolgreich: {check.files} Dateien, {fmt(check.bytes)}.")
            ui.data["verified"] = True
    return EXIT_OK


def cmd_unpack(args: argparse.Namespace, ui: Ui) -> int:
    from_stdin = args.container == "-"
    info = None if from_stdin else container.inspect(args.container)  # Formatfehler vor der Passwortabfrage
    signers = _signers(args)  # Tippfehler in Prüfschlüsseln vor der Schlüsselableitung melden
    if from_stdin:
        _Terminal.stdin_is_data = True
        if args.password_file == "-":
            raise Tres0rError("stdin liefert schon den Container - Passwort bitte per Datei oder Rückfrage.")
    creds = _credentials(args, info)
    if info is not None:
        _unlock_status(ui, info, args)
    else:
        ui.status("Entpacke von stdin (ohne Inhaltsverzeichnis und Speicherplatzprüfung) ...")
    try:
        if from_stdin:
            result = container.extract_stream(sys.stdin.buffer, args.output, creds,
                                              progress=ui.progress("Entschlüsseln"), rename=args.rename,
                                              only=args.only, signers=signers, xattrs=args.xattrs, acls=args.acls)
        else:
            result = container.extract(args.container, args.output, creds,
                                       progress=ui.progress("Entschlüsseln"), rename=args.rename,
                                       check_space=not args.no_space_check, only=args.only, signers=signers,
                                       xattrs=args.xattrs, acls=args.acls)
    finally:
        ui.end_progress()
    if args.only and info is not None and info.has_index and not signers:
        ui.status("Hinweis: Mit --only werden nur die gelesenen Teile geprüft; vollständig prüft 'tres0r verify'.")
    for old, new in result.renamed:
        ui.warn(f"umbenannt: {old} -> {new}")
    for warning in result.warnings:
        ui.warn(warning)
    for name in result.names:
        ui.out(Path(args.output) / name)
    ui.data.update(dest=str(Path(args.output)), names=result.names, entries=result.entries,
                   renamed=[{"from": old, "to": new} for old, new in result.renamed])
    _report_signature(ui, result.signed, result.signer, bool(signers))
    return EXIT_OK


def cmd_verify(args: argparse.Namespace, ui: Ui) -> int:
    info = container.inspect(args.container)
    signers = _signers(args)
    creds = _credentials(args, info)
    _unlock_status(ui, info, args)
    try:
        result = container.verify(args.container, creds, progress=ui.progress("Prüfen"), signers=signers,
                                  threads=args.threads)
    finally:
        ui.end_progress()
    hashes = ", SHA-256 aller Dateien abgeglichen" if result.checked_hashes else ""
    parts = f", {result.segments} Segmente" if result.segments > 1 else ""
    ui.out(f"OK: {args.container} ist intakt ({result.files} Dateien, "
           f"{result.entries} Einträge, {fmt(result.bytes)}{parts}{hashes}).")
    ui.data.update(path=str(args.container), entries=result.entries, files=result.files, bytes=result.bytes,
                   checked_hashes=result.checked_hashes, segments=result.segments)
    _report_signature(ui, result.signed, result.signer, bool(signers))
    return EXIT_OK


def cmd_list(args: argparse.Namespace, ui: Ui) -> int:
    info = container.inspect(args.container)
    creds = _credentials(args, info)
    _unlock_status(ui, info, args)
    entries = container.list_contents(args.container, creds)
    for entry in entries:
        size = fmt(entry.size) if entry.kind == "datei" else ""
        ui.out(f"{entry.kind:<9} {size:>10}  {entry.name}")
    if info.has_index:
        ui.status("(aus dem Inhaltsverzeichnis - 'tres0r verify' prüft den ganzen Container)")
    if info.signed:
        ui.status("Container ist signiert - 'tres0r verify' prüft die Signatur.")
    ui.data["entries"] = [{"name": e.name, "size": e.size, "kind": e.kind, "mtime": e.mtime,
                           "sha256": e.sha256, "segment": e.segment} for e in entries]
    return EXIT_OK


def _slot_rows(info: container.ContainerInfo) -> list[str]:
    return [f"  [{s.index}] {s.description}" for s in info.slots]


def cmd_info(args: argparse.Namespace, ui: Ui) -> int:
    info = container.inspect(args.container)
    content = "tar" if info.payload_type == "tar" else "Datenstrom (roh)"
    if info.has_index:
        content += " mit Inhaltsverzeichnis"
    if info.compression:
        content += f", {info.compression}-komprimiert"
    rows = [
        ("Datei", str(info.path)),
        ("Größe", fmt(info.size)),
        ("Format", f"tres0r v{info.version} (ChaCha20-Poly1305, 64-KiB-Chunks)"),
        *((("Teile", f"{info.volumes} ({volumes.display_name(info.path)})"),) if info.volumes > 1 else ()),
        *((("Segmente", "mit angehängten Segmenten (Anzahl erst nach dem Entsperren)"),) if info.segmented else ()),
        *((("Achtung", "Anhängen wurde unterbrochen - 'tres0r repair'"),) if info.interrupted else ()),
        ("Inhalt", content),
        ("Keyslots", str(len(info.slots))),
    ]
    for label, value in rows:
        ui.out(f"{label + ':':<20}{value}")
    for row in _slot_rows(info):
        ui.out(row)
    if info.signed:
        ui.out(f"{'Signatur:':<20}ja (Unterzeichner steht verschlüsselt im Container)")
    if info.kdf is not None:
        ui.out(f"{'RAM zum Öffnen:':<20}mind. {info.kdf.memory_mib:g} MiB (per Passwort)")
    if info.version == 2:
        ui.status("Hinweis: Diese Angaben bestätigt erst das Entsperren (Header-MAC).")
    ui.data.update(
        path=str(info.path), size=info.size, format_version=info.version, payload_type=info.payload_type,
        compression=info.compression, has_index=info.has_index, level=info.level, signed=info.signed,
        volumes=info.volumes, segmented=info.segmented, interrupted=info.interrupted,
        kdf=None if info.kdf is None else {"algorithm": "argon2id", "memory_kib": info.kdf.memory_kib,
                                           "iterations": info.kdf.iterations, "lanes": info.kdf.lanes},
        slots=[{"index": s.index, "type": s.type, "description": s.description, "level": s.level}
               for s in info.slots],
    )
    return EXIT_OK


def cmd_passwd(args: argparse.Namespace, ui: Ui) -> int:
    info = container.inspect(args.container)
    creds = _credentials(args, info)
    if not args.password_file and not args.identity:
        creds.passwords.append(getpass.getpass("Aktuelles Passwort: "))
    new = _new_password(args, ui, "new_password_file")
    params = _params(args, ui)
    ui.status("Leite Schlüssel ab ...")
    container.change_password(args.container, creds, new, params, check_space=not args.no_space_check)
    level = args.level or container.inspect(args.container).level
    ui.out(f"Passwort geändert{f', Stufe jetzt {args.level}' if args.level else ''}: {args.container}")
    ui.data.update(path=str(args.container), level=level)
    return EXIT_OK


def cmd_diff(args: argparse.Namespace, ui: Ui) -> int:
    info = container.inspect(args.container)
    creds = _credentials(args, info)
    _unlock_status(ui, info, args)
    try:
        result = container.diff(args.container, args.files, creds, exclude=_exclude_rules(args),
                                ignore_files=not args.no_ignore_file, quick=args.quick, times=args.times,
                                progress=ui.progress("Vergleichen"), threads=args.threads)
    finally:
        ui.end_progress()
    width = max((len(c.status) for c in result.changes), default=0)
    for change in result.changes:
        detail = f"  ({change.detail})" if change.detail else ""
        ui.out(f"{change.status:<{width}}  {change.name}{detail}")
    method = "Größe und Änderungszeit" if result.quick else f"SHA-256 ({result.hashed} Dateien gehasht)"
    summary = "keine Unterschiede" if result.identical else f"{len(result.changes)} Unterschied(e)"
    ui.status(f"{summary}, {result.unchanged} Einträge unverändert - verglichen per {method}.")
    ui.data.update(identical=result.identical, unchanged=result.unchanged, hashed=result.hashed,
                   quick=result.quick,
                   changes=[{"name": c.name, "status": c.status, "detail": c.detail} for c in result.changes])
    return EXIT_OK if result.identical else EXIT_DIFFERENT


def cmd_append(args: argparse.Namespace, ui: Ui) -> int:
    info = container.inspect(args.container)
    if info.interrupted:
        raise Tres0rError(container.INTERRUPTED)
    signing_key = _signing_key(args) if args.sign else None
    creds = _credentials(args, info)
    split = volumes.base_of(Path(args.container))
    if split is not None:
        raise Tres0rError("Anhängen an aufgeteilte Container wird nicht unterstützt.")
    plan = container.scan(args.files, exclude=_exclude_rules(args), ignore_files=not args.no_ignore_file,
                          output=args.container)
    for path, reason in plan.skipped:
        ui.warn(f"übersprungen: {path} ({reason})")
    _unlock_status(ui, info, args)
    try:
        result = container.append(args.container, plan, creds, compress=args.compress, sign_with=signing_key,
                                  pad=not args.no_pad, progress=ui.progress("Verschlüsseln"),
                                  strict_names=args.strict_names, check_space=not args.no_space_check,
                                  times=not args.no_times, xattrs=args.xattrs, acls=args.acls, threads=args.threads)
    finally:
        ui.end_progress()
    ui.out(f"{result.path}: Segment {result.segment} angehängt ({result.entries} Einträge, "
           f"+{fmt(result.added)}, jetzt {fmt(result.size)})")
    ui.data.update(path=str(result.path), segment=result.segment, entries=result.entries,
                   added=result.added, size=result.size)
    return EXIT_OK


def cmd_repair(args: argparse.Namespace, ui: Ui) -> int:
    info = container.inspect(args.container)
    creds = _credentials(args, info)
    _unlock_status(ui, info, args)
    result = container.repair(args.container, creds)
    ui.out(result.action)
    ui.data.update(action=result.action, size=result.size)
    return EXIT_OK


def cmd_mount(args: argparse.Namespace, ui: Ui) -> int:
    from . import mount

    info = container.inspect(args.container)
    signers = _signers(args)
    creds = _credentials(args, info)
    if args.verify or signers:
        _unlock_status(ui, info, args)
        try:
            checked = container.verify(args.container, creds, progress=ui.progress("Prüfen"), signers=signers)
        finally:
            ui.end_progress()
        ui.status(f"Geprüft: {checked.files} Dateien intakt" + (f", Signatur {checked.signer}" if checked.signer else ""))
    elif info.signed:
        ui.status("Hinweis: Die Signatur wird beim Einhängen nicht geprüft - dafür --verify oder --signer.")
    ui.status(f"Hänge {args.container} unter {args.mountpoint} ein (schreibgeschützt) - "
              f"Strg+C oder 'tres0r umount {args.mountpoint}' zum Aushängen.")
    mount.mount(args.container, args.mountpoint, creds, allow_other=args.allow_other)
    ui.status("Ausgehängt.")
    ui.data.update(container=str(args.container), mountpoint=str(args.mountpoint))
    return EXIT_OK


def cmd_umount(args: argparse.Namespace, ui: Ui) -> int:
    from . import mount

    mount.unmount(args.mountpoint)
    ui.out(f"Ausgehängt: {args.mountpoint}")
    return EXIT_OK


def cmd_upgrade(args: argparse.Namespace, ui: Ui) -> int:
    info = container.inspect(args.container)
    creds = _credentials(args, info)
    _unlock_status(ui, info, args)
    try:
        result = container.upgrade(args.container, creds, args.output, compress=args.compress,
                                   pad=not args.no_pad, progress=ui.progress("Umwandeln"),
                                   check_space=not args.no_space_check, threads=args.threads,
                                   split=volumes.parse_size(args.split) if args.split else None)
    finally:
        ui.end_progress()
    ui.out(f"{result.path}  (Formatversion 2, {result.entries} Einträge, {fmt(result.size)})")
    ui.data.update(path=str(result.path), entries=result.entries, size=result.size)
    return EXIT_OK


def cmd_salvage(args: argparse.Namespace, ui: Ui) -> int:
    info = container.inspect(args.container)
    creds = _credentials(args, info)
    _unlock_status(ui, info, args)
    try:
        result = container.salvage(args.container, args.output, creds, rename=args.rename,
                                   progress=ui.progress("Retten"))
    finally:
        ui.end_progress()
    for note in result.notes:
        ui.status(f"Hinweis: {note}")
    for old, new in result.renamed:
        ui.warn(f"umbenannt: {old} -> {new}")
    for name, reason in result.damaged:
        ui.warn(f"nicht zu retten: {name} ({reason})")
    method = "über das Inhaltsverzeichnis" if result.used_index else "der Reihe nach"
    ui.out(f"{len(result.recovered)} Einträge gerettet ({method}), {len(result.damaged)} verloren -> {args.output}")
    ui.data.update(dest=str(args.output), recovered=result.recovered, used_index=result.used_index,
                   damaged=[{"name": n, "reason": r} for n, r in result.damaged], notes=result.notes,
                   complete=result.complete)
    return EXIT_OK if result.complete else EXIT_DAMAGED


# ---------------------------------------------------------------------------
# Befehle: Datenströme
# ---------------------------------------------------------------------------
def _refuse_terminal_output(target: str) -> None:
    if target == "-" and sys.stdout.isatty():
        raise Tres0rError("Binärdaten gehen nicht ins Terminal - bitte umleiten oder -o DATEI angeben.")


def cmd_encrypt(args: argparse.Namespace, ui: Ui) -> int:
    if args.json and args.output == "-":
        raise Tres0rError("--json und Ausgabe auf stdout schließen sich aus.")
    _refuse_terminal_output(args.output)
    _Terminal.stdin_is_data = args.input == "-"
    if args.compress:
        container.payload._require_zstd()
    setup = _key_setup(args, ui)
    params = _params(args, ui) if setup["password"] is not None else None
    source = sys.stdin.buffer if args.input == "-" else open(args.input, "rb")
    size = None if args.input == "-" else os.fstat(source.fileno()).st_size
    options = dict(recipients=setup["recipients"], recovery=setup["recovery"], compress=args.compress,
                   pad=not args.no_pad, sign_with=setup["sign_with"], total=size, threads=args.threads,
                   keyfile=setup["keyfile"], threshold=setup["threshold"], fido2=setup["fido2"])
    try:
        if args.output == "-":
            result = container.encrypt_stream(source, sys.stdout.buffer, setup["password"], params,
                                              progress=ui.progress("Verschlüsseln"), **options)
        else:
            split = volumes.parse_size(args.split) if args.split else None
            with container.atomic_output(args.output, overwrite=args.force, split=split) as out:
                result = container.encrypt_stream(source, out, setup["password"], params,
                                                  progress=ui.progress("Verschlüsseln"), **options)
    finally:
        ui.end_progress()
        if source is not sys.stdin.buffer:
            source.close()
    ui.status(f"{fmt(result.bytes)} verschlüsselt.")
    ui.data.update(input=args.input, output=args.output, bytes=result.bytes, compressed=args.compress)
    _deliver_shares(ui, result.shares, args.shares_dir, args.yes)
    return EXIT_OK


def cmd_decrypt(args: argparse.Namespace, ui: Ui) -> int:
    if args.json and args.output == "-":
        raise Tres0rError("--json und Ausgabe auf stdout schließen sich aus.")
    _refuse_terminal_output(args.output)
    _Terminal.stdin_is_data = args.container == "-"
    info = None if args.container == "-" else container.inspect(args.container)
    signers = _signers(args)
    creds = _credentials(args, info)
    if info is not None:
        _unlock_status(ui, info, args)
    if args.container == "-":
        source, size = sys.stdin.buffer, None
    else:
        source, size = volumes.open_read(args.container)  # auch Teilesätze
    try:
        if args.output == "-":
            result = container.decrypt_stream(source, sys.stdout.buffer, creds, signers=signers,
                                              progress=ui.progress("Entschlüsseln"), total=size)
        else:
            with container.atomic_output(args.output, overwrite=args.force) as out:
                result = container.decrypt_stream(source, out, creds, signers=signers,
                                                  progress=ui.progress("Entschlüsseln"), total=size)
    finally:
        ui.end_progress()
        if source is not sys.stdin.buffer:
            source.close()
    ui.status(f"{fmt(result.bytes)} entschlüsselt und vollständig geprüft.")
    ui.data.update(input=args.container, output=args.output, bytes=result.bytes)
    _report_signature(ui, result.signed, result.signer, bool(signers))
    return EXIT_OK


# ---------------------------------------------------------------------------
# Befehle: Schlüssel
# ---------------------------------------------------------------------------
def cmd_keygen(args: argparse.Namespace, ui: Ui) -> int:
    key = keys.generate_signing_key() if args.sign else keys.generate_identity()
    public = keys.public_text(key)
    kind = "Prüfschlüssel" if args.sign else "Öffentlicher Schlüssel"
    if args.output == "-":
        if args.json:
            raise Tres0rError("--json und Ausgabe auf stdout schließen sich aus.")
        if not args.unprotected:
            raise Tres0rError("Ausgabe auf stdout nur mit --unprotected.")
        print(keys.identity_file_text(key), end="", flush=True)
        _eprint(f"{kind}: {public}")
    else:
        if Path(args.output).exists():
            raise Tres0rError(f"{args.output} existiert bereits – wird nicht überschrieben.")
        passphrase = None if args.unprotected else _new_password(args, ui, "passphrase_file", ("Neue Schutz-Passphrase", "Passphrase"))
        params = _params(args, ui) if passphrase is not None else None
        if passphrase is not None:
            ui.status(f"Schütze die Datei - {_level_text(args, params)} ...")
        keys.write_identity_file(args.output, key, passphrase, params)
        protection = "ungeschützt!" if args.unprotected else "mit Passphrase geschützt"
        ui.status(f"Gespeichert: {args.output} (Rechte 0600, {protection})")
        ui.out(public)
    ui.data.update(identity_file=None if args.output == "-" else args.output, public_key=public,
                   kind="ed25519" if args.sign else "x25519", protected=not args.unprotected)
    return EXIT_OK


def cmd_pubkey(args: argparse.Namespace, ui: Ui) -> int:
    found = keys.load_key_file(args.identity_file, _key_passphrase(args, args.identity_file))
    publics = [keys.public_text(k) for k in found.identities + found.signing_keys]
    for public in publics:
        ui.out(public)
    ui.data["public_keys"] = publics
    return EXIT_OK


def cmd_protect(args: argparse.Namespace, ui: Ui) -> int:
    if keys.is_protected(args.identity_file):
        raise Tres0rError(f"{args.identity_file} ist bereits geschützt.")
    keys.load_key_file(args.identity_file)  # nur gültige Dateien schützen
    passphrase = _new_password(args, ui, "passphrase_file", ("Neue Schutz-Passphrase", "Passphrase"))
    params = _params(args, ui)
    ui.status(f"Schütze die Datei - {_level_text(args, params)} ...")
    keys.protect_identity_file(args.identity_file, passphrase, params)
    ui.out(f"{args.identity_file} ist jetzt mit einer Passphrase geschützt.")
    ui.data.update(identity_file=args.identity_file, protected=True)
    return EXIT_OK


def cmd_keys_list(args: argparse.Namespace, ui: Ui) -> int:
    info = container.inspect(args.container)
    for row in _slot_rows(info):
        ui.out(row)
    if info.version == 2:
        ui.status("Hinweis: bestätigt erst beim Entsperren (Header-MAC).")
    ui.data["slots"] = [{"index": s.index, "type": s.type, "description": s.description, "level": s.level}
                        for s in info.slots]
    return EXIT_OK


def _keys_change(args: argparse.Namespace, ui: Ui, **new) -> int:
    info = container.inspect(args.container)
    creds = _credentials(args, info)
    _unlock_status(ui, info, args)
    added = container.add_keys(args.container, creds, check_space=not args.no_space_check, **new)
    final = container.inspect(args.container)
    for i in added:
        ui.out(f"hinzugefügt: [{i}] {final.slots[i].description}")
    ui.data.update(path=str(args.container), added=added,
                   slots=[{"index": s.index, "type": s.type, "description": s.description} for s in final.slots])
    return EXIT_OK


def cmd_keys_add_password(args: argparse.Namespace, ui: Ui) -> int:
    container.inspect(args.container)
    new = _new_password(args, ui, "new_password_file")
    keyfile = keys.keyfile_secret(args.new_keyfile) if args.new_keyfile else None
    fido2 = _fido2_provider() if args.new_fido2 else None
    return _keys_change(args, ui, password=new, params=_params(args, ui), keyfile=keyfile, fido2=fido2)


def cmd_gui(args: argparse.Namespace, ui: Ui) -> int:
    try:
        from . import gui
    except ImportError:
        raise Tres0rError("Die grafische Oberfläche braucht PySide6: pip install 'tres0r[gui]'") from None
    return gui.run(args.folder)


def cmd_tui(args: argparse.Namespace, ui: Ui) -> int:
    try:
        from . import tui
    except ImportError:
        raise Tres0rError("Die Textoberfläche braucht Textual: pip install 'tres0r[tui]'") from None
    tui.run(args.folder)
    return EXIT_OK


def cmd_completion(args: argparse.Namespace, ui: Ui) -> int:
    from . import docgen

    sys.stdout.write(docgen.bash_completion() if args.shell == "bash" else docgen.zsh_completion())
    return EXIT_OK


def cmd_manpage(args: argparse.Namespace, ui: Ui) -> int:
    from . import docgen

    sys.stdout.write(docgen.manpage())
    return EXIT_OK


def cmd_fido2(args: argparse.Namespace, ui: Ui) -> int:
    found = hwtoken.devices()
    for device in found:
        ui.out(hwtoken.describe(device))
    if not found:
        ui.status("Kein FIDO2-Token gefunden.")
    ui.data["tokens"] = [hwtoken.describe(d) for d in found]
    return EXIT_OK


def cmd_keys_add_shares(args: argparse.Namespace, ui: Ui) -> int:
    k, n = _parse_threshold(args.threshold)
    info = container.inspect(args.container)
    creds = _credentials(args, info)
    _unlock_status(ui, info, args)
    index, shares = container.add_threshold(args.container, creds, k, n, check_space=not args.no_space_check)
    ui.out(f"hinzugefügt: [{index}] Schwellwert ({k} von {n} Anteilen)")
    ui.data.update(path=str(args.container), added=[index])
    _deliver_shares(ui, shares, args.shares_dir, args.yes)
    return EXIT_OK


def cmd_keyfile(args: argparse.Namespace, ui: Ui) -> int:
    keys.generate_keyfile(args.output)
    ui.out(f"Keyfile erzeugt: {args.output} ({keys.KEYFILE_BYTES} Byte Zufall, Rechte 0600)")
    ui.status("Aufbewahren wie einen Schlüssel – ohne Keyfile öffnet das Passwort allein nichts.")
    ui.data.update(keyfile=args.output)
    return EXIT_OK


def cmd_keys_add_recovery(args: argparse.Namespace, ui: Ui) -> int:
    container.inspect(args.container)
    return _keys_change(args, ui, recovery=_new_recovery(args, ui))


def cmd_keys_add_recipient(args: argparse.Namespace, ui: Ui) -> int:
    recipients = _recipients(args)
    if not recipients:
        raise Tres0rError("Bitte mindestens einen Empfänger angeben (-r/-R).")
    return _keys_change(args, ui, recipients=recipients)


def cmd_keys_remove(args: argparse.Namespace, ui: Ui) -> int:
    info = container.inspect(args.container)
    creds = _credentials(args, info)
    _unlock_status(ui, info, args)
    removed = container.remove_key(args.container, creds, args.slot, check_space=not args.no_space_check)
    ui.out(f"entfernt: [{removed.index}] {removed.description}")
    remaining = container.inspect(args.container)
    for row in _slot_rows(remaining):
        ui.out(row)
    ui.data.update(path=str(args.container), removed={"index": removed.index, "type": removed.type},
                   slots=[{"index": s.index, "type": s.type, "description": s.description}
                          for s in remaining.slots])
    return EXIT_OK


# ---------------------------------------------------------------------------
# Befehle: Passwörter
# ---------------------------------------------------------------------------
def cmd_genpass(args: argparse.Namespace, ui: Ui) -> int:
    secrets = [_generate(args.kind, args) for _ in range(args.count)]
    for secret in secrets:
        ui.out(secret.value)
    label = "Passphrase" if args.kind == "passphrase" else "Passwort"
    ui.status(f"Entropie: ca. {secrets[0].entropy_bits:.0f} Bit je {label}")
    ui.data.update(kind=secrets[0].kind, entropy_bits=round(secrets[0].entropy_bits, 1),
                   secrets=[s.value for s in secrets])
    return EXIT_OK


def cmd_checkpass(args: argparse.Namespace, ui: Ui) -> int:
    check = passgen.check_password(_existing_password(args.password_file), online=not args.offline)
    ui.out(f"Länge: {check.length} Zeichen, Zeichenarten: {check.classes}/4")
    if check.pwned is not None:
        ui.out(f"HIBP: {'nicht gefunden' if check.pwned == 0 else f'{check.pwned}-mal in Datenlecks'}")
    elif check.hibp_error:
        ui.out(f"HIBP: {check.hibp_error}")
    else:
        ui.out("HIBP: übersprungen (--offline)")
    for problem in check.warnings:
        ui.out(f"Warnung: {problem}.")
    ui.data.update(passed=check.ok, length=check.length, classes=check.classes, pwned=check.pwned,
                   hibp_error=check.hibp_error, problems=check.warnings)
    return EXIT_OK if check.ok else EXIT_ERROR


def _throughput(ui: Ui, directory: str | None, size_mib: int) -> list[dict]:
    """pack/verify mit 1 Thread und automatisch, mit und ohne zstd, auf echten Dateien."""
    import tempfile

    from . import payload, workers

    auto = workers.resolve_threads(None)
    fast = kdf.KdfParams(8 * 1024, 1, 1)
    results = []
    with tempfile.TemporaryDirectory(prefix="tres0r-bench-", dir=directory) as tmp:
        src = Path(tmp) / "daten"
        src.mkdir()
        chunk = os.urandom(1 << 20)
        with open(src / "gross.bin", "wb") as f:  # halb zufällig, halb komprimierbar
            for i in range(size_mib):
                f.write(chunk if i % 2 else (b"tres0r " * 149796)[: 1 << 20])
        for i in range(200):
            (src / f"klein{i}.txt").write_bytes(os.urandom(2048) + b"text " * 2000)
        total = sum(p.stat().st_size for p in src.iterdir()) / 2**20
        modes = [False] + ([True] if payload.zstd_backend() else [])
        thread_counts = [1] + ([auto] if auto > 1 else [])
        ui.out(f"\nDurchsatz ({total:.0f} MiB, {os.cpu_count()} Kerne, Ordner {tmp}):")
        ui.out(f"{'Vorgang':<20} {'Threads':>7} {'Zeit':>8} {'MiB/s':>7}")
        for compress in modes:
            for threads in thread_counts:
                out = Path(tmp) / "b.tres0r"
                for label, action in (
                    ("pack" + (" (zstd)" if compress else ""), lambda: container.create(
                        [src], out, "benchmark", fast, compress=compress, overwrite=True, threads=threads,
                        check_space=False)),
                    ("verify" + (" (zstd)" if compress else ""), lambda: container.verify(
                        out, "benchmark", threads=threads)),
                ):
                    start = time.perf_counter()
                    action()
                    seconds = time.perf_counter() - start
                    ui.out(f"{label:<20} {threads:>7} {seconds:7.2f}s {total / seconds:7.0f}")
                    results.append({"operation": label, "threads": threads, "seconds": round(seconds, 3),
                                    "mib_per_s": round(total / seconds, 1)})
    if auto == 1:
        ui.out("(nur 1 Kern erkannt – Thread-Vergleich nicht möglich)")
    return results


def cmd_bench(args: argparse.Namespace, ui: Ui) -> int:
    ui.out(f"{'Stufe':<9} {'Parameter':<38} Zeit")
    results = []
    for name, params in LEVELS.items():
        start = time.perf_counter()
        try:
            derive_key("benchmark", bytes(16), params)
        except (MemoryError, Tres0rError, ValueError) as e:
            ui.out(f"{name:<9} {params.describe():<38} fehlgeschlagen: {e}")
            results.append({"level": name, "seconds": None, "error": str(e)})
            continue
        seconds = time.perf_counter() - start
        ui.out(f"{name:<9} {params.describe():<38} {seconds:5.2f} s")
        results.append({"level": name, "seconds": round(seconds, 3), "memory_kib": params.memory_kib,
                        "iterations": params.iterations, "lanes": params.lanes})
    auto = kdf.calibrate(args.kdf_time)
    ui.out(f"{'auto':<9} {auto.describe():<38} {kdf.measure(auto):5.2f} s   (-l auto, Ziel {args.kdf_time:g} s)")
    results.append({"level": "auto", "memory_kib": auto.memory_kib, "iterations": auto.iterations,
                    "lanes": auto.lanes, "target_seconds": args.kdf_time})
    ui.out("\nDiese Zeit fällt bei jedem Öffnen an - und für Angreifer bei jedem Rateversuch.")
    ui.data["levels"] = results
    if args.throughput:
        ui.data["throughput"] = _throughput(ui, args.dir, args.size)
    return EXIT_OK


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def _common_options() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--json", action="store_true", help="Ergebnis als JSON auf stdout")
    return parent


def _unlock_options() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    g = parent.add_argument_group("Entsperren")
    g.add_argument("--password-file", metavar="DATEI",
                   help="Passwort/Wiederherstellungsphrase aus erster Zeile ('-' = stdin)")
    g.add_argument("-i", "--identity", action="append", metavar="DATEI", help="X25519-Identität (mehrfach möglich)")
    g.add_argument("--key-passphrase-file", metavar="DATEI",
                   help="Passphrase für geschützte Schlüsseldateien (sonst Rückfrage)")
    g.add_argument("--keyfile", action="append", metavar="DATEI", help="Keyfile als zweiter Faktor (mehrfach möglich)")
    g.add_argument("--fido2", action="store_true", help="FIDO2-Token als zweiten Faktor verwenden (Berührung)")
    g.add_argument("--share", action="append", metavar="ANTEIL", help="Schwellwert-Anteil (tres0r-teil-…), mehrfach")
    g.add_argument("--shares-file", action="append", metavar="DATEI", help="Datei mit Anteilen (einer pro Zeile)")
    return parent


def _signer_options() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    g = parent.add_argument_group("Signatur")
    g.add_argument("--signer", action="append", metavar="SCHLÜSSEL",
                   help="Signatur von diesem Prüfschlüssel (tres0r-sig-...) verlangen, mehrfach möglich")
    g.add_argument("--signers-file", action="append", metavar="DATEI", help="Datei mit erlaubten Prüfschlüsseln")
    return parent


def _generator_options() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    g = parent.add_argument_group("Generator (pwgen)")
    g.add_argument("-w", "--words", type=int, default=passgen.DEFAULT_WORDS,
                   help=f"Wörter je Passphrase ({passgen.PASSPHRASE_MIN_WORDS}-{passgen.PASSPHRASE_MAX_WORDS}, Standard %(default)s)")
    g.add_argument("-n", "--length", type=int, default=passgen.DEFAULT_PASSWORD_LEN,
                   help=f"Zeichen je Passwort ({passgen.PASSWORD_MIN_LEN}-{passgen.PASSWORD_MAX_LEN}, Standard %(default)s)")
    g.add_argument("--wordlist", choices=passgen.LANGUAGES, default="de",
                   help="Wortliste für Passphrasen und Wiederherstellung (Standard %(default)s)")
    g.add_argument("--sep", default=passgen.DEFAULT_SEPARATOR, help="Trennzeichen (Standard '%(default)s')")
    g.add_argument("--capitalize", action="store_true", help="Wörter groß beginnen lassen")
    g.add_argument("--digit", action="store_true", help="Ziffer an die Passphrase anhängen")
    g.add_argument("--no-symbols", action="store_true", help="Passwort ohne Sonderzeichen")
    g.add_argument("--no-ambiguous", action="store_true",
                   help=f"Passwort ohne mehrdeutige Zeichen ({''.join(sorted(passgen.AMBIGUOUS))})")
    return parent


def _new_password_options(file_option: str = "--password-file") -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    g = parent.add_argument_group("Neues Passwort")
    g.add_argument("-g", "--generate", choices=KINDS, help="generieren statt eingeben")
    g.add_argument(file_option, metavar="DATEI", help="erste Zeile als neues Passwort ('-' = stdin)")
    g.add_argument("--offline", action="store_true", help="keine HIBP-Abfrage")
    g.add_argument("-y", "--yes", action="store_true", help="generierte Geheimnisse nicht abtippen lassen")
    return parent


def _key_options() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    g = parent.add_argument_group("Weitere Schlüssel")
    g.add_argument("-r", "--recipient", action="append", metavar="SCHLÜSSEL",
                   help="öffentlicher Schlüssel (tres0r-pub-...), mehrfach möglich")
    g.add_argument("-R", "--recipients-file", action="append", metavar="DATEI",
                   help="Datei mit Empfängern (oder eine Identitätsdatei)")
    g.add_argument("--recovery", action="store_true", help="Wiederherstellungsphrase (20 Wörter) erzeugen")
    g.add_argument("--no-password", action="store_true", help="kein Passwort, nur Empfänger/Phrase")
    g.add_argument("--sign", metavar="DATEI", help="mit dem Signaturschlüssel aus dieser Identitätsdatei signieren")
    g.add_argument("--keyfile", metavar="DATEI", help="Keyfile als zweiter Faktor zum Passwort")
    g.add_argument("--fido2", action="store_true", help="FIDO2-Token als zweiter Faktor zum Passwort (hmac-secret)")
    g.add_argument("--shares", metavar="K/N", help="Schwellwert-Slot: K von N Anteilen öffnen den Container")
    g.add_argument("--shares-dir", metavar="ORDNER", help="Anteile als einzelne Dateien ablegen statt anzeigen")
    g.add_argument("--key-passphrase-file", metavar="DATEI",
                   help="Passphrase für geschützte Schlüsseldateien (sonst Rückfrage)")
    return parent


def _level_option(p: argparse.ArgumentParser, default: str | None, help_prefix: str) -> None:
    level_help = "; ".join(f"{n}: {h}" for n, h in LEVEL_HINTS.items())
    p.add_argument("-l", "--level", choices=[*LEVELS, "auto"], default=default,
                   help=f"{help_prefix} {level_help}; auto: auf --kdf-time kalibrieren")
    p.add_argument("--kdf-time", type=float, default=2.0, metavar="SEK",
                   help="Zielzeit für -l auto in Sekunden (Standard %(default)s)")


def _threads_option(p: argparse.ArgumentParser) -> None:
    p.add_argument("--threads", type=int, metavar="N",
                   help="Threads für Hashen und zstd (Standard: Anzahl Kerne, höchstens 8; 1 = aus)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tres0r",
        description="Dateien und Datenströme verschlüsseln (Argon2id, X25519, ChaCha20-Poly1305).",
        epilog="Exit-Codes: 0 OK, 1 Fehler/Abbruch, 2 falsches Passwort/kein passender Schlüssel, "
               "3 Container beschädigt/manipuliert/unsicher, 4 Unterschiede (diff), 130 Strg+C.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="BEFEHL")
    common, unlock, gen, keyopts = _common_options(), _unlock_options(), _generator_options(), _key_options()
    signer = _signer_options()
    newpass = _new_password_options("--passphrase-file")
    newpw, newpw_named = _new_password_options(), _new_password_options("--new-password-file")

    # -- Container ----------------------------------------------------------
    p = sub.add_parser("pack", parents=[common, newpw, keyopts, gen], help="Dateien/Ordner verschlüsseln")
    p.add_argument("files", nargs="+", metavar="PFAD")
    p.add_argument("-o", "--output", metavar="DATEI", help="Zieldatei (bei einer Quelle: NAME.tres0r)")
    _level_option(p, DEFAULT_LEVEL, f"Stufe des Passworts (Standard {DEFAULT_LEVEL}).")
    p.add_argument("-f", "--force", action="store_true", help="vorhandene Zieldatei überschreiben")
    sel = p.add_argument_group("Auswahl")
    sel.add_argument("-x", "--exclude", action="append", metavar="MUSTER",
                     help="ausschließen, z. B. '*.tmp', 'build/', 'Projekt/entwurf' (mehrfach möglich)")
    sel.add_argument("--exclude-from", action="append", metavar="DATEI", help="Muster aus Datei lesen")
    sel.add_argument("--exclude-junk", action="store_true",
                     help="Systemmüll auslassen (.DS_Store, Thumbs.db, __pycache__, Office-Sperrdateien ...)")
    sel.add_argument("--no-ignore-file", action="store_true", help=".tres0rignore in Quellordnern nicht beachten")
    sel.add_argument("--strict-names", action="store_true",
                     help="abbrechen, wenn Namen nicht auf allen Systemen gültig sind")
    opt = p.add_argument_group("Optionen")
    opt.add_argument("-z", "--compress", action="store_true", help="mit zstd komprimieren")
    opt.add_argument("--no-pad", action="store_true", help="kein Größen-Padding (verrät die exakte Datenmenge)")
    opt.add_argument("--verify", action="store_true", help="fertigen Container danach komplett prüfen")
    opt.add_argument("--no-space-check", action="store_true", help="freien Speicherplatz nicht prüfen")
    opt.add_argument("--split", metavar="GRÖSSE", help="in Teile aufteilen, z. B. 4G, 700M (NAME.001, .002 …)")
    _threads_option(opt)
    meta = p.add_argument_group("Metadaten")
    meta.add_argument("--no-times", action="store_true",
                      help="keine Änderungszeiten speichern (beim Entpacken gilt die aktuelle Zeit)")
    meta.add_argument("--xattrs", action="store_true", help="erweiterte Attribute user.* sichern (Linux)")
    meta.add_argument("--acls", action="store_true", help="POSIX-ACLs sichern (Linux)")
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("unpack", parents=[common, unlock, signer], help="Container entpacken")
    p.add_argument("container", help="Containerdatei oder '-' für stdin")
    p.add_argument("-o", "--output", default=".", metavar="ORDNER", help="Zielordner (Standard: aktueller)")
    p.add_argument("--only", action="append", metavar="MUSTER",
                   help="nur passende Pfade/Ordner, z. B. 'Projekt/docs' oder '*.pdf' (mehrfach möglich)")
    p.add_argument("--rename", action="store_true",
                   help="kollidierende oder hier ungültige Namen umbenennen statt abzubrechen")
    p.add_argument("--no-space-check", action="store_true", help="freien Speicherplatz nicht prüfen")
    p.add_argument("--xattrs", action="store_true", help="gesicherte user.*-Attribute wiederherstellen (Linux)")
    p.add_argument("--acls", action="store_true", help="gesicherte POSIX-ACLs wiederherstellen (Linux)")
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("verify", parents=[common, unlock, signer],
                       help="Container komplett prüfen (inkl. Signatur), ohne zu entpacken")
    p.add_argument("container")
    _threads_option(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("list", parents=[common, unlock], help="Inhalt anzeigen")
    p.add_argument("container")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("info", parents=[common], help="Header und Keyslots anzeigen (ohne Passwort)")
    p.add_argument("container")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("passwd", parents=[common, unlock, newpw_named, gen],
                       help="Passwort/Stufe ändern ohne Neuverschlüsselung")
    p.add_argument("container")
    _level_option(p, None, "neue Stufe (Standard: beibehalten).")
    p.add_argument("--no-space-check", action="store_true", help="freien Speicherplatz nicht prüfen")
    p.set_defaults(func=cmd_passwd)

    p = sub.add_parser("diff", parents=[common, unlock],
                       help="Container mit Ordnern vergleichen (Exit 4 bei Unterschieden)")
    p.add_argument("container")
    p.add_argument("files", nargs="+", metavar="PFAD", help="dieselben Pfade wie beim Packen")
    p.add_argument("--quick", action="store_true", help="nur Größe und Änderungszeit vergleichen (wie rsync)")
    p.add_argument("--times", action="store_true", help="auch reine Zeitunterschiede melden")
    _threads_option(p)
    sel = p.add_argument_group("Auswahl (wie bei pack)")
    sel.add_argument("-x", "--exclude", action="append", metavar="MUSTER")
    sel.add_argument("--exclude-from", action="append", metavar="DATEI")
    sel.add_argument("--exclude-junk", action="store_true")
    sel.add_argument("--no-ignore-file", action="store_true")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("append", parents=[common, unlock],
                       help="Dateien als neues Segment anhängen (Bestand bleibt unberührt)")
    p.add_argument("container")
    p.add_argument("files", nargs="+", metavar="PFAD")
    p.add_argument("-z", "--compress", action="store_true", help="dieses Segment mit zstd komprimieren")
    p.add_argument("--sign", metavar="DATEI", help="dieses Segment mit dem Schlüssel aus DATEI signieren")
    p.add_argument("--no-pad", action="store_true", help="kein Größen-Padding")
    p.add_argument("--no-space-check", action="store_true", help="freien Speicherplatz nicht prüfen")
    p.add_argument("--strict-names", action="store_true", help="abbrechen, wenn Namen nicht überall gültig sind")
    _threads_option(p)
    sel = p.add_argument_group("Auswahl (wie bei pack)")
    sel.add_argument("-x", "--exclude", action="append", metavar="MUSTER")
    sel.add_argument("--exclude-from", action="append", metavar="DATEI")
    sel.add_argument("--exclude-junk", action="store_true")
    sel.add_argument("--no-ignore-file", action="store_true")
    meta = p.add_argument_group("Metadaten (wie bei pack)")
    meta.add_argument("--no-times", action="store_true")
    meta.add_argument("--xattrs", action="store_true")
    meta.add_argument("--acls", action="store_true")
    p.set_defaults(func=cmd_append)

    p = sub.add_parser("repair", parents=[common, unlock], help="nach unterbrochenem Anhängen gültigen Stand herstellen")
    p.add_argument("container")
    p.set_defaults(func=cmd_repair)

    p = sub.add_parser("mount", parents=[common, unlock, signer],
                       help="Container schreibgeschützt einhängen (FUSE, Linux/macOS)")
    p.add_argument("container")
    p.add_argument("mountpoint", metavar="ORDNER")
    p.add_argument("--verify", action="store_true", help="vorher vollständig prüfen (inkl. Signatur)")
    p.add_argument("--allow-other", action="store_true", help="auch anderen Benutzern Zugriff geben (FUSE-Option)")
    p.set_defaults(func=cmd_mount)

    p = sub.add_parser("umount", parents=[common], help="eingehängten Container aushängen")
    p.add_argument("mountpoint", metavar="ORDNER")
    p.set_defaults(func=cmd_umount)

    p = sub.add_parser("upgrade", parents=[common, unlock], help="Container von Formatversion 1 auf 2 umwandeln")
    p.add_argument("container")
    p.add_argument("-o", "--output", metavar="DATEI", help="in neue Datei schreiben (Standard: ersetzen)")
    p.add_argument("-z", "--compress", action="store_true", help="dabei mit zstd komprimieren")
    p.add_argument("--no-pad", action="store_true", help="kein Größen-Padding")
    p.add_argument("--no-space-check", action="store_true", help="freien Speicherplatz nicht prüfen")
    p.add_argument("--split", metavar="GRÖSSE", help="Ergebnis in Teile aufteilen")
    _threads_option(p)
    p.set_defaults(func=cmd_upgrade)

    p = sub.add_parser("salvage", parents=[common, unlock],
                       help="intakte Dateien aus einem beschädigten Container retten")
    p.add_argument("container")
    p.add_argument("-o", "--output", required=True, metavar="ORDNER", help="Zielordner für das Gerettete")
    p.add_argument("--rename", action="store_true", help="kollidierende oder hier ungültige Namen umbenennen")
    p.set_defaults(func=cmd_salvage)

    # -- Datenströme --------------------------------------------------------
    p = sub.add_parser("encrypt", parents=[common, newpw, keyopts, gen],
                       help="Datenstrom/Datei verschlüsseln (z. B. aus einer Pipe)")
    p.add_argument("input", nargs="?", default="-", metavar="EINGABE", help="Datei oder '-' für stdin (Standard)")
    p.add_argument("-o", "--output", required=True, metavar="AUSGABE", help="Zieldatei oder '-' für stdout")
    _level_option(p, DEFAULT_LEVEL, f"Stufe des Passworts (Standard {DEFAULT_LEVEL}).")
    p.add_argument("-z", "--compress", action="store_true", help="mit zstd komprimieren")
    p.add_argument("--no-pad", action="store_true", help="kein Größen-Padding")
    p.add_argument("-f", "--force", action="store_true", help="vorhandene Zieldatei überschreiben")
    p.add_argument("--split", metavar="GRÖSSE", help="in Teile aufteilen, z. B. 4G, 700M")
    _threads_option(p)
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", parents=[common, unlock, signer],
                       help="Datenstrom ausgeben (bei Datei-Containern: den tar-Stream)")
    p.add_argument("container", metavar="CONTAINER", help="Datei oder '-' für stdin")
    p.add_argument("-o", "--output", default="-", metavar="AUSGABE", help="Zieldatei oder '-' für stdout (Standard)")
    p.add_argument("-f", "--force", action="store_true", help="vorhandene Zieldatei überschreiben")
    p.set_defaults(func=cmd_decrypt)

    # -- Schlüssel ----------------------------------------------------------
    p = sub.add_parser("keygen", parents=[common, newpass, gen],
                       help="Schlüsselpaar erzeugen (X25519, mit --sign Ed25519)")
    p.add_argument("-o", "--output", required=True, metavar="DATEI", help="Identitätsdatei ('-' = stdout)")
    p.add_argument("--sign", action="store_true", help="Signaturschlüssel (Ed25519) statt Verschlüsselungsschlüssel")
    p.add_argument("--unprotected", action="store_true", help="Datei NICHT mit einer Passphrase schützen")
    _level_option(p, "stark", "Stufe des Schutzes (Standard stark).")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("gui", parents=[common], help="grafische Oberfläche starten (Extra tres0r[gui])")
    p.add_argument("folder", nargs="?", metavar="ORDNER", help="Startordner (Standard: Home)")
    p.set_defaults(func=cmd_gui)

    p = sub.add_parser("tui", parents=[common], help="Textoberfläche starten (Extra tres0r[tui])")
    p.add_argument("folder", nargs="?", metavar="ORDNER", help="Startordner (Standard: aktueller Ordner)")
    p.set_defaults(func=cmd_tui)

    p = sub.add_parser("completion", parents=[common], help="Shell-Vervollständigung ausgeben (bash oder zsh)")
    p.add_argument("shell", choices=["bash", "zsh"])
    p.set_defaults(func=cmd_completion)

    p = sub.add_parser("manpage", parents=[common], help="Manpage (roff) ausgeben")
    p.set_defaults(func=cmd_manpage)

    p = sub.add_parser("fido2", parents=[common], help="angeschlossene FIDO2-Tokens anzeigen")
    p.set_defaults(func=cmd_fido2)

    p = sub.add_parser("keyfile", parents=[common], help="Keyfile (zweiter Faktor) erzeugen")
    p.add_argument("-o", "--output", required=True, metavar="DATEI")
    p.set_defaults(func=cmd_keyfile)

    p = sub.add_parser("pubkey", parents=[common], help="öffentliche Schlüssel einer Identitätsdatei anzeigen")
    p.add_argument("identity_file", metavar="IDENTITÄT")
    p.add_argument("--key-passphrase-file", metavar="DATEI", help="Passphrase (sonst Rückfrage)")
    p.set_defaults(func=cmd_pubkey)

    p = sub.add_parser("protect", parents=[common, newpass, gen],
                       help="ungeschützte Identitätsdatei mit einer Passphrase schützen")
    p.add_argument("identity_file", metavar="IDENTITÄT")
    _level_option(p, "stark", "Stufe des Schutzes (Standard stark).")
    p.set_defaults(func=cmd_protect)

    keys_parser = sub.add_parser("keys", help="Keyslots eines Containers verwalten")
    keys_sub = keys_parser.add_subparsers(dest="keys_command", required=True, metavar="AKTION")

    k = keys_sub.add_parser("list", parents=[common], help="Keyslots anzeigen (ohne Passwort)")
    k.add_argument("container")
    k.set_defaults(func=cmd_keys_list)

    k = keys_sub.add_parser("add-password", parents=[common, unlock, newpw_named, gen],
                            help="weiteres Passwort hinzufügen")
    k.add_argument("container")
    k.add_argument("--new-keyfile", metavar="DATEI", help="neues Passwort nur zusammen mit diesem Keyfile")
    k.add_argument("--new-fido2", action="store_true", help="neues Passwort nur zusammen mit dem gesteckten FIDO2-Token")
    _level_option(k, DEFAULT_LEVEL, f"Stufe (Standard {DEFAULT_LEVEL}).")
    k.add_argument("--no-space-check", action="store_true", help=argparse.SUPPRESS)
    k.set_defaults(func=cmd_keys_add_password)

    k = keys_sub.add_parser("add-shares", parents=[common, unlock], help="Schwellwert-Slot hinzufügen (K von N)")
    k.add_argument("container")
    k.add_argument("threshold", metavar="K/N", help="z. B. 2/3")
    k.add_argument("--shares-dir", metavar="ORDNER", help="Anteile als einzelne Dateien ablegen")
    k.add_argument("-y", "--yes", action="store_true", help="Anteile nur ausgeben, nicht ausblenden")
    k.add_argument("--no-space-check", action="store_true", help=argparse.SUPPRESS)
    k.set_defaults(func=cmd_keys_add_shares)

    k = keys_sub.add_parser("add-recovery", parents=[common, unlock, gen],
                            help="Wiederherstellungsphrase hinzufügen")
    k.add_argument("container")
    k.add_argument("-y", "--yes", action="store_true", help="Phrase nicht abfragen")
    k.add_argument("--no-space-check", action="store_true", help=argparse.SUPPRESS)
    k.set_defaults(func=cmd_keys_add_recovery)

    k = keys_sub.add_parser("add-recipient", parents=[common, unlock], help="Empfänger hinzufügen")
    k.add_argument("container")
    k.add_argument("-r", "--recipient", action="append", metavar="SCHLÜSSEL")
    k.add_argument("-R", "--recipients-file", action="append", metavar="DATEI")
    k.add_argument("--no-space-check", action="store_true", help=argparse.SUPPRESS)
    k.set_defaults(func=cmd_keys_add_recipient)

    k = keys_sub.add_parser("remove", parents=[common, unlock], help="Keyslot entfernen")
    k.add_argument("container")
    k.add_argument("slot", type=int, metavar="SLOT", help="Nummer laut 'keys list'")
    k.add_argument("--no-space-check", action="store_true", help=argparse.SUPPRESS)
    k.set_defaults(func=cmd_keys_remove)

    # -- Passwörter ---------------------------------------------------------
    p = sub.add_parser("genpass", parents=[common, gen], help="Passwort/Passphrase generieren (pwgen)")
    p.add_argument("kind", nargs="?", choices=KINDS, default="passphrase")
    p.add_argument("-c", "--count", type=int, default=1, help="Anzahl (Standard %(default)s)")
    p.set_defaults(func=cmd_genpass)

    p = sub.add_parser("checkpass", parents=[common], help="Passwort prüfen (Länge, Zeichenarten, HIBP)")
    p.add_argument("--password-file", metavar="DATEI")
    p.add_argument("--offline", action="store_true", help="keine HIBP-Abfrage")
    p.set_defaults(func=cmd_checkpass)

    p = sub.add_parser("bench", parents=[common], help="Stufen, -l auto und Durchsatz auf diesem Rechner messen")
    p.add_argument("--kdf-time", type=float, default=2.0, metavar="SEK", help="Zielzeit für den auto-Vorschlag")
    p.add_argument("--throughput", action="store_true", help="zusätzlich pack/verify mit und ohne Threads messen")
    p.add_argument("--dir", metavar="ORDNER", help="Ordner für die Testdaten (Standard: temporär)")
    p.add_argument("--size", type=int, default=256, metavar="MiB", help="Größe der Testdaten (Standard %(default)s)")
    p.set_defaults(func=cmd_bench)
    return parser


def main(argv: list[str] | None = None) -> int:
    pwgen.setup_stdio()  # UTF-8 auch in der alten Windows-Konsole und bei Umleitung
    _Terminal.stdin_is_data = False
    args = build_parser().parse_args(argv)
    try:
        return _run(args)
    except BrokenPipeError:  # z. B. "tres0r list … | head": Leser hat genug, still beenden
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return EXIT_ERROR


def _run(args: argparse.Namespace) -> int:
    ui = Ui(args.json)
    command = args.command + (f" {args.keys_command}" if args.command == "keys" else "")
    error: BaseException | None = None
    try:
        code = args.func(args, ui)
    except KeyboardInterrupt as e:
        code, error = EXIT_INTERRUPTED, e
    except WrongPassword as e:
        code, error = EXIT_WRONG_PASSWORD, e
    except (IntegrityError, FormatError, UnsafeArchive) as e:
        code, error = EXIT_DAMAGED, e
    except (Tres0rError, ValueError, OSError, EOFError) as e:
        code, error = EXIT_ERROR, e
    finally:
        ui.end_progress()

    message = None
    if error is not None:
        message = {KeyboardInterrupt: "Abgebrochen.", EOFError: "Eingabe vorzeitig beendet."}.get(
            type(error), str(error)
        )
        if not ui.json:
            _eprint(message if isinstance(error, (Cancelled, KeyboardInterrupt)) else f"Fehler: {message}")

    if ui.json:
        payload = {"ok": error is None, "command": command, "exit_code": code, **ui.data}
        if ui.warnings:
            payload["warnings"] = ui.warnings
        if error is not None:
            payload["error"] = {"type": type(error).__name__, "message": message}
        print(json.dumps(payload, ensure_ascii=False, indent=2), flush=True)
    return code
