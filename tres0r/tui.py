"""Textoberfläche (Textual) – ``tres0r tui [ORDNER]``, Extra ``tres0r-crypt[tui]``.

Links ein Dateibaum, rechts Details zur Auswahl. Container lassen sich öffnen
(Inhaltsbaum aus dem Inhaltsverzeichnis), entpacken und prüfen; Dateien und Ordner
lassen sich packen. Lange Vorgänge laufen in Arbeitsthreads mit Fortschritt,
Durchsatz, Restzeit und Abbruch (``progress.Monitor``/``CancelToken``).

Nicht Teil der stabilen API; baut nur auf ihr auf.
"""
from __future__ import annotations

import fnmatch
import os
import threading
from pathlib import Path
from typing import Callable

from rich.markup import escape
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (Button, DataTable, DirectoryTree, Footer, Header, Input, Label, ProgressBar, Select,
                             Static, Switch, Tree)
from textual.worker import Worker, WorkerState, get_current_worker

from . import container, hwtoken, keys, passgen
from .errors import Cancelled, Tres0rError, WrongPassword
from .kdf import LEVELS, calibrate
from .progress import UNIT_ENTRIES, CancelToken, Monitor, ProgressEvent

LEVEL_CHOICES = [(f"{name} – {LEVELS[name].describe()}", name) for name in LEVELS] + [("auto – ca. 2 s", "auto")]


def _size(n: int | None) -> str:
    return "–" if n is None else container.format_size(n)


def _exact(name: str) -> str:
    """Eintragsname als ``only``-Muster, das genau ihn trifft: ``only`` sind fnmatch-Muster –
    "Urlaub [2019].jpg" passte sonst auf "Urlaub 2.jpg" (und "*" auf fremde Einträge)."""
    return "".join(f"[{ch}]" if ch in "*?[" else ch for ch in name)


def _describe_error(error: BaseException) -> str:
    """Meldetext; ``OSError`` ist erwartbar (Rechte, voller Datenträger) – mit Pfad."""
    if isinstance(error, Tres0rError):
        return str(error)
    if isinstance(error, OSError):
        return f"{error.strerror or error}" + (f": {error.filename}" if error.filename else "")
    return f"Unerwarteter Fehler: {error!r}"


def _duration(seconds: float | None) -> str:
    if seconds is None:
        return ""
    seconds = int(seconds + 0.5)
    return f"{seconds // 60}:{seconds % 60:02d}"


# ---------------------------------------------------------------------------
# Fortschritt
# ---------------------------------------------------------------------------
class ProgressScreen(ModalScreen):
    """Führt ``task(monitor)`` in einem Thread aus; Ergebnis per ``dismiss``."""

    DEFAULT_CSS = """
    ProgressScreen { align: center middle; }
    #box { width: 76; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #bar { margin: 1 0; }
    #outcome { width: 1fr; height: auto; }
    """

    def __init__(self, title: str, task: Callable[[Monitor], object], done: Callable[[object], str]) -> None:
        super().__init__()
        self.title_text, self._job, self._summary = title, task, done
        self.token = CancelToken()
        self.outcome: object = None  # Rückgabewert der Aufgabe
        self.failure: BaseException | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="box"):
            yield Label(self.title_text, id="title")
            yield ProgressBar(total=None, show_eta=False, id="bar")
            yield Label("", id="phase")
            yield Label("", id="item")
            yield Label("", id="outcome")
            yield Button("Abbrechen", variant="error", id="cancel")

    def on_mount(self) -> None:
        monitor = Monitor(lambda ev: self.app.call_from_thread(self._show, ev), cancel=self.token, interval=0.1)
        self.run_worker(lambda: self._job(monitor), thread=True, exit_on_error=False, name="aufgabe")

    def on_unmount(self) -> None:
        # Oberfläche beendet, während die Aufgabe läuft: abbrechen wie mit „Abbrechen“ – sie liefe
        # sonst unsichtbar weiter und hielte bis zu ihrem Ende das Prozessende auf.
        self.token.cancel()

    def _show(self, event: ProgressEvent) -> None:
        bar = self.query_one("#bar", ProgressBar)
        if event.total:
            bar.update(total=event.total, progress=event.done)
        labels = {"schlüssel": "Schlüsselableitung (Argon2id) …", "durchsuchen": "Durchsuche …",
                  "packen": "Verschlüssele", "entpacken": "Entpacke", "prüfen": "Prüfe", "lesen": "Lese",
                  "kopieren": "Kopiere", "vergleichen": "Vergleiche", "retten": "Rette"}
        parts = [labels.get(event.phase, event.phase)]
        if event.unit == UNIT_ENTRIES:
            parts.append(f"{event.done} Einträge")
        elif event.phase != "schlüssel":
            parts.append(_size(event.done) + (f" von {_size(event.total)}" if event.total else ""))
            if event.rate:
                parts.append(f"{_size(int(event.rate))}/s")
            if event.eta and event.eta >= 1:
                parts.append(f"noch {_duration(event.eta)}")
        self.query_one("#phase", Label).update(" · ".join(parts))
        self.query_one("#item", Label).update(escape(event.item or ""))

    @on(Worker.StateChanged)
    def _finished(self, event: Worker.StateChanged) -> None:
        if event.state not in (WorkerState.SUCCESS, WorkerState.ERROR, WorkerState.CANCELLED):
            return
        button = self.query_one("#cancel", Button)
        button.label, button.variant = "Schließen", "primary"
        outcome = self.query_one("#outcome", Label)
        if event.state == WorkerState.SUCCESS:
            self.outcome = event.worker.result
            bar = self.query_one("#bar", ProgressBar)
            bar.update(total=1, progress=1)
            outcome.update(escape(self._summary(self.outcome)))
        else:
            self.failure = event.worker.error
            message = ("Abgebrochen – nichts wurde verändert." if isinstance(self.failure, Cancelled)
                       else _describe_error(self.failure))
            outcome.update(f"[b red]{escape(message)}[/]")
        self.is_finished = True

    is_finished = False

    @on(Button.Pressed, "#cancel")
    def _cancel_or_close(self) -> None:
        if self.is_finished:
            self.dismiss(self.outcome)
        else:
            self.token.cancel()
            self.query_one("#phase", Label).update("Breche ab …")


# ---------------------------------------------------------------------------
# Entsperren
# ---------------------------------------------------------------------------
class UnlockScreen(ModalScreen):
    """Zugangsdaten abfragen; Ergebnis: ``keys.Credentials`` oder ``None``."""

    DEFAULT_CSS = """
    UnlockScreen { align: center middle; }
    #box { width: 70; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    Input { margin-bottom: 1; }
    """
    BINDINGS = [Binding("escape", "abort", "Abbrechen")]

    def __init__(self, info: container.ContainerInfo) -> None:
        super().__init__()
        self.info = info

    def compose(self) -> ComposeResult:
        kinds = ", ".join(sorted({s.description.split(" (")[0] for s in self.info.slots}))
        with Vertical(id="box"):
            yield Label(f"[b]{escape(self.info.path.name)}[/] entsperren")
            yield Label(f"Schlüssel im Container: {escape(kinds)}")
            yield Input(placeholder="Passwort oder Wiederherstellungsphrase", password=True, id="password")
            yield Input(placeholder="Keyfile (optional, Pfad)", id="keyfile")
            with Horizontal():
                yield Switch(id="fido2")
                yield Label(" FIDO2-Token verwenden")
            with Horizontal():
                yield Button("Öffnen", variant="primary", id="unlock")
                yield Button("Abbrechen", id="abort")

    @on(Input.Submitted)
    @on(Button.Pressed, "#unlock")
    def _unlock(self) -> None:
        password = self.query_one("#password", Input).value
        keyfile = self.query_one("#keyfile", Input).value.strip()
        try:
            keyfiles = [keys.keyfile_secret(Path(keyfile).expanduser())] if keyfile else []
        except OSError as e:
            self.notify(escape(f"Keyfile nicht lesbar: {e.strerror or e}"), severity="error")
            return
        fido2 = None
        if self.query_one("#fido2", Switch).value:
            fido2 = self.app.token_provider()
        self.dismiss(keys.Credentials(passwords=[password] if password else [], keyfiles=keyfiles, fido2=fido2))

    @on(Button.Pressed, "#abort")
    def action_abort(self) -> None:
        self.dismiss(None)


class PathScreen(ModalScreen):
    """Einen Zielordner abfragen."""

    DEFAULT_CSS = """
    PathScreen { align: center middle; }
    #box { width: 70; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    """
    BINDINGS = [Binding("escape", "abort", "Abbrechen")]

    def __init__(self, question: str, default: Path) -> None:
        super().__init__()
        self.question, self.default = question, default

    def compose(self) -> ComposeResult:
        with Vertical(id="box"):
            yield Label(escape(self.question))
            yield Input(value=str(self.default), id="path")
            with Horizontal():
                yield Button("OK", variant="primary", id="ok")
                yield Button("Abbrechen", id="abort")

    @on(Input.Submitted)
    @on(Button.Pressed, "#ok")
    def _ok(self) -> None:
        self.dismiss(Path(self.query_one("#path", Input).value).expanduser())

    @on(Button.Pressed, "#abort")
    def action_abort(self) -> None:
        self.dismiss(None)


class PinScreen(ModalScreen):
    """PIN des FIDO2-Tokens abfragen (aus einem Arbeitsthread heraus)."""

    DEFAULT_CSS = """
    PinScreen { align: center middle; }
    #box { width: 60; height: auto; border: round $warning; padding: 1 2; background: $surface; }
    """
    BINDINGS = [Binding("escape", "abort", "Abbrechen")]

    def compose(self) -> ComposeResult:
        with Vertical(id="box"):
            yield Label("Der FIDO2-Token verlangt seine PIN.")
            yield Input(password=True, placeholder="PIN des Tokens", id="pin")
            with Horizontal():
                yield Button("OK", variant="primary", id="ok")
                yield Button("Abbrechen", id="abort")

    @on(Input.Submitted)
    @on(Button.Pressed, "#ok")
    def _ok(self) -> None:
        self.dismiss(self.query_one("#pin", Input).value)

    @on(Button.Pressed, "#abort")
    def action_abort(self) -> None:
        self.dismiss(None)


class TextScreen(ModalScreen):
    """Eine Textzeile abfragen (Empfänger, Schwellwert, …); Ergebnis: Text oder None."""

    DEFAULT_CSS = """
    TextScreen { align: center middle; }
    #box { width: 76; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    """
    BINDINGS = [Binding("escape", "abort", "Abbrechen")]

    def __init__(self, question: str, placeholder: str = "", value: str = "") -> None:
        super().__init__()
        self.question, self.placeholder, self.value = question, placeholder, value

    def compose(self) -> ComposeResult:
        with Vertical(id="box"):
            yield Label(escape(self.question))
            yield Input(value=self.value, placeholder=self.placeholder, id="text")
            with Horizontal():
                yield Button("OK", variant="primary", id="ok")
                yield Button("Abbrechen", id="abort")

    @on(Input.Submitted)
    @on(Button.Pressed, "#ok")
    def _ok(self) -> None:
        self.dismiss(self.query_one("#text", Input).value.strip() or None)

    @on(Button.Pressed, "#abort")
    def action_abort(self) -> None:
        self.dismiss(None)


class LeakCheckScreen(ModalScreen):
    """Passwort gegen bekannte Datenlecks prüfen (HIBP); Ergebnis: ``PasswordCheck`` oder None
    (abgebrochen). Schließt sich selbst – die Anfrage dauert meist unter einer Sekunde."""

    DEFAULT_CSS = """
    LeakCheckScreen { align: center middle; }
    #box { width: 66; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    """
    BINDINGS = [Binding("escape", "abort", "Abbrechen")]

    def __init__(self, password: str) -> None:
        super().__init__()
        self._candidate = password
        self._stop = CancelToken()

    def compose(self) -> ComposeResult:
        with Vertical(id="box"):
            yield Label("Prüfe das Passwort gegen bekannte Datenlecks (HIBP) …\n"
                        "[dim]Nur die ersten 5 Zeichen des SHA-1-Hashes verlassen den Rechner.[/]")
            yield Button("Abbrechen", id="abort")

    def on_mount(self) -> None:
        self.run_worker(self._ask, thread=True, exit_on_error=False, name="hibp")

    def _ask(self) -> passgen.PasswordCheck | None:
        # Die Anfrage selbst läuft in einem Daemon-Thread: Sie wartet bei schlechtem Netz bis zu 20 s
        # und ließe sich nicht unterbrechen – so endet der Worker beim Abbrechen oder Beenden sofort
        # (Worker-Threads hielten sonst das Prozessende auf).
        box: dict = {}

        def ask() -> None:
            try:
                box["check"] = passgen.check_password(self._candidate, online=True)
            except BaseException as error:  # an den Worker weiterreichen
                box["error"] = error
        thread = threading.Thread(target=ask, name="tres0r-hibp", daemon=True)
        thread.start()
        while thread.is_alive():
            if self._stop.cancelled:
                return None
            thread.join(0.05)
        if "error" in box:
            raise box["error"]
        return box["check"]

    @on(Worker.StateChanged)
    def _finished(self, event: Worker.StateChanged) -> None:
        if event.state == WorkerState.SUCCESS:
            self.dismiss(event.worker.result)
        elif event.state in (WorkerState.ERROR, WorkerState.CANCELLED):
            if event.state == WorkerState.ERROR:
                self.notify(escape(_describe_error(event.worker.error)), severity="error")
            self.dismiss(None)

    @on(Button.Pressed, "#abort")
    def action_abort(self) -> None:
        self._stop.cancel()  # der Worker endet binnen 0,05 s und schließt das Fenster mit None

    def on_unmount(self) -> None:
        self._stop.cancel()  # Oberfläche beendet: den Worker nicht warten lassen


class ConfirmScreen(ModalScreen):
    DEFAULT_CSS = """
    ConfirmScreen { align: center middle; }
    #box { width: 66; height: auto; border: round $error; padding: 1 2; background: $surface; }
    """
    BINDINGS = [Binding("escape", "no", "Nein")]

    def __init__(self, question: str) -> None:
        super().__init__()
        self.question = question

    def compose(self) -> ComposeResult:
        with Vertical(id="box"):
            yield Label(escape(self.question))
            with Horizontal():
                yield Button("Ja", variant="error", id="yes")
                yield Button("Nein", variant="primary", id="no")

    @on(Button.Pressed, "#yes")
    def _yes(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#no")
    def action_no(self) -> None:
        self.dismiss(False)


class SecretsScreen(ModalScreen):
    """Neue Geheimnisse (Phrase, Anteile) anzeigen – gibt es nur jetzt; optional als Dateien speichern."""

    DEFAULT_CSS = """
    SecretsScreen { align: center middle; }
    #box { width: 100%; max-width: 100; max-height: 90%; height: auto; border: round $warning; padding: 1 2;
           background: $surface; }
    #box > Label { width: 1fr; }
    #secrets { height: auto; margin: 1 0; }
    """
    BINDINGS = [Binding("escape", "close", "Schließen")]

    def __init__(self, title: str, items: list[tuple[str, str]]) -> None:
        super().__init__()
        self.title_text, self.items = title, items

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="box"):
            yield Label(f"[b]{escape(self.title_text)}[/] – nur jetzt sichtbar, bitte sicher notieren oder speichern.")
            yield Static("\n\n".join(f"{escape(label)}:\n[b]{escape(self.readable(value))}[/]"
                                     for label, value in self.items), id="secrets")
            with Horizontal():
                yield Button("Als Dateien speichern", id="save")
                yield Button("Notiert – schließen", variant="primary", id="close")

    @staticmethod
    def readable(value: str) -> str:
        """Lange Anteile in Vierergruppen – lesbar und umbrechbar; beim Einlesen zählen
        Leerzeichen nicht (shamir.parse_share). Phrasen bleiben, wie sie sind."""
        if not value.startswith("tres0r-teil-"):
            return value
        body = value[len("tres0r-teil-"):]
        return "tres0r-teil-" + " ".join(body[i:i + 4] for i in range(0, len(body), 4))

    @on(Button.Pressed, "#save")
    def _save(self) -> None:
        def chosen(folder: Path | None) -> None:
            if folder is None:
                return
            try:
                folder.mkdir(parents=True, exist_ok=True)
                for number, (label, value) in enumerate(self.items, start=1):
                    keys._write_new(folder / f"geheimnis-{number}.txt",
                                    f"# tres0r – {label}\n{value}\n".encode("utf-8"))
            except (OSError, Tres0rError) as e:
                self.notify(escape(f"Nicht gespeichert: {e}"), severity="error")
                return
            self.notify(escape(f"{len(self.items)} Datei(en) in {folder} (Rechte 0600) – einzeln verteilen."))
        self.app.push_screen(PathScreen("In welchen Ordner speichern?", Path.cwd() / "tres0r-geheimnisse"), chosen)

    @on(Button.Pressed, "#close")
    def action_close(self) -> None:
        self.dismiss(None)


class NewPasswordScreen(ModalScreen):
    """Neues Passwort (mit Bestätigung), optional mit zweitem Faktor; Ergebnis: dict oder None."""

    DEFAULT_CSS = """
    NewPasswordScreen { align: center middle; }
    #box { width: 72; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #box Horizontal { height: auto; }
    #box Switch { margin-right: 1; }
    #box Horizontal Label { padding-top: 1; }
    #box Input { border-title-color: $accent; }
    """
    BINDINGS = [Binding("escape", "abort", "Abbrechen")]

    def __init__(self, title: str, second_factor: bool = True) -> None:
        super().__init__()
        self.title_text, self.second_factor = title, second_factor

    def compose(self) -> ComposeResult:
        with Vertical(id="box"):
            yield Label(f"[b]{escape(self.title_text)}[/]")
            for field, title in (("password", "Neues Passwort"), ("confirm", "Wiederholen")):
                widget = Input(password=True, id=field)
                widget.border_title = title
                yield widget
            if self.second_factor:
                keyfile = Input(placeholder="optional: Keyfile als zweiter Faktor", id="keyfile")
                keyfile.border_title = "Keyfile"
                yield keyfile
                with Horizontal():
                    yield Switch(id="fido2")
                    yield Label("FIDO2-Token als zweiter Faktor")
            with Horizontal():
                yield Switch(value=True, id="online")
                yield Label("gegen bekannte Datenlecks prüfen (HIBP, online)")
            with Horizontal():
                yield Button("OK", variant="primary", id="ok")
                yield Button("Abbrechen", id="abort")

    @on(Button.Pressed, "#ok")
    def _ok(self) -> None:
        password = self.query_one("#password", Input).value
        if not password or password != self.query_one("#confirm", Input).value:
            self.notify("Passwort fehlt oder die Wiederholung stimmt nicht.", severity="error")
            return
        result = {"password": password, "keyfile": None, "fido2": None}
        if self.second_factor:
            path = self.query_one("#keyfile", Input).value.strip()
            use_token = self.query_one("#fido2", Switch).value
            if path and use_token:
                self.notify("Bitte entweder Keyfile oder FIDO2-Token.", severity="error")
                return
            if path:
                try:
                    result["keyfile"] = keys.keyfile_secret(Path(path).expanduser())
                except OSError as e:
                    self.notify(escape(f"Keyfile nicht lesbar: {e.strerror or e}"), severity="error")
                    return
            if use_token:
                result["fido2"] = self.app.token_provider()
        # „Trotzdem verwenden? – Nein“: das Fenster bleibt offen, die Eingaben auch
        self.app.vet_password(password, online=self.query_one("#online", Switch).value,
                              proceed=lambda: self.dismiss(result),
                              rejected=lambda why: self.notify(escape(why), severity="warning"))

    @on(Button.Pressed, "#abort")
    def action_abort(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------------------
# Schlüssel verwalten, Vergleich
# ---------------------------------------------------------------------------
class KeysScreen(Screen):
    """Keyslots eines entsperrten Containers ansehen und ändern."""

    BINDINGS = [Binding("n", "add_password", "+Passwort"), Binding("w", "add_recovery", "+Phrase"),
                Binding("e", "add_recipient", "+Empfänger"), Binding("s", "add_shares", "+Anteile"),
                Binding("c", "change_password", "Ändern"), Binding("x", "remove", "Entfernen"),
                Binding("escape", "back", "Zurück")]
    DEFAULT_CSS = """
    #slots { height: 1fr; }
    #hint { padding: 0 1; }
    """

    def __init__(self, path: Path, credentials: keys.Credentials) -> None:
        super().__init__()
        self.path, self.credentials = path, credentials

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="slots", cursor_type="row")
        yield Label("", id="hint")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#slots", DataTable)
        table.add_columns("Nr.", "Art", "Beschreibung")
        self.refresh_slots()

    def refresh_slots(self) -> None:
        table = self.query_one("#slots", DataTable)
        table.clear()
        self.info = container.inspect(self.path)
        for slot in self.info.slots:
            table.add_row(str(slot.index), escape(slot.type), escape(slot.description), key=str(slot.index))
        self.sub_title = f"{self.path.name} – {len(self.info.slots)} Schlüssel"  # Titel sind reiner Text (Content)
        self.query_one("#hint", Label).update(
            "[dim]c = eigenes Passwort ändern · x = gewählten Slot entfernen · Esc = zurück. "
            "Änderungen schreiben nur den Header neu.[/]")

    def _run(self, title: str, task, summary, after=None) -> None:
        def closed(result) -> None:
            self.refresh_slots()
            if result is not None and after is not None:
                after(result)
        self.app.push_screen(ProgressScreen(title, task, summary), closed)

    def action_add_password(self) -> None:
        def chosen(new) -> None:
            if new is None:
                return
            self._run("Passwort hinzufügen", lambda monitor: container.add_keys(
                self.path, self.credentials, password=new["password"],
                # gleiche Stufe wie das vorhandene Passwort – ein schwächerer Slot senkt den Schutz
                params=self.info.kdf or LEVELS["normal"],
                keyfile=new["keyfile"], fido2=new["fido2"], progress=monitor),
                lambda added: f"Hinzugefügt: Slot {', '.join(map(str, added))}")
        self.app.push_screen(NewPasswordScreen("Weiteres Passwort"), chosen)

    def action_add_recovery(self) -> None:
        phrase = keys.generate_recovery().value

        def show(_result) -> None:
            self.app.push_screen(SecretsScreen("Wiederherstellungsphrase", [("Phrase", phrase)]))
        self._run("Wiederherstellungsphrase hinzufügen", lambda monitor: container.add_keys(
            self.path, self.credentials, recovery=phrase, progress=monitor),
            lambda added: f"Hinzugefügt: Slot {', '.join(map(str, added))}", show)

    def action_add_recipient(self) -> None:
        def chosen(text: str | None) -> None:
            if not text:
                return
            try:
                recipient = keys.parse_recipient(text)
            except Tres0rError as e:
                self.notify(escape(str(e)), severity="error")
                return
            self._run("Empfänger hinzufügen", lambda monitor: container.add_keys(
                self.path, self.credentials, recipients=[recipient], progress=monitor),
                lambda added: f"Hinzugefügt: Slot {', '.join(map(str, added))}")
        self.app.push_screen(TextScreen("Öffentlicher Schlüssel des Empfängers", "tres0r-pub-…"), chosen)

    def action_add_shares(self) -> None:
        def chosen(text: str | None) -> None:
            if not text:
                return
            try:
                k, n = (int(part) for part in text.split("/"))
                if not 2 <= k <= n <= 32:
                    raise ValueError
            except ValueError:
                self.notify("Bitte K/N angeben, z. B. 2/3 (2 ≤ K ≤ N ≤ 32).", severity="error")
                return

            def show(result) -> None:
                _, shares = result
                self.app.push_screen(SecretsScreen(f"Anteile ({k} von {n} nötig)",
                                                   [(share.label, share.text()) for share in shares]))
            self._run("Schwellwert hinzufügen", lambda monitor: container.add_threshold(
                self.path, self.credentials, k, n, progress=monitor),
                lambda result: f"Hinzugefügt: Slot {result[0]}", show)
        self.app.push_screen(TextScreen("Wie viele Anteile, wie viele davon nötig? (K/N)", "2/3", "2/3"), chosen)

    def action_change_password(self) -> None:
        def chosen(new) -> None:
            if new is None:
                return

            def done(_result) -> None:  # altes Passwort gilt nicht mehr
                self.credentials = keys.Credentials(passwords=[new["password"]], keyfiles=self.credentials.keyfiles,
                                                    fido2=self.credentials.fido2)
            # change_password gibt nichts zurück – "True" markiert den Erfolg (sonst gälte er als abgebrochen)
            self._run("Passwort ändern", lambda monitor: container.change_password(
                self.path, self.credentials, new["password"], progress=monitor) or True,
                lambda _r: "Passwort geändert (ein zweiter Faktor bleibt bestehen).", done)
        self.app.push_screen(NewPasswordScreen("Passwort ändern", second_factor=False), chosen)

    def action_remove(self) -> None:
        table = self.query_one("#slots", DataTable)
        if table.row_count == 0:
            return
        index = int(table.get_row_at(table.cursor_row)[0])
        if len(self.info.slots) == 1:
            self.notify("Der letzte Schlüssel lässt sich nicht entfernen.", severity="error")
            return
        slot = self.info.slots[index]

        def confirmed(yes: bool) -> None:
            if yes:
                self._run("Schlüssel entfernen", lambda monitor: container.remove_key(
                    self.path, self.credentials, index, progress=monitor),
                    lambda removed: f"Entfernt: {removed.description}")
        self.app.push_screen(ConfirmScreen(f"Slot {index} ({slot.description}) wirklich entfernen? "
                                           "Wer nur diesen Schlüssel hat, kommt danach nicht mehr an den Inhalt."),
                             confirmed)

    def action_back(self) -> None:
        self.app.pop_screen()


class DiffScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Zurück")]

    def __init__(self, title: str, result: container.DiffResult) -> None:
        super().__init__()
        self.title_text, self.result = title, result

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(escape(self.title_text), id="summary")
        yield DataTable(id="changes", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#changes", DataTable)
        table.add_columns("Status", "Eintrag", "Detail")
        colors = {"neu": "green", "entfernt": "red", "geändert": "yellow", "typ": "magenta", "link": "cyan"}
        for change in self.result.changes:
            color = colors.get(change.status, "white")
            table.add_row(f"[{color}]{change.status}[/]", escape(change.name), escape(change.detail))
        verdict = "keine Unterschiede" if self.result.identical else f"{len(self.result.changes)} Unterschied(e)"
        self.sub_title = f"{verdict}, {self.result.unchanged} unverändert"

    def action_back(self) -> None:
        self.app.pop_screen()


# ---------------------------------------------------------------------------
# Container ansehen
# ---------------------------------------------------------------------------
class BrowseScreen(Screen):
    """Inhaltsbaum eines entsperrten Containers."""

    BINDINGS = [Binding("slash", "search", "Suchen"), Binding("e", "extract", "Auswahl entpacken"),
                Binding("a", "extract_all", "Alles entpacken"), Binding("v", "verify", "Prüfen"),
                Binding("escape", "back", "Zurück")]
    DEFAULT_CSS = """
    #contents { width: 2fr; }
    #entry { width: 1fr; padding: 1 2; border-left: solid $accent; }
    #filter { display: none; }
    #filter.shown { display: block; }
    """

    def __init__(self, path: Path, credentials: keys.Credentials, entries: list[container.Entry]) -> None:
        super().__init__()
        self.path, self.credentials, self.entries = path, credentials, entries

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(placeholder="Suchen: Textteil oder Muster wie *.jpg – Esc beendet", id="filter", disabled=True)
        with Horizontal():
            yield Tree(escape(self.path.name), id="contents")
            yield Static("Eintrag wählen …", id="entry")
        yield Footer()

    def on_mount(self) -> None:
        self.by_name = {e.name.strip("/"): e for e in self.entries}
        self._build(self.entries)
        self.query_one("#contents", Tree).focus()  # Tasten gehören dem Baum, nicht der (versteckten) Suche

    @staticmethod
    def matches(entry: container.Entry, pattern: str) -> bool:
        name, pattern = entry.name.lower(), pattern.lower()
        if any(ch in pattern for ch in "*?["):
            return fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(name.rsplit("/", 1)[-1], pattern)
        return pattern in name

    def action_search(self) -> None:
        field = self.query_one("#filter", Input)
        field.disabled = False
        field.add_class("shown")
        field.focus()

    @on(Input.Changed, "#filter")
    def _filter(self, event: Input.Changed) -> None:
        pattern = event.value.strip()
        found = [e for e in self.entries if self.matches(e, pattern)] if pattern else self.entries
        self._build(found, expand=bool(pattern))
        self.sub_title = (f"{len(found)} von {len(self.entries)} Einträgen passen" if pattern
                          else f"{len(self.entries)} Einträge")

    @on(Input.Submitted, "#filter")
    def _to_tree(self) -> None:
        self.query_one("#contents", Tree).focus()

    def _build(self, entries: list[container.Entry], expand: bool = False) -> None:
        tree = self.query_one("#contents", Tree)
        tree.clear()
        nodes = {"": tree.root}
        for entry in sorted(entries, key=lambda e: e.name):
            parts = entry.name.strip("/").split("/")
            for depth in range(1, len(parts) + 1):
                key = "/".join(parts[:depth])
                if key in nodes:
                    continue
                parent = nodes["/".join(parts[:depth - 1])]
                is_leaf = depth == len(parts) and entry.kind != "ordner"
                label = escape(parts[depth - 1]) + ("" if is_leaf else "/")
                nodes[key] = parent.add_leaf(label, data=key) if is_leaf else parent.add(label, data=key)
        tree.root.expand_all() if expand else tree.root.expand()
        self.sub_title = f"{len(self.entries)} Einträge"

    @on(Tree.NodeHighlighted)
    def _details(self, event: Tree.NodeHighlighted) -> None:
        name = event.node.data
        entry = self.by_name.get(name) if name else None
        if entry is None:
            self.query_one("#entry", Static).update(f"[b]{escape(name or self.path.name)}[/]")
            return
        lines = [f"[b]{escape(entry.name)}[/]", f"Art: {entry.kind}", f"Größe: {_size(entry.size)}"]
        if entry.mtime:
            from datetime import datetime

            lines.append(f"Geändert: {datetime.fromtimestamp(entry.mtime):%Y-%m-%d %H:%M}")
        if entry.segment:
            lines.append(f"Segment: {entry.segment} (angehängt)")
        if entry.sha256:
            lines.append(f"SHA-256: {entry.sha256[:16]}…")
        self.query_one("#entry", Static).update("\n".join(lines))

    def _selected(self) -> str | None:
        node = self.query_one("#contents", Tree).cursor_node
        return node.data if node is not None else None

    def action_extract(self) -> None:
        name = self._selected()
        if not name:
            self.notify("Bitte einen Eintrag wählen.", severity="warning")
            return
        self._extract([_exact(name)])

    def action_extract_all(self) -> None:
        self._extract(None)

    def _extract(self, only: list[str] | None) -> None:
        def chosen(dest: Path | None) -> None:
            if dest is None:
                return
            self.app.push_screen(ProgressScreen(
                "Entpacken", lambda monitor: container.extract(self.path, dest, self.credentials, progress=monitor,
                                                                only=only),
                lambda result: f"{result.entries} Einträge nach {dest} entpackt."))
        self.app.push_screen(PathScreen("Wohin entpacken?", Path.cwd()), chosen)

    def action_verify(self) -> None:
        self.app.push_screen(ProgressScreen(
            "Prüfen", lambda monitor: container.verify(self.path, self.credentials, progress=monitor),
            lambda r: f"Intakt: {r.files} Dateien, {_size(r.bytes)}"
                      + (", alle SHA-256 abgeglichen" if r.checked_hashes else "")
                      + (f", signiert von {r.signer}" if r.signer else "")))

    def action_back(self) -> None:
        field = self.query_one("#filter", Input)
        if field.has_class("shown"):  # Esc beendet zuerst die Suche
            field.value = ""
            field.remove_class("shown")
            field.disabled = True
            self.query_one("#contents", Tree).focus()
            return
        self.app.pop_screen()


# ---------------------------------------------------------------------------
# Packen
# ---------------------------------------------------------------------------
class PackScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Zurück")]
    DEFAULT_CSS = """
    #form { padding: 0 2; }
    #form Horizontal { height: auto; }
    #form Switch { margin-right: 1; }
    #form Horizontal Label { padding-top: 1; }
    #form Button { margin-right: 2; }
    #strength { width: 1fr; height: auto; }
    #form Input { border-title-color: $accent; }
    #level-row Label { width: 7; }
    #level-row Select { width: 1fr; }
    """

    def __init__(self, sources: list[Path]) -> None:
        super().__init__()
        self.sources = sources
        self._suggested: str | None = None

    def compose(self) -> ComposeResult:
        first = self.sources[0]
        default = first.with_name(first.name + container.SUFFIX)
        yield Header()
        with VerticalScroll(id="form"):
            yield Label("[b]Packen:[/] " + escape(", ".join(str(p) for p in self.sources)))
            output = Input(value=str(default), id="output")
            output.border_title = "Zieldatei"
            yield output
            with Horizontal(id="level-row"):
                yield Label("Stufe")
                yield Select(LEVEL_CHOICES, value="normal", allow_blank=False, id="level")
            with Horizontal():
                yield Switch(id="compress")
                yield Label("zstd-Kompression   ")
                yield Switch(id="fido2")
                yield Label("+ FIDO2-Token")
            password = Input(password=True, id="password")
            password.border_title = "Passwort"
            yield password
            confirm = Input(password=True, id="confirm")
            confirm.border_title = "Passwort wiederholen"
            yield confirm
            yield Label("", id="strength")
            with Horizontal():  # wie die CLI (dort abschaltbar mit --offline); geprüft wird beim Packen
                yield Switch(value=True, id="online")
                yield Label("beim Packen gegen bekannte Datenlecks prüfen (HIBP, online)")
            with Horizontal():
                yield Button("Passphrase vorschlagen", id="suggest")
                yield Button("Passwort vorschlagen", id="suggest-password")
                yield Button("Packen", variant="primary", id="start")
        yield Footer()

    @on(Input.Changed, "#password")
    def _strength(self, event: Input.Changed) -> None:
        if not event.value:
            self.query_one("#strength", Label).update("")
            return
        if self._suggested == event.value:
            return  # Vorschlag: Hinweis mit dem Geheimnis stehen lassen
        check = passgen.check_password(event.value)  # offline: Länge, Zeichenklassen, bekannte Muster
        verdict = "[green]in Ordnung[/]" if check.ok else "[yellow]" + escape("; ".join(check.warnings)) + "[/]"
        self.query_one("#strength", Label).update(f"Stärke: {verdict}")

    @on(Button.Pressed, "#suggest")
    def _suggest(self) -> None:
        self._offer(passgen.generate_passphrase())

    @on(Button.Pressed, "#suggest-password")
    def _suggest_password(self) -> None:
        # ohne Sonderzeichen (^ und ` sind auf deutschen Tastaturen Tottasten) und ohne
        # Verwechselbares (0/O, 1/l/I) – der Vorschlag wird abgeschrieben; gut 110 Bit
        self._offer(passgen.generate_password(symbols=False, exclude_ambiguous=True))

    def _offer(self, secret: passgen.Secret) -> None:
        text = secret.value  # str(secret) ist absichtlich geschwärzt
        self._suggested = text
        for field in ("#password", "#confirm"):
            self.query_one(field, Input).value = text
        self.query_one("#strength", Label).update(  # eigene Zeile: das Geheimnis muss ganz lesbar sein
            f"Vorschlag ({secret.entropy_bits:.0f} Bit) – bitte vollständig notieren:\n[b]{escape(text)}[/]")

    @on(Button.Pressed, "#start")
    def _start(self) -> None:
        password = self.query_one("#password", Input).value
        if not password:
            self.notify("Bitte ein Passwort eingeben.", severity="error")
            return
        if password != self.query_one("#confirm", Input).value:
            self.notify("Die Passwörter stimmen nicht überein.", severity="error")
            return
        output = Path(self.query_one("#output", Input).value).expanduser()
        if container.volumes.exists(output):
            self.notify(escape(f"{output} existiert bereits."), severity="error")
            return
        level = self.query_one("#level", Select).value
        compress = self.query_one("#compress", Switch).value
        fido2 = self.app.token_provider() if self.query_one("#fido2", Switch).value else None

        def task(monitor: Monitor):
            params = calibrate() if level == "auto" else LEVELS[level]
            extra = {"fido2": fido2} if fido2 is not None else {}
            return container.create(self.sources, output, password, params, compress=compress, progress=monitor,
                                    **extra)

        def closed(result) -> None:
            if result is not None:
                self.app.pop_screen()
                self.app.notify(escape(f"Gepackt: {result.path}"))
                self.app.refresh_files()

        def pack() -> None:
            self.app.push_screen(ProgressScreen(
                "Packen", task, lambda r: f"{r.path} – {_size(r.size)}, {r.entries} Einträge"), closed)

        def rejected(why: str) -> None:  # „Trotzdem verwenden? – Nein“: zurück, die Eingaben bleiben
            self.query_one("#strength", Label).update(f"[yellow]{escape(why)}[/]")

        if password == self._suggested:  # unveränderter Vorschlag: zufällig, keine Prüfung nötig
            pack()
        else:
            self.app.vet_password(password, online=self.query_one("#online", Switch).value,
                                  proceed=pack, rejected=rejected)

    def action_back(self) -> None:
        self.app.pop_screen()


# ---------------------------------------------------------------------------
# Hauptansicht
# ---------------------------------------------------------------------------
class MainScreen(Screen):
    """Dateibaum und Details; Kürzel gelten nur hier."""

    BINDINGS = [Binding("o", "open", "Öffnen"), Binding("p", "pack", "Packen"), Binding("v", "verify", "Prüfen"),
                Binding("a", "append", "Anhängen"), Binding("d", "diff", "Vergleich"),
                Binding("k", "keys", "Schlüssel"), Binding("r", "refresh_files", "Neu laden", show=False),
                Binding("q", "app.quit", "Beenden", show=False)]
    DEFAULT_CSS = """
    #files { width: 1fr; }
    #details { width: 1fr; padding: 1 2; border-left: solid $accent; }
    """

    def __init__(self, start: Path) -> None:
        super().__init__()
        self.start = start
        self.selected: Path | None = None
        self.info: container.ContainerInfo | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            yield DirectoryTree(self.start, id="files")
            yield Static("Datei oder Ordner wählen …", id="details")
        yield Footer()

    # -- Auswahl ------------------------------------------------------------
    @on(DirectoryTree.FileSelected)
    @on(DirectoryTree.DirectorySelected)
    def _selected(self, event) -> None:
        self.select(Path(event.path))

    @on(Tree.NodeHighlighted, "#files")
    def _highlighted(self, event: Tree.NodeHighlighted) -> None:
        entry = event.node.data
        if entry is not None and hasattr(entry, "path"):
            self.select(Path(entry.path))

    def select(self, path: Path) -> None:
        self.selected, self.info = path, None
        details = self.query_one("#details", Static)
        if path.is_file():
            try:
                self.info = container.inspect(path)
            except (Tres0rError, OSError):
                self.info = None
        if self.info is None:
            kind = "Ordner" if path.is_dir() else "Datei"
            size = "" if path.is_dir() else f"\nGröße: {_size(path.stat().st_size)}"
            details.update(f"[b]{escape(path.name)}[/]\n{kind}{size}\n\n[dim]p packen · r neu laden · q beenden[/]")
            return
        info = self.info
        lines = [f"[b]{escape(path.name)}[/]", f"tres0r-Container, Format v{info.version}",
                 f"Größe: {_size(info.size)}", "Schlüssel:"] + [
            escape(f"  [{s.index}] {s.description}") for s in info.slots]
        if info.signed:
            lines.append("signiert")
        if info.segmented:
            lines.append("mit angehängten Segmenten")
        if info.volumes > 1:
            lines.append(f"{info.volumes} Teile")
        if info.interrupted:
            lines.append("[b red]Anhängen unterbrochen – 'tres0r repair'[/]")
        lines.append("\n[dim]o öffnen · v prüfen · a anhängen · d vergleichen · k Schlüssel · q beenden[/]")
        details.update("\n".join(lines))

    def refresh_files(self) -> None:
        self.query_one("#files", DirectoryTree).reload()

    def action_refresh_files(self) -> None:
        self.refresh_files()

    # -- Aktionen -------------------------------------------------------------
    def _need_container(self) -> bool:
        if self.info is None:
            self.notify("Bitte zuerst einen tres0r-Container wählen.", severity="warning")
            return False
        return True

    def action_pack(self) -> None:
        if self.selected is None:
            self.notify("Bitte zuerst eine Datei oder einen Ordner wählen.", severity="warning")
            return
        if self.info is not None:
            self.notify("Das ist schon ein Container.", severity="warning")
            return
        self.app.push_screen(PackScreen([self.selected]))

    def _with_credentials(self, then: Callable[[keys.Credentials], None]) -> None:
        def unlocked(credentials) -> None:
            if credentials is not None:
                then(credentials)
        self.app.push_screen(UnlockScreen(self.info), unlocked)

    def action_open(self) -> None:
        if not self._need_container():
            return
        path = self.info.path

        def listed(entries) -> None:
            if entries is not None:
                self.app.push_screen(BrowseScreen(path, credentials_box[0], entries))

        credentials_box: list = []

        def unlocked(credentials: keys.Credentials) -> None:
            credentials_box.append(credentials)
            self.app.push_screen(ProgressScreen(
                "Öffnen", lambda monitor: container.list_contents(path, credentials, progress=monitor),
                lambda entries: f"{len(entries)} Einträge"), listed)

        self._with_credentials(unlocked)

    def action_keys(self) -> None:
        if not self._need_container():
            return
        path = self.info.path

        def unlocked(credentials: keys.Credentials) -> None:
            # Erst prüfen, ob die Zugangsdaten passen (nur der Header – auch bei Rohdaten), dann verwalten
            def checked(slot) -> None:
                if slot is not None:
                    self.app.push_screen(KeysScreen(path, credentials))
            self.app.push_screen(ProgressScreen(
                "Entsperren", lambda monitor: container.check_credentials(path, credentials, progress=monitor),
                lambda slot: f"Entsperrt über Slot {slot.index} ({slot.description})."), checked)
        self._with_credentials(unlocked)

    def action_append(self) -> None:
        if not self._need_container():
            return
        path = self.info.path

        def chosen(source: Path | None) -> None:
            if source is None:
                return
            if not source.exists():
                self.notify(escape(f"{source} gibt es nicht."), severity="error")
                return
            self._with_credentials(lambda credentials: self.app.push_screen(ProgressScreen(
                "Anhängen", lambda monitor: container.append(path, [source], credentials, progress=monitor),
                lambda r: f"Segment {r.segment} angehängt: {r.entries} Einträge, +{_size(r.added)}"),
                lambda _r: (self.select(path), self.refresh_files())))
        self.app.push_screen(PathScreen("Welche Datei oder welchen Ordner anhängen?", Path.cwd()), chosen)

    def action_diff(self) -> None:
        if not self._need_container():
            return
        path = self.info.path
        sibling = path.with_name(path.name[:-len(container.SUFFIX)]) if path.name.endswith(container.SUFFIX) else None
        default = sibling if sibling is not None and sibling.exists() else Path.cwd()

        def chosen(local: Path | None) -> None:
            if local is None:
                return

            def compared(result) -> None:
                if result is not None:
                    self.app.push_screen(DiffScreen(f"{path.name} ↔ {local}", result))
            self._with_credentials(lambda credentials: self.app.push_screen(ProgressScreen(
                "Vergleichen", lambda monitor: container.diff(path, [local], credentials, progress=monitor),
                lambda r: "keine Unterschiede" if r.identical else f"{len(r.changes)} Unterschied(e)"), compared))
        self.app.push_screen(PathScreen("Womit vergleichen? (dieselben Pfade wie beim Packen)", default), chosen)

    def action_verify(self) -> None:
        if not self._need_container():
            return
        path = self.info.path
        self._with_credentials(lambda credentials: self.app.push_screen(ProgressScreen(
            "Prüfen", lambda monitor: container.verify(path, credentials, progress=monitor),
            lambda r: f"Intakt: {r.files} Dateien, {_size(r.bytes)}"
                      + (f", {r.segments} Segmente" if r.segments > 1 else "")
                      + (f", signiert von {r.signer}" if r.signer else ""))))




class Tres0rApp(App):
    TITLE = "tres0r"
    ENABLE_COMMAND_PALETTE = False  # ungenutzt; spart Platz in der Fußzeile

    def __init__(self, start: Path | None = None) -> None:
        super().__init__()
        self.main = MainScreen((start or Path.cwd()).expanduser().resolve())

    def on_mount(self) -> None:
        self.push_screen(self.main)

    def select(self, path: Path) -> None:
        self.main.select(path)

    def vet_password(self, password: str, *, online: bool, proceed: Callable[[], None],
                     rejected: Callable[[str], None]) -> None:
        """Selbst gewähltes Passwort prüfen wie die CLI: Länge und Zeichenarten, dazu – wenn
        ``online`` – der Abgleich mit bekannten Datenlecks (HIBP). Bei Schwächen oder
        übersprungenem Abgleich nachfragen; ``proceed()``, wenn es verwendet wird, sonst
        ``rejected(grund)`` – das aufrufende Fenster bleibt offen, die Eingaben auch."""
        def decide(check: passgen.PasswordCheck | None) -> None:
            if check is None:
                rejected("Prüfung abgebrochen.")
                return
            problems = [f"{warning}." for warning in check.warnings]
            if check.hibp_error:
                problems.append(f"{check.hibp_error} – die Datenleck-Prüfung wurde übersprungen.")
            if not problems:
                proceed()
                return

            def answered(yes: bool) -> None:
                if yes:
                    proceed()
                else:
                    rejected(" ".join(problems))
            self.push_screen(ConfirmScreen("Hinweise zum Passwort:\n\n" + "\n".join(f"• {p}" for p in problems)
                                           + "\n\nTrotzdem verwenden?"), answered)
        if online:
            self.push_screen(LeakCheckScreen(password), decide)
        else:
            decide(passgen.check_password(password))

    def token_provider(self) -> hwtoken.TokenProvider:
        """FIDO2 für Arbeitsthreads: Hinweise als Benachrichtigung, PIN über ein Fenster."""
        return hwtoken.TokenProvider(notify=lambda msg: self.call_from_thread(self.notify, msg), pin=self.ask_pin)

    def ask_pin(self) -> str:
        """Aus einem Arbeitsthread: PIN-Fenster zeigen und auf die Eingabe warten.

        Endet die Oberfläche vorher (Beenden bei offenem Fenster), bricht Textual den Worker ab –
        dann nicht weiter warten: Der Thread hielte sonst das Prozessende für immer auf.
        """
        answered, box = threading.Event(), {}

        def answer(value) -> None:
            box["pin"] = value
            answered.set()
        worker = get_current_worker()
        self.call_from_thread(self.push_screen, PinScreen(), answer)
        while not answered.wait(0.1):
            if worker.is_cancelled:
                raise Cancelled("Abgebrochen.")
        if not box.get("pin"):
            raise WrongPassword("PIN-Eingabe abgebrochen.")
        return box["pin"]

    def refresh_files(self) -> None:
        self.main.refresh_files()


def run(start: str | os.PathLike[str] | None = None) -> None:
    Tres0rApp(Path(start) if start else None).run()


__all__ = ["Tres0rApp", "MainScreen", "run"]
