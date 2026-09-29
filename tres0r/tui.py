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

from rich.console import Group
from rich.markup import escape
from rich.table import Table
from rich.text import Text
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


def _key_hints(*pairs: tuple[str, str]) -> str:
    """Tastenhinweise untereinander – im Fließtext umbrochen endete eine Zeile auf "·"."""
    return "\n".join(f"[dim][b]{key}[/b]  {escape(text)}[/]" for key, text in pairs)


def _duration(seconds: float | None) -> str:
    if seconds is None:
        return ""
    seconds = int(seconds + 0.5)
    return f"{seconds // 60}:{seconds % 60:02d}"


# ---------------------------------------------------------------------------
# Fortschritt
# ---------------------------------------------------------------------------
class ProgressScreen(ModalScreen):
    """Führt ``task(monitor)`` in einem Thread aus; Ergebnis per ``dismiss``. Nach Erfolg steht
    ``success`` als grüne Kopfzeile mit ✓ über der Zusammenfassung – eindeutig auch ohne Farbe."""

    # Rahmen je Ausgang. Der Balken heißt nicht "#bar": So heißt auch der Balken *in* Textuals
    # ProgressBar – der Rand schob ihn aus seiner einzeiligen Leiste, zu sehen war nur „100%“.
    DEFAULT_CSS = """
    ProgressScreen { align: center middle; }
    #box { width: 76; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #box.-ok { border: round $success; }
    #box.-failed { border: round $error; }
    #box.-cancelled { border: round $warning; }
    #progress { margin: 1 0; }
    #outcome { width: 1fr; height: auto; }
    """
    BINDINGS = [Binding("escape", "cancel_or_close", "Abbrechen")]

    def __init__(self, title: str, task: Callable[[Monitor], object], done: Callable[[object], str],
                 success: str = "Erfolgreich abgeschlossen") -> None:
        super().__init__()
        self.title_text, self._job, self._summary, self.success = title, task, done, success
        self.token = CancelToken()
        self.outcome: object = None  # Rückgabewert der Aufgabe
        self.failure: BaseException | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="box"):
            yield Label(f"[b]{escape(self.title_text)}[/]", id="title")
            yield ProgressBar(total=None, show_eta=False, id="progress")
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

    _progressed = False  # schon eine Fortschrittsmeldung angezeigt?

    def _show(self, event: ProgressEvent) -> None:
        if self.is_finished:
            return  # verspätete Meldung: den Ausgang nicht wieder überschreiben
        self._progressed = True
        bar = self.query_one("#progress", ProgressBar)
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
        box = self.query_one("#box")
        if event.state == WorkerState.SUCCESS:
            self.outcome = event.worker.result
            self.query_one("#progress", ProgressBar).update(total=1, progress=1)
            for label in ("#phase", "#item"):  # „Verschlüssele …“ und die letzte Datei sind jetzt überholt
                self.query_one(label, Label).display = False
            outcome.update(f"[b green]✓ {escape(self.success)}[/]\n{escape(self._summary(self.outcome))}")
            box.add_class("-ok")
        else:
            bar = self.query_one("#progress", ProgressBar)
            if bar.total is None:  # unbestimmt: der wandernde Balken täte so, als liefe noch etwas
                bar.display = False
            if not self._progressed:  # keine Meldung kam an: leere Zeilen weglassen
                for label in ("#phase", "#item"):
                    self.query_one(label, Label).display = False
            if isinstance(event.worker.error, Cancelled) or event.state == WorkerState.CANCELLED:
                self.failure = event.worker.error or Cancelled("Abgebrochen.")
                outcome.update("[b yellow]Abgebrochen – nichts wurde verändert.[/]")
                box.add_class("-cancelled")
            else:
                self.failure = event.worker.error
                outcome.update(f"[b red]✗ Fehlgeschlagen: {escape(_describe_error(self.failure))}[/]")
                box.add_class("-failed")
        self.is_finished = True

    is_finished = False

    @on(Button.Pressed, "#cancel")
    def action_cancel_or_close(self) -> None:
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
        """Wie in der GUI: Anteile in Vierergruppen, Phrasen mit Leerzeichen zwischen den Wörtern –
        so bricht Rich nur zwischen Wörtern um. Mit "-" brach die Phrase mitten im Wort um
        ("vertiefe⏎n-strom", gesehen bei 80 Spalten). Beides gilt so abgetippt wieder: Anteile
        ignorieren Leerzeichen, Phrasen werden kanonisiert (keys.canonical_secret)."""
        if not value.startswith("tres0r-teil-"):
            return value.replace("-", " ")
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
# Hilfe
# ---------------------------------------------------------------------------
KEY_NAMES = {"escape": "Esc", "slash": "/", "question_mark": "?", "f1": "F1"}


class Page(Screen):
    """Vollbild-Ansicht. ? / h / F1 öffnen die Hilfe, q beendet – vorn in der Fußzeile, damit sie auch
    bei 80 Spalten sichtbar bleiben (Textual schneidet rechts ab). In Eingabefeldern gehören ?, h und q
    dem Feld; die Fußzeile zeigt dann F1 (von mehreren Tasten einer Aktion zeigt sie die erste nutzbare)."""

    BINDINGS = [Binding("question_mark", "app.help", "Hilfe", tooltip="Tasten und Erklärungen zu dieser Ansicht"),
                Binding("f1", "app.help", "Hilfe", key_display="F1"),
                Binding("h", "app.help", "Hilfe", show=False),
                Binding("q", "app.quit", "Beenden", tooltip="tres0r beenden")]
    HELP_TITLE = ""
    HELP = ""  # Erklärung für die Hilfe; die Tasten stellt HelpScreen aus BINDINGS zusammen


class HelpScreen(ModalScreen):
    """Hilfe zur Ansicht darunter: ihre Erklärung und ihre Tasten – aus ihren BINDINGS erzeugt, damit
    die Hilfe nie etwas anderes sagt, als die Tasten tun."""

    DEFAULT_CSS = """
    HelpScreen { align: center middle; }
    #box { width: 100%; max-width: 90; max-height: 90%; height: auto; border: round $accent; padding: 1 2;
           background: $surface; }
    #box > Static { width: 1fr; }
    #close { margin-top: 1; }
    """
    BINDINGS = [Binding("escape", "close", "Schließen"), Binding("question_mark", "close", show=False),
                Binding("h", "close", show=False), Binding("f1", "close", show=False),
                Binding("q", "app.quit", "Beenden", show=False)]
    COMMON = [("? · h · F1", "diese Hilfe (in Eingabefeldern nur F1 – am Mac oft mit fn)"),
              ("q", "tres0r beenden (in Eingabefeldern und Fenstern: Strg+Q)"),
              ("Esc", "zurück bzw. abbrechen"),
              ("Tab · Umschalt+Tab", "zum nächsten bzw. vorigen Feld oder Knopf"),
              ("Pfeiltasten", "auswählen"),
              ("Enter · Leertaste", "Knopf drücken, Schalter umlegen, Ordner auf- und zuklappen"),
              ("Maus", "Klicken und Scrollen gehen auch")]

    def __init__(self, page: Page) -> None:
        super().__init__()
        self.page = page

    def rows(self) -> list[tuple[str, str]]:
        """Tasten der Ansicht (auch ausgeblendete wie r), ohne die gemeinsamen von ``Page``."""
        return [(KEY_NAMES.get(b.key, b.key), b.tooltip or b.description)
                for b in type(self.page).__dict__.get("BINDINGS", [])]

    @staticmethod
    def table(rows: list[tuple[str, str]]) -> Table:
        """Zwei Spalten; lange Erklärungen brechen in ihrer Spalte um (reiner Text, kein Markup)."""
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold", no_wrap=True)
        grid.add_column()
        for key, text in rows:
            grid.add_row(Text(key), Text(text))
        return grid

    def compose(self) -> ComposeResult:
        page = type(self.page)
        with VerticalScroll(id="box"):
            yield Static(f"[b]Hilfe – {escape(page.HELP_TITLE)}[/]\n\n{escape(page.HELP)}\n", id="about")
            if rows := self.rows():
                yield Label("[b]Tasten in dieser Ansicht[/]")
                yield Static(self.table(rows), id="keys")
            yield Label("\n[b]Überall[/]")
            yield Static(self.table(self.COMMON), id="common")
            yield Button("Schließen", variant="primary", id="close")

    @on(Button.Pressed, "#close")
    def action_close(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------------------
# Schlüssel verwalten, Vergleich
# ---------------------------------------------------------------------------
class KeysScreen(Page):
    """Keyslots eines entsperrten Containers ansehen und ändern."""

    # w, e und s nur im Hinweis unter der Tabelle (ausgeschrieben) – alle in der Fußzeile passten nicht in 80 Spalten
    BINDINGS = [Binding("n", "add_password", "+Passwort", tooltip="weiteres Passwort hinzufügen"),
                Binding("w", "add_recovery", "+Phrase", show=False, tooltip="Wiederherstellungsphrase hinzufügen"),
                Binding("e", "add_recipient", "+Empfänger", show=False,
                        tooltip="Empfänger (öffentlicher Schlüssel) hinzufügen"),
                Binding("s", "add_shares", "+Anteile", show=False,
                        tooltip="Anteile hinzufügen (K von N öffnen gemeinsam)"),
                Binding("c", "change_password", "Ändern", tooltip="eigenes Passwort ändern"),
                Binding("x", "remove", "Entfernen", tooltip="gewählten Schlüssel entfernen"),
                Binding("escape", "back", "Zurück", tooltip="zurück zur Hauptansicht")]
    HINTS = [("n", "Passwort hinzufügen"), ("c", "eigenes Passwort ändern"),
             ("w", "Wiederherstellungsphrase hinzufügen"), ("x", "gewählten Schlüssel entfernen"),
             ("e", "Empfänger hinzufügen"), ("Esc", "zurück"),
             ("s", "Anteile hinzufügen (K von N)"), ("?", "Hilfe")]
    HELP_TITLE = "Schlüssel verwalten"
    HELP = ("Jede Zeile ist ein Schlüssel (Keyslot), der den Container für sich allein öffnet – Anteile nur "
            "gemeinsam (K von N). Änderungen schreiben nur den Kopf des Containers neu, der Inhalt bleibt, "
            "wie er ist.")
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
        yield Static("", id="hint")
        yield Footer(compact=True)

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
        # zwei Spalten: passt in 80 Spalten, als Fließtext war der Hinweis rechts abgeschnitten
        grid = Table.grid(padding=(0, 2))
        for _ in range(2):
            grid.add_column(style="bold dim", no_wrap=True)
            grid.add_column(style="dim")
        for (key1, text1), (key2, text2) in zip(self.HINTS[::2], self.HINTS[1::2]):
            grid.add_row(key1, text1, key2, text2)
        self.query_one("#hint", Static).update(
            Group(grid, Text("Änderungen schreiben nur den Header neu.", style="dim")))

    def _run(self, title: str, success: str, task, summary, after=None) -> None:
        def closed(result) -> None:
            self.refresh_slots()
            if result is not None and after is not None:
                after(result)
        self.app.push_screen(ProgressScreen(title, task, summary, success), closed)

    def action_add_password(self) -> None:
        def chosen(new) -> None:
            if new is None:
                return
            self._run("Passwort hinzufügen", "Passwort hinzugefügt", lambda monitor: container.add_keys(
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
        self._run("Wiederherstellungsphrase hinzufügen", "Wiederherstellungsphrase hinzugefügt",
                  lambda monitor: container.add_keys(self.path, self.credentials, recovery=phrase, progress=monitor),
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
            self._run("Empfänger hinzufügen", "Empfänger hinzugefügt", lambda monitor: container.add_keys(
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
            self._run("Schwellwert hinzufügen", "Schwellwert hinzugefügt", lambda monitor: container.add_threshold(
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
            self._run("Passwort ändern", "Passwort geändert", lambda monitor: container.change_password(
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
                self._run("Schlüssel entfernen", "Schlüssel entfernt", lambda monitor: container.remove_key(
                    self.path, self.credentials, index, progress=monitor),
                    lambda removed: f"Entfernt: {removed.description}")
        self.app.push_screen(ConfirmScreen(f"Slot {index} ({slot.description}) wirklich entfernen? "
                                           "Wer nur diesen Schlüssel hat, kommt danach nicht mehr an den Inhalt."),
                             confirmed)

    def action_back(self) -> None:
        self.app.pop_screen()


class DiffScreen(Page):
    BINDINGS = [Binding("escape", "back", "Zurück", tooltip="zurück zur Hauptansicht")]
    HELP_TITLE = "Vergleich"
    HELP = ("Unterschiede zwischen dem Container und den Dateien auf der Platte: neu, entfernt, geändert, "
            "anderer Typ oder anderes Linkziel.")

    def __init__(self, title: str, result: container.DiffResult) -> None:
        super().__init__()
        self.title_text, self.result = title, result

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(escape(self.title_text), id="summary")
        yield DataTable(id="changes", cursor_type="row")
        yield Footer(compact=True)

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
class BrowseScreen(Page):
    """Inhaltsbaum eines entsperrten Containers."""

    BINDINGS = [Binding("slash", "search", "Suchen", tooltip="Einträge filtern: Textteil oder Muster wie *.jpg"),
                Binding("e", "extract", "Entpacken", tooltip="gewählten Eintrag entpacken"),
                Binding("a", "extract_all", "Alles entpacken", tooltip="gesamten Inhalt entpacken"),
                Binding("v", "verify", "Prüfen", tooltip="Container vollständig prüfen (schreibt nichts)"),
                Binding("escape", "back", "Zurück", tooltip="Suche beenden bzw. zurück zur Hauptansicht")]
    HELP_TITLE = "Inhalt eines Containers"
    HELP = ("Der entschlüsselte Inhalt; rechts stehen Details zum gewählten Eintrag. Entpacken schreibt in "
            "einen Ordner nach Wahl – der Container selbst bleibt unverändert.")
    DEFAULT_CSS = """
    #contents { width: 2fr; }
    #entry { width: 1fr; height: 1fr; padding: 1 2; border-left: solid $accent; }
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
        yield Footer(compact=True)

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
                lambda result: f"{result.entries} Einträge nach {dest} entpackt.", "Erfolgreich entpackt"))
        self.app.push_screen(PathScreen("Wohin entpacken?", Path.cwd()), chosen)

    def action_verify(self) -> None:
        self.app.push_screen(ProgressScreen(
            "Prüfen", lambda monitor: container.verify(self.path, self.credentials, progress=monitor),
            lambda r: f"Intakt: {r.files} Dateien, {_size(r.bytes)}"
                      + (", alle SHA-256 abgeglichen" if r.checked_hashes else "")
                      + (f", signiert von {r.signer}" if r.signer else ""), "Prüfung erfolgreich"))

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
class PackScreen(Page):
    BINDINGS = [Binding("escape", "back", "Zurück", tooltip="zurück, ohne zu packen")]
    # Tippen geht gleich ins Passwort – sonst läge der Fokus auf dem Formular, und ein q (Beenden) oder
    # h (Hilfe) am Anfang des Passworts wäre eine Taste statt ein Zeichen
    AUTO_FOCUS = "#password"
    HELP_TITLE = "Packen"
    HELP = ("Verschlüsselt die Auswahl in einen neuen Container; das Original bleibt, wie es ist. Zieldatei "
            "und Stufe wählen (höher = Angriffe auf das Passwort teurer, Öffnen dauert länger), dann das "
            "Passwort zweimal eingeben – oder einen Vorschlag erzeugen lassen und vollständig notieren.\n\n"
            "Ohne das Passwort kommt niemand mehr an den Inhalt – auch nicht mit tres0r.")
    DEFAULT_CSS = """
    #form { padding: 0 2; scrollbar-gutter: stable; }  /* Breite fest: der Vorschlag ist darauf umbrochen */
    #form Horizontal { height: auto; }
    #form Switch { margin-right: 1; }
    #form Horizontal Label { padding-top: 1; }
    #form Button { margin-right: 2; }
    #strength { width: 1fr; height: auto; }
    #form Input { border-title-color: $accent; }
    #level-row Label { width: 7; }
    #level-row Select { width: 1fr; }
    #lengths Input { margin-right: 2; }
    #words, #suggest { width: 26; }
    #length, #suggest-password { width: 24; }
    """

    def __init__(self, sources: list[Path]) -> None:
        super().__init__()
        self.sources = sources
        self._suggested: str | None = None
        self._secret: passgen.Secret | None = None

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
            with Horizontal(id="lengths"):  # Länge wie -w/-n der CLI – jeweils über dem passenden Knopf
                words = Input(str(passgen.DEFAULT_WORDS), restrict=r"[0-9]*", max_length=2, id="words")
                words.border_title = f"Wörter ({passgen.PASSPHRASE_MIN_WORDS}–{passgen.PASSPHRASE_MAX_WORDS})"
                yield words
                length = Input(str(passgen.DEFAULT_PASSWORD_LEN), restrict=r"[0-9]*", max_length=3, id="length")
                length.border_title = f"Zeichen ({passgen.PASSWORD_MIN_LEN}–{passgen.PASSWORD_MAX_LEN})"
                yield length
            with Horizontal():
                yield Button("Passphrase vorschlagen", id="suggest")
                yield Button("Passwort vorschlagen", id="suggest-password")
                yield Button("Packen", variant="primary", id="start")
        yield Footer(compact=True)

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
        self._offer(lambda: passgen.generate_passphrase(self._amount("#words")))

    @on(Button.Pressed, "#suggest-password")
    def _suggest_password(self) -> None:
        # ohne Sonderzeichen (^ und ` sind auf deutschen Tastaturen Tottasten) und ohne
        # Verwechselbares (0/O, 1/l/I) – der Vorschlag wird abgeschrieben; mit 20 Zeichen gut 110 Bit
        self._offer(lambda: passgen.generate_password(self._amount("#length"), symbols=False,
                                                      exclude_ambiguous=True))

    def _amount(self, selector: str) -> int:
        text = self.query_one(selector, Input).value
        return int(text) if text.isdigit() else 0  # leer zählt als außerhalb der Grenzen

    def _offer(self, make: Callable[[], passgen.Secret]) -> None:
        try:
            secret = make()
        except ValueError as e:  # Länge außerhalb der Grenzen – dieselbe Meldung wie in der CLI
            self.notify(escape(str(e)), severity="error")
            return
        self._secret, self._suggested = secret, secret.value  # str(secret) ist absichtlich geschwärzt
        for field in ("#password", "#confirm"):
            self.query_one(field, Input).value = secret.value
        self._show_suggestion()

    def _show_suggestion(self) -> None:
        """Vorschlag in eigenen Zeilen, ganz lesbar: selbst umbrochen (nur zwischen Wörtern, nie
        nach "-") auf die tatsächliche Breite – Rich bräche einen langen Vorschlag an
        beliebiger Stelle um, bei 80 Spalten schon manche Standard-Passphrase."""
        secret = self._secret
        if secret is None or self.query_one("#password", Input).value != secret.value:
            return  # eigenes Passwort eingegeben: dort steht jetzt die Stärke
        label = self.query_one("#strength", Label)
        lines = passgen._display_lines(secret, label.content_size.width or 60)  # vor dem Layout: 0
        note = ", ohne die Zeilenumbrüche" if len(lines) > 1 else ""
        text = (f"Vorschlag ({secret.entropy_bits:.0f} Bit) – bitte vollständig notieren{note}:\n[b]"
                + "\n".join(escape(line) for line in lines) + "[/]")
        if not secret.strong_enough:  # wie die CLI
            text += f"\n[yellow]Hinweis: unter {passgen.RECOMMENDED_BITS} Bit – für einen Container eher knapp.[/]"
        label.update(text)

    def on_resize(self) -> None:  # andere Breite: den Vorschlag neu umbrechen
        self.call_after_refresh(self._show_suggestion)

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
                self.app.notify(escape(f"✓ Erfolgreich gepackt: {result.path}"))
                self.app.refresh_files()

        def pack() -> None:
            self.app.push_screen(ProgressScreen(
                "Packen", task, lambda r: f"{r.path} – {_size(r.size)}, {r.entries} Einträge", "Erfolgreich gepackt"),
                closed)

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
class MainScreen(Page):
    """Dateibaum und Details; Kürzel gelten nur hier."""

    BINDINGS = [Binding("o", "open", "Öffnen", tooltip="Container öffnen: Inhalt ansehen und entpacken"),
                Binding("p", "pack", "Packen", tooltip="Datei oder Ordner in einen neuen Container verschlüsseln"),
                Binding("v", "verify", "Prüfen", tooltip="Container vollständig prüfen (schreibt nichts)"),
                Binding("a", "append", "Anhängen", tooltip="Datei oder Ordner an den Container anhängen"),
                Binding("d", "diff", "Vergleich", tooltip="Container mit Dateien auf der Platte vergleichen"),
                Binding("k", "keys", "Schlüssel", tooltip="Passwörter und andere Schlüssel des Containers verwalten"),
                Binding("r", "refresh_files", "Neu laden", show=False, tooltip="Dateibaum neu einlesen")]
    HELP_TITLE = "Hauptansicht"
    HELP = ("Links steht der Dateibaum, rechts stehen Details zur Auswahl.\n\n"
            "Verschlüsseln: Datei oder Ordner wählen und p drücken – tres0r packt die Auswahl in einen neuen "
            "Container (Endung .tres0r). Das Original bleibt, wie es ist.\n\n"
            "Einen Container wählen, dann: o öffnen (Inhalt ansehen und entpacken), v prüfen, a etwas anhängen, "
            "d mit Dateien auf der Platte vergleichen, k Schlüssel verwalten (Passwörter, "
            "Wiederherstellungsphrase …).")
    # Details über die volle Höhe: sonst endete die Trennlinie nach wenigen Zeilen (macOS-Bildschirmfoto)
    DEFAULT_CSS = """
    #files { width: 1fr; }
    #details { width: 1fr; height: 1fr; padding: 1 2; border-left: solid $accent; }
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
        yield Footer(compact=True)

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
            details.update(f"[b]{escape(path.name)}[/]\n{kind}{size}\n\n" + _key_hints(
                ("p", "packen (verschlüsseln)"), ("r", "neu laden"), ("?", "Hilfe"), ("q", "beenden")))
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
        lines.append("\n" + _key_hints(("o", "öffnen"), ("v", "prüfen"), ("a", "anhängen"), ("d", "vergleichen"),
                                       ("k", "Schlüssel"), ("?", "Hilfe"), ("q", "beenden")))
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
                lambda entries: f"{len(entries)} Einträge", "Erfolgreich geöffnet"), listed)

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
                lambda slot: f"Entsperrt über Slot {slot.index} ({slot.description}).", "Erfolgreich entsperrt"),
                checked)
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
                lambda r: f"Segment {r.segment} angehängt: {r.entries} Einträge, +{_size(r.added)}",
                "Erfolgreich angehängt"),
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
                lambda r: "keine Unterschiede" if r.identical else f"{len(r.changes)} Unterschied(e)",
                "Vergleich abgeschlossen"), compared))
        self.app.push_screen(PathScreen("Womit vergleichen? (dieselben Pfade wie beim Packen)", default), chosen)

    def action_verify(self) -> None:
        if not self._need_container():
            return
        path = self.info.path
        self._with_credentials(lambda credentials: self.app.push_screen(ProgressScreen(
            "Prüfen", lambda monitor: container.verify(path, credentials, progress=monitor),
            lambda r: f"Intakt: {r.files} Dateien, {_size(r.bytes)}"
                      + (f", {r.segments} Segmente" if r.segments > 1 else "")
                      + (f", signiert von {r.signer}" if r.signer else ""), "Prüfung erfolgreich")))




class Tres0rApp(App):
    TITLE = "tres0r"
    ENABLE_COMMAND_PALETTE = False  # ungenutzt; spart Platz in der Fußzeile
    # Befunde aus dem Test unter macOS: Textual zeigt den Fokus eines Knopfs mit invertierter Beschriftung –
    # das sah wie ein weißer Kasten im Knopf aus; jetzt fett und unterstrichen. Die Spur der Scrollleisten
    # ist bei Textual schwarz (#000) und wirkte neben dem grauen Dateibaum wie ein Darstellungsfehler; jetzt
    # hat sie die Farbe der Flächen, sichtbar bleibt der Balken.
    # Knopfreihen in Fenstern: Textuals Horizontal ist 1fr hoch – jedes Fenster reichte bis zum Bildschirmrand.
    CSS = """
    Button:focus { text-style: bold underline; }
    * { scrollbar-background: $surface; scrollbar-background-hover: $surface; scrollbar-background-active: $surface;
        scrollbar-corner-color: $surface; }
    #box Horizontal { height: auto; }
    """

    def __init__(self, start: Path | None = None) -> None:
        super().__init__()
        self.main = MainScreen((start or Path.cwd()).expanduser().resolve())

    def on_mount(self) -> None:
        self.push_screen(self.main)

    def action_help(self) -> None:
        if isinstance(self.screen, Page):  # nicht über Fenstern, nicht doppelt
            self.push_screen(HelpScreen(self.screen))

    def action_help_quit(self) -> None:
        """Strg+C beendet in Textual nicht (kopiert in Eingabefeldern) – auf Deutsch sagen, was geht."""
        self.notify("Beenden mit q – in Eingabefeldern und Fenstern mit Strg+Q.", title="tres0r beenden?")

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
