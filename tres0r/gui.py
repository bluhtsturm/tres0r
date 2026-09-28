"""Grafische Oberfläche (PySide6) – ``tres0r gui [ORDNER]``, Extra ``tres0r[gui]``.

Baut nur auf der stabilen API auf; nicht selbst Teil davon. Lange Vorgänge laufen
in Threads und melden sich über Qt-Signale (werden im GUI-Thread zugestellt).
Text von außen (Datei- und Eintragsnamen, Fehlermeldungen) wird immer als reiner
Text angezeigt – Qt würde ihn sonst als HTML deuten.

Alle Dialoge laufen über ``MainWindow.run_dialog`` und alle Meldungen über
``show_error``/``show_info`` – so lassen sich die Abläufe ohne Bildschirm testen.
"""
from __future__ import annotations

import fnmatch
import os
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QDir, QLibraryInfo, QLocale, QObject, Qt, QTranslator, Signal, Slot
from PySide6.QtGui import QAction, QFont, QKeySequence
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
                               QFileDialog, QFileSystemModel, QFormLayout, QHBoxLayout, QHeaderView, QInputDialog,
                               QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
                               QSplitter, QTableWidget, QTableWidgetItem, QTreeView, QTreeWidget, QTreeWidgetItem,
                               QVBoxLayout, QWidget)

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


def describe_error(error: BaseException) -> str:
    """Meldetext für einen Fehler aus einer Aufgabe. ``OSError`` ist erwartbar (fehlende
    Rechte, voller Datenträger) – mit Pfad statt "Unerwarteter Fehler: PermissionError(…)"."""
    if isinstance(error, Tres0rError):
        return str(error)
    if isinstance(error, OSError):
        where = f": {error.filename}" if error.filename else ""
        return f"{error.strerror or error}{where}"
    return f"Unerwarteter Fehler: {error!r}"


def _plain(label: QLabel) -> QLabel:
    """Reiner Text, umbrechend, markierbar – nie HTML."""
    label.setTextFormat(Qt.PlainText)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return label


# ---------------------------------------------------------------------------
# Hintergrundarbeit
# ---------------------------------------------------------------------------
class _Task(QObject):
    progress = Signal(object)
    done = Signal(object)
    failed = Signal(object)

    def __init__(self, job: Callable[[Monitor], object], token: CancelToken) -> None:
        super().__init__()
        self.job, self.token = job, token

    def start(self) -> None:
        monitor = Monitor(self.progress.emit, cancel=self.token, interval=0.1)

        def run() -> None:
            try:
                result = self.job(monitor)
            except BaseException as error:  # an den GUI-Thread weiterreichen
                self.failed.emit(error)
            else:
                self.done.emit(result)
        threading.Thread(target=run, name="tres0r-gui-task", daemon=True).start()


class ProgressDialog(QDialog):
    """Führt eine Aufgabe aus; schließt sich danach selbst (Ergebnis bzw. Fehler in Attributen)."""

    def __init__(self, parent: QWidget | None, title: str, job: Callable[[Monitor], object]) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(520)
        self.token = CancelToken()
        self.result_value: object = None
        self.error: BaseException | None = None
        self.running = True
        layout = QVBoxLayout(self)
        self.bar = QProgressBar()
        self.bar.setRange(0, 0)  # unbestimmt, bis die Gesamtgröße bekannt ist
        self.phase = _plain(QLabel("Starte …"))
        self.item = _plain(QLabel(""))
        self.cancel_button = QPushButton("Abbrechen")
        self.cancel_button.clicked.connect(self.cancel)
        for widget in (self.bar, self.phase, self.item, self.cancel_button):
            layout.addWidget(widget)
        self.task = _Task(job, self.token)
        self.task.progress.connect(self._show)
        self.task.done.connect(self._done)
        self.task.failed.connect(self._failed)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not getattr(self, "_started", False):
            self._started = True
            self.task.start()

    @Slot(object)
    def _show(self, event: ProgressEvent) -> None:
        labels = {"schlüssel": "Schlüsselableitung (Argon2id) …", "durchsuchen": "Durchsuche …",
                  "packen": "Verschlüssele", "entpacken": "Entpacke", "prüfen": "Prüfe", "lesen": "Lese",
                  "kopieren": "Kopiere", "vergleichen": "Vergleiche", "retten": "Rette"}
        parts = [labels.get(event.phase, event.phase)]
        if event.total:
            self.bar.setRange(0, 1000)
            self.bar.setValue(int(1000 * min(1.0, event.done / event.total)))
        elif not event.finished:
            self.bar.setRange(0, 0)  # Gesamtgröße unbekannt (z. B. Schlüsselableitung): "beschäftigt"
        if event.unit == UNIT_ENTRIES:
            parts.append(f"{event.done} Einträge")
        elif event.phase != "schlüssel":
            parts.append(_size(event.done) + (f" von {_size(event.total)}" if event.total else ""))
            if event.rate:
                parts.append(f"{_size(int(event.rate))}/s")
            if event.eta and event.eta >= 1:
                seconds = int(event.eta + 0.5)
                parts.append(f"noch {seconds // 60}:{seconds % 60:02d}")
        self.phase.setText(" · ".join(parts))
        self.item.setText(event.item or "")

    @Slot(object)
    def _done(self, result: object) -> None:
        self.running, self.result_value = False, result
        self.accept()

    @Slot(object)
    def _failed(self, error: BaseException) -> None:
        self.running, self.error = False, error
        super().reject()

    def cancel(self) -> None:
        if self.running:
            self.token.cancel()
            self.phase.setText("Breche ab …")
            self.cancel_button.setEnabled(False)

    def reject(self) -> None:  # Esc/Fenster schließen = abbrechen, nicht verlassen
        self.cancel()


# ---------------------------------------------------------------------------
# Dialoge
# ---------------------------------------------------------------------------
class PasswordFields(QWidget):
    """Passwort + Wiederholung mit Stärkeanzeige und optionalem Vorschlag."""

    def __init__(self, suggest: bool = True) -> None:
        super().__init__()
        form = QFormLayout(self)
        form.setContentsMargins(0, 0, 0, 0)
        self.password, self.confirm = QLineEdit(), QLineEdit()
        for field in (self.password, self.confirm):
            field.setEchoMode(QLineEdit.Password)
        form.addRow("Passwort", self.password)
        form.addRow("Wiederholen", self.confirm)
        self.strength = _plain(QLabel(""))
        form.addRow("", self.strength)
        # Vorschlag einzeilig: ein Umbruch nach "-" wäre beim Abschreiben mehrdeutig
        self.suggestion = QLineEdit()
        self.suggestion.setReadOnly(True)
        self.suggestion.setFont(QFont("monospace"))
        self.suggestion.setVisible(False)
        self.suggestion_hint = _plain(QLabel(""))
        if suggest:
            button = QPushButton("Passphrase vorschlagen")
            button.clicked.connect(self.suggest)
            form.addRow("", button)
            form.addRow("", self.suggestion_hint)
            form.addRow("", self.suggestion)
        self.password.textChanged.connect(self._strength)

    def _strength(self, text: str) -> None:
        suggested = text == getattr(self, "_suggested", None)
        if not suggested:  # eigenes Passwort: der Vorschlag gilt nicht mehr – nicht stehen lassen
            self.suggestion.setVisible(False)
            self.suggestion_hint.setText("")
        if not text or suggested:
            self.strength.setText("")
            return
        check = passgen.check_password(text)
        self.strength.setText("Stärke: in Ordnung" if check.ok else "Stärke: " + "; ".join(check.warnings))

    def suggest(self) -> None:
        phrase = passgen.generate_passphrase()
        self._suggested = phrase.value  # str(phrase) ist absichtlich geschwärzt
        self.password.setText(phrase.value)
        self.confirm.setText(phrase.value)
        self.suggestion_hint.setText(f"Vorschlag ({phrase.entropy_bits:.0f} Bit) – bitte vollständig notieren "
                                     "(markieren und kopieren möglich):")
        self.suggestion.setText(phrase.value)
        self.suggestion.setVisible(True)
        self.suggestion.setCursorPosition(0)
        # ganz sichtbar, ohne Scrollen – sonst übersieht man beim Abschreiben das Ende. Das Feld
        # selbst wird sofort breit genug, ragte aber über den Dialogrand hinaus (gemessen: 48 px
        # abgeschnitten, Hinweis darüber zu niedrig) – deshalb das ganze Fenster auf seine neue
        # Wunschgröße bringen (adjustSize() vergrößert sichtbare Dialoge nicht zuverlässig).
        self.suggestion.setMinimumWidth(self.suggestion.fontMetrics().horizontalAdvance(phrase.value) + 24)
        window = self.window()
        self.layout().activate()  # zuerst die eigene Ebene – sonst ist die Wunschgröße des Dialogs veraltet
        window.layout().activate()
        wanted = window.sizeHint()
        window.resize(max(window.width(), wanted.width()), max(window.height(), wanted.height()))

    def value(self) -> str | None:
        """Passwort oder None (mit Hinweis im Stärkefeld), wenn leer oder abweichend."""
        if not self.password.text():
            self.strength.setText("Bitte ein Passwort eingeben.")
            return None
        if self.password.text() != self.confirm.text():
            self.strength.setText("Die Passwörter stimmen nicht überein.")
            return None
        return self.password.text()


def _path_row(placeholder: str, pick: Callable[[], str]) -> tuple[QWidget, QLineEdit]:
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    field = QLineEdit()
    field.setPlaceholderText(placeholder)
    button = QPushButton("…")
    button.setFixedWidth(32)
    button.clicked.connect(lambda: (lambda chosen: chosen and field.setText(chosen))(pick()))
    layout.addWidget(field)
    layout.addWidget(button)
    return row, field


class PackDialog(QDialog):
    def __init__(self, parent: QWidget | None, sources: list[Path]) -> None:
        super().__init__(parent)
        self.setWindowTitle("Packen")
        self.setMinimumWidth(560)
        self.sources = sources
        layout = QVBoxLayout(self)
        layout.addWidget(_plain(QLabel("Packen: " + ", ".join(str(p) for p in sources))))
        form = QFormLayout()
        first = sources[0]
        output_row, self.output = _path_row("Zieldatei", lambda: QFileDialog.getSaveFileName(
            self, "Zieldatei", self.output.text(), "tres0r-Container (*.tres0r)")[0])
        self.output.setText(str(first.with_name(first.name + container.SUFFIX)))
        form.addRow("Zieldatei", output_row)
        self.level = QComboBox()
        for label, name in LEVEL_CHOICES:
            self.level.addItem(label, name)
        self.level.setCurrentIndex([n for _, n in LEVEL_CHOICES].index("normal"))
        form.addRow("Stufe", self.level)
        self.compress = QCheckBox("mit zstd komprimieren")
        self.fido2 = QCheckBox("zusätzlich FIDO2-Token als zweiter Faktor")
        form.addRow("", self.compress)
        form.addRow("", self.fido2)
        layout.addLayout(form)
        self.passwords = PasswordFields()
        layout.addWidget(self.passwords)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Packen")
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _accept(self) -> None:
        if self.passwords.value() is None:
            return
        text = self.output.text().strip()
        output = Path(text).expanduser()
        parent = output.parent if str(output.parent) else Path(".")
        problem = ("Bitte eine Zieldatei angeben." if not text
                   else f"{text} ist ein Ordner – bitte einen Dateinamen angeben." if output.is_dir()
                   else f"Zielordner {parent} existiert nicht." if not parent.is_dir()
                   else f"{text} existiert bereits." if container.volumes.exists(output) else None)
        if problem:
            self.passwords.strength.setText(problem)
            return
        self.accept()


class UnlockDialog(QDialog):
    def __init__(self, parent: QWidget | None, info: container.ContainerInfo) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{info.path.name} entsperren")
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        kinds = ", ".join(sorted({s.description.split(" (")[0] for s in info.slots}))
        layout.addWidget(_plain(QLabel(f"Schlüssel im Container: {kinds}")))
        form = QFormLayout()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        form.addRow("Passwort / Phrase", self.password)
        keyfile_row, self.keyfile = _path_row("optional", lambda: QFileDialog.getOpenFileName(self, "Keyfile")[0])
        form.addRow("Keyfile", keyfile_row)
        self.fido2 = QCheckBox("FIDO2-Token verwenden")
        form.addRow("", self.fido2)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Öffnen")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class NewPasswordDialog(QDialog):
    def __init__(self, parent: QWidget | None, title: str, second_factor: bool = True) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        self.passwords = PasswordFields(suggest=False)
        layout.addWidget(self.passwords)
        self.keyfile = QLineEdit()
        self.fido2 = QCheckBox("FIDO2-Token als zweiter Faktor")
        if second_factor:
            form = QFormLayout()
            row, self.keyfile = _path_row("optional: zweiter Faktor",
                                          lambda: QFileDialog.getOpenFileName(self, "Keyfile")[0])
            form.addRow("Keyfile", row)
            form.addRow("", self.fido2)
            layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _accept(self) -> None:
        if self.passwords.value() is None:
            return
        if self.keyfile.text().strip() and self.fido2.isChecked():
            self.passwords.strength.setText("Bitte entweder Keyfile oder FIDO2-Token.")
            return
        self.accept()


class SecretsDialog(QDialog):
    """Neue Geheimnisse (Phrase, Anteile) – nur jetzt sichtbar; optional als Dateien speichern."""

    def __init__(self, parent: QWidget | None, title: str, items: list[tuple[str, str]]) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(640, 320)
        self.items = items
        layout = QVBoxLayout(self)
        layout.addWidget(_plain(QLabel(f"{title} – nur jetzt sichtbar, bitte sicher notieren oder speichern.")))
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(QFont("monospace"))
        self.text.setPlainText("\n\n".join(f"{label}:\n{self.readable(value)}" for label, value in items))
        layout.addWidget(self.text)
        self.saved_note = _plain(QLabel(""))
        layout.addWidget(self.saved_note)
        buttons = QDialogButtonBox()
        save = buttons.addButton("Als Dateien speichern …", QDialogButtonBox.ActionRole)
        save.clicked.connect(lambda: self.save())  # clicked liefert sonst "checked" als Ordner
        done = buttons.addButton("Notiert – schließen", QDialogButtonBox.AcceptRole)
        done.clicked.connect(self.accept)
        layout.addWidget(buttons)

    @staticmethod
    def readable(value: str) -> str:
        """Anteile in Vierergruppen, Wiederherstellungsphrasen mit Leerzeichen zwischen den
        Wörtern – so wird nur zwischen Wörtern umbrochen, nie nach einem "-" (mehrdeutig beim
        Abschreiben). Beides gilt so abgetippt wieder: Anteile ignorieren Leerzeichen,
        Phrasen werden kanonisiert (keys.canonical_secret)."""
        if not value.startswith("tres0r-teil-"):
            return value.replace("-", " ")
        body = value[len("tres0r-teil-"):]
        return "tres0r-teil-" + " ".join(body[i:i + 4] for i in range(0, len(body), 4))

    def save(self, folder: Path | None = None) -> Path | None:
        folder = folder or Path(QFileDialog.getExistingDirectory(self, "Ordner für die Dateien") or "")
        if not str(folder) or str(folder) == ".":
            return None
        try:
            folder.mkdir(parents=True, exist_ok=True)
            for number, (label, value) in enumerate(self.items, start=1):
                keys._write_new(folder / f"geheimnis-{number}.txt",
                                f"# tres0r – {label}\n{value}\n".encode("utf-8"))
        except (OSError, Tres0rError) as e:
            box = QMessageBox(QMessageBox.Critical, "tres0r", f"Nicht gespeichert: {e}", parent=self)
            box.setTextFormat(Qt.PlainText)
            box.exec()
            return None
        rights = " (Rechte 0600)" if os.name == "posix" else ""  # Windows kennt keine Unix-Rechte
        self.saved_note.setText(f"{len(self.items)} Datei(en) in {folder} gespeichert{rights} – "
                                "einzeln weitergeben bzw. sicher verwahren, danach dort löschen.")
        return folder


# ---------------------------------------------------------------------------
# Fenster: Container-Inhalt, Schlüssel, Vergleich
# ---------------------------------------------------------------------------
class BrowseWindow(QWidget):
    def __init__(self, main: MainWindow, path: Path, credentials: keys.Credentials,
                 entries: list[container.Entry]) -> None:
        super().__init__()
        self.main, self.path, self.credentials, self.entries = main, path, credentials, entries
        self.setWindowTitle(f"{path.name} – {len(entries)} Einträge")
        self.resize(760, 520)
        layout = QVBoxLayout(self)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Suchen: Textteil oder Muster wie *.jpg")
        self.search.textChanged.connect(self.filter)
        layout.addWidget(self.search)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Größe", "Geändert", "Segment"])
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        for column in (1, 2, 3):  # Datum und Größe nie abschneiden
            self.tree.header().setSectionResizeMode(column, QHeaderView.ResizeToContents)
        layout.addWidget(self.tree)
        row = QHBoxLayout()
        for text, slot in (("Auswahl entpacken …", self.extract_selected), ("Alles entpacken …", self.extract_all),
                           ("Prüfen", self.verify)):
            button = QPushButton(text)
            button.clicked.connect(slot)
            row.addWidget(button)
        layout.addLayout(row)
        self.items: dict[str, QTreeWidgetItem] = {}
        self._build()

    def _build(self) -> None:
        for entry in sorted(self.entries, key=lambda e: e.name):
            parts = entry.name.strip("/").split("/")
            for depth in range(1, len(parts) + 1):
                key = "/".join(parts[:depth])
                if key in self.items:
                    continue
                parent = self.items.get("/".join(parts[:depth - 1]))
                item = QTreeWidgetItem([parts[depth - 1]])  # reiner Text
                item.setData(0, Qt.UserRole, key)
                item.setToolTip(0, key)  # lange Namen werden in der Spalte gekürzt
                item.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
                (parent.addChild(item) if parent else self.tree.addTopLevelItem(item))
                self.items[key] = item
            item = self.items["/".join(parts)]
            if entry.kind != "ordner":
                item.setText(1, _size(entry.size))
            if entry.mtime:
                item.setText(2, datetime.fromtimestamp(entry.mtime).strftime("%Y-%m-%d %H:%M"))
            if entry.segment:
                item.setText(3, str(entry.segment))
        self.tree.expandToDepth(0)
        self.tree.setColumnHidden(3, not any(entry.segment for entry in self.entries))

    def filter(self, text: str) -> None:
        pattern = text.strip().lower()
        visible = set()
        for key in self.items:
            name = key.lower()
            hit = not pattern or (fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(name.rsplit("/", 1)[-1], pattern)
                                  if any(c in pattern for c in "*?[") else pattern in name)
            if hit:
                parts = key.split("/")
                visible.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
        for key, item in self.items.items():
            item.setHidden(key not in visible)
        if pattern:
            self.tree.expandAll()
        self.setWindowTitle(f"{self.path.name} – {len([k for k in visible if k in self.items])} von "
                            f"{len(self.items)} sichtbar" if pattern else f"{self.path.name} – {len(self.entries)} Einträge")

    def selected(self) -> list[str]:
        return [item.data(0, Qt.UserRole) for item in self.tree.selectedItems()]

    def extract_selected(self) -> None:
        names = self.selected()
        if not names:
            self.main.show_info("Bitte Einträge auswählen.")
            return
        self._extract([_exact(name) for name in names])

    def extract_all(self) -> None:
        self._extract(None)

    def _extract(self, only: list[str] | None) -> None:
        dest = self.main.choose_directory("Wohin entpacken?")
        if dest is None:
            return
        result = self.main.run_task("Entpacken", lambda m: container.extract(
            self.path, dest, self.credentials, progress=m, only=only))
        if result is not None:
            self.main.show_info(f"{result.entries} Einträge nach {dest} entpackt.")

    def verify(self) -> None:
        result = self.main.run_task("Prüfen", lambda m: container.verify(self.path, self.credentials, progress=m))
        if result is not None:
            self.main.show_info(self.main.verified_text(result))


class KeysDialog(QDialog):
    def __init__(self, main: MainWindow, path: Path, credentials: keys.Credentials) -> None:
        super().__init__(main)
        self.main, self.path, self.credentials = main, path, credentials
        self.setWindowTitle(f"Schlüssel – {path.name}")
        self.resize(720, 360)
        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Nr.", "Schlüssel"])  # "Art" zeigte interne Bezeichner
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)  # sonst zweite Nummerierung (1, 2 …) neben "Nr."
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        layout.addWidget(self.table)
        row = QHBoxLayout()
        for text, slot in (("+ Passwort …", self.add_password), ("+ Phrase", self.add_recovery),
                           ("+ Empfänger …", self.add_recipient), ("+ Anteile …", self.add_shares),
                           ("Passwort ändern …", self.change_password), ("Entfernen", self.remove)):
            button = QPushButton(text)
            button.clicked.connect(slot)
            row.addWidget(button)
        layout.addLayout(row)
        layout.addWidget(_plain(QLabel("Änderungen schreiben nur den Header neu; der Inhalt bleibt unverändert.")))
        self.refresh()

    def refresh(self) -> None:
        self.info = container.inspect(self.path)
        self.table.setRowCount(len(self.info.slots))
        for row, slot in enumerate(self.info.slots):
            for column, text in enumerate((str(slot.index), slot.description)):
                self.table.setItem(row, column, QTableWidgetItem(text))  # reiner Text

    def _run(self, title: str, job) -> object:
        result = self.main.run_task(title, job)
        self.refresh()
        return result

    def _new_password(self, title: str, second_factor: bool = True) -> dict | None:
        dialog = NewPasswordDialog(self, title, second_factor)
        if not self.main.run_dialog(dialog):
            return None
        keyfile = None
        if dialog.keyfile.text().strip():
            try:
                keyfile = keys.keyfile_secret(Path(dialog.keyfile.text().strip()).expanduser())
            except OSError as e:
                self.main.show_error(f"Keyfile nicht lesbar: {e.strerror or e}")
                return None
        return {"password": dialog.passwords.value(), "keyfile": keyfile,
                "fido2": self.main.token_provider() if dialog.fido2.isChecked() else None}

    def add_password(self) -> None:
        new = self._new_password("Weiteres Passwort")
        if new is not None:
            self._run("Passwort hinzufügen", lambda m: container.add_keys(
                self.path, self.credentials, password=new["password"],
                # gleiche Stufe wie das vorhandene Passwort – ein schwächerer Slot senkt den Schutz
                params=self.info.kdf or LEVELS["normal"],
                keyfile=new["keyfile"], fido2=new["fido2"], progress=m))

    def add_recovery(self) -> None:
        phrase = keys.generate_recovery().value
        if self._run("Phrase hinzufügen", lambda m: container.add_keys(
                self.path, self.credentials, recovery=phrase, progress=m)) is not None:
            self.main.run_dialog(SecretsDialog(self, "Wiederherstellungsphrase", [("Phrase", phrase)]))

    def add_recipient(self) -> None:
        text = self.main.ask_text("Öffentlicher Schlüssel des Empfängers (tres0r-pub-…)")
        if not text:
            return
        try:
            recipient = keys.parse_recipient(text)
        except Tres0rError as e:
            self.main.show_error(str(e))
            return
        self._run("Empfänger hinzufügen", lambda m: container.add_keys(
            self.path, self.credentials, recipients=[recipient], progress=m))

    def add_shares(self) -> None:
        text = self.main.ask_text("Wie viele Anteile, wie viele davon nötig? (K/N, z. B. 2/3)", "2/3")
        if not text:
            return
        try:
            k, n = (int(part) for part in text.split("/"))
            if not 2 <= k <= n <= 32:
                raise ValueError
        except ValueError:
            self.main.show_error("Bitte K/N angeben, z. B. 2/3 (2 ≤ K ≤ N ≤ 32).")
            return
        result = self._run("Anteile hinzufügen", lambda m: container.add_threshold(
            self.path, self.credentials, k, n, progress=m))
        if result is not None:
            self.main.run_dialog(SecretsDialog(self, f"Anteile ({k} von {n} nötig)",
                                               [(share.label, share.text()) for share in result[1]]))

    def change_password(self) -> None:
        new = self._new_password("Passwort ändern", second_factor=False)
        if new is None:
            return
        # change_password gibt nichts zurück – "True" markiert den Erfolg
        if self._run("Passwort ändern", lambda m: container.change_password(
                self.path, self.credentials, new["password"], progress=m) or True):
            self.credentials = keys.Credentials(passwords=[new["password"]], keyfiles=self.credentials.keyfiles,
                                                fido2=self.credentials.fido2)
            self.main.show_info("Passwort geändert (ein zweiter Faktor bleibt bestehen).")

    def remove(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            self.main.show_info("Bitte einen Schlüssel auswählen.")
            return
        if len(self.info.slots) == 1:
            self.main.show_error("Der letzte Schlüssel lässt sich nicht entfernen.")
            return
        slot = self.info.slots[row]
        if self.main.confirm(f"Slot {slot.index} ({slot.description}) wirklich entfernen? "
                             "Wer nur diesen Schlüssel hat, kommt danach nicht mehr an den Inhalt."):
            self._run("Schlüssel entfernen", lambda m: container.remove_key(
                self.path, self.credentials, slot.index, progress=m))


class DiffDialog(QDialog):
    def __init__(self, parent: QWidget | None, title: str, result: container.DiffResult) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(700, 420)
        layout = QVBoxLayout(self)
        verdict = "keine Unterschiede" if result.identical else f"{len(result.changes)} Unterschied(e)"
        layout.addWidget(_plain(QLabel(f"{verdict}, {result.unchanged} unverändert")))
        self.table = QTableWidget(len(result.changes), 3)
        self.table.setHorizontalHeaderLabels(["Status", "Eintrag", "Detail"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        for row, change in enumerate(result.changes):
            for column, text in enumerate((change.status, change.name, change.detail)):
                self.table.setItem(row, column, QTableWidgetItem(text))
        layout.addWidget(self.table)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


# ---------------------------------------------------------------------------
# Hauptfenster
# ---------------------------------------------------------------------------
class _Bridge(QObject):
    """Anfragen aus Arbeitsthreads an den GUI-Thread (PIN, Hinweise)."""

    pin_requested = Signal(object)
    notice = Signal(str)


class MainWindow(QMainWindow):
    def __init__(self, start: Path | None = None) -> None:
        super().__init__()
        self.setWindowTitle("tres0r")
        self.resize(1000, 620)
        self.setAcceptDrops(True)
        self.start = (start or Path.home()).expanduser().resolve()
        self.selected: Path | None = None
        self.info: container.ContainerInfo | None = None
        self.windows: list[QWidget] = []  # offene Inhaltsfenster am Leben halten
        self.bridge = _Bridge()
        self.bridge.pin_requested.connect(self._answer_pin)
        self.bridge.notice.connect(lambda text: self.statusBar().showMessage(text, 8000))

        self.model = QFileSystemModel()
        self.model.setRootPath(str(self.start))
        self.model.setFilter(QDir.AllEntries | QDir.NoDotAndDotDot | QDir.AllDirs)
        self.view = QTreeView()
        self.view.setModel(self.model)
        self.view.setRootIndex(self.model.index(str(self.start)))
        self.view.setColumnWidth(0, 320)
        self.view.setColumnHidden(2, True)  # "Typ" – zeigt bei Containern nur "unbekannt"
        self.view.selectionModel().currentChanged.connect(lambda index, _: self.select(Path(self.model.filePath(index))))
        self.view.doubleClicked.connect(self._double_clicked)
        self.title = _plain(QLabel("tres0r"))
        title_font = self.title.font()
        title_font.setBold(True)
        title_font.setPointSizeF(title_font.pointSizeF() * 1.25)
        self.title.setFont(title_font)
        self.details = _plain(QLabel("Datei oder Ordner wählen – oder hierher ziehen."))
        self.details.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        panel = QWidget()
        panel.setMinimumWidth(320)
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(12, 12, 12, 12)
        panel_layout.addWidget(self.title)
        panel_layout.addWidget(self.details, 1)
        splitter = QSplitter()
        splitter.addWidget(self.view)
        splitter.addWidget(panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        self.setCentralWidget(splitter)

        toolbar = self.addToolBar("Aktionen")
        toolbar.setMovable(False)
        self.actions_by_name = {}
        for name, text, shortcut in (("pack", "Packen …", "Ctrl+P"), ("open", "Öffnen", "Ctrl+O"),
                                     ("verify", "Prüfen", "Ctrl+T"), ("append", "Anhängen …", "Ctrl+A"),
                                     ("diff", "Vergleichen …", "Ctrl+D"), ("keys", "Schlüssel …", "Ctrl+K")):
            action = QAction(text, self)
            action.setShortcut(QKeySequence(shortcut))
            action.triggered.connect(getattr(self, name))
            toolbar.addAction(action)
            self.actions_by_name[name] = action
        self.statusBar().showMessage(f"Ordner: {self.start}")
        self._update_actions()

    # -- Dialoge und Meldungen (in Tests ersetzbar) ------------------------------
    def run_dialog(self, dialog: QDialog) -> bool:
        return dialog.exec() == QDialog.Accepted

    def show_error(self, text: str) -> None:
        box = QMessageBox(QMessageBox.Critical, "tres0r", text, parent=self)
        box.setTextFormat(Qt.PlainText)
        box.exec()

    def show_info(self, text: str) -> None:
        self.statusBar().showMessage(text, 10000)

    def confirm(self, text: str) -> bool:
        box = QMessageBox(QMessageBox.Warning, "tres0r", text, QMessageBox.Yes | QMessageBox.No, self)
        box.setTextFormat(Qt.PlainText)
        box.setDefaultButton(QMessageBox.No)
        return box.exec() == QMessageBox.Yes

    def ask_text(self, question: str, default: str = "") -> str | None:
        text, ok = QInputDialog.getText(self, "tres0r", question, QLineEdit.Normal, default)
        return text.strip() if ok and text.strip() else None

    def choose_directory(self, title: str) -> Path | None:
        chosen = QFileDialog.getExistingDirectory(self, title, str(self.start))
        return Path(chosen) if chosen else None

    def choose_source(self, title: str, start: Path | None = None) -> Path | None:
        chosen = QFileDialog.getExistingDirectory(self, title, str(start or self.start))
        return Path(chosen) if chosen else None

    def choose_sources(self, title: str, start: Path | None = None) -> list[Path] | None:
        """Einen Ordner oder Dateien wählen – Qt kennt keinen gemeinsamen Dialog für beides."""
        box = QMessageBox(QMessageBox.Question, "tres0r", title, parent=self)
        folder = box.addButton("Ordner …", QMessageBox.AcceptRole)
        files = box.addButton("Dateien …", QMessageBox.AcceptRole)
        box.addButton("Abbrechen", QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is folder:
            chosen = self.choose_source(title, start)
            return [chosen] if chosen else None
        if box.clickedButton() is files:
            names, _ = QFileDialog.getOpenFileNames(self, title, str(start or self.start))
            return [Path(name) for name in names] or None
        return None

    def request_pin(self) -> str | None:
        pin, ok = QInputDialog.getText(self, "FIDO2-Token", "Der Token verlangt seine PIN:", QLineEdit.Password)
        return pin if ok and pin else None

    # -- Hintergrundarbeit ------------------------------------------------------
    def run_task(self, title: str, job: Callable[[Monitor], object]) -> object:
        """Aufgabe mit Fortschrittsdialog; Ergebnis oder None (Fehler wurde gemeldet)."""
        dialog = ProgressDialog(self, title, job)
        self.run_dialog(dialog)
        if dialog.error is not None:
            error = dialog.error
            if isinstance(error, Cancelled):
                self.show_info("Abgebrochen – nichts wurde verändert.")
            else:
                self.show_error(describe_error(error))
            return None
        return dialog.result_value

    def token_provider(self) -> hwtoken.TokenProvider:
        return hwtoken.TokenProvider(notify=self.bridge.notice.emit, pin=self.ask_pin)

    def ask_pin(self) -> str:
        """Aus einem Arbeitsthread: PIN im GUI-Thread abfragen und warten."""
        box = {"event": threading.Event()}
        self.bridge.pin_requested.emit(box)
        box["event"].wait()
        if not box.get("pin"):
            raise WrongPassword("PIN-Eingabe abgebrochen.")
        return box["pin"]

    @Slot(object)
    def _answer_pin(self, box: dict) -> None:
        box["pin"] = self.request_pin()
        box["event"].set()

    # -- Auswahl --------------------------------------------------------------
    def select(self, path: Path) -> None:
        self.selected, self.info = path, None
        if path.is_file():
            try:
                self.info = container.inspect(path)
            except (Tres0rError, OSError):
                self.info = None
        self.title.setText(path.name)
        if self.info is None:
            kind = "Ordner" if path.is_dir() else "Datei"
            size = "" if path.is_dir() else f"\nGröße: {_size(path.stat().st_size)}" if path.exists() else ""
            self.details.setText(f"{kind}{size}\n\nPacken mit Strg+P – oder in das Fenster ziehen.")
        else:
            info = self.info
            lines = [f"tres0r-Container, Format v{info.version}", f"Größe: {_size(info.size)}",
                     "", "Schlüssel:"] + [f"  [{s.index}] {s.description}" for s in info.slots]
            if info.signed:
                lines.append("signiert")
            if info.segmented:
                lines.append("mit angehängten Segmenten")
            if info.volumes > 1:
                lines.append(f"{info.volumes} Teile")
            if info.interrupted:
                lines.append("Achtung: Anhängen unterbrochen – 'tres0r repair'")
            if info.payload_type != "tar":
                lines += ["", "Inhalt: ein Datenstrom (tres0r encrypt), keine Dateien – "
                              "entschlüsseln mit 'tres0r decrypt'. Prüfen und Schlüssel verwalten gehen."]
            self.details.setText("\n".join(lines))
        self._update_actions()

    def _has_files(self) -> bool:
        return self.info is not None and self.info.payload_type == "tar"

    def _update_actions(self) -> None:
        is_container = self.info is not None
        self.actions_by_name["pack"].setEnabled(self.selected is not None and not is_container)
        for name in ("verify", "keys"):
            self.actions_by_name[name].setEnabled(is_container)
        for name in ("open", "append", "diff"):  # Rohdaten-Container enthalten keine Dateien
            self.actions_by_name[name].setEnabled(self._has_files())

    def _double_clicked(self, index) -> None:
        path = Path(self.model.filePath(index))
        self.select(path)
        if self._has_files():
            self.open()

    # -- Drag & Drop ------------------------------------------------------------
    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        paths = [Path(url.toLocalFile()) for url in event.mimeData().urls() if url.isLocalFile()]
        self.dropped(paths)

    def dropped(self, paths: list[Path]) -> None:
        if not paths:
            return
        if len(paths) == 1 and paths[0].is_file():
            self.select(paths[0])
            if self._has_files():
                self.open()
            if self.info is not None:
                return  # auch Rohdaten-Container nicht noch einmal einpacken
        self.pack(paths)

    # -- Aktionen -------------------------------------------------------------
    def _credentials(self) -> keys.Credentials | None:
        dialog = UnlockDialog(self, self.info)
        if not self.run_dialog(dialog):
            return None
        keyfiles = []
        if dialog.keyfile.text().strip():
            try:
                keyfiles = [keys.keyfile_secret(Path(dialog.keyfile.text().strip()).expanduser())]
            except OSError as e:
                self.show_error(f"Keyfile nicht lesbar: {e.strerror or e}")
                return None
        password = dialog.password.text()
        return keys.Credentials(passwords=[password] if password else [], keyfiles=keyfiles,
                                fido2=self.token_provider() if dialog.fido2.isChecked() else None)

    def pack(self, sources: list[Path] | None = None) -> None:
        sources = sources if isinstance(sources, list) else ([self.selected] if self.selected else [])
        if not sources:
            return
        dialog = PackDialog(self, sources)
        if not self.run_dialog(dialog):
            return
        password, output = dialog.passwords.value(), Path(dialog.output.text()).expanduser()
        level, compress = dialog.level.currentData(), dialog.compress.isChecked()
        fido2 = self.token_provider() if dialog.fido2.isChecked() else None

        def job(monitor: Monitor):
            params = calibrate() if level == "auto" else LEVELS[level]
            extra = {"fido2": fido2} if fido2 is not None else {}
            return container.create(sources, output, password, params, compress=compress, progress=monitor, **extra)
        result = self.run_task("Packen", job)
        if result is not None:
            self.show_info(f"Gepackt: {result.path} – {_size(result.size)}, {result.entries} Einträge")
            self.select(result.path)

    def open(self) -> None:
        if self.info is None:
            return
        path, credentials = self.info.path, self._credentials()
        if credentials is None:
            return
        entries = self.run_task("Öffnen", lambda m: container.list_contents(path, credentials, progress=m))
        if entries is not None:
            window = BrowseWindow(self, path, credentials, entries)
            self.windows.append(window)
            window.show()

    def verified_text(self, result: container.VerifyResult) -> str:
        return (f"Intakt: {result.files} Dateien, {_size(result.bytes)}"
                + (f", {result.segments} Segmente" if result.segments > 1 else "")
                + (", alle SHA-256 abgeglichen" if result.checked_hashes else "")
                + (f", signiert von {result.signer}" if result.signer else ""))

    def verify(self) -> None:
        if self.info is None:
            return
        path, credentials = self.info.path, self._credentials()
        if credentials is not None:
            result = self.run_task("Prüfen", lambda m: container.verify(path, credentials, progress=m))
            if result is not None:
                self.show_info(self.verified_text(result))

    def append(self) -> None:
        if self.info is None:
            return
        path = self.info.path
        sources = self.choose_sources("Was soll angehängt werden?", path.parent)
        if not sources:
            return
        credentials = self._credentials()
        if credentials is None:
            return
        result = self.run_task("Anhängen", lambda m: container.append(path, sources, credentials, progress=m))
        if result is not None:
            self.show_info(f"Segment {result.segment} angehängt: {result.entries} Einträge, +{_size(result.added)}")
            self.select(path)

    def diff(self) -> None:
        if self.info is None:
            return
        path = self.info.path
        # Vorschlag wie in der TUI: der gleichnamige Ordner neben dem Container
        sibling = path.with_name(path.name[:-len(container.SUFFIX)]) if path.name.endswith(container.SUFFIX) else None
        local = self.choose_source("Womit vergleichen? (dieselben Pfade wie beim Packen)",
                                   sibling if sibling is not None and sibling.is_dir() else path.parent)
        if local is None:
            return
        credentials = self._credentials()
        if credentials is None:
            return
        result = self.run_task("Vergleichen", lambda m: container.diff(path, [local], credentials, progress=m))
        if result is not None:
            self.run_dialog(DiffDialog(self, f"{path.name} ↔ {local}", result))

    def keys(self) -> None:
        if self.info is None:
            return
        path, credentials = self.info.path, self._credentials()
        if credentials is None:
            return
        if self.run_task("Entsperren", lambda m: container.check_credentials(path, credentials, progress=m)) is not None:
            self.run_dialog(KeysDialog(self, path, credentials))
            self.select(path)


def install_translations(app: QApplication) -> bool:
    """Qt-eigene Texte (Abbrechen, Spaltenköpfe) in der Systemsprache, falls vorhanden."""
    translator = QTranslator(app)
    folder = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    if translator.load(QLocale.system(), "qtbase", "_", folder):
        app.installTranslator(translator)
        app._tres0r_translator = translator  # am Leben halten
        return True
    return False


def run(start: str | os.PathLike[str] | None = None) -> int:
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("tres0r")
    install_translations(app)
    window = MainWindow(Path(start) if start else None)
    window.show()
    return app.exec()


__all__ = ["MainWindow", "run"]
