"""Grafische Oberfläche (PySide6) – ``tres0r gui [ORDNER]``, Extra ``tres0r-crypt[gui]``.

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

from PySide6.QtCore import QDir, QLibraryInfo, QLocale, QMimeData, QObject, Qt, QTranslator, Signal, Slot
from PySide6.QtGui import QAction, QFontDatabase, QKeySequence
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
                               QFileDialog, QFileSystemModel, QFormLayout, QGridLayout, QHBoxLayout, QHeaderView,
                               QInputDialog, QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar,
                               QPushButton, QSpinBox, QSplitter, QTableWidget, QTableWidgetItem, QTreeView, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from . import container, hwtoken, keys, passgen
from .errors import Cancelled, Tres0rError, WrongPassword
from .kdf import LEVELS, calibrate
from .progress import UNIT_ENTRIES, CancelToken, Monitor, ProgressEvent

LEVEL_CHOICES = [(f"{name} – {LEVELS[name].describe()}", name) for name in LEVELS] + [("auto – ca. 2 s", "auto")]


def _size(n: int | None) -> str:
    return "–" if n is None else container.format_size(n)


def _slots_text(added: list[int]) -> str:
    return f"Slot {', '.join(map(str, added))}"


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


def _fixed_font():
    """Festbreitenschrift der Plattform (Menlo, Consolas, DejaVu Sans Mono …). Ein fester Name
    wie "monospace" existiert unter macOS nicht – Qt sucht dann teuer nach Ersatz und warnt
    („Populating font family aliases took … ms“, gemeldet unter macOS Tahoe 26.7)."""
    return QFontDatabase.systemFont(QFontDatabase.FixedFont)


def _shortcut_text(sequence: str) -> str:
    """Tastenkürzel, wie die Plattform es schreibt: ⌘P unter macOS (Qt legt Ctrl dort auf die
    Befehlstaste), sonst Strg+P bzw. Ctrl+P je nach Übersetzung – fest „Strg+P“ war unter macOS falsch."""
    return QKeySequence(sequence).toString(QKeySequence.NativeText)


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
    """Führt eine Aufgabe aus (Ergebnis bzw. Fehler in Attributen). Ohne ``success`` schließt es
    sich danach selbst. Mit ``success`` bleibt es offen und meldet den Erfolg eindeutig: grüne
    Kopfzeile mit ✓, darunter ``summary(ergebnis)``, dann „Schließen“ – wie die TUI. Vorher stand
    der Erfolg nur zehn Sekunden in der Statuszeile (Wunsch nach dem Test unter macOS)."""

    def __init__(self, parent: QWidget | None, title: str, job: Callable[[Monitor], object],
                 success: str | None = None, summary: Callable[[object], str] | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(520)
        self.token = CancelToken()
        self.result_value: object = None
        self.error: BaseException | None = None
        self.running = True
        self.success, self.summary = success, summary
        layout = QVBoxLayout(self)
        self.bar = QProgressBar()
        self.bar.setRange(0, 0)  # unbestimmt, bis die Gesamtgröße bekannt ist
        self.phase = _plain(QLabel("Starte …"))
        self.item = _plain(QLabel(""))
        self.headline = _plain(QLabel(""))
        self.headline.setStyleSheet("color: #2e8b57; font-weight: bold;")  # auf hellem und dunklem Grund lesbar
        self.outcome = _plain(QLabel(""))
        self.cancel_button = QPushButton("Abbrechen")
        self.cancel_button.clicked.connect(self.cancel)
        for widget in (self.bar, self.phase, self.item, self.headline, self.outcome, self.cancel_button):
            layout.addWidget(widget)
        self.headline.hide()
        self.outcome.hide()
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
        if self.success is None:
            self.accept()
            return
        self.bar.setRange(0, 1000)
        self.bar.setValue(1000)
        self.phase.hide()  # „Verschlüssele …“ und die letzte Datei sind jetzt überholt
        self.item.hide()
        self.headline.setText(f"✓ {self.success}")
        self.headline.show()
        self.outcome.setText(self.summary(result) if self.summary is not None else "")
        self.outcome.setVisible(bool(self.outcome.text()))
        self.cancel_button.setText("Schließen")
        self.cancel_button.setEnabled(True)
        self.cancel_button.setDefault(True)
        self.cancel_button.setFocus()
        # umbrochene Zusammenfassung ganz zeigen: innere Ebene zuerst, dann die Höhe für diese Breite
        self.layout().activate()
        needed = self.layout().totalHeightForWidth(self.width())
        self.resize(self.width(), max(self.height(), needed if needed > 0 else self.sizeHint().height()))

    @Slot(object)
    def _failed(self, error: BaseException) -> None:
        self.running, self.error = False, error
        super().reject()

    def cancel(self) -> None:
        if self.running:
            self.token.cancel()
            self.phase.setText("Breche ab …")
            self.cancel_button.setEnabled(False)
        elif self.error is None:  # Erfolg angezeigt: der Knopf heißt jetzt „Schließen“
            self.accept()

    def reject(self) -> None:  # Esc/Fenster schließen = abbrechen, nicht verlassen
        self.cancel()


# ---------------------------------------------------------------------------
# Dialoge
# ---------------------------------------------------------------------------
class SecretView(QPlainTextEdit):
    """Vorschlag zum Abschreiben: ganz sichtbar, nur an eindeutigen Stellen umbrochen
    (``passgen._display_lines`` – nie endet eine Zeile auf "-"). Markieren und Kopieren
    liefert das Geheimnis ohne die Zeilenumbrüche."""

    COLUMNS = 100  # die Standardvorschläge passen in eine Zeile; bis 40 Wörter bzw. 128 Zeichen in mehrere

    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setFont(_fixed_font())
        self.setLineWrapMode(QPlainTextEdit.NoWrap)  # umbrochen wird nur an unseren Stellen
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._value = ""

    def show_secret(self, secret: passgen.Secret) -> list[str]:
        self._value = secret.value
        lines = passgen._display_lines(secret, self.COLUMNS)
        self.setPlainText("\n".join(lines))
        # so groß wie der Inhalt: nichts abgeschnitten, kein Scrollen nötig
        metrics = self.fontMetrics()
        frame = 2 * (self.frameWidth() + round(self.document().documentMargin()))
        self.setFixedSize(max(metrics.horizontalAdvance(line) for line in lines) + frame + 8,
                          metrics.lineSpacing() * len(lines) + frame + 4)
        return lines

    def text(self) -> str:
        """Das Geheimnis selbst, ohne Zeilenumbrüche."""
        return self._value

    def createMimeDataFromSelection(self) -> QMimeData:  # Kopieren, Ziehen: ohne unsere Umbrüche
        # Das Objekt muss von Qt stammen: ein in Python erzeugtes QMimeData gehörte danach Python
        # UND der Zwischenablage und wurde beim Prozessende doppelt freigegeben (CI: Segmentation
        # fault nach bestandenen Tests). Nur reiner Text – HTML, Markdown und ODF, die Qt dazulegt,
        # enthielten die Umbrüche noch.
        data = super().createMimeDataFromSelection()
        text = data.text().replace("\n", "")  # löst zugleich Qts verzögerte Aufbereitung aus
        for fmt in data.formats():
            data.removeFormat(fmt)
        data.setText(text)
        return data


class PasswordFields(QWidget):
    """Passwort + Wiederholung mit Stärkeanzeige, optionalem Vorschlag (Passphrase oder
    Passwort, Länge wählbar wie mit ``-w``/``-n`` der CLI) und der Wahl, ob beim Bestätigen
    online gegen Datenlecks geprüft wird."""

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
        # wie die CLI (dort abschaltbar mit --offline); geprüft wird erst beim Bestätigen
        self.online = QCheckBox("Beim Bestätigen gegen bekannte Datenlecks prüfen (HIBP, online)")
        self.online.setChecked(True)
        self.online.setToolTip("Nur die ersten 5 Zeichen des SHA-1-Hashes gehen an api.pwnedpasswords.com "
                               "(k-Anonymität) – das Passwort selbst verlässt den Rechner nicht.")
        form.addRow("", self.online)
        self._suggested: str | None = None
        self.suggestion = SecretView()
        self.suggestion.setVisible(False)
        self.suggestion_hint = _plain(QLabel(""))
        self.suggestion_hint.setVisible(False)
        # Länge wie -w/-n der CLI, Grenzen aus pwgen; ein Zahlenfeld statt eines Schiebereglers
        self.words, self.length = QSpinBox(), QSpinBox()
        self.words.setRange(passgen.PASSPHRASE_MIN_WORDS, passgen.PASSPHRASE_MAX_WORDS)
        self.words.setValue(passgen.DEFAULT_WORDS)
        self.words.setSuffix(" Wörter")
        self.words.setToolTip(f"Wörter je Passphrase ({passgen.PASSPHRASE_MIN_WORDS}–{passgen.PASSPHRASE_MAX_WORDS}, "
                              "wie -w in der CLI)")
        self.length.setRange(passgen.PASSWORD_MIN_LEN, passgen.PASSWORD_MAX_LEN)
        self.length.setValue(passgen.DEFAULT_PASSWORD_LEN)
        self.length.setSuffix(" Zeichen")
        self.length.setToolTip(f"Zeichen je Passwort ({passgen.PASSWORD_MIN_LEN}–{passgen.PASSWORD_MAX_LEN}, "
                               "wie -n in der CLI)")
        if suggest:
            buttons = QWidget()
            grid = QGridLayout(buttons)
            grid.setContentsMargins(0, 0, 0, 0)
            for row, (label, kind, amount) in enumerate((("Passphrase vorschlagen", "passphrase", self.words),
                                                         ("Passwort vorschlagen", "passwort", self.length))):
                button = QPushButton(label)
                button.clicked.connect(lambda _checked=False, kind=kind: self.suggest(kind))
                grid.addWidget(button, row, 0)
                grid.addWidget(amount, row, 1)
            grid.setColumnStretch(2, 1)
            form.addRow("", buttons)
            form.addRow("", self.suggestion_hint)
            form.addRow("", self.suggestion)
        self.password.textChanged.connect(self._strength)

    def is_suggestion(self) -> bool:
        """Steht noch der unveränderte Vorschlag im Feld? Er ist zufällig – keine Prüfung nötig."""
        return bool(self.password.text()) and self.password.text() == self._suggested

    def _strength(self, text: str) -> None:
        suggested = text == self._suggested
        if not suggested:  # eigenes Passwort: der Vorschlag gilt nicht mehr – nicht stehen lassen
            self.suggestion.setVisible(False)
            self.suggestion_hint.setText("")
            self.suggestion_hint.setVisible(False)
        if not text or suggested:
            self.strength.setText("")
            return
        check = passgen.check_password(text)
        self.strength.setText("Stärke: in Ordnung" if check.ok else "Stärke: " + "; ".join(check.warnings))

    def suggest(self, kind: str = "passphrase") -> None:
        """Zufälliges Geheimnis vorschlagen: ``"passphrase"`` (so viele Wörter wie im Feld
        ``words``) oder ``"passwort"`` (Zeichen wie im Feld ``length``). Das Passwort kommt
        ohne Sonderzeichen und ohne Verwechselbares (0/O, 1/l/I) aus – ^ und ` sind auf
        deutschen Tastaturen Tottasten, und beim Abschreiben zählt jedes Zeichen; mit den
        voreingestellten 20 Zeichen hat es trotzdem gut 110 Bit."""
        secret = (passgen.generate_password(self.length.value(), symbols=False, exclude_ambiguous=True)
                  if kind == "passwort" else passgen.generate_passphrase(self.words.value()))
        self._suggested = secret.value  # str(secret) ist absichtlich geschwärzt
        self.password.setText(secret.value)
        self.confirm.setText(secret.value)
        lines = self.suggestion.show_secret(secret)
        hint = f"Vorschlag ({secret.entropy_bits:.0f} Bit) – bitte vollständig notieren (markieren und kopieren möglich"
        hint += "; die Zeilenumbrüche gehören nicht dazu):" if len(lines) > 1 else "):"
        if not secret.strong_enough:  # wie die CLI
            hint = f"Hinweis: unter {passgen.RECOMMENDED_BITS} Bit – für einen Container eher knapp.\n" + hint
        self.suggestion_hint.setText(hint)
        self.suggestion_hint.setVisible(True)
        self.suggestion.setVisible(True)
        # ganz sichtbar, ohne Scrollen – sonst übersieht man beim Abschreiben das Ende. Das Feld
        # selbst hat sofort seine Größe, ragte aber über den Dialogrand hinaus (gemessen: 48 px
        # abgeschnitten, Hinweis darüber zu niedrig) – deshalb das ganze Fenster auf seine neue
        # Wunschgröße bringen (adjustSize() vergrößert sichtbare Dialoge nicht zuverlässig).
        window = self.window()
        before = window.height()
        # Der umbrechende Hinweis bekäme sonst die Höhe für seine schmale Wunschbreite (6 statt
        # 2 Zeilen) und stünde mit Lücken darüber und darunter (Bildschirmfoto mit 40 Wörtern) –
        # also vorläufig eine Zeile, die echte Höhe erst, wenn die Breite feststeht.
        hint = self.suggestion_hint
        hint.setFixedHeight(hint.fontMetrics().lineSpacing())
        self.layout().activate()  # zuerst die eigene Ebene – sonst ist die Wunschgröße des Dialogs veraltet
        window.layout().activate()
        width = max(window.width(), window.sizeHint().width())
        window.resize(width, window.height())
        window.layout().activate()
        hint.setFixedHeight(hint.heightForWidth(hint.width()))
        self.layout().activate()  # wieder innen zuerst – sonst ist die Wunschhöhe veraltet (Dialog zu niedrig)
        window.layout().activate()
        window.resize(width, max(before, window.sizeHint().height()))

    def value(self) -> str | None:
        """Passwort oder None (mit Hinweis im Stärkefeld), wenn leer oder abweichend."""
        if not self.password.text():
            self.strength.setText("Bitte ein Passwort eingeben.")
            return None
        if self.password.text() != self.confirm.text():
            self.strength.setText("Die Passwörter stimmen nicht überein.")
            return None
        return self.password.text()


def _leak_check(password: str) -> Callable[[Monitor], passgen.PasswordCheck]:
    """Aufgabe für ``run_task``: Passwort prüfen, mit Abgleich gegen bekannte Datenlecks.
    Die Anfrage läuft in einem eigenen Thread, damit „Abbrechen“ sofort wirkt – sie selbst
    wartet bei schlechtem Netz bis zu 20 s."""
    def job(monitor: Monitor) -> passgen.PasswordCheck:
        box: dict = {}

        def ask() -> None:
            try:
                box["check"] = passgen.check_password(password, online=True)
            except BaseException as error:  # an die Aufgabe weiterreichen
                box["error"] = error
        worker = threading.Thread(target=ask, name="tres0r-hibp", daemon=True)
        worker.start()
        while worker.is_alive():
            monitor.cancel.check()
            worker.join(0.05)
        if "error" in box:
            raise box["error"]
        return box["check"]
    return job


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
        layout.addStretch()  # übrige Höhe (nach einem längeren Vorschlag) hier, nicht zwischen den Zeilen
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
        self.text.setFont(_fixed_font())
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
            self.path, dest, self.credentials, progress=m, only=only),
            "Erfolgreich entpackt", lambda r: f"{r.entries} Einträge nach {dest}")
        if result is not None:
            self.main.show_info(f"✓ Erfolgreich entpackt: {result.entries} Einträge nach {dest}")

    def verify(self) -> None:
        result = self.main.run_task("Prüfen", lambda m: container.verify(self.path, self.credentials, progress=m),
                                    "Prüfung erfolgreich", self.main.verified_text)
        if result is not None:
            self.main.show_info(f"✓ Prüfung erfolgreich – {self.main.verified_text(result)}")


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

    def _run(self, title: str, job, success: str, summary: Callable[[object], str] | None = None) -> object:
        result = self.main.run_task(title, job, success, summary)
        self.refresh()
        return result

    def _new_password(self, title: str, second_factor: bool = True) -> dict | None:
        dialog = NewPasswordDialog(self, title, second_factor)
        while True:  # „Trotzdem verwenden? – Nein“ führt zurück in den Dialog
            if not self.main.run_dialog(dialog):
                return None
            if self.main.acceptable_password(dialog.passwords):
                break
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
                keyfile=new["keyfile"], fido2=new["fido2"], progress=m),
                "Passwort hinzugefügt", _slots_text)

    def add_recovery(self) -> None:
        phrase = keys.generate_recovery().value
        if self._run("Phrase hinzufügen", lambda m: container.add_keys(
                self.path, self.credentials, recovery=phrase, progress=m),
                "Wiederherstellungsphrase hinzugefügt", _slots_text) is not None:
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
            self.path, self.credentials, recipients=[recipient], progress=m), "Empfänger hinzugefügt", _slots_text)

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
            self.path, self.credentials, k, n, progress=m), "Anteile hinzugefügt", lambda r: f"Slot {r[0]}")
        if result is not None:
            self.main.run_dialog(SecretsDialog(self, f"Anteile ({k} von {n} nötig)",
                                               [(share.label, share.text()) for share in result[1]]))

    def change_password(self) -> None:
        new = self._new_password("Passwort ändern", second_factor=False)
        if new is None:
            return
        # change_password gibt nichts zurück – "True" markiert den Erfolg
        if self._run("Passwort ändern", lambda m: container.change_password(
                self.path, self.credentials, new["password"], progress=m) or True,
                "Passwort geändert", lambda _r: "Ein zweiter Faktor bleibt bestehen."):
            self.credentials = keys.Credentials(passwords=[new["password"]], keyfiles=self.credentials.keyfiles,
                                                fido2=self.credentials.fido2)
            self.main.show_info("✓ Passwort geändert (ein zweiter Faktor bleibt bestehen).")

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
                self.path, self.credentials, slot.index, progress=m),
                "Schlüssel entfernt", lambda removed: f"Entfernt: {removed.description}")


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


class HelpDialog(QDialog):
    """Kurzanleitung: was wohin führt, dazu die Tastenkürzel dieser Plattform – aus den Aktionen
    gelesen, also unter macOS mit ⌘ und immer passend zu dem, was die Tasten tun."""

    TEXT = ("tres0r verschlüsselt Dateien und Ordner in Container (Endung .tres0r).\n\n"
            "Verschlüsseln: links eine Datei oder einen Ordner wählen (oder ins Fenster ziehen), dann "
            "„Packen …“. Das Original bleibt, wie es ist.\n\n"
            "Einen Container wählen, dann: Öffnen (Inhalt ansehen und entpacken, auch per Doppelklick), "
            "Prüfen, Anhängen, Vergleichen (mit Dateien auf der Platte) oder Schlüssel (Passwörter, "
            "Wiederherstellungsphrase …).\n\n"
            "Ohne das Passwort kommt niemand mehr an den Inhalt – auch nicht mit tres0r.")

    WIDTH = 560

    def __init__(self, main: MainWindow) -> None:
        super().__init__(main)
        self.setWindowTitle("tres0r – Kurzanleitung")
        layout = QVBoxLayout(self)
        layout.addWidget(_plain(QLabel(self.TEXT)))
        layout.addSpacing(8)
        heading = QLabel("Tastenkürzel")
        heading.setTextFormat(Qt.PlainText)
        font = heading.font()
        font.setBold(True)
        heading.setFont(font)
        layout.addWidget(heading)
        # nur das Hauptkürzel: unter Linux kennt Qt für die Hilfe zusätzlich eine eigene Help-Taste
        actions = [*main.actions_by_name.values(), main.menu_actions["help"], main.menu_actions["quit"]]
        self.rows = [(action.text().rstrip(" …"), action.shortcut().toString(QKeySequence.NativeText))
                     for action in actions]
        self.rows.append(("Abbrechen, Fenster schließen", _shortcut_text("Esc")))
        grid = QGridLayout()
        for row, (what, shortcut) in enumerate(self.rows):
            for column, text in enumerate((what, shortcut)):
                label = QLabel(text)
                label.setTextFormat(Qt.PlainText)
                grid.addWidget(label, row, column)
        grid.setColumnStretch(1, 1)
        grid.setHorizontalSpacing(24)
        layout.addLayout(grid)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        # Der umbrechende Text bekäme sonst die Höhe seiner schmalen Wunschbreite – das Fenster wäre
        # zu hoch, der Rest verteilte sich als Lücken (Stolperfalle aus CLAUDE.md): Höhe für die Breite.
        layout.activate()
        needed = layout.totalHeightForWidth(self.WIDTH)
        self.resize(self.WIDTH, needed if needed > 0 else self.sizeHint().height())


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
        self._build_menus()
        self.statusBar().showMessage(f"Ordner: {self.start}")
        self._update_actions()

    def _build_menus(self) -> None:
        """Menüleiste mit Hilfe und Beenden (Wunsch nach dem Test unter macOS: beides „für doofe“) –
        mit den Kürzeln der Plattform: Beenden Strg+Q bzw. ⌘Q (Windows kennt keins, dort Strg+Q),
        Hilfe F1 bzw. ⌘?. Unter macOS wandern „Beenden“ und „Über“ ins Programmmenü."""
        menu = self.menuBar().addMenu("&Datei")
        for name in ("pack", "open", "verify", "append", "diff", "keys"):
            menu.addAction(self.actions_by_name[name])
        menu.addSeparator()
        quit_action = QAction("Beenden", self)
        quit_action.setShortcuts(QKeySequence.keyBindings(QKeySequence.Quit) or [QKeySequence("Ctrl+Q")])
        quit_action.setMenuRole(QAction.QuitRole)
        quit_action.triggered.connect(self.close)
        menu.addAction(quit_action)
        help_menu = self.menuBar().addMenu("&Hilfe")
        guide = QAction("Kurzanleitung", self)
        guide.setShortcuts(QKeySequence.keyBindings(QKeySequence.HelpContents) or [QKeySequence("F1")])
        guide.triggered.connect(self.show_help)
        help_menu.addAction(guide)
        about = QAction("Über tres0r", self)
        about.setMenuRole(QAction.AboutRole)
        about.triggered.connect(self.show_about)
        help_menu.addAction(about)
        self.menu_actions = {"quit": quit_action, "help": guide, "about": about}  # immer verfügbar
        self.help_keys = guide.shortcut().toString(QKeySequence.NativeText)  # für Hinweistexte

    def show_help(self) -> None:
        self.run_dialog(HelpDialog(self))

    def show_about(self) -> None:
        from . import __version__
        box = QMessageBox(QMessageBox.Information, "Über tres0r",
                          f"tres0r {__version__}\n\nVerschlüsselte Container für Dateien und Ordner: Argon2id, "
                          "ChaCha20-Poly1305, Ed25519-Signaturen.\n\nLizenz: MIT", parent=self)
        box.setTextFormat(Qt.PlainText)
        self.run_dialog(box)

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
    def run_task(self, title: str, job: Callable[[Monitor], object], success: str | None = None,
                 summary: Callable[[object], str] | None = None) -> object:
        """Aufgabe mit Fortschrittsdialog; Ergebnis oder None (Fehler wurde gemeldet). Mit ``success``
        meldet der Dialog den Erfolg und bleibt offen, bis man ihn schließt (``ProgressDialog``)."""
        dialog = ProgressDialog(self, title, job, success, summary)
        self.run_dialog(dialog)
        if dialog.error is not None:
            error = dialog.error
            if isinstance(error, Cancelled):
                self.show_info("Abgebrochen – nichts wurde verändert.")
            else:
                self.show_error(describe_error(error))
            return None
        return dialog.result_value

    def acceptable_password(self, fields: PasswordFields) -> bool:
        """Neues, selbst gewähltes Passwort prüfen wie die CLI: Länge und Zeichenarten, dazu –
        wenn angehakt – der Abgleich mit bekannten Datenlecks (HIBP). Bei Schwächen oder
        übersprungenem Abgleich nachfragen; False heißt: zurück in den Dialog. Ein unveränderter
        Vorschlag ist zufällig und bleibt ungeprüft (auch nicht online)."""
        if fields.is_suggestion():
            return True
        password = fields.password.text()
        if fields.online.isChecked():
            check = self.run_task("Datenleck-Prüfung (HIBP)", _leak_check(password))
            if check is None:  # abgebrochen oder Fehler – bereits gemeldet
                return False
        else:
            check = passgen.check_password(password)
        problems = [f"{warning}." for warning in check.warnings]
        if check.hibp_error:
            problems.append(f"{check.hibp_error} – die Datenleck-Prüfung wurde übersprungen.")
        if not problems:
            return True
        if self.confirm("Hinweise zum Passwort:\n\n" + "\n".join(f"• {p}" for p in problems)
                        + "\n\nTrotzdem verwenden?"):
            return True
        fields.strength.setText(" ".join(problems))
        return False

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
            self.details.setText(f"{kind}{size}\n\nPacken mit {_shortcut_text('Ctrl+P')} – oder in das Fenster "
                                 f"ziehen. Hilfe: {self.help_keys}")
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
        while True:  # „Trotzdem verwenden? – Nein“ führt zurück in den Dialog, die Eingaben bleiben
            if not self.run_dialog(dialog):
                return
            if self.acceptable_password(dialog.passwords):
                break
        password, output = dialog.passwords.value(), Path(dialog.output.text()).expanduser()
        level, compress = dialog.level.currentData(), dialog.compress.isChecked()
        fido2 = self.token_provider() if dialog.fido2.isChecked() else None

        def job(monitor: Monitor):
            params = calibrate() if level == "auto" else LEVELS[level]
            extra = {"fido2": fido2} if fido2 is not None else {}
            return container.create(sources, output, password, params, compress=compress, progress=monitor, **extra)
        result = self.run_task("Packen", job, "Erfolgreich gepackt",
                               lambda r: f"{r.path} – {_size(r.size)}, {r.entries} Einträge")
        if result is not None:
            self.show_info(f"✓ Erfolgreich gepackt: {result.path} – {_size(result.size)}, "
                           f"{result.entries} Einträge")
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
            result = self.run_task("Prüfen", lambda m: container.verify(path, credentials, progress=m),
                                   "Prüfung erfolgreich", self.verified_text)
            if result is not None:
                self.show_info(f"✓ Prüfung erfolgreich – {self.verified_text(result)}")

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
        result = self.run_task("Anhängen", lambda m: container.append(path, sources, credentials, progress=m),
                               "Erfolgreich angehängt",
                               lambda r: f"Segment {r.segment}: {r.entries} Einträge, +{_size(r.added)}")
        if result is not None:
            self.show_info(f"✓ Erfolgreich angehängt: Segment {result.segment}, {result.entries} Einträge, "
                           f"+{_size(result.added)}")
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
