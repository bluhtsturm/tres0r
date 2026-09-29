import os
import re
import subprocess
import sys
import textwrap
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtCore import QPoint, Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QPushButton  # noqa: E402

from tres0r import container, gui, passgen, shamir  # noqa: E402
from tres0r.errors import Cancelled, HibpUnavailable, WrongPassword  # noqa: E402
from tres0r.keys import Credentials  # noqa: E402
from tres0r.kdf import LEVELS  # noqa: E402
from tres0r.progress import CancelToken, Monitor  # noqa: E402

from conftest import FAST, PASSWORD  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def fast_levels(monkeypatch):
    for name in LEVELS:
        monkeypatch.setitem(LEVELS, name, FAST)


@pytest.fixture(autouse=True)
def hibp(monkeypatch):
    """Kein Netz in den Tests: HIBP-Abfragen landen hier. ``pwned`` ordnet Passwörtern
    Treffer zu, ``fail`` lässt die Abfrage scheitern wie ohne Netz."""
    fake = {"pwned": {}, "fail": None, "asked": []}

    def count(password):
        fake["asked"].append(password)
        if fake["fail"] is not None:
            raise fake["fail"]
        return fake["pwned"].get(password, 0)
    monkeypatch.setattr(passgen, "hibp_count", count)
    return fake


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "Projekt"
    (root / "Unter").mkdir(parents=True)
    (root / "notiz.txt").write_text("Hallo")
    (root / "Unter" / "daten.bin").write_bytes(os.urandom(300_000))
    return root


class Driver:
    """Ersetzt Dialoge und Meldungen des Hauptfensters – Abläufe ohne Bildschirm."""

    def __init__(self, app, window):
        self.app, self.window = app, window
        self.errors, self.infos, self.handlers, self.progress = [], [], {}, []
        self.cancel_next = False
        window.run_dialog = self.run_dialog
        window.show_error = self.errors.append
        window.show_info = self.infos.append
        window.confirm = lambda text: self.handlers["confirm"](text)
        window.ask_text = lambda question, default="": self.handlers["ask_text"](question)
        window.choose_directory = lambda title: self.handlers["directory"]()
        self.starts = []  # vorgeschlagene Startordner der Auswahldialoge
        window.choose_source = lambda title, start=None: self.starts.append(start) or self.handlers["source"]()
        window.choose_sources = lambda title, start=None: self.starts.append(start) or self.handlers["sources"]()
        window.request_pin = lambda: self.handlers["pin"]()

    def run_dialog(self, dialog):
        if isinstance(dialog, gui.ProgressDialog):
            self.progress.append(dialog)
            dialog.show()
            deadline = time.monotonic() + 60
            cancelled = False
            while dialog.running:
                self.app.processEvents()
                if self.cancel_next and not cancelled and dialog.phase.text().startswith("Verschlüssele"):
                    dialog.cancel_button.click()
                    cancelled = True
                assert time.monotonic() < deadline, "Aufgabe hängt"
                time.sleep(0.005)
            self.app.processEvents()
            dialog.close()
            return dialog.error is None
        handler = self.handlers[type(dialog).__name__]
        result = handler(dialog)
        dialog.close()
        return result


def make(app, tmp_path):
    window = gui.MainWindow(tmp_path)
    return window, Driver(app, window)


def fill_passwords(fields, password=PASSWORD):
    fields.password.setText(password)
    fields.confirm.setText(password)


def unlock_with(password=PASSWORD, fido2=False):
    def handler(dialog):
        dialog.password.setText(password)
        dialog.fido2.setChecked(fido2)
        return True
    return handler


def test_pack_and_mismatch(app, tmp_path, project):
    window, driver = make(app, tmp_path)

    def pack_dialog(dialog):
        dialog.passwords.password.setText(PASSWORD)
        dialog.passwords.confirm.setText("anders")
        dialog._accept()
        assert dialog.result() != QDialog.Accepted and "stimmen nicht" in dialog.passwords.strength.text()
        dialog.passwords.confirm.setText(PASSWORD)
        dialog.compress.setChecked(True)
        dialog._accept()
        return dialog.result() == QDialog.Accepted
    driver.handlers["PackDialog"] = pack_dialog
    window.select(project)
    window.pack()
    out = tmp_path / "Projekt.tres0r"
    assert not driver.errors and any(i.startswith("✓ Erfolgreich gepackt: ") for i in driver.infos)
    assert container.verify(out, PASSWORD).files == 2
    assert window.info is not None and "tres0r-Container" in window.details.text()

    from PySide6.QtCore import QLocale
    QLocale.setDefault(QLocale(QLocale.German))


def test_suggested_passphrase_is_real_and_fully_shown(app, tmp_path, project):
    window, driver = make(app, tmp_path)
    shown = {}

    def pack_dialog(dialog):
        dialog.show()
        app.processEvents()
        dialog.passwords.suggest()
        app.processEvents()
        phrase = dialog.passwords.password.text()
        assert "***" not in phrase and len(phrase) > 20
        field = dialog.passwords.suggestion  # einzeilig, markierbar – kein mehrdeutiger Umbruch
        assert field.text() == phrase and field.isReadOnly() and not field.isHidden()
        assert field.width() >= field.fontMetrics().horizontalAdvance(phrase)  # breit genug …
        # … und ganz im Dialog (Fund per Bildschirmfoto: das Feld ragte 48 px über den Rand,
        # das Ende der Phrase war abgeschnitten; der Hinweis darüber war zu niedrig)
        assert field.mapTo(dialog, QPoint(field.width(), 0)).x() <= dialog.width()
        hint = dialog.passwords.suggestion_hint
        assert hint.height() >= hint.heightForWidth(hint.width())
        shown["phrase"] = phrase
        return True
    driver.handlers["PackDialog"] = pack_dialog
    window.pack([project])
    assert container.verify(tmp_path / "Projekt.tres0r", shown["phrase"]).files == 2


def test_open_search_extract_and_wrong_password(app, tmp_path, project):
    out = container.create([project], tmp_path / "c.tres0r", PASSWORD, FAST).path
    window, driver = make(app, tmp_path)
    window.select(out)
    driver.handlers["UnlockDialog"] = unlock_with("falsch")
    window.open()
    assert any("Falsches Passwort" in e for e in driver.errors) and not window.windows
    driver.handlers["UnlockDialog"] = unlock_with()
    window.open()
    browse = window.windows[-1]
    assert set(browse.items) == {"Projekt", "Projekt/notiz.txt", "Projekt/Unter", "Projekt/Unter/daten.bin"}
    browse.search.setText("*.bin")
    visible = {k for k, item in browse.items.items() if not item.isHidden()}
    assert visible == {"Projekt", "Projekt/Unter", "Projekt/Unter/daten.bin"}
    browse.search.setText("")
    driver.handlers["directory"] = lambda: tmp_path / "ziel"
    browse.items["Projekt/notiz.txt"].setSelected(True)
    browse.extract_selected()
    assert (tmp_path / "ziel" / "Projekt" / "notiz.txt").read_text() == "Hallo"
    assert not (tmp_path / "ziel" / "Projekt" / "Unter").exists()
    browse.verify()
    assert any("Intakt" in i for i in driver.infos)
    browse.close()


def test_extract_selection_with_glob_characters_in_name(app, tmp_path):
    """Fund: "Urlaub [2019].jpg" auswählen entpackte "Urlaub 2.jpg" (Name als fnmatch-Muster)."""
    root = tmp_path / "Fotos"
    root.mkdir()
    (root / "Urlaub [2019].jpg").write_text("richtig")
    (root / "Urlaub 2.jpg").write_text("falsch")
    (root / "a*b.txt").write_text("stern")
    (root / "axxb.txt").write_text("fremd")
    out = container.create([root], tmp_path / "f.tres0r", PASSWORD, FAST).path
    window, driver = make(app, tmp_path)
    window.select(out)
    driver.handlers["UnlockDialog"] = unlock_with()
    window.open()
    browse = window.windows[-1]
    driver.handlers["directory"] = lambda: tmp_path / "ziel"
    for name in ("Fotos/Urlaub [2019].jpg", "Fotos/a*b.txt"):
        browse.items[name].setSelected(True)
    browse.extract_selected()
    assert sorted(os.listdir(tmp_path / "ziel" / "Fotos")) == ["Urlaub [2019].jpg", "a*b.txt"]
    browse.close()


def test_cancel_leaves_nothing(app, tmp_path, project, monkeypatch):
    def slow_create(sources, output, password, params, *, compress, progress):
        from tres0r.progress import Tracker

        tracker = Tracker(progress, "packen", 10_000)
        while True:
            tracker(1)
            time.sleep(0.01)
    monkeypatch.setattr(gui.container, "create", slow_create)
    window, driver = make(app, tmp_path)
    driver.handlers["PackDialog"] = lambda d: (fill_passwords(d.passwords), True)[1]
    driver.cancel_next = True
    window.pack([project])
    assert any("Abgebrochen" in i for i in driver.infos) and not driver.errors
    assert not (tmp_path / "Projekt.tres0r").exists()


def test_key_management(app, tmp_path, project):
    out = container.create([project], tmp_path / "k.tres0r", PASSWORD, FAST).path
    window, driver = make(app, tmp_path)
    window.select(out)
    driver.handlers["UnlockDialog"] = unlock_with()
    secrets = []

    def secrets_dialog(dialog):
        secrets.append([value for _, value in dialog.items])
        for value in secrets[-1]:  # vollständig und so abgetippt wieder gültig
            shown = gui.SecretsDialog.readable(value)
            assert shown in dialog.text.toPlainText()
            if value.startswith("tres0r-teil-"):
                assert shamir.parse_share(shown) == shamir.parse_share(value)
        if len(secrets) == 1:
            assert dialog.save(tmp_path / "geheim") is not None
        return True
    driver.handlers["SecretsDialog"] = secrets_dialog
    driver.handlers["confirm"] = lambda text: True
    driver.handlers["ask_text"] = lambda question: "2/2"

    def new_password(dialog):
        fill_passwords(dialog.passwords, driver.next_password)
        dialog._accept()
        return dialog.result() == QDialog.Accepted
    driver.handlers["NewPasswordDialog"] = new_password

    def keys_dialog(dialog):
        driver.next_password = "zweites-passwort"
        dialog.add_password()
        dialog.add_recovery()
        dialog.add_shares()
        driver.next_password = "neues-passwort"
        dialog.change_password()
        assert dialog.table.rowCount() == 4
        dialog.table.selectRow(1)
        dialog.remove()
        assert dialog.table.rowCount() == 3
        return True
    driver.handlers["KeysDialog"] = keys_dialog
    window.keys()
    assert not driver.errors, driver.errors
    assert [s.type for s in container.inspect(out).slots] == ["passwort", "wiederherstellung", "schwellwert"]
    container.verify(out, "neues-passwort")
    container.verify(out, secrets[0][0])
    container.verify(out, Credentials(shares=[shamir.parse_share(t) for t in secrets[1]]))
    assert secrets[0][0] in (tmp_path / "geheim" / "geheimnis-1.txt").read_text(encoding="utf-8")


def test_append_and_diff(app, tmp_path, project):
    out = container.create([project], tmp_path / "Projekt.tres0r", PASSWORD, FAST).path
    extra = tmp_path / "Nachtrag"
    extra.mkdir()
    (extra / "neu.txt").write_text("neu")
    (project / "notiz.txt").write_text("Hallo Welt")
    window, driver = make(app, tmp_path)
    window.select(out)
    driver.handlers["UnlockDialog"] = unlock_with()
    driver.handlers["sources"] = lambda: [extra]
    window.append()
    assert any("Segment 1" in i for i in driver.infos) and "angehängten Segmenten" in window.details.text()
    rows = []

    def diff_dialog(dialog):
        rows.extend(tuple(dialog.table.item(r, c).text() for c in range(2)) for r in range(dialog.table.rowCount()))
        return True
    driver.handlers["DiffDialog"] = diff_dialog
    driver.handlers["source"] = lambda: project
    window.diff()
    assert ("geändert", "Projekt/notiz.txt") in rows and ("entfernt", "Nachtrag/neu.txt") in rows
    assert driver.starts[-1] == project  # vorgeschlagen: der gleichnamige Ordner (wie in der TUI)
    # Anhängen geht auch mit einzelnen Dateien (früher nur Ordner; der Hinweis "in das
    # Fenster ziehen" packte in Wahrheit einen neuen Container)
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    driver.handlers["sources"] = lambda: [tmp_path / "a.txt", tmp_path / "b.txt"]
    window.append()
    assert any("Segment 2" in i and "2 Einträge" in i for i in driver.infos)
    assert {"a.txt", "b.txt"} <= {e.name for e in container.list_contents(out, PASSWORD)}
    # Inhaltsfenster zeigt die Segment-Spalte, weil es angehängte Segmente gibt
    window.open()
    assert not window.windows[-1].tree.isColumnHidden(3)
    window.windows[-1].close()


def test_keys_for_raw_container_and_level_of_new_password(app, tmp_path):
    """Fund: "Schlüssel …" entsperrte über list_contents – das lehnt Rohdaten-Container
    (encrypt, geschützte Identitätsdateien) ab. Und "+ Passwort" legte pauschal Stufe
    "normal" an, auch wenn der Container stärker geschützt war."""
    import io

    from tres0r.kdf import KdfParams

    strong = KdfParams(memory_kib=16 * 1024, iterations=2, lanes=1)
    raw = tmp_path / "roh.tres0r"
    with container.atomic_output(raw) as out:
        container.encrypt_stream(io.BytesIO(b"daten"), out, PASSWORD, strong)
    window, driver = make(app, tmp_path)
    window.select(raw)
    driver.handlers["UnlockDialog"] = unlock_with()

    def new_password(dialog):
        fill_passwords(dialog.passwords, "zweites-passwort")
        dialog._accept()
        return dialog.result() == QDialog.Accepted
    driver.handlers["NewPasswordDialog"] = new_password
    driver.handlers["KeysDialog"] = lambda dialog: dialog.add_password() or True
    window.keys()
    assert not driver.errors, driver.errors
    slots = container.inspect(raw).slots
    assert len(slots) == 2 and slots[1].description == slots[0].description  # gleiche Stufe
    container.check_credentials(raw, "zweites-passwort")


def test_errors_are_readable(app, tmp_path):
    """OSError (z. B. keine Schreibrechte) ist erwartbar: Meldung mit Pfad statt
    "Unerwarteter Fehler: PermissionError(13, …)"."""
    assert gui.describe_error(PermissionError(13, "Keine Berechtigung", "/ziel")) == "Keine Berechtigung: /ziel"
    assert gui.describe_error(OSError("kaputt")) == "kaputt"
    assert gui.describe_error(ValueError("x")).startswith("Unerwarteter Fehler")
    window, driver = make(app, tmp_path)

    def job(monitor):
        raise PermissionError(13, "Keine Berechtigung", str(tmp_path / "ziel"))
    assert window.run_task("Test", job) is None
    assert driver.errors == [f"Keine Berechtigung: {tmp_path / 'ziel'}"]


def test_pack_dialog_checks_output_before_starting(app, tmp_path, project):
    dialog = gui.PackDialog(None, [project])
    fill_passwords(dialog.passwords, PASSWORD)
    for text, expected in (("", "Bitte eine Zieldatei angeben."),
                           (str(tmp_path), "ist ein Ordner"),
                           (str(tmp_path / "fehlt" / "x.tres0r"), "existiert nicht"),
                           (str(project / "notiz.txt"), "existiert bereits")):
        dialog.output.setText(text)
        dialog._accept()
        assert dialog.result() != QDialog.Accepted and expected in dialog.passwords.strength.text(), text
    dialog.output.setText(str(tmp_path / "gut.tres0r"))
    dialog._accept()
    assert dialog.result() == QDialog.Accepted


def test_secrets_saved_note_and_busy_progress(app, tmp_path):
    from tres0r.progress import ProgressEvent

    dialog = gui.SecretsDialog(None, "Phrase", [("Phrase", "eins-zwei-drei")])
    assert dialog.save(tmp_path / "ablage") == tmp_path / "ablage"
    assert str(tmp_path / "ablage") in dialog.saved_note.text()
    progress = gui.ProgressDialog(None, "Test", lambda monitor: None)
    progress._show(ProgressEvent("packen", 50, 100))
    assert progress.bar.maximum() == 1000 and progress.bar.value() == 500
    progress._show(ProgressEvent("schlüssel", 0, None))  # neue Phase ohne Gesamtgröße
    assert progress.bar.maximum() == 0  # "beschäftigt" statt eines stehengebliebenen Balkens


def test_suggestion_disappears_when_own_password_is_typed(app, project):
    """Bildschirmfoto: nach eigenem Passwort stand "Vorschlag … bitte notieren" samt Phrase
    weiter da – als würde die Phrase verwendet."""
    dialog = gui.PackDialog(None, [project])
    dialog.show()
    dialog.passwords.suggest()
    assert dialog.passwords.suggestion.isVisible() and dialog.passwords.suggestion_hint.text()
    fill_passwords(dialog.passwords, "ganz-anderes-passwort")
    assert not dialog.passwords.suggestion.isVisible() and not dialog.passwords.suggestion_hint.text()
    dialog.close()


def test_pwned_password_asks_and_leads_back_to_dialog(app, tmp_path, project, hibp):
    """Fund beim Test unter Debian 13: Die GUI prüfte Passwörter nicht gegen bekannte
    Datenlecks (nur die CLI). Jetzt wie dort – bei „Nein“ zurück in den Dialog, die
    Eingaben bleiben; ein Vorschlag ist zufällig und wird nicht abgefragt."""
    hibp["pwned"][PASSWORD] = 1234
    window, driver = make(app, tmp_path)
    rounds, questions, chosen = [], [], {}

    def pack_dialog(dialog):
        rounds.append(dialog.passwords.password.text())
        if len(rounds) == 1:
            fill_passwords(dialog.passwords)
        else:
            assert "1.234-mal in bekannten Datenlecks" in dialog.passwords.strength.text()
            dialog.passwords.suggest("passwort")
            chosen["password"] = dialog.passwords.password.text()
        dialog._accept()
        return dialog.result() == QDialog.Accepted
    driver.handlers["PackDialog"] = pack_dialog
    driver.handlers["confirm"] = lambda text: questions.append(text) or False
    window.pack([project])
    assert rounds == ["", PASSWORD]  # zweite Runde: das Eingetippte steht noch da
    assert len(questions) == 1 and "1.234-mal in bekannten Datenlecks" in questions[0]
    assert "Trotzdem verwenden?" in questions[0]
    assert hibp["asked"] == [PASSWORD] and not driver.errors
    assert container.verify(tmp_path / "Projekt.tres0r", chosen["password"]).files == 2


def test_unreachable_hibp_is_mentioned_not_skipped_silently(app, tmp_path, project, hibp):
    hibp["fail"] = HibpUnavailable("HIBP nicht erreichbar: kein Netz")
    window, driver = make(app, tmp_path)
    questions = []
    driver.handlers["PackDialog"] = lambda d: (fill_passwords(d.passwords), d._accept(),
                                               d.result() == QDialog.Accepted)[2]
    driver.handlers["confirm"] = lambda text: questions.append(text) or True
    window.pack([project])
    assert len(questions) == 1 and "kein Netz" in questions[0] and "übersprungen" in questions[0]
    assert container.verify(tmp_path / "Projekt.tres0r", PASSWORD).files == 2


def test_leak_check_can_be_switched_off_weak_password_still_asks(app, tmp_path, project, hibp):
    window, driver = make(app, tmp_path)
    questions, rounds = [], []

    def pack_dialog(dialog):
        rounds.append(1)
        dialog.passwords.online.setChecked(False)  # wie --offline in der CLI
        fill_passwords(dialog.passwords, "kurz" if len(rounds) == 1 else PASSWORD)
        dialog._accept()
        return dialog.result() == QDialog.Accepted
    driver.handlers["PackDialog"] = pack_dialog
    driver.handlers["confirm"] = lambda text: questions.append(text) or False
    window.pack([project])
    assert len(rounds) == 2 and len(questions) == 1 and "kürzer als 12 Zeichen" in questions[0]
    assert hibp["asked"] == []  # nichts ging ins Netz
    assert container.verify(tmp_path / "Projekt.tres0r", PASSWORD).files == 2


def test_password_can_be_suggested_instead_of_passphrase(app, tmp_path, project, hibp):
    """Fund beim Test unter Debian 13: Die GUI schlug nur Passphrasen vor, obwohl der
    Generator auch Passwörter kann."""
    window, driver = make(app, tmp_path)
    chosen = {}

    def pack_dialog(dialog):
        dialog.show()
        app.processEvents()
        buttons = {button.text(): button for button in dialog.findChildren(QPushButton)}
        buttons["Passphrase vorschlagen"].click()
        assert "-" in dialog.passwords.password.text()
        buttons["Passwort vorschlagen"].click()
        app.processEvents()
        password = dialog.passwords.password.text()
        # ohne Sonderzeichen (Tottasten ^ und `) und ohne Verwechselbares – leicht abzuschreiben
        assert len(password) == passgen.DEFAULT_PASSWORD_LEN and password.isalnum()
        assert not set(password) & set("Il1O0")
        assert dialog.passwords.confirm.text() == password == dialog.passwords.suggestion.text()
        assert int(re.search(r"(\d+) Bit", dialog.passwords.suggestion_hint.text()).group(1)) >= 100
        chosen["password"] = password
        dialog._accept()
        return dialog.result() == QDialog.Accepted
    driver.handlers["PackDialog"] = pack_dialog
    window.pack([project])
    assert hibp["asked"] == [] and not driver.errors
    assert container.verify(tmp_path / "Projekt.tres0r", chosen["password"]).files == 2


def test_suggestion_length_can_be_chosen_like_cli(app, tmp_path, project, hibp):
    """Wunsch aus dem Handtest von 1.1.0: die Länge wählen wie mit -w/-n der CLI – bis 40
    Wörter bzw. 128 Zeichen. Lange Vorschläge sind ganz sichtbar, brechen nie nach "-" um,
    und Kopieren liefert sie ohne die Zeilenumbrüche."""
    window, driver = make(app, tmp_path)
    chosen = {}

    def pack_dialog(dialog):
        dialog.show()
        app.processEvents()
        fields = dialog.passwords
        assert (fields.words.minimum(), fields.words.maximum(), fields.words.value()) == (8, 40, 8)
        assert (fields.length.minimum(), fields.length.maximum(), fields.length.value()) == (8, 128, 20)
        fields.length.setValue(128)
        fields.suggest("passwort")
        assert len(fields.password.text()) == 128 and fields.password.text().isalnum()
        fields.words.setValue(40)
        fields.suggest("passphrase")
        app.processEvents()
        phrase = fields.password.text()
        assert len(phrase.split("-")) == 40 and fields.confirm.text() == phrase
        view = fields.suggestion
        lines = view.toPlainText().split("\n")
        assert len(lines) > 1 and "".join(lines) == phrase == view.text()
        assert not any(line.endswith("-") for line in lines)
        # ganz sichtbar: jede Zeile in der Breite, alle in der Höhe, über den Knöpfen und im Dialog
        # (Bildschirmfoto: nach dem ersten Umbau verdeckten die Knöpfe die letzte Zeile)
        metrics = view.fontMetrics()
        assert view.viewport().width() >= max(metrics.horizontalAdvance(line) for line in lines)
        assert view.viewport().height() >= metrics.lineSpacing() * len(lines)
        bottom_right = view.mapTo(dialog, QPoint(view.width(), view.height()))
        assert bottom_right.x() <= dialog.width()
        assert bottom_right.y() <= dialog.findChild(QDialogButtonBox).geometry().top()
        hint = fields.suggestion_hint
        assert "Zeilenumbrüche gehören nicht dazu" in hint.text() and "unter 80 Bit" not in hint.text()
        assert hint.height() >= hint.heightForWidth(hint.width())
        view.selectAll()
        view.copy()
        assert QApplication.clipboard().text() == phrase
        chosen["phrase"] = phrase
        dialog._accept()
        return dialog.result() == QDialog.Accepted
    driver.handlers["PackDialog"] = pack_dialog
    window.pack([project])
    assert hibp["asked"] == [] and not driver.errors  # Vorschläge sind zufällig: keine Abfrage
    assert container.verify(tmp_path / "Projekt.tres0r", chosen["phrase"]).files == 2


def test_short_suggestion_warns_like_cli(app, project):
    """8 Zeichen sind erlaubt (wie -n 8), haben aber nur 46 Bit – derselbe Hinweis wie in der CLI."""
    dialog = gui.PackDialog(None, [project])
    dialog.show()
    fields = dialog.passwords
    fields.length.setValue(8)
    fields.suggest("passwort")
    assert len(fields.password.text()) == 8 and "unter 80 Bit" in fields.suggestion_hint.text()
    fields.length.setValue(14)
    fields.suggest("passwort")
    assert "unter 80 Bit" not in fields.suggestion_hint.text()
    fields.password.setText("eigenes-passwort")  # eigenes Passwort: der Vorschlag verschwindet
    assert fields.suggestion.isHidden() and fields.suggestion_hint.isHidden()
    dialog.close()


def test_copying_a_suggestion_survives_process_exit(tmp_path):
    """CI-Fund: Ein in Python erzeugtes QMimeData gehörte nach dem Kopieren Python und der
    Zwischenablage – beim Prozessende doppelt freigegeben (Segmentation fault, Exit 139),
    obwohl alle Tests bestanden hatten. Deshalb in einem eigenen Prozess bis zum Ende.
    Außerdem: in der Zwischenablage nur reiner Text, ohne Umbrüche (Qt legt sonst HTML,
    Markdown und ODF mit den Umbrüchen dazu)."""
    script = tmp_path / "kopieren.py"
    script.write_text(textwrap.dedent("""
        from PySide6.QtWidgets import QApplication
        from tres0r import gui, passgen

        app = QApplication([])
        view = gui.SecretView()
        secret = passgen.generate_passphrase(40)
        assert len(view.show_secret(secret)) > 1
        view.selectAll()
        view.copy()
        data = QApplication.clipboard().mimeData()
        assert data.formats() == ["text/plain"], data.formats()
        assert data.text() == secret.value
        view.deleteLater()  # Ansicht weg, Zwischenablage bleibt – wie nach dem Dialog
        app.processEvents()
        assert QApplication.clipboard().text() == secret.value
        print("fertig")
    """), encoding="utf-8")
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=120,
                            env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    assert result.returncode == 0 and "fertig" in result.stdout, (result.returncode, result.stderr[-2000:])


def test_new_password_in_key_management_is_checked_too(app, tmp_path, project, hibp):
    out = container.create([project], tmp_path / "k.tres0r", PASSWORD, FAST).path
    hibp["pwned"]["zweites-passwort"] = 7
    window, driver = make(app, tmp_path)
    window.select(out)
    driver.handlers["UnlockDialog"] = unlock_with()
    typed, questions = iter(["zweites-passwort", "drittes-passwort"]), []

    def new_password(dialog):
        fill_passwords(dialog.passwords, next(typed))
        dialog._accept()
        return dialog.result() == QDialog.Accepted
    driver.handlers["NewPasswordDialog"] = new_password
    driver.handlers["KeysDialog"] = lambda dialog: dialog.add_password() or True
    driver.handlers["confirm"] = lambda text: questions.append(text) or False
    window.keys()
    assert not driver.errors, driver.errors
    assert len(questions) == 1 and "7-mal" in questions[0]
    assert hibp["asked"] == ["zweites-passwort", "drittes-passwort"]
    container.check_credentials(out, "drittes-passwort")
    with pytest.raises(WrongPassword):
        container.check_credentials(out, "zweites-passwort")


def test_leak_check_cancels_at_once(monkeypatch):
    """Die HIBP-Anfrage wartet bei schlechtem Netz bis zu 20 s – „Abbrechen“ muss sofort wirken."""
    release = threading.Event()
    monkeypatch.setattr(passgen, "hibp_count", lambda password: release.wait(30) and 0)
    token = CancelToken()
    threading.Timer(0.2, token.cancel).start()
    started = time.monotonic()
    with pytest.raises(Cancelled):
        gui._leak_check(PASSWORD)(Monitor(cancel=token))
    assert time.monotonic() - started < 2
    release.set()  # die liegengebliebene Anfrage beenden
    for thread in threading.enumerate():
        if thread.name == "tres0r-hibp":
            thread.join(5)


def test_phrase_wraps_only_between_words_and_still_unlocks():
    """Projektregel: Phrasen nie nach "-" umbrechen (Bildschirmfoto: "besagen-⏎westseite")."""
    from tres0r import keys

    phrase = keys.generate_recovery().value
    shown = gui.SecretsDialog.readable(phrase)
    assert "-" not in shown and len(shown.split(" ")) == keys.RECOVERY_WORDS
    assert keys.canonical_secret(shown) == keys.canonical_secret(phrase)
    share = shamir.split(bytes(32), 2, 2)[0].text()
    assert shamir.parse_share(gui.SecretsDialog.readable(share)) == shamir.parse_share(share)


def test_tables_without_second_numbering(app, tmp_path, project):
    out = container.create([project], tmp_path / "t.tres0r", PASSWORD, FAST).path
    window, driver = make(app, tmp_path)
    dialog = gui.KeysDialog(window, out, Credentials(passwords=[PASSWORD]))
    assert dialog.table.columnCount() == 2 and not dialog.table.verticalHeader().isVisible()
    assert dialog.table.item(0, 1).text().startswith("Passwort")
    (project / "notiz.txt").write_text("anders")
    diff = gui.DiffDialog(window, "x", container.diff(out, [project], PASSWORD))
    assert not diff.table.verticalHeader().isVisible()
    browse = gui.BrowseWindow(window, out, Credentials(passwords=[PASSWORD]), container.list_contents(out, PASSWORD))
    assert browse.items["Projekt/notiz.txt"].toolTip(0) == "Projekt/notiz.txt"
    assert browse.tree.header().sectionResizeMode(2) == gui.QHeaderView.ResizeToContents  # Datum nie gekürzt
    assert browse.tree.isColumnHidden(3)  # keine Segmente
    for widget in (dialog, diff, browse):
        widget.close()


def test_raw_container_offers_only_what_works(app, tmp_path):
    """Bildschirmfoto: bei Rohdaten-Containern (encrypt) waren Öffnen/Anhängen/Vergleichen
    aktiv – alle scheitern zwangsläufig; ein Doppelklick führte in eine Fehlermeldung."""
    import io

    raw = tmp_path / "daten.tres0r"
    with container.atomic_output(raw) as out:
        container.encrypt_stream(io.BytesIO(b"daten"), out, PASSWORD, FAST)
    window, driver = make(app, tmp_path)
    window.select(raw)
    enabled = {name for name, action in window.actions_by_name.items() if action.isEnabled()}
    assert enabled == {"verify", "keys"} and "Datenstrom" in window.details.text()
    window._double_clicked(window.model.index(str(raw)))
    window.dropped([raw])  # weder öffnen noch erneut einpacken
    assert not driver.errors and not window.windows


def test_fido2_pin_from_worker_thread(app, tmp_path, project, monkeypatch):
    pytest.importorskip("fido2")
    from soft_token import SoftToken

    from tres0r import hwtoken

    token = SoftToken(pin="4711")
    monkeypatch.setattr(hwtoken, "devices", lambda: [token])
    window, driver = make(app, tmp_path)
    asked = []
    driver.handlers["pin"] = lambda: asked.append(1) or "4711"
    driver.handlers["PackDialog"] = lambda d: (fill_passwords(d.passwords), d.fido2.setChecked(True), True)[2]
    window.pack([project])
    out = tmp_path / "Projekt.tres0r"
    assert not driver.errors and asked == [1]
    assert container.inspect(out).slots[0].type == "passwort+fido2"


def test_hostile_names_stay_plain_text(app, tmp_path):
    root = tmp_path / "<b>fett<b>"  # "/" ist in Dateinamen unmöglich, HTML-Tags ohne "/" nicht
    root.mkdir()
    (root / "<a href='x'>link").write_text("x")
    out = container.create([root], tmp_path / "<i>c.tres0r", PASSWORD, FAST).path
    window, driver = make(app, tmp_path)
    window.select(root)
    assert window.title.textFormat() == Qt.PlainText and window.title.text() == "<b>fett<b>"
    window.select(out)
    assert window.title.text() == "<i>c.tres0r" and window.details.textFormat() == Qt.PlainText
    driver.handlers["UnlockDialog"] = unlock_with()
    window.open()
    browse = window.windows[-1]
    assert browse.items["<b>fett<b>"].text(0) == "<b>fett<b>"
    assert browse.items["<b>fett<b>/<a href='x'>link"].text(0) == "<a href='x'>link"
    browse.close()


def test_drop_folder_opens_pack_dialog(app, tmp_path, project):
    window, driver = make(app, tmp_path)
    seen = []
    driver.handlers["PackDialog"] = lambda d: seen.append(d.sources) or False
    window.dropped([project])
    assert seen == [[project]]


def test_cli_without_pyside(monkeypatch, capsys):
    import sys

    import tres0r

    monkeypatch.delattr(tres0r, "gui", raising=False)
    monkeypatch.setitem(sys.modules, "tres0r.gui", None)
    from tres0r.cli import main

    assert main(["gui"]) == 1
    assert "tres0r-crypt[gui]" in capsys.readouterr().err


# --- Erfolg, Hilfe und Beenden, Schrift (Wünsche und Befunde aus dem Test unter macOS) --------------
def test_fixed_font_is_the_platform_font(app, monkeypatch):
    """macOS meldete „Populating font family aliases took 133 ms. Replace uses of missing font family
    "Monospace" …“ – die Schrift hieß fest "monospace", die gibt es dort nicht. Jetzt die
    Festbreitenschrift der Plattform (Menlo, Consolas, DejaVu Sans Mono …). Unter Linux heißt auch
    die "monospace" (fontconfig) – deshalb prüft der Test die Herkunft, nicht nur den Namen."""
    from PySide6.QtGui import QFont, QFontDatabase, QFontInfo

    fixed = gui._fixed_font()
    assert fixed == QFontDatabase.systemFont(QFontDatabase.FixedFont) and QFontInfo(fixed).fixedPitch()
    monkeypatch.setattr(gui, "_fixed_font", lambda: QFont("Plattform-Festbreite"))
    view = gui.SecretView()
    dialog = gui.SecretsDialog(None, "Phrase", [("Phrase", "a-b-c")])
    assert view.font().family() == dialog.text.font().family() == "Plattform-Festbreite"
    dialog.close()


def test_success_stays_visible_until_closed(app):
    """Der Erfolg stand nur zehn Sekunden in der Statuszeile. Jetzt bleibt der Fortschrittsdialog
    offen: grüne Kopfzeile mit ✓, Zusammenfassung, „Schließen“ (auch Esc) – ohne ``success`` schließt
    er sich wie bisher selbst (Öffnen, Entsperren, HIBP-Prüfung)."""
    def finish(dialog):
        dialog.show()
        deadline = time.monotonic() + 30
        while dialog.running:
            app.processEvents()
            assert time.monotonic() < deadline
            time.sleep(0.005)
        app.processEvents()

    long_path = "/sehr/langer/pfad/" + "unterordner/" * 12 + "archiv.tres0r"
    dialog = gui.ProgressDialog(None, "Packen", lambda m: 42, "Erfolgreich gepackt",
                                lambda r: f"{long_path} – {r} Einträge")
    finish(dialog)
    assert dialog.isVisible() and dialog.headline.text() == "✓ Erfolgreich gepackt"
    assert dialog.outcome.text().endswith("42 Einträge") and dialog.cancel_button.text() == "Schließen"
    assert dialog.phase.isHidden() and dialog.item.isHidden() and dialog.bar.value() == dialog.bar.maximum()
    # alles sichtbar, nichts überdeckt: die umbrochene Zusammenfassung über dem Knopf, im Dialog
    outcome, button = dialog.outcome.geometry(), dialog.cancel_button.geometry()
    assert outcome.height() >= dialog.outcome.heightForWidth(outcome.width()) and outcome.bottom() < button.top()
    assert button.bottom() <= dialog.height()
    dialog.reject()  # Esc: schließt jetzt, statt abzubrechen
    assert not dialog.isVisible() and dialog.result() == QDialog.Accepted and dialog.result_value == 42

    quiet = gui.ProgressDialog(None, "Öffnen", lambda m: 7)
    finish(quiet)
    assert not quiet.isVisible() and quiet.result_value == 7


def test_pack_reports_success_in_the_dialog(app, tmp_path, project):
    window, driver = make(app, tmp_path)
    driver.handlers["PackDialog"] = lambda dialog: (dialog.passwords.password.setText(PASSWORD),
                                                    dialog.passwords.confirm.setText(PASSWORD),
                                                    dialog._accept(), dialog.result() == QDialog.Accepted)[-1]
    window.select(project)
    window.pack()
    dialog = driver.progress[-1]
    assert dialog.headline.text() == "✓ Erfolgreich gepackt" and "Projekt.tres0r" in dialog.outcome.text()
    assert any(i.startswith("✓ Erfolgreich gepackt: ") for i in driver.infos)


def test_help_about_and_quit_in_the_menu(app, tmp_path, project):
    """Wunsch „Hilfe und Beenden für doofe“ – auch in der GUI, mit den Kürzeln der Plattform."""
    from PySide6.QtGui import QAction, QKeySequence

    window, driver = make(app, tmp_path)
    window.show()
    menus = [action.text() for action in window.menuBar().actions()]
    assert menus == ["&Datei", "&Hilfe"]
    quit_action, guide, about = (window.menu_actions[name] for name in ("quit", "help", "about"))
    assert quit_action.menuRole() == QAction.QuitRole and about.menuRole() == QAction.AboutRole
    assert quit_action.shortcuts() and guide.shortcuts()  # Windows kennt kein Standardkürzel fürs Beenden
    shown = {}
    driver.handlers["HelpDialog"] = lambda dialog: shown.update(dialog.rows) or True
    driver.handlers["QMessageBox"] = lambda box: shown.update(about=box.text()) or True
    guide.trigger()
    assert shown["Packen"] == QKeySequence("Ctrl+P").toString(QKeySequence.NativeText)
    assert shown["Beenden"] and shown["Kurzanleitung"]
    about.trigger()
    assert shown["about"].startswith("tres0r ")
    window.select(project)  # der Hinweis nennt die Kürzel der Plattform (unter macOS ⌘P, nicht „Strg+P“)
    assert f"Packen mit {QKeySequence('Ctrl+P').toString(QKeySequence.NativeText)}" in window.details.text()
    quit_action.trigger()
    assert not window.isVisible()

