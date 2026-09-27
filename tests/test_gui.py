import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog  # noqa: E402

from tres0r import container, gui, shamir  # noqa: E402
from tres0r.keys import Credentials  # noqa: E402
from tres0r.kdf import LEVELS  # noqa: E402

from conftest import FAST, PASSWORD  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def fast_levels(monkeypatch):
    for name in LEVELS:
        monkeypatch.setitem(LEVELS, name, FAST)


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
        self.errors, self.infos, self.handlers = [], [], {}
        self.cancel_next = False
        window.run_dialog = self.run_dialog
        window.show_error = self.errors.append
        window.show_info = self.infos.append
        window.confirm = lambda text: self.handlers["confirm"](text)
        window.ask_text = lambda question, default="": self.handlers["ask_text"](question)
        window.choose_directory = lambda title: self.handlers["directory"]()
        window.choose_source = lambda title: self.handlers["source"]()
        window.request_pin = lambda: self.handlers["pin"]()

    def run_dialog(self, dialog):
        if isinstance(dialog, gui.ProgressDialog):
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
    assert not driver.errors and any("Gepackt" in i for i in driver.infos)
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
        assert field.width() >= field.fontMetrics().horizontalAdvance(phrase)  # sichtbar breit genug
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
    driver.handlers["source"] = lambda: extra
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
    assert "tres0r[gui]" in capsys.readouterr().err
