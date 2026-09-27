import asyncio
import os

import pytest

pytest.importorskip("textual")

from textual.widgets import Input, Label, Static, Tree  # noqa: E402

from tres0r import container, tui  # noqa: E402
from tres0r.errors import Cancelled  # noqa: E402
from tres0r.kdf import LEVELS  # noqa: E402

from conftest import FAST, PASSWORD  # noqa: E402


@pytest.fixture(autouse=True)
def fast_levels(monkeypatch):
    for name in LEVELS:
        monkeypatch.setitem(LEVELS, name, FAST)


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "Projekt"
    (root / "Unterordner").mkdir(parents=True)
    (root / "notiz.txt").write_text("Hallo")
    (root / "Unterordner" / "daten.bin").write_bytes(os.urandom(300_000))
    return root


def run(scenario, start):
    async def main():
        app = tui.Tres0rApp(start)
        async with app.run_test(size=(120, 40)) as pilot:
            await scenario(app, pilot)
    asyncio.run(main())


async def until(pilot, condition, timeout=30.0):
    for _ in range(int(timeout / 0.05)):
        if condition():
            return
        await pilot.pause(0.05)
    raise AssertionError("Zeitüberschreitung in der Oberfläche")


def text(app, selector) -> str:
    widget = app.screen.query_one(selector)
    return str(widget.render()) if isinstance(widget, (Label, Static)) else str(widget.value)


CLICK_PAUSE = 0.3  # Textual ignoriert Klicks ~0,2 s nach dem letzten Klick auf denselben Knopf


async def finish_progress(app, pilot) -> str:
    await until(pilot, lambda: isinstance(app.screen, tui.ProgressScreen) and app.screen.is_finished)
    outcome = text(app, "#outcome")
    await pilot.pause(CLICK_PAUSE)
    await pilot.click("#cancel")  # jetzt "Schließen"
    await pilot.pause()
    return outcome


def test_pack_with_password(project, tmp_path):
    async def scenario(app, pilot):
        app.select(project)
        assert "Ordner" in text(app, "#details")
        await pilot.press("p")
        assert isinstance(app.screen, tui.PackScreen)
        app.screen.query_one("#password", Input).value = PASSWORD
        app.screen.query_one("#confirm", Input).value = PASSWORD + "x"
        await pilot.click("#start")
        assert isinstance(app.screen, tui.PackScreen)  # abweichende Wiederholung: nichts passiert
        app.screen.query_one("#confirm", Input).value = PASSWORD
        await pilot.pause(CLICK_PAUSE)
        await pilot.click("#start")
        outcome = await finish_progress(app, pilot)
        assert "3 Einträge" in outcome or "Einträge" in outcome
        await until(pilot, lambda: not isinstance(app.screen, tui.PackScreen))
    run(scenario, tmp_path)
    out = tmp_path / "Projekt.tres0r"
    assert container.verify(out, PASSWORD).files == 2


def test_suggested_passphrase_is_the_real_one(project, tmp_path):
    shown = {}

    async def scenario(app, pilot):
        app.select(project)
        await pilot.press("p")
        await pilot.click("#suggest")
        password = app.screen.query_one("#password", Input).value
        assert password == app.screen.query_one("#confirm", Input).value
        assert "***" not in password and "Secret" not in password and len(password) > 20
        assert password in text(app, "#strength")  # angezeigt, damit man sie notieren kann
        shown["phrase"] = password
        await pilot.click("#start")
        await finish_progress(app, pilot)
    run(scenario, tmp_path)
    assert container.verify(tmp_path / "Projekt.tres0r", shown["phrase"]).files == 2


def test_open_browse_and_extract(project, tmp_path):
    out = container.create([project], tmp_path / "c.tres0r", PASSWORD, FAST).path
    dest = tmp_path / "ziel"

    async def scenario(app, pilot):
        app.select(out)
        details = text(app, "#details")
        assert "tres0r-Container" in details and "Passwort" in details
        await pilot.press("o")
        assert isinstance(app.screen, tui.UnlockScreen)
        app.screen.query_one("#password", Input).value = PASSWORD
        await pilot.click("#unlock")
        await finish_progress(app, pilot)
        await until(pilot, lambda: isinstance(app.screen, tui.BrowseScreen))
        tree = app.screen.query_one("#contents", Tree)
        labels = {str(n.label) for n in tree.root.children}
        assert labels == {"Projekt/"}
        await pilot.press("a")
        assert isinstance(app.screen, tui.PathScreen)
        app.screen.query_one("#path", Input).value = str(dest)
        await pilot.click("#ok")
        outcome = await finish_progress(app, pilot)
        assert "entpackt" in outcome
    run(scenario, tmp_path)
    assert (dest / "Projekt" / "notiz.txt").read_text() == "Hallo"


def test_extract_selection_with_glob_characters_in_name(tmp_path):
    """Fund: "Auswahl entpacken" von "Urlaub [2019].jpg" entpackte "Urlaub 2.jpg" –
    der Name ging ungeschützt als fnmatch-Muster an ``only``."""
    root = tmp_path / "Fotos"
    root.mkdir()
    (root / "Urlaub [2019].jpg").write_text("richtig")
    (root / "Urlaub 2.jpg").write_text("falsch")
    out = container.create([root], tmp_path / "f.tres0r", PASSWORD, FAST).path
    dest = tmp_path / "ziel"

    async def scenario(app, pilot):
        app.select(out)
        await pilot.press("o")
        await unlock(app, pilot)
        await finish_progress(app, pilot)
        await until(pilot, lambda: isinstance(app.screen, tui.BrowseScreen))
        tree = app.screen.query_one("#contents", Tree)
        tree.root.children[0].expand()
        await pilot.pause()
        node = next(n for n in tree.root.children[0].children if n.data == "Fotos/Urlaub [2019].jpg")
        tree.move_cursor(node)
        await pilot.press("e")
        await until(pilot, lambda: isinstance(app.screen, tui.PathScreen))
        app.screen.query_one("#path", Input).value = str(dest)
        await pilot.click("#ok")
        assert "1 Einträge" in await finish_progress(app, pilot)
    run(scenario, tmp_path)
    assert os.listdir(dest / "Fotos") == ["Urlaub [2019].jpg"]


def test_wrong_password_shows_error(project, tmp_path):
    out = container.create([project], tmp_path / "c.tres0r", PASSWORD, FAST).path

    async def scenario(app, pilot):
        app.select(out)
        await pilot.press("o")
        app.screen.query_one("#password", Input).value = "falsch"
        await pilot.click("#unlock")
        outcome = await finish_progress(app, pilot)
        assert "Falsches Passwort" in outcome
        assert not isinstance(app.screen, tui.BrowseScreen)
    run(scenario, tmp_path)


def test_cancel_during_pack(project, tmp_path, monkeypatch):
    started = {}

    def slow_create(sources, output, password, params, *, compress, progress):
        from tres0r.progress import Tracker

        tracker = Tracker(progress, "packen", 10_000)
        started["yes"] = True
        while True:  # läuft, bis abgebrochen wird
            tracker(1)
            import time
            time.sleep(0.01)

    monkeypatch.setattr(tui.container, "create", slow_create)

    async def scenario(app, pilot):
        app.select(project)
        await pilot.press("p")
        for field in ("#password", "#confirm"):
            app.screen.query_one(field, Input).value = PASSWORD
        await pilot.click("#start")
        await until(pilot, lambda: started.get("yes"))
        await pilot.pause(0.3)
        assert "Verschlüssele" in text(app, "#phase")
        await pilot.click("#cancel")
        outcome = await finish_progress(app, pilot)
        assert "Abgebrochen" in outcome
        assert isinstance(app.screen, tui.PackScreen)  # zurück im Formular, nichts gepackt
    run(scenario, tmp_path)
    assert not (tmp_path / "Projekt.tres0r").exists()
    assert Cancelled  # Import genutzt: die Abbruch-Ausnahme stammt aus dem Kern


def test_cli_without_textual(monkeypatch, capsys):
    import sys

    import tres0r

    # "from . import tui" schaut zuerst ins Paket-Attribut, dann in sys.modules – beides sperren,
    # sonst startet hier die echte Oberfläche und wartet auf Eingaben.
    monkeypatch.delattr(tres0r, "tui", raising=False)
    monkeypatch.setitem(sys.modules, "tres0r.tui", None)
    from tres0r.cli import main

    assert main(["tui"]) == 1
    assert "tres0r[tui]" in capsys.readouterr().err


def test_hostile_names_are_shown_literally(tmp_path):
    """Dateinamen mit Rich-Markup dürfen weder die Anzeige verfälschen noch abstürzen lassen."""
    root = tmp_path / "[bold]fett"  # "/" ist in Namen unmöglich, öffnende Tags aber nicht
    root.mkdir()
    for name in ("[i]kursiv", "[red]rot", "normal.txt"):
        (root / name).write_text("x")
    out = container.create([root], tmp_path / "[link=x]c.tres0r", PASSWORD, FAST).path

    async def scenario(app, pilot):
        app.select(root)
        assert "[bold]fett" in text(app, "#details")
        app.select(out)
        assert "[link=x]c.tres0r" in text(app, "#details")
        await pilot.press("o")
        app.screen.query_one("#password", Input).value = PASSWORD
        await pilot.click("#unlock")
        await finish_progress(app, pilot)
        await until(pilot, lambda: isinstance(app.screen, tui.BrowseScreen))
        tree = app.screen.query_one("#contents", Tree)
        top = tree.root.children[0]
        top.expand()
        await pilot.pause()
        assert {str(n.label) for n in top.children} == {"[i]kursiv", "[red]rot", "normal.txt"}
        await pilot.press("down", "down")
        await pilot.pause()
        assert "[bold]fett" in text(app, "#entry")
        # Titelzeilen sind reiner Text: kein sichtbarer Escape-Backslash (Fund in der Schlüsselansicht)
        await pilot.press("escape")
        await pilot.press("k")
        await unlock(app, pilot)
        await finish_progress(app, pilot)
        await until(pilot, lambda: isinstance(app.screen, tui.KeysScreen))
        assert app.screen.sub_title == "[link=x]c.tres0r – 1 Schlüssel"
    run(scenario, tmp_path)


def test_main_shortcuts_only_on_main_screen(project, tmp_path):
    async def scenario(app, pilot):
        app.select(project)
        await pilot.press("p")
        assert isinstance(app.screen, tui.PackScreen)
        await pilot.click("#suggest")  # Fokus auf einem Knopf, nicht in einem Eingabefeld
        await pilot.press("p", "o", "v")
        assert isinstance(app.screen, tui.PackScreen) and len(app.screen_stack) == 3  # Standard, Haupt, Packen
    run(scenario, tmp_path)


# --- FIDO2 mit PIN, Schlüssel, Anhängen, Vergleichen, Suchen ------------------------------
def test_pack_with_pin_token(project, tmp_path, monkeypatch):
    pytest.importorskip("fido2")
    from soft_token import SoftToken

    from tres0r import hwtoken
    from tres0r.keys import Credentials

    token = SoftToken(pin="4711")
    monkeypatch.setattr(hwtoken, "devices", lambda: [token])

    async def scenario(app, pilot):
        app.select(project)
        await pilot.press("p")
        for field in ("#password", "#confirm"):
            app.screen.query_one(field, Input).value = PASSWORD
        app.screen.query_one("#fido2").value = True
        await pilot.click("#start")
        await until(pilot, lambda: isinstance(app.screen, tui.PinScreen))  # aus dem Arbeitsthread geöffnet
        app.screen.query_one("#pin", Input).value = "4711"
        await pilot.click("#ok")
        outcome = await finish_progress(app, pilot)
        assert "Einträge" in outcome
    run(scenario, tmp_path)
    out = tmp_path / "Projekt.tres0r"
    assert container.inspect(out).slots[0].type == "passwort+fido2" and token.pin_prompts_seen == 1
    assert container.verify(out, Credentials(passwords=[PASSWORD], fido2=hwtoken.TokenProvider([token]))).files == 2


def test_pin_dialog_cancel_aborts_cleanly(project, tmp_path, monkeypatch):
    pytest.importorskip("fido2")
    from soft_token import SoftToken

    from tres0r import hwtoken

    monkeypatch.setattr(hwtoken, "devices", lambda: [SoftToken(pin="4711")])

    async def scenario(app, pilot):
        app.select(project)
        await pilot.press("p")
        for field in ("#password", "#confirm"):
            app.screen.query_one(field, Input).value = PASSWORD
        app.screen.query_one("#fido2").value = True
        await pilot.click("#start")
        await until(pilot, lambda: isinstance(app.screen, tui.PinScreen))
        await pilot.press("escape")
        outcome = await finish_progress(app, pilot)
        assert "PIN-Eingabe abgebrochen" in outcome
    run(scenario, tmp_path)
    assert not (tmp_path / "Projekt.tres0r").exists()


async def unlock(app, pilot, password=PASSWORD):
    # Knöpfe in verschachtelten Containern werden später eingehängt als das Passwortfeld
    # (Windows-CI: "#unlock" fehlte noch) – auf das vollständige Fenster warten.
    await until(pilot, lambda: isinstance(app.screen, tui.UnlockScreen) and bool(app.screen.query("#unlock")))
    app.screen.query_one("#password", Input).value = password
    await pilot.click("#unlock")


def test_key_management(project, tmp_path):
    out = container.create([project], tmp_path / "k.tres0r", PASSWORD, FAST).path
    saved = tmp_path / "geheim"

    async def scenario(app, pilot):
        app.select(out)
        await pilot.press("k")
        await unlock(app, pilot)
        await finish_progress(app, pilot)
        await until(pilot, lambda: isinstance(app.screen, tui.KeysScreen))
        keys_screen = app.screen
        # weiteres Passwort
        await pilot.press("n")
        for field in ("#password", "#confirm"):
            app.screen.query_one(field, Input).value = "zweites-passwort"
        await pilot.click("#ok")
        assert "Slot 1" in await finish_progress(app, pilot)
        # Wiederherstellungsphrase: Geheimnis-Fenster, als Datei speichern
        await pilot.press("w")
        await finish_progress(app, pilot)
        await until(pilot, lambda: isinstance(app.screen, tui.SecretsScreen))
        phrase = app.screen.items[0][1]
        assert phrase in text(app, "#secrets")
        await pilot.click("#save")
        app.screen.query_one("#path", Input).value = str(saved)
        await pilot.click("#ok")
        await pilot.pause(0.3)
        await pilot.click("#close")
        # Anteile 2/2
        await until(pilot, lambda: app.screen is keys_screen)
        await pilot.press("s")
        app.screen.query_one("#text", Input).value = "2/2"
        await pilot.click("#ok")
        await finish_progress(app, pilot)
        await until(pilot, lambda: isinstance(app.screen, tui.SecretsScreen))
        shares = [value for _, value in app.screen.items]
        shown = text(app, "#secrets")
        from tres0r import shamir as _shamir
        for share in shares:  # angezeigt in Gruppen – genau so abgetippt muss es wieder passen
            grouped = tui.SecretsScreen.readable(share)
            assert grouped in shown and _shamir.parse_share(grouped) == _shamir.parse_share(share)
        await pilot.click("#close")
        await until(pilot, lambda: app.screen is keys_screen)
        assert keys_screen.query_one("#slots").row_count == 4
        # Passwort ändern, danach Slot 1 entfernen (mit Rückfrage)
        await pilot.press("c")
        for field in ("#password", "#confirm"):
            app.screen.query_one(field, Input).value = "neues-passwort"
        await pilot.click("#ok")
        assert "geändert" in await finish_progress(app, pilot)
        table = keys_screen.query_one("#slots")
        table.move_cursor(row=1)
        await pilot.press("x")
        await until(pilot, lambda: isinstance(app.screen, tui.ConfirmScreen))
        await pilot.click("#yes")
        assert "Entfernt" in await finish_progress(app, pilot)
        await until(pilot, lambda: app.screen is keys_screen)
        state["shares"], state["phrase"] = shares, phrase

    state = {}
    run(scenario, tmp_path)
    from tres0r import shamir
    from tres0r.keys import Credentials

    assert [s.type for s in container.inspect(out).slots] == ["passwort", "wiederherstellung", "schwellwert"]
    container.verify(out, "neues-passwort")
    container.verify(out, state["phrase"])
    container.verify(out, Credentials(shares=[shamir.parse_share(t) for t in state["shares"]]))
    stored = (saved / "geheimnis-1.txt").read_text(encoding="utf-8")
    assert state["phrase"] in stored
    if os.name == "posix":  # Windows kennt keine Unix-Rechte
        assert oct(os.stat(saved / "geheimnis-1.txt").st_mode & 0o777) == "0o600"


def test_append_diff_and_search(project, tmp_path):
    out = container.create([project], tmp_path / "Projekt.tres0r", PASSWORD, FAST).path
    extra = tmp_path / "nachtrag.txt"
    extra.write_text("neu")
    (project / "notiz.txt").write_text("Hallo Welt")  # lokale Änderung für den Vergleich

    async def scenario(app, pilot):
        app.select(out)
        await pilot.press("a")
        app.screen.query_one("#path", Input).value = str(extra)
        await pilot.click("#ok")
        await unlock(app, pilot)
        assert "Segment 1 angehängt" in await finish_progress(app, pilot)
        assert "angehängten Segmenten" in text(app, "#details")
        # Vergleich mit dem gleichnamigen Ordner (vorgeschlagen)
        await pilot.press("d")
        assert app.screen.query_one("#path", Input).value == str(project)
        await pilot.click("#ok")
        await unlock(app, pilot)
        await finish_progress(app, pilot)
        await until(pilot, lambda: isinstance(app.screen, tui.DiffScreen))
        rows = [app.screen.query_one("#changes").get_row_at(i) for i in range(app.screen.query_one("#changes").row_count)]
        assert [(str(r[0]), str(r[1])) for r in rows] == [("[yellow]geändert[/]", "Projekt/notiz.txt"),
                                                          ("[red]entfernt[/]", "nachtrag.txt")]
        await pilot.press("escape")
        # Suchen im Inhaltsbaum
        await pilot.press("o")
        await unlock(app, pilot)
        await finish_progress(app, pilot)
        await until(pilot, lambda: isinstance(app.screen, tui.BrowseScreen))
        await pilot.press("slash")
        await pilot.press(*"*.bin")
        await pilot.pause()
        tree = app.screen.query_one("#contents", Tree)
        leaves = [str(n.label) for n in tree.root.children[0].children[0].children]
        assert leaves == ["daten.bin"] and "1 von" in app.screen.sub_title
        await pilot.press("escape")  # Suche beenden
        await pilot.pause()
        assert app.screen.sub_title.endswith("Einträge") and isinstance(app.screen, tui.BrowseScreen)
    run(scenario, tmp_path)
