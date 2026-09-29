import asyncio
import os
import threading
import time

import pytest

pytest.importorskip("textual")

from textual.widgets import Input, Label, Static, Switch, Tree  # noqa: E402

from tres0r import container, keys, passgen, tui  # noqa: E402
from tres0r.errors import Cancelled, HibpUnavailable, WrongPassword  # noqa: E402
from tres0r.kdf import LEVELS  # noqa: E402

from conftest import FAST, PASSWORD  # noqa: E402


@pytest.fixture(autouse=True)
def fast_levels(monkeypatch):
    for name in LEVELS:
        monkeypatch.setitem(LEVELS, name, FAST)


@pytest.fixture(autouse=True)
def hibp(monkeypatch):
    """Kein Netz in den Tests: HIBP-Abfragen landen hier. ``pwned`` ordnet Passwörtern
    Treffer zu, ``fail`` lässt die Abfrage scheitern wie ohne Netz, ``block`` hält sie an."""
    fake = {"pwned": {}, "fail": None, "block": None, "asked": []}

    def count(password):
        fake["asked"].append(password)
        if fake["block"] is not None:
            fake["block"].wait(30)
        if fake["fail"] is not None:
            raise fake["fail"]
        return fake["pwned"].get(password, 0)
    monkeypatch.setattr(passgen, "hibp_count", count)
    yield fake
    if fake["block"] is not None:  # liegengebliebene Anfrage-Threads beenden
        fake["block"].set()
        for thread in threading.enumerate():
            if thread.name == "tres0r-hibp":
                thread.join(5)


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "Projekt"
    (root / "Unterordner").mkdir(parents=True)
    (root / "notiz.txt").write_text("Hallo")
    (root / "Unterordner" / "daten.bin").write_bytes(os.urandom(300_000))
    return root


def run(scenario, start, size=(120, 40)):
    async def main():
        app = tui.Tres0rApp(start)
        async with app.run_test(size=size) as pilot:
            await scenario(app, pilot)
    asyncio.run(main())


async def until(pilot, condition, timeout=30.0):
    for _ in range(int(timeout / 0.05)):
        if condition():
            return
        await pilot.pause(0.05)
    raise AssertionError("Zeitüberschreitung in der Oberfläche")


async def showing(app, pilot, screen_type, timeout=30.0) -> None:
    """Warten, bis ``screen_type`` oben liegt UND fertig aufgebaut ist. Ein Fenster, das
    zwischen zwei Abfragen geöffnet wird (etwa aus einem Callback), liegt schon auf dem
    Stapel, bevor ``compose`` gelaufen ist – eine sofortige Abfrage darin fand dann nichts
    (Windows-CI: ``NoMatches`` für das Label im Rückfragefenster). ``is_mounted`` setzt
    Textual erst, wenn der Inhalt eingehängt ist."""
    await until(pilot, lambda: isinstance(app.screen, screen_type) and app.screen.is_mounted, timeout)


async def shows_text(app, pilot, screen_type, selector: str, needle: str, timeout=30.0) -> None:
    """Warten, bis ``screen_type`` oben liegt und ``selector`` ``needle`` zeigt. Den Rückruf
    eines geschlossenen Fensters reiht Textual per ``call_next`` ein – der Bildschirm darunter
    liegt also schon oben, bevor der Rückruf den Text setzt (macOS-CI: „Stärke: in Ordnung“
    statt „abgebrochen“). Nur auf den Bildschirm zu warten reicht deshalb nicht."""
    await until(pilot, lambda: isinstance(app.screen, screen_type) and app.screen.is_mounted
                and needle in text(app, selector), timeout)


async def click(app, pilot, selector: str) -> None:
    """Klicken, sobald das Widget eingehängt UND ausgelegt ist, und prüfen, dass der Klick
    trifft. Pilot klickt auf ``widget.region.offset`` – vor dem Layout ist das (0, 0), der
    Klick geht dann stillschweigend ins Leere (Windows-CI: langsamer Aufbau, "#unlock"
    fehlte bzw. "OK" im Speichern-Dialog wirkte nicht)."""
    def ready() -> bool:
        found = app.screen.query(selector)
        return bool(found) and found.first().region.area > 0
    await until(pilot, ready)
    assert await pilot.click(selector), f"Klick auf {selector} hat das Ziel verfehlt"


def text(app, selector) -> str:
    widget = app.screen.query_one(selector)
    return str(widget.render()) if isinstance(widget, (Label, Static)) else str(widget.value)


CLICK_PAUSE = 0.3  # Textual ignoriert Klicks ~0,2 s nach dem letzten Klick auf denselben Knopf


async def finish_progress(app, pilot) -> str:
    await until(pilot, lambda: isinstance(app.screen, tui.ProgressScreen) and app.screen.is_finished)
    outcome = text(app, "#outcome")
    await pilot.pause(CLICK_PAUSE)
    await click(app, pilot, "#cancel")  # jetzt "Schließen"
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
        await click(app, pilot, "#start")
        assert isinstance(app.screen, tui.PackScreen)  # abweichende Wiederholung: nichts passiert
        app.screen.query_one("#confirm", Input).value = PASSWORD
        await pilot.pause(CLICK_PAUSE)
        await click(app, pilot, "#start")
        messages = []
        app.notify = lambda message, **kwargs: messages.append(message)
        outcome = await finish_progress(app, pilot)
        # Wunsch nach dem Test unter macOS: Erfolg eindeutig – eigene grüne Kopfzeile mit ✓
        assert outcome.startswith("✓ Erfolgreich gepackt\n") and "Einträge" in outcome
        await until(pilot, lambda: not isinstance(app.screen, tui.PackScreen))
        await until(pilot, lambda: any(m.startswith("✓ Erfolgreich gepackt: ") for m in messages))
    run(scenario, tmp_path)
    out = tmp_path / "Projekt.tres0r"
    assert container.verify(out, PASSWORD).files == 2


def test_suggested_passphrase_is_the_real_one(project, tmp_path):
    shown = {}

    async def scenario(app, pilot):
        app.select(project)
        await pilot.press("p")
        await click(app, pilot, "#suggest")
        password = app.screen.query_one("#password", Input).value
        assert password == app.screen.query_one("#confirm", Input).value
        assert "***" not in password and "Secret" not in password and len(password) > 20
        assert password in text(app, "#strength")  # angezeigt, damit man sie notieren kann
        shown["phrase"] = password
        await click(app, pilot, "#start")
        await finish_progress(app, pilot)
    run(scenario, tmp_path)
    assert container.verify(tmp_path / "Projekt.tres0r", shown["phrase"]).files == 2


def suggestion_lines(app) -> list[str]:
    """Die Zeilen des angezeigten Vorschlags (ohne Überschrift und Hinweis)."""
    return [line for line in text(app, "#strength").splitlines()[1:] if not line.startswith("Hinweis")]


def test_suggestion_length_can_be_chosen(project, tmp_path, hibp):
    """Wunsch aus dem Handtest von 1.1.0: die Länge wählen wie mit -w/-n der CLI – bis 40
    Wörter bzw. 128 Zeichen. Lange Vorschläge brechen nur zwischen Wörtern um, auch nach
    einer Größenänderung; ungültige Längen melden dasselbe wie die CLI."""
    chosen, messages = {}, []

    async def scenario(app, pilot):
        app.select(project)
        await pilot.press("p")
        screen = app.screen
        screen.notify = lambda message, **kwargs: messages.append(message)
        assert screen.query_one("#words", Input).value == "8" and screen.query_one("#length", Input).value == "20"
        screen.query_one("#length", Input).value = "128"
        await click(app, pilot, "#suggest-password")
        assert len(screen.query_one("#password", Input).value) == 128
        screen.query_one("#words", Input).value = "41"
        await click(app, pilot, "#suggest")
        assert messages == ["Wortanzahl muss zwischen 8 und 40 liegen."]
        assert len(screen.query_one("#password", Input).value) == 128  # nichts verändert
        screen.query_one("#words", Input).value = "40"
        await pilot.pause(CLICK_PAUSE)
        await click(app, pilot, "#suggest")
        phrase = screen.query_one("#password", Input).value
        assert len(phrase.split("-")) == 40 and screen.query_one("#confirm", Input).value == phrase
        for size in ((80, 24), (120, 40)):  # schmaler und wieder breiter: jedes Mal neu umbrochen
            await pilot.resize_terminal(*size)
            await pilot.pause(0.3)
            lines = suggestion_lines(app)
            width = screen.query_one("#strength", Label).content_size.width
            assert len(lines) > 1 and "".join(lines) == phrase
            assert not any(line.endswith("-") for line in lines) and all(len(line) <= width for line in lines)
        assert "ohne die Zeilenumbrüche" in text(app, "#strength") and "unter 80 Bit" not in text(app, "#strength")
        chosen["phrase"] = phrase
        await click(app, pilot, "#start")
        await finish_progress(app, pilot)
    run(scenario, tmp_path)
    assert hibp["asked"] == []  # Vorschläge sind zufällig: keine Abfrage
    assert container.verify(tmp_path / "Projekt.tres0r", chosen["phrase"]).files == 2


def test_short_suggestion_warns_and_bad_length_is_refused(project, tmp_path):
    """8 Zeichen sind erlaubt (wie -n 8), haben aber nur 46 Bit – derselbe Hinweis wie in der
    CLI. Leere oder zu große Längen erzeugen nichts."""
    messages = []

    async def scenario(app, pilot):
        app.select(project)
        await pilot.press("p")
        screen = app.screen
        screen.notify = lambda message, **kwargs: messages.append(message)
        screen.query_one("#length", Input).value = "8"
        await click(app, pilot, "#suggest-password")
        password = screen.query_one("#password", Input).value
        assert len(password) == 8 and suggestion_lines(app) == [password]
        assert "unter 80 Bit – für einen Container eher knapp" in text(app, "#strength")
        for bad in ("", "129"):
            screen.query_one("#length", Input).value = bad
            await pilot.pause(CLICK_PAUSE)
            await click(app, pilot, "#suggest-password")
        assert messages == ["Passwortlänge muss zwischen 8 und 128 liegen."] * 2
        assert screen.query_one("#password", Input).value == password
        field = screen.query_one("#length", Input)
        field.value = ""
        field.focus()
        await pilot.press("a", "1", "x", "2", "-", "8", "9")  # getippt: nur Ziffern, höchstens drei
        assert field.value == "128"
    run(scenario, tmp_path)


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
        await click(app, pilot, "#unlock")
        await finish_progress(app, pilot)
        await showing(app, pilot, tui.BrowseScreen)
        tree = app.screen.query_one("#contents", Tree)
        labels = {str(n.label) for n in tree.root.children}
        assert labels == {"Projekt/"}
        await pilot.press("a")
        assert isinstance(app.screen, tui.PathScreen)
        app.screen.query_one("#path", Input).value = str(dest)
        await click(app, pilot, "#ok")
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
        await showing(app, pilot, tui.BrowseScreen)
        tree = app.screen.query_one("#contents", Tree)
        tree.root.children[0].expand()
        await pilot.pause()
        node = next(n for n in tree.root.children[0].children if n.data == "Fotos/Urlaub [2019].jpg")
        tree.move_cursor(node)
        await pilot.press("e")
        await showing(app, pilot, tui.PathScreen)
        app.screen.query_one("#path", Input).value = str(dest)
        await click(app, pilot, "#ok")
        assert "1 Einträge" in await finish_progress(app, pilot)
    run(scenario, tmp_path)
    assert os.listdir(dest / "Fotos") == ["Urlaub [2019].jpg"]


def test_wrong_password_shows_error(project, tmp_path):
    out = container.create([project], tmp_path / "c.tres0r", PASSWORD, FAST).path

    async def scenario(app, pilot):
        app.select(out)
        await pilot.press("o")
        app.screen.query_one("#password", Input).value = "falsch"
        await click(app, pilot, "#unlock")
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
        await click(app, pilot, "#start")
        await until(pilot, lambda: started.get("yes"))
        await pilot.pause(0.3)
        assert "Verschlüssele" in text(app, "#phase")
        await click(app, pilot, "#cancel")
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
    assert "tres0r-crypt[tui]" in capsys.readouterr().err


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
        await click(app, pilot, "#unlock")
        await finish_progress(app, pilot)
        await showing(app, pilot, tui.BrowseScreen)
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
        await showing(app, pilot, tui.KeysScreen)
        assert app.screen.sub_title == "[link=x]c.tres0r – 1 Schlüssel"
    run(scenario, tmp_path)


def test_main_shortcuts_only_on_main_screen(project, tmp_path):
    async def scenario(app, pilot):
        app.select(project)
        await pilot.press("p")
        assert isinstance(app.screen, tui.PackScreen)
        await click(app, pilot, "#suggest")  # Fokus auf einem Knopf, nicht in einem Eingabefeld
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
        await click(app, pilot, "#start")
        await showing(app, pilot, tui.PinScreen)  # aus dem Arbeitsthread geöffnet
        app.screen.query_one("#pin", Input).value = "4711"
        await click(app, pilot, "#ok")
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
        await click(app, pilot, "#start")
        await showing(app, pilot, tui.PinScreen)
        await pilot.press("escape")
        outcome = await finish_progress(app, pilot)
        assert "PIN-Eingabe abgebrochen" in outcome
    run(scenario, tmp_path)
    assert not (tmp_path / "Projekt.tres0r").exists()


def run_detached(scenario, start, timeout=30.0):
    """``run`` in einem eigenen Thread: Endet die TUI nicht (ein Arbeitsthread läuft nach dem
    Beenden weiter), scheitert der Test nach ``timeout``, statt die Sitzung zu blockieren."""
    errors = []

    def target():
        try:
            run(scenario, start)
        except BaseException as exc:  # an den Test weiterreichen
            errors.append(exc)
    thread = threading.Thread(target=target, name="tui-test", daemon=True)
    thread.start()
    thread.join(timeout)
    assert not thread.is_alive(), "Die TUI endet nicht – ein Arbeitsthread läuft nach dem Beenden weiter"
    if errors:
        raise errors[0]


def test_quit_with_open_pin_dialog_does_not_hang(project, tmp_path, monkeypatch):
    """Beenden bei offenem PIN-Fenster: Der Arbeitsthread wartete ohne Zeitlimit auf die
    Antwort, der Prozess endete nie (CI: Windows-Job hing sechs Stunden)."""
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
        await click(app, pilot, "#start")
        await showing(app, pilot, tui.PinScreen)
        await pilot.press("ctrl+q")
    run_detached(scenario, tmp_path)
    assert [p.name for p in tmp_path.iterdir()] == ["Projekt"]  # weder Container noch Teildatei


def test_quit_during_task_cancels_it(project, tmp_path, monkeypatch):
    """Beenden während einer Aufgabe: Sie lief unsichtbar bis zum Ende weiter und hielt so
    lange das Prozessende auf. Jetzt wird sie abgebrochen wie mit „Abbrechen“."""
    stopped = []

    def endless(*args, progress, **kwargs):
        try:
            while True:
                progress.cancel.check()
                time.sleep(0.01)
        except Cancelled:
            stopped.append(True)
            raise
    monkeypatch.setattr(container, "create", endless)

    async def scenario(app, pilot):
        app.select(project)
        await pilot.press("p")
        for field in ("#password", "#confirm"):
            app.screen.query_one(field, Input).value = PASSWORD
        await click(app, pilot, "#start")
        await showing(app, pilot, tui.ProgressScreen)
        await pilot.press("ctrl+q")
    run_detached(scenario, tmp_path)
    assert stopped == [True]


def question(app) -> str:
    return str(app.screen.query_one(Label).render())


async def fill_pack(app, pilot, project, password=PASSWORD):
    app.select(project)
    await pilot.press("p")
    for field in ("#password", "#confirm"):
        app.screen.query_one(field, Input).value = password


def test_pwned_password_asks_and_stays_on_pack_screen(project, tmp_path, hibp):
    """Wie in der GUI (Befund aus dem Test unter Debian 13): Die TUI prüfte Passwörter nur
    offline und schlug nur Passphrasen vor. Jetzt HIBP wie in der CLI – bei „Nein“ bleibt
    der Packbildschirm mit allen Eingaben – und auf Wunsch ein zufälliges Passwort."""
    hibp["pwned"][PASSWORD] = 1234
    chosen = {}

    async def scenario(app, pilot):
        await fill_pack(app, pilot, project)
        await click(app, pilot, "#start")
        await showing(app, pilot, tui.ConfirmScreen)
        assert "1.234-mal in bekannten Datenlecks" in question(app) and "Trotzdem" in question(app)
        await click(app, pilot, "#no")
        await shows_text(app, pilot, tui.PackScreen, "#strength", "1.234-mal")
        assert app.screen.query_one("#password", Input).value == PASSWORD  # Eingaben bleiben
        await click(app, pilot, "#suggest-password")
        password = app.screen.query_one("#password", Input).value
        # ohne Sonderzeichen (Tottasten ^ und `) und ohne Verwechselbares – leicht abzuschreiben
        assert len(password) == passgen.DEFAULT_PASSWORD_LEN and password.isalnum()
        assert not set(password) & set("Il1O0") and password in text(app, "#strength")
        chosen["password"] = password
        await pilot.pause(CLICK_PAUSE)
        await click(app, pilot, "#start")
        await finish_progress(app, pilot)
    run(scenario, tmp_path)
    assert hibp["asked"] == [PASSWORD]  # der Vorschlag ist zufällig – keine Abfrage
    assert container.verify(tmp_path / "Projekt.tres0r", chosen["password"]).files == 2


def test_unreachable_hibp_is_mentioned(project, tmp_path, hibp):
    hibp["fail"] = HibpUnavailable("HIBP nicht erreichbar: kein Netz")

    async def scenario(app, pilot):
        await fill_pack(app, pilot, project)
        await click(app, pilot, "#start")
        await showing(app, pilot, tui.ConfirmScreen)
        assert "kein Netz" in question(app) and "übersprungen" in question(app)
        await click(app, pilot, "#yes")
        await finish_progress(app, pilot)
    run(scenario, tmp_path)
    assert container.verify(tmp_path / "Projekt.tres0r", PASSWORD).files == 2


def test_leak_check_switched_off_weak_password_still_asks(project, tmp_path, hibp):
    async def scenario(app, pilot):
        await fill_pack(app, pilot, project, "kurz")
        app.screen.query_one("#online", Switch).value = False  # wie --offline in der CLI
        await click(app, pilot, "#start")
        await showing(app, pilot, tui.ConfirmScreen)
        assert "kürzer als 12 Zeichen" in question(app)
        await click(app, pilot, "#no")
        await showing(app, pilot, tui.PackScreen)
        for field in ("#password", "#confirm"):
            app.screen.query_one(field, Input).value = PASSWORD
        await pilot.pause(CLICK_PAUSE)
        await click(app, pilot, "#start")
        await finish_progress(app, pilot)
    run(scenario, tmp_path)
    assert hibp["asked"] == []  # nichts ging ins Netz
    assert container.verify(tmp_path / "Projekt.tres0r", PASSWORD).files == 2


def test_new_password_in_key_management_is_checked(project, tmp_path, hibp):
    out = container.create([project], tmp_path / "k.tres0r", PASSWORD, FAST).path
    hibp["pwned"]["zweites-passwort"] = 7

    async def scenario(app, pilot):
        app.select(out)
        await pilot.press("k")
        await unlock(app, pilot)
        await finish_progress(app, pilot)
        await showing(app, pilot, tui.KeysScreen)
        await pilot.press("n")
        for field in ("#password", "#confirm"):
            app.screen.query_one(field, Input).value = "zweites-passwort"
        await click(app, pilot, "#ok")
        await showing(app, pilot, tui.ConfirmScreen)
        assert "7-mal" in question(app)
        await click(app, pilot, "#no")
        await showing(app, pilot, tui.NewPasswordScreen)  # bleibt offen
        for field in ("#password", "#confirm"):
            app.screen.query_one(field, Input).value = "drittes-passwort"
        await pilot.pause(CLICK_PAUSE)
        await click(app, pilot, "#ok")
        assert "Slot 1" in await finish_progress(app, pilot)
    run(scenario, tmp_path)
    assert hibp["asked"] == ["zweites-passwort", "drittes-passwort"]
    container.check_credentials(out, "drittes-passwort")
    with pytest.raises(WrongPassword):
        container.check_credentials(out, "zweites-passwort")


def test_leak_check_can_be_cancelled(project, tmp_path, hibp):
    """Die HIBP-Anfrage wartet bei schlechtem Netz bis zu 20 s – Esc muss sofort zurückführen."""
    hibp["block"] = threading.Event()

    async def scenario(app, pilot):
        await fill_pack(app, pilot, project)
        await click(app, pilot, "#start")
        await showing(app, pilot, tui.LeakCheckScreen)
        await pilot.press("escape")
        await shows_text(app, pilot, tui.PackScreen, "#strength", "abgebrochen", timeout=5)
    run(scenario, tmp_path)
    assert [p.name for p in tmp_path.iterdir()] == ["Projekt"]


def test_quit_during_leak_check_does_not_hang(project, tmp_path, hibp):
    """Beenden, während die HIBP-Anfrage hängt: Der Prozess darf nicht auf sie warten
    (Worker-Threads halten das Prozessende auf – siehe PIN-Fenster)."""
    hibp["block"] = threading.Event()

    async def scenario(app, pilot):
        await fill_pack(app, pilot, project)
        await click(app, pilot, "#start")
        await showing(app, pilot, tui.LeakCheckScreen)
        await pilot.press("ctrl+q")
    run_detached(scenario, tmp_path)
    assert [p.name for p in tmp_path.iterdir()] == ["Projekt"]


async def unlock(app, pilot, password=PASSWORD):
    await showing(app, pilot, tui.UnlockScreen)
    app.screen.query_one("#password", Input).value = password
    await click(app, pilot, "#unlock")


def test_key_management(project, tmp_path):
    out = container.create([project], tmp_path / "k.tres0r", PASSWORD, FAST).path
    saved = tmp_path / "geheim"

    async def scenario(app, pilot):
        app.select(out)
        await pilot.press("k")
        await unlock(app, pilot)
        await finish_progress(app, pilot)
        await showing(app, pilot, tui.KeysScreen)
        keys_screen = app.screen
        # weiteres Passwort
        await pilot.press("n")
        for field in ("#password", "#confirm"):
            app.screen.query_one(field, Input).value = "zweites-passwort"
        await click(app, pilot, "#ok")
        assert "Slot 1" in await finish_progress(app, pilot)
        # Wiederherstellungsphrase: Geheimnis-Fenster, als Datei speichern
        await pilot.press("w")
        await finish_progress(app, pilot)
        await showing(app, pilot, tui.SecretsScreen)
        phrase = app.screen.items[0][1]
        shown = tui.SecretsScreen.readable(phrase)  # Wörter mit Leerzeichen: bricht nur zwischen Wörtern um
        assert shown in text(app, "#secrets") and "-" not in shown
        assert keys.canonical_secret(shown) == keys.canonical_secret(phrase)
        await click(app, pilot, "#save")
        await showing(app, pilot, tui.PathScreen)
        app.screen.query_one("#path", Input).value = str(saved)
        await click(app, pilot, "#ok")
        await showing(app, pilot, tui.SecretsScreen)  # statt fester Pause
        # gespeichert wird im eingereihten Rückruf des Pfadfensters – erst danach schließen
        await until(pilot, lambda: (saved / "geheimnis-1.txt").exists())
        await click(app, pilot, "#close")
        # Anteile 2/2
        await until(pilot, lambda: app.screen is keys_screen)
        await pilot.press("s")
        app.screen.query_one("#text", Input).value = "2/2"
        await click(app, pilot, "#ok")
        await finish_progress(app, pilot)
        await showing(app, pilot, tui.SecretsScreen)
        shares = [value for _, value in app.screen.items]
        shown = text(app, "#secrets")
        from tres0r import shamir as _shamir
        for share in shares:  # angezeigt in Gruppen – genau so abgetippt muss es wieder passen
            grouped = tui.SecretsScreen.readable(share)
            assert grouped in shown and _shamir.parse_share(grouped) == _shamir.parse_share(share)
        await click(app, pilot, "#close")
        await until(pilot, lambda: app.screen is keys_screen)
        assert keys_screen.query_one("#slots").row_count == 4
        # Passwort ändern, danach Slot 1 entfernen (mit Rückfrage)
        await pilot.press("c")
        for field in ("#password", "#confirm"):
            app.screen.query_one(field, Input).value = "neues-passwort"
        await click(app, pilot, "#ok")
        assert "geändert" in await finish_progress(app, pilot)
        table = keys_screen.query_one("#slots")
        table.move_cursor(row=1)
        await pilot.press("x")
        await showing(app, pilot, tui.ConfirmScreen)
        await click(app, pilot, "#yes")
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


def test_keys_for_raw_container_keep_level(tmp_path):
    """Fund: "k" entsperrte über list_contents – Rohdaten-Container (encrypt, geschützte
    Identitätsdateien) wurden abgelehnt; "+Passwort" nahm pauschal Stufe "normal"."""
    import io

    from tres0r.kdf import KdfParams

    strong = KdfParams(memory_kib=16 * 1024, iterations=2, lanes=1)
    raw = tmp_path / "roh.tres0r"
    with container.atomic_output(raw) as out:
        container.encrypt_stream(io.BytesIO(b"daten"), out, PASSWORD, strong)

    async def scenario(app, pilot):
        app.select(raw)
        await pilot.press("k")
        await unlock(app, pilot)
        assert "Slot 0" in await finish_progress(app, pilot)
        await showing(app, pilot, tui.KeysScreen)
        await pilot.press("n")
        await showing(app, pilot, tui.NewPasswordScreen)
        for field in ("#password", "#confirm"):
            app.screen.query_one(field, Input).value = "zweites-passwort"
        await click(app, pilot, "#ok")
        assert "Slot 1" in await finish_progress(app, pilot)
    run(scenario, tmp_path)
    slots = container.inspect(raw).slots
    assert len(slots) == 2 and slots[1].description == slots[0].description
    container.check_credentials(raw, "zweites-passwort")


def test_append_diff_and_search(project, tmp_path):
    out = container.create([project], tmp_path / "Projekt.tres0r", PASSWORD, FAST).path
    extra = tmp_path / "nachtrag.txt"
    extra.write_text("neu")
    (project / "notiz.txt").write_text("Hallo Welt")  # lokale Änderung für den Vergleich

    async def scenario(app, pilot):
        app.select(out)
        await pilot.press("a")
        app.screen.query_one("#path", Input).value = str(extra)
        await click(app, pilot, "#ok")
        await unlock(app, pilot)
        assert "Segment 1 angehängt" in await finish_progress(app, pilot)
        await shows_text(app, pilot, tui.MainScreen, "#details", "angehängten Segmenten")
        # Vergleich mit dem gleichnamigen Ordner (vorgeschlagen)
        await pilot.press("d")
        assert app.screen.query_one("#path", Input).value == str(project)
        await click(app, pilot, "#ok")
        await unlock(app, pilot)
        await finish_progress(app, pilot)
        await showing(app, pilot, tui.DiffScreen)
        rows = [app.screen.query_one("#changes").get_row_at(i) for i in range(app.screen.query_one("#changes").row_count)]
        assert [(str(r[0]), str(r[1])) for r in rows] == [("[yellow]geändert[/]", "Projekt/notiz.txt"),
                                                          ("[red]entfernt[/]", "nachtrag.txt")]
        await pilot.press("escape")
        # Suchen im Inhaltsbaum
        await pilot.press("o")
        await unlock(app, pilot)
        await finish_progress(app, pilot)
        await showing(app, pilot, tui.BrowseScreen)
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


def test_error_texts_are_readable():
    """OSError ist erwartbar (Rechte, voller Datenträger): Meldung mit Pfad statt
    "Unerwarteter Fehler: PermissionError(13, …)" – wie in der GUI."""
    assert tui._describe_error(PermissionError(13, "Keine Berechtigung", "/ziel")) == "Keine Berechtigung: /ziel"
    assert tui._describe_error(OSError("kaputt")) == "kaputt"
    assert tui._describe_error(ValueError("x")).startswith("Unerwarteter Fehler")


# --- Erfolg, Hilfe und Beenden, Darstellung (Wünsche und Befunde aus dem Test unter macOS) ------------
def test_success_is_unmistakable_and_the_bar_is_visible(project, tmp_path):
    """Bildschirmfoto nach dem Packen: nur „100%“, der Balken selbst fehlte – die ID "bar" traf auch
    Textuals inneren Balken, dessen Rand schob ihn aus der einzeiligen Leiste. Und der Erfolg war von
    den Fortschrittszeilen nicht zu unterscheiden."""
    out = tmp_path / "p.tres0r"

    async def scenario(app, pilot):
        app.push_screen(tui.ProgressScreen(
            "Packen", lambda monitor: container.create([project], out, PASSWORD, FAST, progress=monitor),
            lambda r: f"{r.path} – {r.entries} Einträge", "Erfolgreich gepackt"))
        await until(pilot, lambda: isinstance(app.screen, tui.ProgressScreen) and app.screen.is_finished)
        screen = app.screen
        assert text(app, "#outcome").startswith("✓ Erfolgreich gepackt\n")
        assert screen.query_one("#box").has_class("-ok")
        # „Verschlüssele …“ und die letzte Datei sind überholt
        assert not screen.query_one("#phase").display and not screen.query_one("#item").display
        bar = screen.query_one("#progress").query_one("Bar")  # Textuals innerer Balken (per Typname)
        await until(pilot, lambda: screen.get_widget_at(bar.region.x, bar.region.y)[0] is bar)
        assert "━" in app.export_screenshot()
    run(scenario, tmp_path)


def test_failure_and_cancel_are_marked_and_escape_works(tmp_path):
    """Fehler rot mit ✗, Abbruch gelb; Esc bricht eine laufende Aufgabe ab und schließt danach."""
    stopped = []

    def wrong(monitor):
        raise WrongPassword("Falsches Passwort oder falscher Schlüssel.")

    def endless(monitor):
        try:
            while True:
                monitor.cancel.check()
                time.sleep(0.01)
        except Cancelled:
            stopped.append(True)
            raise

    async def scenario(app, pilot):
        app.push_screen(tui.ProgressScreen("Öffnen", wrong, str, "Erfolgreich geöffnet"))
        await until(pilot, lambda: isinstance(app.screen, tui.ProgressScreen) and app.screen.is_finished)
        assert text(app, "#outcome").startswith("✗ Fehlgeschlagen: Falsches Passwort")
        assert app.screen.query_one("#box").has_class("-failed")
        assert not app.screen.query_one("#progress").display  # unbestimmt: nicht weiterwandern lassen
        await pilot.press("escape")  # schließt wie „Schließen“
        await until(pilot, lambda: not isinstance(app.screen, tui.ProgressScreen))
        app.push_screen(tui.ProgressScreen("Packen", endless, str, "Erfolgreich gepackt"))
        await showing(app, pilot, tui.ProgressScreen)
        await pilot.press("escape")  # bricht ab
        await until(pilot, lambda: app.screen.is_finished)
        assert stopped == [True] and text(app, "#outcome").startswith("Abgebrochen – nichts wurde verändert")
        assert app.screen.query_one("#box").has_class("-cancelled")
    run(scenario, tmp_path)


def test_help_with_question_mark_h_and_f1(project, tmp_path):
    """Wunsch nach dem Test unter macOS: Hilfe „für doofe“ – ?, h und F1 öffnen sie, Esc oder dieselbe
    Taste schließt sie. Sie nennt die Tasten der Ansicht darunter, auch ausgeblendete wie r."""
    async def scenario(app, pilot):
        app.select(project)
        for key in ("question_mark", "h", "f1"):
            await pilot.press(key)
            await showing(app, pilot, tui.HelpScreen)
            shown = dict(app.screen.rows())
            assert shown["p"].startswith("Datei oder Ordner") and "r" in shown and "q" not in shown
            await pilot.press("escape" if key == "question_mark" else key)
            await showing(app, pilot, tui.MainScreen)
        assert "Hilfe" in text(app, "#details") and "beenden" in text(app, "#details")
    run(scenario, tmp_path)


def test_q_quits_but_is_a_letter_in_input_fields(project, tmp_path):
    """q beendet. In Eingabefeldern sind q, h und ? Zeichen – deshalb liegt beim Packen der Fokus gleich
    im Passwortfeld (vorher auf dem Formular: ein q am Anfang des Passworts hätte tres0r beendet)."""
    async def scenario(app, pilot):
        quits = []
        app.exit = lambda *args, **kwargs: quits.append(True)
        try:
            app.select(project)
            await pilot.press("p")
            await showing(app, pilot, tui.PackScreen)
            assert app.focused.id == "password"
            await pilot.press("q", "h", "question_mark")
            assert app.screen.query_one("#password", Input).value == "qh?" and not quits
            await pilot.press("f1")  # Hilfe geht auch beim Tippen
            await showing(app, pilot, tui.HelpScreen)
            await pilot.press("escape")
            await showing(app, pilot, tui.PackScreen)
            await pilot.press("escape")
            await showing(app, pilot, tui.MainScreen)
            await pilot.press("q")
            assert quits == [True]
        finally:
            del app.exit
    run(scenario, tmp_path)


def test_footer_fits_80_columns_with_help_and_quit_first(project, tmp_path):
    """Textual schneidet die Fußzeile rechts ab: Hilfe und Beenden stehen vorn, und bei 80 Spalten
    passt jede Ansicht ganz hinein (die Schlüsselansicht war schon vorher zu breit)."""
    from textual.widgets import Footer
    out = container.create([project], tmp_path / "f.tres0r", PASSWORD, FAST).path

    async def footer_shows(app, pilot, screen_type, expected_start):
        await showing(app, pilot, screen_type)

        def keys_shown():
            return [(k.key_display, k.description) for k in app.screen.query_one(Footer).query("FooterKey")]
        await until(pilot, lambda: keys_shown()[:len(expected_start)] == expected_start)
        keys = list(app.screen.query_one(Footer).query("FooterKey"))
        assert all(k.region.right <= 80 for k in keys), [(k.description, k.region) for k in keys]

    async def scenario(app, pilot):
        app.select(out)
        await footer_shows(app, pilot, tui.MainScreen, [("?", "Hilfe"), ("q", "Beenden")])
        await pilot.press("o")
        await unlock(app, pilot)
        await finish_progress(app, pilot)
        await footer_shows(app, pilot, tui.BrowseScreen, [("?", "Hilfe"), ("q", "Beenden")])
        await pilot.press("escape")
        await pilot.press("k")
        await unlock(app, pilot)
        await finish_progress(app, pilot)
        await footer_shows(app, pilot, tui.KeysScreen, [("?", "Hilfe"), ("q", "Beenden")])
        await pilot.press("escape")
        app.select(project)
        await pilot.press("p")  # im Passwortfeld: F1 statt ?, kein q
        await footer_shows(app, pilot, tui.PackScreen, [("F1", "Hilfe"), ("esc", "Zurück")])
    run(scenario, tmp_path, size=(80, 24))


def test_ctrl_c_explains_quitting_in_german(tmp_path):
    """Strg+C beendet Textual-Programme nicht – der Hinweis dazu kam auf Englisch."""
    async def scenario(app, pilot):
        messages = []
        app.notify = lambda message, **kwargs: messages.append(message)
        await pilot.press("ctrl+c")
        await until(pilot, lambda: bool(messages))
        assert messages[0].startswith("Beenden mit q") and "Strg+Q" in messages[0]
    run(scenario, tmp_path)


def test_look_findings_from_macos(project, tmp_path):
    """Bildschirmfotos unter macOS (Tahoe 26.7): Der Knopf mit dem Fokus hatte einen weißen Kasten
    (Textual invertiert die Beschriftung), die Scrollleiste eine schwarze Spur neben dem grauen
    Dateibaum, Fenster reichten bis zum Bildschirmrand, die Trennlinie der Details war nur so hoch
    wie ihr Text."""
    from textual.color import Color

    async def scenario(app, pilot):
        app.select(project)
        files, details = app.screen.query_one("#files"), app.screen.query_one("#details")
        assert files.styles.scrollbar_background == Color.parse(app.get_css_variables()["surface"])
        assert details.region.height == files.region.height
        app.push_screen(tui.ConfirmScreen("Wirklich?"))
        await showing(app, pilot, tui.ConfirmScreen)
        yes = app.screen.query_one("#yes")
        yes.focus()
        await until(pilot, lambda: bool(yes.styles.text_style.underline))
        assert not yes.styles.text_style.reverse
        assert app.screen.query_one("#box").region.height < 15  # kompakt – der Bildschirm hat 40 Zeilen
    run(scenario, tmp_path)


def test_recovery_phrase_wraps_only_between_words(tmp_path):
    """Die Phrase brach bei 80 Spalten mitten im Wort um ("vertiefe⏎n-strom") – beim Abschreiben
    eine Falle. Jetzt wie in der GUI: Leerzeichen zwischen den Wörtern (entsperrt genauso)."""
    from textual.geometry import Region
    phrase = keys.generate_recovery().value

    async def scenario(app, pilot):
        app.push_screen(tui.SecretsScreen("Wiederherstellungsphrase", [("Phrase", phrase)]))
        await showing(app, pilot, tui.SecretsScreen)
        widget = app.screen.query_one("#secrets")
        await until(pilot, lambda: widget.size.height > 2)
        lines = [strip.text for strip in widget.render_lines(Region(0, 0, widget.size.width, widget.size.height))]
        assert [word for line in lines for word in line.split()] == ["Phrase:"] + phrase.split("-")
    run(scenario, tmp_path, size=(80, 24))

