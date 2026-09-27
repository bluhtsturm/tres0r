import unicodedata

import pytest

from tres0r.exclude import JUNK_PATTERNS, ExcludeRules
from tres0r.padding import padme
from tres0r.portability import (
    KIND_CHARS,
    KIND_COLLISION,
    KIND_LONG,
    KIND_RESERVED,
    KIND_TRAILING,
    check_names,
    collision_key,
    component_problem,
    numbered_variant,
    sanitize_component,
)

NFC = lambda s: unicodedata.normalize("NFC", s)  # noqa: E731
NFD = lambda s: unicodedata.normalize("NFD", s)  # noqa: E731


# --- Portabilität -----------------------------------------------------------
@pytest.mark.parametrize(
    "name, kind",
    [
        ("CON", KIND_RESERVED),
        ("con.txt", KIND_RESERVED),
        ("nul.tar.gz", KIND_RESERVED),
        ("COM1", KIND_RESERVED),
        ("LPT\u00b9", KIND_RESERVED),
        ("a:b", KIND_CHARS),
        ("frage?", KIND_CHARS),
        ("back\\slash", KIND_CHARS),
        ("tab\tname", KIND_CHARS),
        ("ende.", KIND_TRAILING),
        ("ende ", KIND_TRAILING),
    ],
)
def test_component_problems(name, kind):
    assert component_problem(name)[0] == kind
    assert component_problem(sanitize_component(name)) is None


@pytest.mark.parametrize("name", ["normal.txt", "CONSOLE", "icon.png", "Straße", ".bashrc", "..", "a.b.c"])
def test_valid_components(name):
    assert component_problem(name) is None


def test_collisions():
    items = [
        ("P", True),
        ("P/Datei.txt", False),
        ("P/datei.txt", False),  # Groß-/Kleinschreibung
        ("P/" + NFC("ä.txt"), False),
        ("P/" + NFD("ä.txt"), False),  # Unicode-Form
        ("P/Straße", False),
        ("P/Strasse", False),  # NTFS unterscheidet das -> keine Kollision
        ("p", True),  # zwei Ordner -> werden nur zusammengelegt
        ("X", True),
        ("x", False),  # Ordner vs. Datei -> Kollision
    ]
    collisions = {(i.path, i.other) for i in check_names(items) if i.kind == KIND_COLLISION}
    assert collisions == {
        ("P/datei.txt", "P/Datei.txt"),
        ("P/" + NFD("ä.txt"), "P/" + NFC("ä.txt")),
        ("x", "X"),
    }
    assert collision_key("P/Datei.TXT") == collision_key("p/datei.txt")


def test_problem_folder_reported_once():
    items = [("a:b", True)] + [(f"a:b/datei{i}", False) for i in range(5)]
    issues = check_names(items)
    assert [(i.path, i.kind) for i in issues] == [("a:b", KIND_CHARS)]


def test_long_path():
    issues = check_names([("x/" + "a" * 250, False)])
    assert [i.kind for i in issues] == [KIND_LONG]


def test_numbered_variant():
    assert numbered_variant("bericht.pdf", 1) == "bericht (1).pdf"
    assert numbered_variant(".bashrc", 2) == ".bashrc (2)"
    assert numbered_variant("Ordner", 3) == "Ordner (3)"


# --- Ausschlussmuster -------------------------------------------------------
def test_exclude_patterns():
    rules = ExcludeRules(["*.tmp", "build/", "docs/entwurf", "/root.txt", "# Kommentar", ""])
    assert rules.matches("Projekt/a/b.tmp", False)
    assert rules.matches("Projekt/build", True)
    assert not rules.matches("Projekt/build", False)  # nur Ordner
    assert rules.matches("docs/entwurf", False)
    assert not rules.matches("x/docs/entwurf", False)  # verankert
    assert rules.matches("root.txt", False)
    assert not rules.matches("sub/root.txt", False)
    assert not rules.matches("Projekt/B.TMP", False)  # Groß-/Kleinschreibung zählt


def test_exclude_rejects_negation_and_combines(tmp_path):
    with pytest.raises(ValueError):
        ExcludeRules(["!wichtig.tmp"])
    f = tmp_path / "muster"
    f.write_text("*.log\n", encoding="utf-8")
    rules = ExcludeRules(["*.tmp"]) + ExcludeRules.from_file(f)
    assert rules.matches("a.log", False) and rules.matches("a.tmp", False)
    assert not ExcludeRules() and rules


def test_junk_rules():
    junk = ExcludeRules.junk()
    assert len(JUNK_PATTERNS) > 5
    for path, is_dir in [(".DS_Store", False), ("x/Thumbs.db", False), ("x/__pycache__", True),
                         ("~$Bericht.docx", False), (".~lock.tabelle.ods#", False)]:
        assert junk.matches(path, is_dir), path
    assert not junk.matches("x/wichtig.docx", False)


# --- Padmé ------------------------------------------------------------------
def test_padme_properties():
    values = [padme(n) for n in range(5000)]
    assert values == sorted(values)  # monoton
    for n in list(range(5000)) + [10**6 + 7, 2**30 + 1, 100 * 2**30 + 12345]:
        p = padme(n)
        assert p >= n and padme(p) == p  # nie kleiner, idempotent
        if n >= 1024:
            assert (p - n) / n < 0.065  # max. ca. 6,2 % ab 1 KiB, bei großen Dateien weniger


def test_padme_reduces_distinct_sizes():
    sizes = {padme(n) for n in range(2**20, 2**21)}
    assert len(sizes) < 40
