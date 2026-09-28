# Mitmachen

## Einrichten

```bash
git clone https://github.com/bluhtsturm/tres0r && cd tres0r
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,zstd,tui,gui,fido2,mount]" pyflakes
```

Für alle Tests unter Linux zusätzlich: `libfuse2t64` (Einhängen), `groff-base` und
`zsh` (Doku-Tests). GUI-Tests laufen ohne Bildschirm mit `QT_QPA_PLATFORM=offscreen`.

## Vor jedem Commit

```bash
python -m pyflakes $(git ls-files '*.py' | grep -v '^tres0r/pwgen.py$')
python -m pytest -q
TRES0R_TEST_CPUS=4 python -m pytest -q     # Mehrkern-Pfade (Hintergrund-Dekodierer, Worker)
```

## Regeln

* **Format:** `FORMAT.md` ist als Spezifikation 1.0 eingefroren. Änderungen nur
  rückwärtskompatibel über neue Werte (Abschnitt 13) – und immer zusammen mit
  Spezifikation, Referenz-Leser (`tests/reference_decoder.py`, darf nichts aus
  tres0r importieren) und einem Testvektor (`tests/vectors/generate.py`).
  Reproduzierbare Vektoren dürfen sich nie ändern.
* **Öffentliche API:** was in `API.md` steht, bleibt in 1.x stabil. Nach bewussten
  Ergänzungen `python tests/api_surface.py --update` und den Grund im CHANGELOG
  nennen. Jeder Parameter einer öffentlichen Funktion muss dokumentiert sein
  (Docstring oder `docgen.PARAMETERS`) – ein Test erzwingt das.
* **Erzeugte Dateien:** `man/`, `completions/` und `API.md` kommen aus
  `python -m tres0r.docgen`; ein Test prüft, dass sie aktuell sind.
* **`tres0r/pwgen.py`** ist ein unverändertes Original (Test mit Prüfsumme);
  Anpassungen gehören nach `tres0r/passgen.py`.
* **Oberflächen:** Text von außen (Dateinamen, Fehlermeldungen) nie als Markup
  anzeigen – in der TUI `rich.markup.escape`, in der GUI reiner Text.
* **Sprache:** Oberfläche, Meldungen und Doku auf Deutsch.

## Fuzzing

```bash
pip install -e ".[dev,zstd,fuzz]"
python fuzz/make_seeds.py
python fuzz/fuzz_container.py fuzz/corpus/container -max_total_time=300 -max_len=20000
python fuzz/fuzz_header.py fuzz/corpus/header -max_total_time=120
python fuzz/fuzz_text.py fuzz/corpus/text -max_total_time=120
```

Jeder Fund bekommt einen Regressionstest.

## Veröffentlichen

1. Version in `pyproject.toml` und `tres0r/__init__.py`, CHANGELOG, `python -m tres0r.docgen`.
2. `git tag v1.0.0 && git push origin v1.0.0` – `release.yml` baut, legt eine
   GitHub-Release an und lädt nach PyPI hoch (dafür einmalig auf PyPI einen
   „Trusted Publisher“ für das Projekt `tres0r-crypt`, dieses Repository,
   `release.yml` und die Umgebung `pypi` anlegen).
