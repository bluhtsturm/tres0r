# CLAUDE.md – tres0r

Projektwissen für die Arbeit an diesem Repository. Kommunikation, Oberflächentexte,
Meldungen und Doku sind **deutsch**. Julian (Maintainer) erwartet ehrliche Berichte:
was getestet ist, was nicht, und Funde offen benennen.

## Was tres0r ist

Verschlüsselte Container für Dateien/Ordner/Datenströme: Argon2id + ChaCha20-Poly1305
(STREAM, 64-KiB-Chunks), bis zu 16 Keyslots, Ed25519-Signaturen, tar mit
Inhaltsverzeichnis, optional zstd. CLI, TUI (Textual), GUI (PySide6). Stand:
1.2.0 (`pyproject.toml`), Lizenz MIT. Paketname auf PyPI: `tres0r-crypt` (`tres0r`
lehnt PyPI als zu ähnlich zu `tresor` ab) – Import und Befehl bleiben `tres0r`.

## Aufbau

| Modul | Aufgabe |
|---|---|
| `container.py` | Kern-API: create/append/extract/verify/list/diff/salvage/repair/upgrade, Schlüsselverwaltung, `_NameGuard` (Entpack-Sicherheit), `_open_segments` |
| `header2.py` / `header.py` | Format v2 (Keyslots Typ 1–7, Header-MAC mit Key-Commitment) / v1 (nur lesen) |
| `stream.py` | ChaCha20-Poly1305-STREAM (`EncryptingWriter`, `DecryptingReader`) |
| `payload.py` | Blockrahmung, zstd-Frames, Index, wahlfreier Zugriff, `Prefetcher` |
| `segments.py` | angehängte Segmente: Tabelle am Ende, Journal, `Window` |
| `volumes.py` | `--split` (Teilesätze lesen/schreiben) |
| `sign.py`, `keys.py`, `shamir.py`, `hwtoken.py` | Signaturen, Schlüssel/Identitäten/Keyfiles, Schwellwert (GF(2⁸)), FIDO2 (hmac-secret) |
| `kdf.py`, `workers.py`, `progress.py` | Argon2-Stufen und `calibrate`, Hash-Worker/Threads, Fortschritt + `CancelToken` |
| `mount.py` | FUSE (`ContainerFS` ohne FUSE testbar) |
| `cli.py`, `tui.py`, `gui.py` | Oberflächen – bauen nur auf der öffentlichen API auf |
| `docgen.py` | erzeugt `man/`, `completions/`, `API.md` aus Parser bzw. Code |
| `pwgen.py` | **Julians unverändertes Original** – nie ändern (Test mit SHA-256); Anpassungen in `passgen.py` |

Öffentliche API: `tres0r.__all__` plus `keys`, `shamir`, `progress`, `errors`,
`passgen`, `hwtoken`, `mount` (`docgen.PUBLIC_MODULES`). Alles andere intern.

## Verbindliche Regeln

* **Format eingefroren** (`FORMAT.md`, Spezifikation 1.0, Abschnitt 13): nur neue Werte
  (Slot-Typen, Flag-Bits …). Jede Formatänderung = Spezifikation + Referenz-Leser
  (`tests/reference_decoder.py`, importiert nichts aus tres0r und rechnet bewusst
  anders) + Testvektor. Reproduzierbare Vektoren ändern sich nie.
* **API eingefroren:** `tests/api_surface.json`; Änderung nur bewusst mit
  `python tests/api_surface.py --update`. Jeder öffentliche Parameter dokumentiert
  (Docstring oder `docgen.PARAMETERS`).
* **Erzeugte Dateien** nach CLI-/API-Änderungen: `python -m tres0r.docgen`.
* **Sicherheit beim Entpacken:** alles über `_NameGuard`; erst in einen Staging-Ordner,
  Signatur prüfen, dann verschieben. Text von außen in TUI (`rich.markup.escape`) und
  GUI (reiner Text) nie als Markup.
* **Jeder Fund** (Fuzzing, Test, Bildschirmfoto) bekommt einen Regressionstest.
* **Branch-Schutz:** `main` nimmt nur PRs an; ein Ruleset (Settings → Rules) verlangt
  alle 9 CI-Checks unter ihren **Jobnamen** aus `ci.yml`. Wer einen Job umbenennt oder
  hinzufügt, passt das Ruleset mit an – sonst wartet jede PR auf einen Check, der nie
  kommt („Expected – Waiting for status to be reported“).

## Befehle

```bash
pip install -e ".[dev,zstd,tui,gui,fido2,mount]" pyflakes
python -m pytest -q                              # ~1 min
TRES0R_TEST_CPUS=4 python -m pytest -q           # Mehrkern-Pfade (täuscht os.cpu_count vor)
QT_QPA_PLATFORM=offscreen python -m pytest tests/test_gui.py
HYPOTHESIS_PROFILE=fuzz python -m pytest tests/test_properties.py
python -m pyflakes $(git ls-files '*.py' | grep -v '^tres0r/pwgen.py$')
python fuzz/make_seeds.py && python fuzz/fuzz_container.py fuzz/corpus/container -max_total_time=300 -max_len=20000
python -m tres0r.docgen && python tests/api_surface.py
```

Test-Helfer: `tests/conftest.py` (`FAST`-KDF, `sample_tree`, `write_raw_container(_v2)`
mit eigenem Index, Prüfung auf hängende Threads nach jedem Test),
`tests/soft_token.py` (Software-FIDO2-Token mit hmac-secret und PIN).

## Stolperfallen (alle schon einmal passiert)

* **GIL:** `hashlib` und zstd (beide Backends) geben ihn frei, ChaCha20-Poly1305 aus
  `cryptography` kaum → Threads fürs Hashen/Dekomprimieren, nicht fürs Verschlüsseln.
* **tarfile:** großer `bufsize` im Lese-Stream-Modus macht es *langsamer*
  (Puffer wird bei jedem kleinen read umkopiert); nur `copybufsize` beim Schreiben groß.
* **tarfile `data_filter`** lässt `a/../b` zu (bleibt im Ziel) → `_NameGuard` lehnt `..` ab.
* **`passgen.Secret`:** `str()` ist absichtlich geschwärzt – immer `.value`.
* **Passphrasen/Anteile anzeigen:** nie abschneiden, nie nach `-` umbrechen lassen.
  Vorschläge (bis 40 Wörter/128 Zeichen) über `passgen._display_lines`: nur zwischen
  Wörtern, das `-` beginnt die Folgezeile; GUI `SecretView` kopiert ohne Umbrüche, TUI
  bricht bei Größenänderung neu um. Rich bricht Text ohne Leerzeichen sonst an
  beliebiger Stelle um (auch mitten im Wort). Anteile in Vierergruppen.
* **python-fido2 2.x:** Erweiterungsergebnisse sind base64url-Text (`websafe_decode`);
  vor jedem getAssertion eine Vorabanfrage mit `up=False`; PIN nur beim Registrieren.
* **Textual:** Klicks ~0,2 s nach einem Klick auf denselben Knopf werden ignoriert
  (Tests: pausieren); versteckte Eingabefelder fangen Fokus/Tasten → `disabled`;
  `Screen` hat eigene Attribute (`task` …) – eigene Namen eindeutig wählen.
* **Qt:** `QLabel` deutet Text als HTML → `setTextFormat(Qt.PlainText)`;
  `adjustSize()` vergrößert sichtbare Dialoge nicht zuverlässig. Umbrechende Labels
  bekommen im Formular die Höhe ihrer *schmalen* Wunschbreite → Höhe nach dem Layout
  selbst setzen; vor `sizeHint()` des Fensters die innere Ebene zuerst `activate()`,
  sonst ist die Wunschhöhe veraltet (Dialog zu niedrig, Knöpfe verdecken Inhalt).
  Objekte, die Qt übernimmt (etwa `QMimeData` aus `createMimeDataFromSelection`), nie in
  Python erzeugen, sondern das von `super()` anpassen – sonst Doppelfreigabe beim
  Prozessende: Segmentation fault *nach* bestandenen Tests. Deshalb bei pytest den
  Exit-Code prüfen, nicht nur die letzte Zeile (`| tail` verdeckt ihn).
* **Tests mit Import-Sperren:** `from . import x` prüft zuerst das Paket-Attribut, dann
  `sys.modules` – beides sperren. Dateinamen können kein `/` enthalten (Markup-Tests
  mit öffnenden Tags).
* **API-Schnappschuss/Doku:** Speicheradressen und `typing`-Darstellungen sind nicht
  stabil über Python-Versionen → normalisieren. groff warnt bei UTF-8 nicht immer →
  Manpage komplett als ASCII-Escapes.
* **Header an Ort und Stelle** umschreiben (Anhängen) nur bei gleicher Länge (`with_flags`).
* Die Sandbox, in der tres0r entstand, hatte **einen Kern**: Mehrkern-Gewinne sind
  dort nicht gemessen – auf echter Hardware mit `tres0r bench --throughput` prüfen.

## Offen

* macOS: GUI und FUSE ungetestet (die CI-Jobs dort laufen ohne diese Extras).
  `mount` ist nur für Linux und macOS vorgesehen.
* GUI auf echten Desktops: Julian hat sie von Hand ausprobiert – 1.0 unter Debian 13
  (seine Befunde → 1.1.0) und 1.0.1 von PyPI unter Windows Server 2025, beides lief.
  Nicht gezielt geprüft: X11/Wayland, Themes, HiDPI, Drag & Drop, Dateidialoge.
  Aus 1.1.0 hat Julian die Datenleck-Warnung, „Passwort vorschlagen“ und den Abbruch
  mit Esc von Hand bestätigt. Die Längenwahl der Vorschläge (1.2.0) ist bisher nur
  automatisch getestet.
* FIDO2 mit echter Hardware (YubiKey o. Ä.) inkl. PIN.
* Gewinn des Hintergrund-Dekodierers auf Mehrkern-Rechnern messen (`verify (zstd)`).
* Später: Post-Quanten-Empfänger (Slot-Typ 4, reserviert), paralleles Dekomprimieren
  mehrerer Frames, externes Audit.
