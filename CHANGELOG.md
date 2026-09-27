# Changelog

## 1.0.0rc7 – bereit für GitHub

Keine Änderung am Programmverhalten.

* **CI** (`.github/workflows/ci.yml`): Linux mit Python 3.10–3.14 und allen Extras,
  jeweils mit 1 und 4 simulierten Kernen; statische Prüfung; Minimalinstallation;
  Paket-Build mit `twine check --strict` und Tests aus dem Quellpaket; Windows und
  macOS zur Erprobung (färben die CI nicht rot). Geprüft mit actionlint/shellcheck.
* **Fuzzing** wöchentlich und auf Knopfdruck (`fuzz.yml`), Funde als Artefakt.
* **Veröffentlichen** per Versions-Tag (`release.yml`): Paket, GitHub-Release, PyPI
  über Trusted Publishing. Dependabot für die Actions.
* `CONTRIBUTING.md`, `SECURITY.md`, `CLAUDE.md` (Projektwissen fürs Weiterarbeiten),
  erweiterte `.gitignore`, Paket-Metadaten (Autor, Links, Klassifikatoren).
* README-Einleitung ehrlich aktualisiert (Status, getestete Plattformen, kein Audit).
* Test, der `tres0r/pwgen.py` als unverändertes Original festschreibt.
* Python 3.11 erstmals getestet (alle Extras): grün.

## 1.0.0rc6 – Grafische Oberfläche

* **`tres0r gui [ORDNER]`** (Extra `tres0r[gui]`, PySide6 ≥ 6.8): Hauptfenster mit
  Dateibaum und Details, Werkzeugleiste mit Tastenkürzeln, Drag & Drop, Packdialog
  (Stufe, zstd, FIDO2, Stärkeanzeige, Passphrase-Vorschlag), Entsperren mit
  Passwort/Keyfile/FIDO2 samt PIN-Abfrage aus dem Arbeitsthread, Inhaltsfenster mit
  Suche und Mehrfachauswahl, Schlüsselverwaltung, Anhängen, Vergleichen, Fortschritt
  mit Abbruch. Arbeit in Threads, Rückmeldung über Qt-Signale.
* 10 automatische Tests ohne Bildschirm (Qt „offscreen“): Packen, Vorschlag,
  Öffnen/Suchen/Entpacken, falsches Passwort, Abbruch, Schlüssel, Anhängen/Vergleich,
  FIDO2 mit PIN, Namen mit HTML (`<b>…`) bleiben reiner Text, Drag & Drop.
* Beim Anschauen gefunden und behoben: der Passphrase-Vorschlag brach nach einem
  Bindestrich um (mehrdeutig) und war danach rechts abgeschnitten – jetzt einzeilig
  und so breit wie die Phrase (per Test gemessen); „Speichern“ der Geheimnisse legt
  den Ordner an und meldet Fehler; Qt-Texte auf Deutsch; Typspalte ausgeblendet.

## 1.0.0rc5 – schnelleres Entpacken, gründlich getestet

* **Hintergrund-Dekodierer** für komprimierte Container: Entschlüsseln und zstd
  laufen in einem eigenen Thread, tar und Hashen im Hauptthread. Grundlage ist eine
  Messung: zstd gibt den GIL frei (beide Backends). Höchstens 8 MiB vorab, Fehler
  kommen an ihrer Stelle im Datenstrom an, Threads werden bei jedem Ende angehalten.
  Nur mit mehreren Kernen (auf einem Kern gemessen ~8 % Aufwand) und an `--threads`
  gekoppelt, damit `bench --throughput` den Effekt zeigt.
* **Fuzzer-Fund behoben:** Einträge mit `..` im Namen (z. B. `@/..`, nur aus
  präparierten Containern) ließen das Entpacken mit einem rohen `FileExistsError`
  abbrechen – kein Ausbruch aus dem Ziel, aber ein ungeordneter Absturz. Jetzt lehnt
  der Namensschutz sie vorab ab (`UnsafeArchive`); `salvage` überspringt und meldet sie.
* **Testphase:** Suite unter 3.10–3.14 und minimal, jeweils mit 1 und 4 simulierten
  Kernen (`TRES0R_TEST_CPUS=4`); Prüfung auf hängende Threads nach jedem Test;
  Abdeckung gemessen (89 %) und 36 gezielte Tests für die Lücken ergänzt
  (fehlerhafte Segmenttabellen, Anhängen in vorhandene Ordner, Index/Archiv-Abgleich,
  Ablehnungen); Fuzzing mit Mehrkern-Pfaden, Property-Tests mit 5000 Beispielen.

## 1.0.0rc4 – TUI komplett, FIDO2 mit PIN

* **FIDO2-Tokens mit PIN**: Der Software-Token der Tests spricht jetzt auch das
  PIN-Protokoll (PIN-Token, Nachweis beim Registrieren, Fehlversuchszähler). Belegt:
  PIN nur beim Registrieren, Entsperren nur mit Berührung; verständliche Meldungen
  für falsche, fehlende und gesperrte PIN. In der TUI fragt ein Fenster aus dem
  Arbeitsthread heraus nach der PIN; Abbrechen bricht sauber ab.
* **TUI**: Schlüsselverwaltung (`k`: +Passwort mit Keyfile/FIDO2, +Phrase,
  +Empfänger, +Anteile, Passwort ändern, Slot entfernen), Anhängen (`a`),
  Vergleichen (`d`, vorgeschlagen wird der gleichnamige Ordner), Suche im
  Inhaltsbaum (`/`, Textteil oder Muster), FIDO2 beim Packen.
* Beim Testen gefunden und behoben: nach „Passwort ändern“ scheiterten weitere
  Aktionen (Zugangsdaten nicht umgestellt); das versteckte Suchfeld fing Tasten ab;
  Anteile wurden in 80 Spalten abgeschnitten – jetzt in Vierergruppen umbrechend.

## 1.0.0rc3 – Textoberfläche

* **`tres0r tui [ORDNER]`** (Extra `tres0r[tui]`, Textual ≥ 8): Dateibaum mit
  Container-Details, Packen mit Stärkeanzeige und Passphrase-Vorschlag, Öffnen mit
  Passwort/Keyfile/FIDO2, Inhaltsbaum mit Entpacken einzelner Einträge oder aller,
  Prüfen; Fortschritt mit Durchsatz/Restzeit und Abbruch über den Kern.
* Automatisiert getestet (Textual-Pilot, ohne Bildschirm): Packen, Vorschlag,
  Öffnen/Entpacken, falsches Passwort, Abbruch, Kürzel nur auf der Hauptansicht,
  Dateinamen mit Markup (`[red]…`) werden wörtlich gezeigt.
* Beim Bau gefunden und behoben: `str()` eines `passgen.Secret` ist absichtlich
  geschwärzt – der Vorschlag nutzt `.value`; die vorgeschlagene Phrase steht in
  eigener, umbrechender Zeile (war am Rand abgeschnitten); Formular passt in 80×24.

## 1.0.0rc2 – Lizenz

* tres0r steht unter der **MIT-Lizenz** (`LICENSE`, SPDX `MIT` in den Paketmetadaten
  nach PEP 639). Die Wortlisten behalten ihre Lizenzen.
* API-Schnappschuss hält `__version__` nur als Namen fest, nicht als Wert – eine
  neue Versionsnummer ist keine API-Änderung.

## 1.0.0rc1 – Kern eingefroren

Keine Formatänderung, kein geändertes Verhalten.

* **FORMAT.md ist Spezifikation 1.0** mit Regeln zur Weiterentwicklung (Abschnitt 13):
  neue Fähigkeiten nur über neue Slot-Typen, Flag-Bits und Kennungen, die ältere
  Leser sicher überspringen bzw. ablehnen.
* **Stabile Python-API** festgelegt: `tres0r.__all__` plus `keys`, `shamir`,
  `progress`, `errors`, `passgen`, `hwtoken`, `mount`; alle anderen Module intern.
  `API.md` wird aus dem Code erzeugt, `tests/api_surface.json` friert 149
  Signaturen ein; jeder Parameter jeder öffentlichen Funktion ist dokumentiert
  (per Test erzwungen, gemeinsame Parameter einmal in API.md).
* Alle Fehlerklassen in `tres0r.errors` (`SignatureError`, `KeyFormatError` zogen
  um; die alten Namen in `sign`/`keys` bleiben gültig).
* **Manpage und Shell-Vervollständigung** aus dem Parser: `tres0r manpage`,
  `tres0r completion bash|zsh`, Dateien in `man/` und `completions/` (reines ASCII,
  groff ohne Warnung; bash und zsh funktional getestet).
* Quellpaket vollständig (`MANIFEST.in`): Doku, Vektoren und Tests laufen aus dem
  entpackten sdist.

## 0.11.1 – Kalibrierung nach echten Messwerten

* **`-l auto` trifft die Zielzeit:** Messungen auf zwei Rechnern zeigten 1,34 s bzw.
  1,20 s statt 2 s. Ursache: Die Dauer ist A + B·t mit festem Anteil A (Speicher
  bereitstellen); nur mit t = 1 zu rechnen zählt A bei jeder Iteration mit. Jetzt
  werden t = 1 und t = 2 gemessen (nach einem Aufwärmlauf) und daraus A und B
  getrennt; bei unplausibler zweiter Messung wird vorsichtig gerechnet. Tests mit
  den gemessenen Modellen: Ziel auf ±½ Iteration.
* README: Kalibrieren auf dem langsamsten Rechner, der öffnen soll; `bench` und tmpfs;
  gemessene Durchsatzwerte. Thread-Voreinstellung bestätigt (auf beiden Rechnern
  schneller, nirgends langsamer).

## 0.11.0 – FIDO2-Token

Neuer Keyslot-Typ 7 (FORMAT.md 4.1); bestehende Container unverändert (Vektoren).

* **Passwort + FIDO2-Token** (`--fido2`, `keys add-password --new-fido2`, `tres0r fido2`):
  hmac-secret über python-fido2 (Extra `tres0r[fido2]`), RP-ID `tres0r.local`,
  Berührung statt PIN (PIN nur, wenn der Token sie verlangt). Mehrere Tokens werden
  durchprobiert, fremde ohne Berührung übersprungen; `passwd` behält den Faktor ohne
  zweite Berührung.
* Tests gegen einen Software-Token (CTAP 2.1, hmac-secret, ECDH/Protokoll 1 und 2)
  über die echte Bibliothek; **nicht mit echter Hardware geprüft**.
* Beim Testen gefunden: Ein präparierter, zu kurzer Slot mit variabler Länge hätte
  einen IndexError statt FormatError ausgelöst – behoben, Mindestlänge wird zuerst
  geprüft; Property-Tests und Header-Fuzzer kennen Typ 7.
* Referenz-Leser liest Typ 7, neuer reproduzierbarer Testvektor.

## 0.10.0 – Anhängen

Formaterweiterung: Header-Flag Bit 2 und Segmenttabelle (FORMAT.md 9b). Container
ohne angehängte Segmente sind unverändert (Testvektoren); 0.9.0 lehnt Container mit
Segmenten sauber ab.

* **`tres0r append`**: Dateien als neues Segment an Ort und Stelle anhängen – eigene
  Nonce, eigener Index, eigenes Padding, optional eigene Signatur und Kompression.
  Neuere Fassungen gleicher Namen gelten in list/unpack/mount/diff.
* **`tres0r repair`** und Journal: Abbruch/Fehler kürzt sofort zurück; nach einem
  Absturz wird abgeschlossen oder zurückgesetzt, ohne Journal auf die letzte
  gültige Tabelle gekürzt. Vorherige Tabellen werden entwertet (gegen Abschneiden).
* `verify` prüft jedes Segment (mit `--signer` muss jedes signiert sein), `salvage`
  rettet segmentweise – bei zerstörter Tabelle findet es das Ende von Segment 0
  über dessen Abschluss-Chunk und damit auch dessen Inhaltsverzeichnis.
* Schlüsseländerungen funktionieren weiter (Tabellen-Offsets relativ zum Header-Ende).
* Referenz-Leser liest Segmente, neuer Testvektor (signiert, Segment 1 komprimiert).
* Fuzzing: eigener Segmentmodus mit gültig verschlüsselten, aber verbogenen Tabellen.

## 0.9.0 – Aufteilen und Einhängen

Keine Formatänderung.

* **`--split GRÖSSE`** (pack, encrypt, upgrade): Container in Teile `NAME.001 …`;
  alle Befehle lesen Teilesätze transparent (auch wahlfrei über Teilgrenzen),
  Schlüsseländerungen behalten die Aufteilung, Wechsel zwischen aufgeteilt und
  einzeln räumt alte Teile auf. `cat NAME.* | tres0r unpack -` funktioniert.
* **`tres0r mount` / `umount`**: schreibgeschützt per FUSE (Extra `tres0r[mount]`),
  auch aufgeteilte, komprimierte, signierte und v1-Container; präparierte Namen
  werden ausgeblendet; beschädigte Chunks ergeben EIO, der Rest bleibt lesbar.
  `--verify`/`--signer` prüft vorab vollständig. API: `tres0r.mount.ContainerFS`.
* Fuzzing fand in der neuen Mount-Logik einen nicht übersetzten tarfile-Fehler
  (leeres tar in v1) – behoben, Regressionstest.
* `tres0r … | head` endet still statt mit „Broken pipe“.

## 0.8.0 – Zweiter Faktor und Schwellwert

Neue Keyslot-Typen 5 und 6 (Typ 7 für FIDO2 reserviert); bestehende Container sind
unverändert (per Testvektoren belegt), 0.7.0 kann die neuen Slots nicht öffnen.

* **Passwort + Keyfile** (`--keyfile`, `tres0r keyfile`): beides nötig; falsches Keyfile
  fällt vor Argon2 auf. `passwd` behält den zweiten Faktor, `keys add-password --new-keyfile`.
* **Schwellwert-Slots** (`--shares K/N`, `keys add-shares`, `--share`/`--shares-file`):
  Shamirs Secret Sharing über GF(2⁸), 2 ≤ k ≤ n ≤ 32, Anteile mit Prüfsumme;
  `--shares-dir` legt sie als Dateien ab. Öffnen ohne Passwortabfrage.
* `encrypt_stream` gibt jetzt ein `EncryptResult` zurück (Bytes, Anteile);
  `CreateResult.shares`, neue API `add_threshold`.
* FORMAT.md 4.1/4.3/5.3, zwei neue reproduzierbare Testvektoren; der Referenz-Leser
  rechnet GF(2⁸) bewusst anders (Schieben statt Logarithmentabellen).

## 0.7.0 – Leistung und Metadaten

Keine Formatänderung (Zeit 0 und xattrs sind tar-Ebene, in FORMAT.md präzisiert).

* **`-l auto`** (+ `--kdf-time`): Argon2 auf eine Zielzeit kalibrieren – Speicher
  zuerst (höchstens 1 GiB und ¼ des freien RAMs), dann Iterationen. `bench` zeigt
  den Vorschlag.
* **`--threads`**: SHA-256 in einem Hintergrund-Thread (pack, verify, upgrade),
  zstd-Worker (pack, encrypt, upgrade), paralleles Hashen in `diff`. Grundlage ist
  eine Messung: hashlib gibt den GIL frei, ChaCha20-Poly1305 kaum.
* **`bench --throughput`**: pack/verify mit und ohne Threads auf dem eigenen Rechner.
* **`--no-times`**: keine Änderungszeiten (0 = unbekannt, beim Entpacken jetzt).
  `diff --quick` hasht dann, `--times` ignoriert fehlende Zeiten.
* **`--xattrs` / `--acls`**: user.*-Attribute und POSIX-ACLs sichern und
  wiederherstellen (Linux); `security.*`/`trusted.*` werden nie gesetzt.
* Lesepfad: weniger Kopien im `DecryptingReader`, `peek()` statt Zusammenkleben
  (Effekt gemessen: klein, ca. 2–3 %). Beim Packen kopiert tarfile nun in 1-MiB-Stücken.

## 0.6.0 – Vergleichen, Pipes, Fortschritt

Keine Formatänderung.

* **`tres0r diff CONTAINER PFAD...`:** vergleicht einen Container mit Ordnern –
  gleiche Pfade und Ausschlussmuster wie beim Packen. Meldet neu, entfernt,
  geändert, Typ- und Linkänderungen, mit `--times` auch reine Zeitunterschiede;
  gleich große Dateien per SHA-256, `--quick` nur Größe + Zeit. Funktioniert auch
  mit v1-Containern (Hashes beim Durchlesen). Neuer Exit-Code 4 = Unterschiede.
* **`tres0r unpack -`:** Entpacken aus einer Pipe mit Namensschutz, data-Filter und
  Signaturprüfung (API: `extract_stream`).
* **Fortschritt und Abbruch:** `progress=` nimmt zusätzlich einen `Monitor` mit
  `ProgressEvent`s (Phase, Datei, Durchsatz, Restzeit; gedrosselt) und einem
  threadsicheren `CancelToken` – für TUI/GUI. Neu mit Fortschritt: Durchsuchen,
  Schlüsselableitung, `encrypt`/`decrypt`, `salvage` und das Umschreiben bei
  Schlüsseländerungen. Alte `(erledigt, gesamt)`-Callbacks funktionieren weiter.
* Die CLI zeigt Durchsatz, Restzeit und die aktuelle Datei.

## 0.5.0 – Schlüssel: Signaturen und geschützte Identitäten

Format v2 bekommt Flag-Bit 1 (signiert). Unsignierte Container sind byte-identisch
zu 0.4.0 (per Testvektoren belegt); 0.4.0 lehnt signierte Container als
"unbekanntes Flag" ab.

* **Signierte Container (Ed25519):** `keygen --sign`, `pack/encrypt --sign`,
  `verify/unpack/decrypt --signer` bzw. `--signers-file`. Der Anhang liegt in der
  Verschlüsselung und deckt den gesamten Klartext ab; Keyslots bleiben unsigniert,
  damit Schlüsselverwaltung die Signatur nicht bricht. Beim Entpacken landet nichts
  im Ziel, bevor die Signatur stimmt; `unpack --only` liest mit `--signer` den
  ganzen Container.
* **Geschützte Identitätsdateien:** `keygen` fragt standardmäßig eine Passphrase ab
  (Stufe „stark“), `--unprotected` für ungeschützte Dateien, `tres0r protect` für
  bestehende. Eine geschützte Datei ist ein tres0r-Rohdaten-Container.
  `--key-passphrase-file` für Skripte. Identitätsdateien können X25519- und
  Signaturschlüssel enthalten.
* `decrypt_stream` gibt jetzt ein `DecryptResult` zurück (Bytes, signiert, Unterzeichner).
* FORMAT.md Abschnitt 9a, zwei signierte Testvektoren, Referenz-Leser prüft
  Signaturen, Fuzz-Harness signiert Eingaben selbst gültig.

Behoben (Fuzzing, Runde 2):

* Präparierte PAX-Zeitstempel (`1e30`, `inf`, `nan`) ließen `unpack`, `salvage`,
  `list` und `upgrade` mit `OverflowError`/`ValueError` abstürzen. Nicht
  darstellbare Zeitstempel werden jetzt durch 0 ersetzt.
* `upgrade` reichte fremde PAX-Erweiterungen unverändert weiter; ein Schlüsselwort
  aus ungültigem UTF-8 ließ es abstürzen. Übernommen werden jetzt nur noch die
  Standardfelder, Kodierungsfehler gelten als Formatfehler.

Kleinere Verbesserungen: Tippfehler in `--signer` fallen vor der Schlüsselableitung
auf; `keygen`/`protect` fragen nach der „Schutz-Passphrase“; die Statusmeldung vor
der Passwortabfrage heißt jetzt „Entsperre …“.

## 0.4.0 – Robustheit

Keine Formatänderung.

* **`FORMAT.md`:** vollständige, codeunabhängige Spezifikation (v2 und v1) mit
  **Testvektoren** (`tests/vectors/`) und einem **unabhängigen Referenz-Leser**
  (`tests/reference_decoder.py`), der nur nach dem Dokument geschrieben ist.
* **Property-Tests (Hypothesis)** für alle Parser und Roundtrips, **Fuzzing (atheris)**
  mit drei Harnesses; beides auch in der CI.
* **`tres0r salvage`:** intakte Dateien aus beschädigten Containern retten
  (über das Inhaltsverzeichnis oder der Reihe nach, SHA-256-geprüft).
* **`tres0r upgrade`:** Format v1 → v2 als Stream, Original erst nach vollständiger Prüfung ersetzt.
* Alle Zufallswerte kommen aus einem Modul (`tres0r/rng.py`).

Durch Fuzzing und Property-Tests gefundene und behobene Fehler:

* `pack` brach bei Linux-Dateinamen ohne gültiges UTF-8 ab (`UnicodeEncodeError`).
  Solche Namen werden jetzt unverändert gesichert, beim Packen gemeldet und unter
  Windows mit `--rename` als Latin-1 gedeutet.
* Präparierte Inhaltsverzeichnisse führten zu `TypeError` (falsche Feldtypen) bzw.
  `RecursionError` (tief verschachteltes JSON) statt eines Formatfehlers.
* Beschädigte zstd-Daten kamen als `ZstdError`/`EOFError` statt als Formatfehler an;
  mit dem Paket `zstandard` wurde ein abgeschnittener letzter Frame sogar
  stillschweigend akzeptiert. Neuer, für beide Backends gleicher Frame-Leser; er
  begrenzt zudem die Ausgabe pro Schritt (Dekompressionsbomben).
* Präparierte Container mit zulässigen, aber für den Rechner zu hohen
  Argon2-Parametern (bis 4 GiB) konnten den OOM-Killer auslösen. Jetzt wird vorher
  der verfügbare Arbeitsspeicher geprüft (Linux, Windows, macOS).
* Die kanonische Form der Wiederherstellungsphrase ist jetzt exakt spezifiziert
  (Ergebnis für alle bisherigen Phrasen unverändert).

## 0.3.0 – Formatversion 2

Neue Container werden im Format v2 geschrieben. Container von 0.1/0.2 (v1) werden
weiter gelesen, entpackt und können ihr Passwort ändern.

* **Mehrere Keyslots (bis 16):** Passwörter (Argon2id, max. 4), Wiederherstellungsphrase
  (20 Wörter aus den pwgen-Listen, HKDF), öffentliche X25519-Schlüssel.
  Neue Befehle: `keygen`, `pubkey`, `keys list|add-password|add-recovery|add-recipient|remove`.
  `pack`/`encrypt`: `-r`, `-R`, `--recovery`, `--no-password`. Entsperren mit `-i`.
* **Header-MAC mit Key-Commitment** (HMAC-SHA256, Schlüssel aus dem DEK).
* **Inhaltsverzeichnis** am Ende (Größe, mtime, SHA-256, Einstiegspunkt): `list` ist
  sofort fertig, `unpack --only` springt direkt zu den Einträgen (Hardlink-Ziele werden
  mitgenommen), `verify` gleicht jede Datei per SHA-256 ab.
* **zstd-Kompression** (`-z`), Frames spätestens alle 1 MiB für wahlfreien Zugriff.
  Standardbibliothek ab Python 3.14, sonst Extra `tres0r[zstd]`.
* **Datenströme:** `encrypt`/`decrypt` für Pipes und Einzeldateien; `decrypt` gibt bei
  Datei-Containern den tar-Stream aus.
* `passwd` ersetzt genau den Passwort-Slot, mit dem entsperrt wurde. Die Optionen
  heißen jetzt `--password-file` (aktuelles) und `--new-password-file` (neues).
* Schlüsseltexte werden nur in kanonischer Schreibweise akzeptiert.
* Fix: Der Namensschutz zählte Ordner doppelt (Python ruft den tar-Filter für Ordner
  zweimal auf).

## 0.2.0

Keine Formatänderung – Container von 0.1.0 lassen sich weiter öffnen und umgekehrt.

* **Portabilitäts-Check:** `pack` warnt vor Namen, die unter Windows ungültig sind
  oder unter Windows/macOS kollidieren (Groß-/Kleinschreibung, NFC/NFD);
  `--strict-names` bricht ab. `unpack` erkennt Kollisionen am Dateisystem und bricht
  ab oder benennt mit `--rename` um.
* **`tres0r verify`:** prüft den ganzen Container ohne zu schreiben; `pack --verify`
  prüft direkt nach dem Schreiben.
* **Padmé-Padding** gegen Rückschlüsse aus der Containergröße (Standard, `--no-pad`).
* **Ausschlüsse:** `-x/--exclude`, `--exclude-from`, `--exclude-junk`, `.tres0rignore`.
* **Speicherplatzprüfung** vor `pack`, `unpack`, `passwd` (`--no-space-check`).
* **`--json`** für alle Befehle; eindeutige Exit-Codes (2 = falsches Passwort,
  3 = Container beschädigt/unsicher).
* **Generierte Geheimnisse** werden nach dem Notieren ausgeblendet und müssen zur
  Kontrolle abgetippt werden.
* Übersicht vor dem Packen (Dateien, Größe, Ausschlüsse, geschätzte Containergröße).
* API: `scan()`/`Plan`, `estimate_size()`, `verify()`, `ExtractResult`,
  `check_free_space()`, `ExcludeRules`.

## 0.1.0

* Erste Version: Argon2id-Stufen, ChaCha20-Poly1305-STREAM, tar-Container,
  Keyslot mit Passwortwechsel ohne Neuverschlüsselung, pwgen-Integration, CLI.
