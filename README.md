# tres0r

[![CI](https://github.com/bluhtsturm/tres0r/actions/workflows/ci.yml/badge.svg)](https://github.com/bluhtsturm/tres0r/actions/workflows/ci.yml)
[![Lizenz: MIT](https://img.shields.io/badge/Lizenz-MIT-blue.svg)](LICENSE)

Dateien, Ordner und Datenströme in einen verschlüsselten Container packen – mit
Kommandozeile, Textoberfläche und grafischer Oberfläche, mehreren Schlüsseln pro
Container und eingebautem Passphrasen-Generator (pwgen) samt Have-I-Been-Pwned-Prüfung.

* **Verschlüsselung:** ChaCha20-Poly1305 in 64-KiB-Chunks (STREAM-Konstruktion, wie
  bei age); Argon2id für Passwörter, Stufen schnell/normal/stark oder `-l auto`
* **Schlüssel:** bis zu 16 Keyslots – Passwörter, Wiederherstellungsphrase,
  X25519-Empfänger, Passwort + Keyfile, Passwort + FIDO2-Token (hmac-secret),
  Schwellwert-Anteile (Shamir, k von n); Header-MAC mit Key-Commitment
* **Signaturen (Ed25519):** belegen, wer einen Container (bzw. ein Segment) erstellt hat
* **Container:** tar mit Inhaltsverzeichnis, optional zstd; Dateinamen und Metadaten
  sind mitverschlüsselt; Anhängen, Aufteilen (`--split`), Einhängen (FUSE),
  Vergleichen, Retten beschädigter Container
* **Format:** eingefrorene Spezifikation [`FORMAT.md`](FORMAT.md) 1.0 mit
  unabhängigem Referenz-Leser und Testvektoren
* **Abhängigkeiten:** nur `cryptography`; alles Weitere als optionale Extras

> **Status: 1.2.0.** Getestet unter Linux mit Python 3.10–3.14 (automatische Tests,
> Fuzzing, Property-Tests). Unter Windows und macOS laufen die automatischen Tests
> (ohne GUI und FUSE) in der CI ebenfalls durch. Die GUI von Version 1.0 lief im
> Handtest unter Debian 13 und unter Windows Server 2025 (von PyPI installiert), GUI
> und TUI von 1.2.0 unter macOS Tahoe 26.7; die
> Neuerungen aus 1.1.0 (Datenleck-Warnung, Passwort-Vorschlag, Abbruch) und 1.2.0
> (Längenwahl der Vorschläge) sind von Hand bestätigt. FIDO2
> ist nur gegen einen Software-Token getestet, noch nicht mit echter Hardware. Eine
> unabhängige Sicherheitsprüfung (Audit) gab es bisher nicht – siehe
> [`SECURITY.md`](SECURITY.md).

## Installation

Von PyPI – dort heißt das Paket `tres0r-crypt`, weil PyPI `tres0r` als zu ähnlich zum
bestehenden Projekt `tresor` ablehnt. Import (`import tres0r`) und Befehl (`tres0r`)
bleiben gleich:

```bash
pipx install "tres0r-crypt[zstd]"
pipx install "tres0r-crypt[zstd,tui,gui]"   # mit Oberflächen
```

Direkt von GitHub:

```bash
pipx install "tres0r-crypt[zstd] @ git+https://github.com/bluhtsturm/tres0r"
pipx install "tres0r-crypt[zstd,tui,gui] @ git+https://github.com/bluhtsturm/tres0r"   # mit Oberflächen
```

Aus einem Checkout:

```bash
pipx install .                 # CLI systemweit
pipx install ".[zstd]"         # mit Kompression unter Python < 3.14
pipx install ".[zstd,mount,fido2]"   # dazu Einhängen (libfuse2) und FIDO2-Token
pipx install ".[zstd,tui]"     # mit Textoberfläche (tres0r tui)
pipx install ".[zstd,gui]"     # mit grafischer Oberfläche (tres0r gui, PySide6)
pip install -e ".[dev]"        # Entwicklung inkl. Tests
```

Manpage und Shell-Vervollständigung kommen aus dem Programm selbst (immer passend
zur installierten Version; fertige Dateien liegen auch in `man/` und `completions/`):

```bash
mkdir -p ~/.local/share/man/man1 ~/.local/share/bash-completion/completions ~/.zfunc
tres0r manpage > ~/.local/share/man/man1/tres0r.1                  # man tres0r
tres0r completion bash > ~/.local/share/bash-completion/completions/tres0r
tres0r completion zsh > ~/.zfunc/_tres0r        # in ~/.zshrc vor compinit: fpath=(~/.zfunc $fpath)
```

## Textoberfläche

```bash
tres0r tui ~/Backups          # Startordner optional
```

Links ein Dateibaum, rechts Details – bei Containern schon vor dem Entsperren
Format, Größe, Schlüssel-Slots, Signatur und Segmente.

| Taste | Hauptansicht | im Inhaltsbaum | in der Schlüsselverwaltung |
|---|---|---|---|
| `p` | packen (Stufe, zstd, FIDO2, Passwort mit Stärkeanzeige und HIBP-Prüfung oder Vorschlag als Passphrase/Passwort mit wählbarer Länge) | | |
| `o` | öffnen → Inhaltsbaum | | |
| `v` | prüfen | prüfen | |
| `a` | Datei/Ordner anhängen | alles entpacken | |
| `d` | mit Ordner vergleichen (Tabelle neu/entfernt/geändert) | | |
| `k` | Schlüssel verwalten | | |
| `/` | | suchen (Textteil oder `*.jpg`) | |
| `e` | | Auswahl entpacken | +Empfänger |
| `n` `w` `s` | | | +Passwort (optional Keyfile/FIDO2), +Phrase, +Anteile K/N |
| `c` `x` | | | Passwort ändern, Slot entfernen (mit Rückfrage) |

Überall: `?`, `h` oder `F1` zeigen die Hilfe zur Ansicht – Erklärung und alle Tasten
(in Eingabefeldern tippen `?` und `h` Zeichen, dort hilft `F1`, am Mac oft mit `fn`);
`q` beendet (in Eingabefeldern und Fenstern `Strg+Q`), `Esc` führt zurück bzw. bricht
ab. Hilfe und Beenden stehen in der Fußzeile immer vorn.

Entsperren mit Passwort, Keyfile oder FIDO2-Token; verlangt der Token seine PIN,
fragt ein eigenes Fenster danach. Neue Geheimnisse (Phrase, Anteile) erscheinen
nur einmal – vollständig und umbrechend, Anteile in Vierergruppen (so abgetippt
passen sie) – und lassen sich als Dateien (0600) speichern. Lange Vorgänge zeigen
Balken, Datei, Durchsatz und Restzeit und lassen sich abbrechen (Knopf oder `Esc`);
wie in der CLI bleibt dabei nichts Halbes zurück. Danach steht das Ergebnis eindeutig
da: grün mit ✓ („Erfolgreich gepackt“ und Zusammenfassung), Fehler rot mit ✗, ein
Abbruch gelb. Passt in ein 80×24-Terminal. Die TUI ist nicht Teil der stabilen API.

## Grafische Oberfläche

```bash
tres0r gui ~/Backups          # Startordner optional
```

Dateibaum mit Details (bei Containern schon vor dem Entsperren), Werkzeugleiste mit
Packen (Strg+P), Öffnen (Strg+O, auch Doppelklick), Prüfen (Strg+T), Anhängen
(Strg+A, ein Ordner oder einzelne Dateien), Vergleichen (Strg+D, vorgeschlagen wird
der gleichnamige Ordner) und Schlüssel (Strg+K); unter macOS ⌘ statt Strg. Das Menü
„Hilfe“ hat eine Kurzanleitung mit allen Tastenkürzeln (F1, unter macOS ⌘?), „Datei“
das Beenden (Strg+Q bzw. ⌘Q). Nach Packen, Entpacken, Prüfen, Anhängen und
Schlüsseländerungen bleibt der Fortschrittsdialog mit „✓ Erfolgreich …“ und
Zusammenfassung offen, bis man ihn schließt. Ordner ins Fenster ziehen
öffnet den Packdialog, ein gezogener Container wird geöffnet. Rohdaten-Container
(`tres0r encrypt`) enthalten keine Dateien – für sie gibt es Prüfen und Schlüssel.
Der Inhalt eines Containers erscheint in einem eigenen Fenster mit Größe, Datum und
(bei angehängten Segmenten) Segment, Suche (Textteil oder `*.jpg`) und
Mehrfachauswahl zum Entpacken. Die Schlüsselverwaltung kann dasselbe wie in der TUI;
ein neues Passwort bekommt die Stufe des vorhandenen. Neue Phrasen und Anteile
erscheinen einmal vollständig (Phrasen mit Leerzeichen zwischen den Wörtern, Anteile
in Vierergruppen – so abgetippt gelten beide) und lassen sich als Dateien (0600)
speichern. Beim
Packen schlägt sie wahlweise eine Passphrase oder ein Passwort vor; die Länge wählt ein
Zahlenfeld daneben (8–40 Wörter bzw. 8–128 Zeichen, wie `-w`/`-n` der CLI, unter 80 Bit
mit Hinweis). Lange Vorschläge brechen nur zwischen Wörtern um, der Bindestrich beginnt
dann die nächste Zeile – eine Zeile, die auf „-“ endet, wäre beim Abschreiben mehrdeutig;
Markieren und Kopieren liefert den Vorschlag ohne die Umbrüche. Selbst gewählte
Passwörter prüft sie wie die CLI gegen bekannte Datenlecks (HIBP, per Häkchen
abschaltbar). Namen und Fehlermeldungen werden
stets als reiner Text gezeigt (nie als HTML). Qt-eigene Texte folgen der
Systemsprache. Nicht Teil der stabilen API.

## Stabilität (ab 1.0)

* **Format:** `FORMAT.md` ist als Spezifikation 1.0 eingefroren. Container, die
  tres0r 1.0 schreibt, lesen alle späteren 1.x-Versionen; Erweiterungen kommen nur
  rückwärtskompatibel dazu (Abschnitt 13). Ein unabhängiger Referenz-Leser und
  Testvektoren belegen die Spezifikation.
* **Python-API:** `API.md` (aus dem Code erzeugt) – was dort steht, bleibt in 1.x
  stabil; ein Test mit Schnappschuss aller Signaturen (`tests/api_surface.json`)
  verhindert unbemerkte Änderungen. Alles andere ist intern.
* **Kommandozeile:** Befehle, Optionen und Exit-Codes sind stabil, ebenso die
  Schlüssel der `--json`-Ausgaben (neue können hinzukommen). Die Textausgabe ist
  für Menschen, nicht zum Auswerten.

## Nutzung

`tres0r help` (oder nur `tres0r`) zeigt alle Befehle, `tres0r help pack` bzw.
`tres0r pack -h` die Optionen eines Befehls.

```bash
# Verschlüsseln – Passwort wird abgefragt und geprüft
tres0r pack Dokumente/ steuer.pdf -o backup.tres0r -l stark

# ... oder gleich eine Passphrase generieren lassen (8 Wörter ≈ 103 Bit)
tres0r pack Dokumente/ -o backup.tres0r -g passphrase
tres0r pack Dokumente/ -o backup.tres0r -g passphrase --wordlist en -w 10 --digit

# Auswahl eingrenzen, danach komplett gegenprüfen
tres0r pack Projekt/ -x '*.tmp' -x build/ --exclude-junk --verify

# Komprimieren, zusätzlich eine Wiederherstellungsphrase anlegen
tres0r pack Projekt/ -z --recovery

tres0r info backup.tres0r              # Header und Keyslots (ohne Passwort)
tres0r list backup.tres0r              # Inhalt (aus dem Inhaltsverzeichnis, sofort)
tres0r verify backup.tres0r            # komplett prüfen inkl. SHA-256 jeder Datei
tres0r unpack backup.tres0r -o ziel/   # Entpacken
tres0r unpack backup.tres0r --only 'Projekt/docs' --only '*.pdf'   # nur Teile
tres0r unpack backup.tres0r --rename   # kollidierende/ungültige Namen umbenennen
tres0r passwd backup.tres0r -l stark   # Passwort/Stufe ändern, ohne Neuverschlüsselung
tres0r diff backup.tres0r Projekt/     # Was hat sich seit dem Packen geändert? (Exit 4 = ja)
tres0r pack Projekt/ -l auto --kdf-time 3  # Argon2 auf ~3 s auf diesem Rechner kalibrieren
tres0r pack Fotos/ --no-times --xattrs     # ohne Zeitstempel, mit user.*-Attributen
tres0r salvage kaputt.tres0r -o rettung/   # Intaktes aus einem beschädigten Container retten
tres0r upgrade alt.tres0r              # Container von 0.1/0.2 (Format v1) auf v2 umwandeln

# Generator & Prüfung (aus pwgen)
tres0r genpass                         # Passphrase, deutsch, 8 Wörter
tres0r genpass passwort -n 32 --no-ambiguous
tres0r checkpass                       # Länge, Zeichenarten, HIBP
tres0r bench                           # Dauer der Stufen auf diesem Rechner
```

Für Skripte: `--password-file DATEI` (erste Zeile) bzw. `--password-file -` (stdin).
Passwörter werden bewusst nie als Argument angenommen – sie landeten sonst in der
Shell-History und der Prozessliste.

Eine generierte Passphrase wird angezeigt, nach Enter vom Bildschirm entfernt und
muss zur Kontrolle einmal abgetippt werden. Wer das schafft, hat sie wirklich
notiert. `-y` überspringt das (Skripte); aus dem Scrollback des Terminals kann
das Ausblenden sie nicht entfernen.

### Schlüssel und Empfänger

```bash
tres0r keygen -o ~/.config/tres0r/nas.key   # X25519-Schlüsselpaar, fragt eine Schutz-Passphrase ab
tres0r pubkey ~/.config/tres0r/nas.key       # öffentlichen Schlüssel erneut anzeigen
tres0r protect alt.key                      # ältere, ungeschützte Identitätsdatei schützen

# Für einen Empfänger verschlüsseln – ohne dessen Geheimnis zu kennen
tres0r pack Fotos/ -r tres0r-pub-… --no-password
tres0r unpack Fotos.tres0r -i ~/.config/tres0r/nas.key

tres0r keys list backup.tres0r                        # Keyslots anzeigen
tres0r keys add-password backup.tres0r                # weiteres Passwort
tres0r keys add-recovery backup.tres0r                # Wiederherstellungsphrase
tres0r keys add-recipient backup.tres0r -r tres0r-pub-…
tres0r keys remove backup.tres0r 1                    # Slot 1 entfernen
```

Ideal für automatische Backups: Der Server kennt nur den öffentlichen Schlüssel und
kann verschlüsseln, aber nichts entschlüsseln. Der private Schlüssel liegt offline.
Welcher Empfänger einen Container öffnen kann, steht nirgends im Klartext.

Die **Wiederherstellungsphrase** besteht aus 20 zufälligen Wörtern der pwgen-Listen
(ca. 258 Bit). Sie wird nach dem Notieren ausgeblendet; drei zufällig gewählte Wörter
müssen zur Kontrolle eingegeben werden. Beim Entsperren wird sie einfach statt des
Passworts eingegeben – Leerzeichen statt Bindestriche und Großschreibung sind egal.

Identitätsdateien sind standardmäßig mit einer **Passphrase geschützt** (Stufe
„stark“, Rechte 0600). Technisch ist die geschützte Datei ein tres0r-Container –
`tres0r decrypt nas.key` zeigt ihren Inhalt. `--unprotected` legt sie ungeschützt an
(z. B. für einen Server mit verschlüsseltem Datenträger), `--key-passphrase-file`
liefert die Passphrase in Skripten.

### Zweiter Faktor: Keyfile

```bash
tres0r keyfile -o /media/usbstick/tres0r.key         # 64 Byte Zufall, Rechte 0600
tres0r pack Tresor/ --keyfile /media/usbstick/tres0r.key
tres0r unpack Tresor.tres0r --keyfile /media/usbstick/tres0r.key
```

Mit `--keyfile` braucht der Passwort-Slot **beides**: Passwort und Keyfile
(`KEK = HKDF(Argon2id(Passwort) ‖ Keyfile)`). Ein falsches Keyfile fällt sofort auf,
noch bevor Argon2 rechnet. Beliebige Dateien funktionieren auch, ein erzeugtes
Keyfile ist aber sicherer (512 Bit Zufall, ändert sich nie). `passwd` behält den
zweiten Faktor, `keys add-password --new-keyfile` legt weitere solche Slots an.

### Zweiter Faktor: FIDO2-Token

```bash
pip install 'tres0r-crypt[fido2]'
tres0r fido2                                         # angeschlossene Tokens anzeigen
tres0r pack Tresor/ --fido2 --shares 2/3             # Passwort + Token, dazu Notfall-Anteile
tres0r unpack Tresor.tres0r --fido2                  # Passwort eingeben, dann Token berühren
tres0r keys add-password Tresor.tres0r --fido2 --new-fido2   # Ersatz-Token (einzeln einstecken)
```

Der Slot braucht Passwort **und** Token (`KEK = HKDF(Argon2id(Passwort) ‖ H)`), wobei
`H` das hmac-secret des Tokens ist: 32 Byte, die nur der Token berechnen kann und nur
nach Berührung herausgibt. Geeignet sind Tokens mit der Erweiterung hmac-secret
(YubiKey 5, Nitrokey 3, SoloKey 2, Google Titan v2 u. a.). Die Token-PIN wird nur
abgefragt, wenn der Token sie verlangt. Mehrere gesteckte Tokens werden der Reihe
nach gefragt; fremde lehnen ohne Berührung ab. `passwd` behält den Token-Faktor.

**Wichtig:** Ein verlorener oder defekter Token ist nicht ersetzbar. Deshalb immer
einen zweiten Weg einrichten – Ersatz-Token, Wiederherstellungsphrase oder
Schwellwert-Anteile.

**Teststand:** Geprüft gegen einen Software-Token, der CTAP 2.1 mit hmac-secret
spricht, über die echte python-fido2-Bibliothek (`tests/soft_token.py`). Noch nicht
mit echter Hardware – USB-Übertragung und Geräte-Eigenheiten sind damit ungeprüft.
Vor dem ernsthaften Einsatz: einen Testcontainer mit Token anlegen, mit Token
öffnen, und zusätzlich den Ersatzweg ausprobieren.

### Schwellwert: k von n Anteilen

```bash
tres0r pack Nachlass/ --shares 2/3 --shares-dir anteile/     # 3 Anteile, je 2 öffnen
tres0r unpack Nachlass.tres0r --shares-file a1.txt --shares-file a3.txt
tres0r keys add-shares backup.tres0r 3/5                    # auch nachträglich
```

Shamirs Secret Sharing über GF(2⁸): Beliebige k Anteile öffnen den Container,
k−1 verraten nichts darüber. Typisch: je ein Anteil an Vertrauenspersonen oder an
getrennte Orte. Wer mit Anteilen öffnet, wird nicht nach einem Passwort gefragt.
Die Anteile gibt es nur beim Erzeugen – `--shares-dir` legt sie als einzelne
Dateien (0600) ab, sonst werden sie einmal angezeigt.

### Signaturen

```bash
tres0r keygen --sign -o ~/.config/tres0r/server-sign.key   # Ed25519, gibt tres0r-sig-… aus

# Auf dem Server: für dich verschlüsseln und signieren
tres0r pack /srv/daten -r tres0r-pub-… --no-password --sign server-sign.key

# Bei dir: nur annehmen, was wirklich vom Server kommt
tres0r verify daten.tres0r -i nas.key --signer tres0r-sig-…
tres0r unpack daten.tres0r -i nas.key --signer tres0r-sig-…
```

Wer deinen öffentlichen Schlüssel kennt, kann dir Container unterschieben – etwa
ein ausgetauschtes Backup. Mit `--signer` nimmt tres0r nur Container an, die der
angegebene Schlüssel signiert hat (Exit-Code 3 sonst). Die Signatur deckt den
gesamten Inhalt ab: Auch ein anderer Empfänger desselben Containers, der den
Datenschlüssel kennt, kann nichts unbemerkt ändern. Keyslots sind bewusst nicht
signiert – Schlüssel hinzufügen oder entfernen bricht die Signatur nicht.
Geprüft wird beim vollständigen Lesen (`verify`, `unpack`, `decrypt`); beim
Entpacken landet nichts im Ziel, bevor die Signatur stimmt.

### Datenströme

```bash
pg_dump db | tres0r encrypt -o db.tres0r -r tres0r-pub-… --no-password -z
tres0r decrypt db.tres0r -i nas.key | psql db
tar c Projekt | ssh nas 'tres0r encrypt -o /backup/projekt.tres0r -R ~/.tres0r-empfaenger'
tres0r decrypt backup.tres0r --password-file pw | tar t     # tar-Stream eines Datei-Containers
ssh nas cat /backup/projekt.tres0r | tres0r unpack - -o wiederhergestellt/
```

`unpack -` entpackt direkt aus einer Pipe – mit Namensschutz, `data`-Filter und
Signaturprüfung, anders als `decrypt | tar x`. Ohne wahlfreien Zugriff gibt es dabei
kein Inhaltsverzeichnis und keine Speicherplatzprüfung; nichts landet im Ziel,
bevor der Container vollständig geprüft ist.

Bei Pipes fließen die Daten, bevor der Abschluss geprüft ist – ein abgeschnittener
oder manipulierter Container zeigt sich erst am **Exit-Code 3**. In Skripten also
`set -o pipefail` verwenden und das Ergebnis erst bei Exit-Code 0 übernehmen.
Passwortabfragen laufen über das Terminal, auch wenn stdin die Daten liefert.

### Vergleichen: Ist das Backup noch aktuell?

```bash
tres0r diff backup.tres0r Projekt/ -x '*.tmp'     # dieselben Pfade und Muster wie beim Packen
tres0r diff backup.tres0r Projekt/ --quick         # nur Größe + Änderungszeit, wie rsync
```

`diff` vergleicht über das Inhaltsverzeichnis und meldet `neu`, `entfernt`,
`geändert`, `typ` (z. B. Datei → Ordner) und `link`; mit `--times` auch reine
Zeitunterschiede. Dateien gleicher Größe werden per SHA-256 verglichen. Exit-Code 0
heißt „identisch“, 4 „Unterschiede gefunden“ – praktisch für Cron-Jobs, die nur bei
Bedarf neu packen.

### Anhängen: append

```bash
tres0r append Backup.tres0r Projekt/neue-datei.txt Fotos/2026/   # nur das Neue wird verschlüsselt
tres0r append Backup.tres0r Projekt/ --sign ich.key -z           # auch signiert/komprimiert
tres0r repair Backup.tres0r                                       # nach Stromausfall beim Anhängen
```

Neue Dateien kommen als eigenständig verschlüsseltes **Segment** ans Ende – der
Bestand wird weder gelesen noch neu verschlüsselt, der Aufwand hängt nur von den
neuen Daten ab. Gleiche Namen: **die neuere Fassung gilt** (`list`, `unpack`,
`mount`, `diff`); `list --json` zeigt das Segment je Eintrag. `verify` prüft jedes
Segment vollständig; mit `--signer` muss **jedes** Segment gültig signiert sein.

Absturzsicherheit: Ein Journal neben dem Container hält den Stand vorher fest; bei
Abbruch oder Fehler wird sofort zurückgekürzt, nach einem Stromausfall stellt
`repair` einen gültigen Stand her (fertig geschriebenes Anhängen abschließen, sonst
zurücksetzen). Nach jedem Anhängen wird die vorherige Segmenttabelle entwertet – wer
die Datei auf einen früheren Stand abschneidet, erhält keinen gültigen Container.
Eine vollständige ältere Kopie lässt sich naturgemäß nicht als „veraltet“ erkennen.

Grenzen: nicht für aufgeteilte (`--split`) und Rohdaten-Container, nicht aus einer
Pipe entpackbar (die Segmenttabelle steht am Ende); ältere tres0r-Versionen lehnen
Container mit Segmenten ab (unbekanntes Header-Flag).

### Aufteilen: --split

```bash
tres0r pack Archiv/ --split 4G           # Archiv.tres0r.001, .002, … (je 4 GiB)
tres0r verify Archiv.tres0r              # Basisname oder beliebiger Teil
cat Archiv.tres0r.* | tres0r unpack -    # Teile sind nur aneinandergehängte Bytes
```

Für FAT32-Sticks, Cloud-Upload-Grenzen oder DVDs. Das Format bleibt unverändert:
Die Teile hintereinander ergeben den normalen Container. Alle Befehle nehmen den
Basisnamen oder einen Teil; ein fehlender Teil wird mit Nummer gemeldet, ein
abgeschnittener fällt bei der Prüfung auf. Schlüsseländerungen behalten die
Aufteilung. Größen: `4G`/`700M` (1024er), `650MB` (1000er), mindestens 1 MiB.

### Einhängen: mount

```bash
tres0r mount Backup.tres0r ~/tresor     # schreibgeschützt, bis Strg+C
tres0r umount ~/tresor                  # von einem anderen Terminal aus
tres0r mount Backup.tres0r ~/tresor --verify --signer tres0r-sig-…
```

Dateien direkt im Dateimanager ansehen, ohne alles zu entpacken. Braucht
`pip install 'tres0r-crypt[mount]'` und libfuse2 (`apt install libfuse2t64`) bzw.
macFUSE. Jeder gelesene Chunk ist authentifiziert; fortlaufendes Lesen ist schnell,
Sprünge zurück beginnen am Dateianfang neu. Dateirechte sind im
Inhaltsverzeichnis nicht gespeichert – Dateien erscheinen als 0444. Die Signatur
wird nur mit `--verify`/`--signer` (vorab, vollständig) geprüft.

### Beschädigte Container retten

`salvage` holt aus einem beschädigten Container alles, was noch vollständig und
authentisch ist – der Header muss sich dafür entsperren lassen:

* **Mit Inhaltsverzeichnis** wird jeder Eintrag einzeln über seinen Einstiegspunkt
  gelesen. Ein gekipptes Bit kostet nur die Dateien, die den betroffenen Chunk
  berühren (bei Kompression: den betroffenen zstd-Frame, höchstens ca. 1 MiB).
  Jede gerettete Datei wird per SHA-256 gegengeprüft.
* **Ohne lesbares Inhaltsverzeichnis** (abgebrochenes Kopieren, Format v1) wird der
  Reihe nach bis zur ersten beschädigten Stelle gerettet; die Datei, in der sie
  liegt, wird verworfen – halbe Dateien gibt es nicht.

Exit-Code 0 heißt „alles gerettet“, 3 „teilweise gerettet“ (Details in der Ausgabe
bzw. mit `--json`). Reparaturdaten à la par2 erzeugt tres0r nicht; wer Bitfäule auf
dem Speichermedium fürchtet, kann zusätzlich `par2 create` über den Container laufen
lassen.

### Skripte, Cron, JSON

Jeder Befehl versteht `--json`: stdout enthält dann genau ein JSON-Objekt, Status
und Fortschritt entfallen. Bei `pack -g … --json` steht das generierte Geheimnis
im JSON – diese Ausgabe also nicht loggen.

| Exit-Code | Bedeutung |
|-----------|-----------|
| 0 | OK |
| 1 | Fehler oder Abbruch, auch Bedienfehler wie eine unbekannte Option (und: `checkpass` hat Probleme gefunden) |
| 2 | falsches Passwort bzw. kein passender Schlüssel |
| 3 | Container beschädigt, manipuliert oder mit unsicherem Inhalt; Signatur fehlt/falsch |
| 4 | `diff`: Unterschiede gefunden |
| 130 | Strg+C |

```bash
# Nächtlicher Backup-Check
tres0r verify /mnt/nas/backup.tres0r --password-file ~/.config/tres0r/pw --json \
  > /var/log/tres0r-check.json || notify-send "Backup-Check fehlgeschlagen"
```

## Für Frontends: Fortschritt und Abbruch

Alle langen Funktionen nehmen `progress=` – eine Funktion `(erledigt, gesamt)` oder
einen `Monitor` mit Ereignissen (Phase, aktuelle Datei, Durchsatz, Restzeit) und
einem threadsicheren `CancelToken`:

```python
from tres0r import CancelToken, Monitor, create

token = CancelToken()
monitor = Monitor(lambda ev: print(ev.phase, ev.fraction, ev.item, ev.eta), cancel=token)
create(["Projekt"], "p.tres0r", "passwort", progress=monitor)   # token.cancel() bricht ab
```

Ein Abbruch räumt auf wie jeder Fehler: keine halben Container, beim Entpacken bleibt
der Zielordner unberührt. Die Argon2-Ableitung selbst ist nicht unterbrechbar (C-Code);
geprüft wird direkt davor und danach.

## Auswahl: Ausschlussmuster

```
*.tmp          ohne "/": passt auf den Namen in jeder Tiefe
build/         "/" am Ende: nur Ordner (samt Inhalt)
Projekt/docs   mit "/": Pfad, wie ihn `tres0r list` zeigt
/notizen.txt   führender "/": nur direkt in der Wurzel
```

Quellen: `-x MUSTER` (mehrfach), `--exclude-from DATEI`, `--exclude-junk`
(`.DS_Store`, `Thumbs.db`, `desktop.ini`, `__pycache__/`, Office-Sperrdateien …)
und eine `.tres0rignore` direkt in einem Quellordner (Muster relativ zu diesem
Ordner, abschaltbar mit `--no-ignore-file`). Groß-/Kleinschreibung zählt auf allen
Systemen gleich. Explizit angegebene Quellen werden nie ausgeschlossen.

## Portable Dateinamen

Unter Linux ist fast jeder Name erlaubt – beim Entpacken unter Windows oder macOS
drohen aber Probleme. `pack` warnt vor:

* unter Windows reservierten Namen (`CON`, `NUL`, `COM1`, auch `aux.txt`),
  verbotenen Zeichen (`< > : " \ | ? *`), Punkt/Leerzeichen am Namensende, sehr
  langen Pfaden
* Namen, die sich nur in Groß-/Kleinschreibung (`Datei.txt`/`datei.txt`) oder
  Unicode-Form (NFC/NFD) unterscheiden – unter Windows/macOS würde die zweite
  Datei die erste **still überschreiben**

`--strict-names` bricht stattdessen ab. Beim Entpacken erkennt tres0r solche
Kollisionen direkt am Dateisystem und bricht ab; mit `--rename` wird umbenannt
(`datei (1).txt`, unter Windows `CON.txt` → `CON_.txt`). Die Umbenennungen werden
aufgelistet.

## Stufen

Die Stufen ändern **nicht** den Cipher, sondern nur die Kosten der
Schlüsselableitung – also wie teuer jeder Rateversuch für einen Angreifer ist.

| Stufe   | Argon2id                | gemessen (1 CPU-Kern) | RAM beim Öffnen |
|---------|-------------------------|-----------------------|-----------------|
| schnell | 64 MiB, t=3, p=4        | ca. 0,2 s             | 64 MiB          |
| normal  | 256 MiB, t=4, p=4       | ca. 1,1 s             | 256 MiB         |
| stark   | 1 GiB, t=4, p=4         | ca. 5 s               | 1 GiB           |

Die Parameter stehen im Header. Der Rechner, der **entschlüsselt**, braucht
denselben RAM – ein „stark“-Container lässt sich auf einem Gerät mit sehr wenig
Speicher unter Umständen nicht öffnen. `tres0r bench` zeigt die Werte für den
eigenen Rechner.

Den größten Einfluss hat trotzdem das Passwort. Eine generierte Passphrase mit
8 Wörtern (≈ 103 Bit) ist auch in Stufe „schnell“ praktisch nicht zu erraten.

Mit `-l auto` misst tres0r diesen Rechner und wählt Argon2-Parameter für eine
Zielzeit (`--kdf-time`, Standard 2 s): so viel Speicher wie möglich – höchstens
1 GiB und ein Viertel des freien RAMs, weil der öffnende Rechner genauso viel
braucht –, dann so viele Iterationen, wie in die Zielzeit passen. `tres0r bench`
zeigt den Vorschlag, ohne etwas zu verschlüsseln.

**Kalibriert wird für den Rechner, auf dem gepackt wird.** Ein Beispiel aus echten
Messungen: `-l auto` ergibt auf einem schnellen Rechner (DDR5) 1 GiB mit t=12 für
2 s – derselbe Container braucht auf einem älteren Rechner (DDR4) zum Öffnen etwa
6 s. Werden Container auf mehreren Rechnern geöffnet, auf dem langsamsten
kalibrieren (`tres0r bench` zeigt dort den passenden Vorschlag) oder eine feste
Stufe wählen.

## Leistung

`--threads N` (pack, verify, diff, upgrade, encrypt; Standard: Anzahl Kerne,
höchstens 8) verteilt Arbeit, wo es nachweislich etwas bringt:

* **SHA-256 auf einem zweiten Kern**, parallel zur Verschlüsselung. Gemessen:
  `hashlib` gibt Pythons GIL frei, `cryptography`s ChaCha20-Poly1305 hält ihn
  weitgehend – die Verschlüsselung selbst lässt sich daher nicht sinnvoll auf
  Threads verteilen.
* **zstd-Worker** (C, unabhängig vom GIL) – vor allem bei großen Dateien.
* **`diff`** hasht mehrere Dateien gleichzeitig.

Wie viel das auf deinem Rechner bringt, zeigt
`tres0r bench --throughput [--dir /pfad/zum/ziel] [--size 1024]` (pack/verify mit 1
Thread und automatisch, mit und ohne zstd). Ist `/tmp` ein tmpfs (Standard bei
neueren Debian-Versionen), liegen die Testdaten im RAM und die Zahlen zeigen die
CPU; `--dir` auf dem echten Zieldatenträger bezieht Platte bzw. NAS mit ein.

Gemessen (258 MiB, halb komprimierbar): auf 24 Kernen/DDR5 pack 620 → 845 MiB/s und
verify 798 → 1382 MiB/s mit Threads, auf 4 Kernen/DDR4 pack 218 → 253 und verify
251 → 313 MiB/s. Beim Prüfen komprimierter Container begrenzt die zstd-Dekompression
(ein Kern). Ein großer Teil der Zeit beim Packen ist
`fsync` – das Warten darauf, dass die Daten wirklich auf dem Datenträger liegen.

## Metadaten

| Option | Wirkung |
|---|---|
| `pack --no-times` | keine Änderungszeiten speichern (Zeit 0); beim Entpacken gilt die aktuelle Zeit |
| `pack --xattrs` / `unpack --xattrs` | erweiterte Attribute `user.*` sichern/wiederherstellen (Linux) |
| `pack --acls` / `unpack --acls` | POSIX-ACLs sichern/wiederherstellen (Linux) |

Wiederhergestellt wird nur mit dem jeweiligen Schalter und nur aus diesen beiden
Bereichen – nie `security.*` (z. B. Datei-Capabilities) oder `trusted.*`, auch nicht
aus präparierten Containern. Lässt sich ein Attribut im Ziel nicht setzen (etwa ein
Dateisystem ohne ACLs), gibt es eine Warnung statt eines Abbruchs. Besitzer und
Gruppen werden grundsätzlich nicht gespeichert.

## pwgen-Integration

`tres0r/pwgen.py` ist eine **unveränderte** Kopie von pwgen.py, die Wortlisten
sind dieselben. `tres0r/passgen.py` ist nur eine dünne Schicht darüber
(strukturierte Rückgaben, exakte Entropie, NFC-Normalisierung, Fehler-Mapping).
Zum Aktualisieren pwgen.py ersetzen – `tests/test_passgen.py` enthält einen
Vertragstest, der meldet, wenn sich eine genutzte Schnittstelle ändert.

## Passwort-Prüfung (HIBP)

Beim Festlegen eines Passworts fragt tres0r – in CLI, Text- und grafischer Oberfläche –
die Pwned-Passwords-API ab (abschaltbar mit `--offline` bzw. per Schalter oder
Häkchen). Übertragen werden nur die ersten **5 Hex-Zeichen**
des SHA-1-Hashes (k-Anonymität); mit `Add-Padding` ist auch die Antwortgröße
unabhängig vom Präfix. Ist die API nicht erreichbar, gibt es einen Hinweis statt
eines Abbruchs.

Für selbst gewählte Passwörter zeigt tres0r bewusst **keine** Entropie-Schätzung –
Heuristiken überschätzen menschliche Passwörter massiv. Exakte Entropie gibt es nur
für generierte Geheimnisse.

## Format (Version 2)

```
Header (Klartext, variabel lang)
  "TRS0" | Version 2 | Länge | Nutzdatentyp | Kompression | Flags | Stream-Nonce(16)
  | Anzahl Keyslots | Keyslots (Typ, Länge, Inhalt) … | HMAC-SHA256(32)
Payload (ChaCha20-Poly1305-Chunks à 64 KiB, Nonce = 11 Byte Zähler + Abschluss-Flag)
  Blöcke [u32 Länge][Daten] … [u32 0]   Daten = tar- bzw. Rohdatenstrom, ggf. zstd-Frames
  Nullbytes bis zur Padmé-Größe
  Inhaltsverzeichnis: zlib(JSON) | u64 Länge | "TRS0IDX\x01"
```

* Zufälliger Datenschlüssel (DEK); jeder Keyslot verschlüsselt ihn unter eigenem KEK:
  Passwort → Argon2id, Wiederherstellungsphrase → HKDF, X25519 → ephemerer
  Diffie-Hellman + HKDF. Typ 4 ist für einen Post-Quanten-Hybrid reserviert,
  unbekannte Typen werden übersprungen und beim Umschreiben erhalten.
* `HMAC-SHA256(HKDF(DEK), Header)` schützt alle Header-Felder und bindet den
  Header an genau einen DEK (Key-Commitment, siehe unten).
* `Payload-Key = HKDF-SHA256(DEK, salt=Stream-Nonce)`.
* Einstiegspunkte: Jeder Chunk ist über seinen Zähler einzeln entschlüsselbar. Das
  Inhaltsverzeichnis speichert je Eintrag Blockoffset, Überspring-Bytes, Größe,
  mtime und SHA-256. Bei Kompression beginnt spätestens alle 1 MiB ein neuer zstd-Frame.
* UID/GID und Benutzernamen im tar werden auf 0/leer gesetzt.
* Container der Version 1 (0.1/0.2) werden weiterhin gelesen, nicht mehr geschrieben.

Details: Docstrings in `tres0r/header2.py`, `tres0r/payload.py` und `tres0r/stream.py`.

## Sicherheitseigenschaften

* Verändern, Vertauschen, Duplizieren, Abschneiden oder Verlängern des Containers
  wird erkannt (siehe `tests/test_stream.py`, `tests/test_container.py`).
* **Key-Commitment:** ChaCha20-Poly1305 bindet einen Chiffretext nicht fest an einen
  Schlüssel; ein präparierter Keyslot könnte unter mehreren Passwörtern „gültig“
  entschlüsseln (Partitioning-Oracle-Angriffe). Weil der Header-MAC aus dem DEK
  abgeleitet ist, passt er höchstens zu einem davon – erst dann gilt ein Container
  als entsperrt.
* Keyslot-Anzahl (16) und Passwort-Slots (4) sind begrenzt, ebenso Argon2-Parameter,
  Blockgrößen, JSON-Tiefe und -Größe des Inhaltsverzeichnisses und die Ausgabemenge
  pro zstd-Schritt (gegen präparierte Container als DoS).
* Vor jeder Schlüsselableitung prüft tres0r den verfügbaren Arbeitsspeicher und
  bricht mit einer klaren Meldung ab, statt den Rechner in den OOM-Killer zu treiben.
* Linux-Dateinamen ohne gültiges UTF-8 (z. B. alte Latin-1-Namen) werden unverändert
  gesichert und wiederhergestellt; `pack` warnt, weil andere Systeme sie anders
  darstellen, und `unpack --rename` deutet sie unter Windows als Latin-1.
* Entpackt wird in einen Staging-Ordner; erst nach vollständiger Authentifizierung
  wird verschoben. Bei jedem Fehler bleibt der Zielordner unverändert.
* tar-`data`-Filter: keine Pfade außerhalb des Ziels, keine Links nach außen,
  keine Gerätedateien, keine setuid-Bits.
* Präparierte Header können keine absurden Argon2-Kosten erzwingen (Obergrenzen).
* Container und temporäre Dateien entstehen mit Rechten `0600`, geschrieben wird
  atomar über `os.replace`.
* **Größen-Padding (Padmé):** Ohne Padding verrät die Containergröße die exakte
  Datenmenge. tres0r füllt nach dem tar-Ende mit Nullbytes auf eine von wenigen
  möglichen Größen auf (im Mittel ca. 1 %, maximal ca. 6 % Overhead; zwischen 1 und
  2 GiB gibt es nur 33 mögliche Größen). Das Padding ist Teil des authentifizierten
  Streams und ändert das Format nicht. Abschaltbar mit `--no-pad`.
* Freier Speicherplatz wird vor `pack`, `unpack` und `passwd` geprüft
  (abschaltbar mit `--no-space-check`, z. B. bei Netzlaufwerken mit unzuverlässigen
  Angaben).

## Grenzen (ehrlich)

* `list` und `unpack --only` lesen nur das Inhaltsverzeichnis bzw. die benötigten
  Teile (jeweils authentifiziert). Eine Vollprüfung macht `verify` oder ein
  vollständiges `unpack`.
* Kompression kann über die Containergröße etwas über den Inhalt verraten; das
  Padding mildert das, beseitigt es aber nicht.
* Kein Post-Quanten-Schutz für X25519-Empfänger (Passwörter und Phrasen sind davon
  nicht betroffen).

* Python kann Schlüssel nicht zuverlässig aus dem RAM löschen.
* Originale werden nicht „sicher gelöscht“ – auf SSDs ist das nicht verlässlich machbar.
* Einzelzugriff (`unpack --only`, `mount`) nutzt das Inhaltsverzeichnis; innerhalb
  komprimierter Frames wird ab dem Frame-Anfang gelesen, ein Sprung zurück beginnt neu.
* Dateinamen, die unter Windows ungültig sind (z. B. mit `:`), bricht `unpack` dort
  sauber ab – oder benennt sie mit `--rename` um.
* Eigenes Format ohne externes Audit – die Primitive stammen aber komplett aus
  `cryptography`, nichts ist selbst implementiert.

## Tests, Fuzzing, Spezifikation

```bash
pip install -e ".[dev,zstd,tui,gui,fido2,mount]"
python -m pytest -q                                   # alles (ca. 1 min)
TRES0R_TEST_CPUS=4 python -m pytest -q                # dieselben Tests über die Mehrkern-Pfade
HYPOTHESIS_PROFILE=fuzz python -m pytest tests/test_properties.py   # gründlich (ca. 4 min)
python -m tres0r.docgen                               # Manpage, Vervollständigung, API.md neu
python tests/api_surface.py                           # öffentliche API gegen den Schnappschuss
```

Die CI (`.github/workflows/ci.yml`) führt das bei jedem Push unter Python 3.10–3.14
aus, dazu eine Minimalinstallation, den Paket-Build samt Tests aus dem Quellpaket und
die Tests unter Windows und macOS (dort ohne GUI und FUSE). `fuzz.yml` fuzzt
wöchentlich. Mehr zum Mitmachen in [`CONTRIBUTING.md`](CONTRIBUTING.md).

* **Spezifikation:** [`FORMAT.md`](FORMAT.md) beschreibt das Format vollständig und
  unabhängig vom Code. `tests/reference_decoder.py` ist ein zweiter Leser, der nur
  nach diesem Dokument geschrieben ist und nichts aus tres0r importiert.
* **Testvektoren:** `tests/vectors/*.json` (v1 und v2, alle Slot-Typen, mit und ohne
  zstd, leerer Datenstrom). Beide Leser müssen sie öffnen; die Vektoren ohne
  Kompression entstehen byte-genau neu (`python tests/vectors/generate.py`).
* **Property-Tests (Hypothesis):** Parser liefern bei beliebigen Eingaben nur
  tres0r-Fehler; jede Änderung an einem Container schlägt fehl und hinterlässt nichts.
* **Fuzzing (atheris/libFuzzer, Linux):**

  ```bash
  pip install -e ".[fuzz]"
  python fuzz/make_seeds.py
  python fuzz/fuzz_container.py fuzz/corpus/container -max_total_time=600
  python fuzz/fuzz_header.py fuzz/corpus/header -max_total_time=300
  python fuzz/fuzz_text.py fuzz/corpus/text -max_total_time=300
  ```

  `fuzz_container` verpackt die Fuzz-Eingabe als *gültig verschlüsselte* Nutzdaten
  und testet damit alles hinter der Kryptografie (Blöcke, zstd, tar, Index,
  Namensschutz, `salvage`, `upgrade`) – die Angriffsfläche eines böswilligen
  Absenders, der das Passwort kennt oder einen öffentlichen Schlüssel nutzt.

## Lizenzen

tres0r steht unter der **MIT-Lizenz** (`LICENSE`): nutzen, verändern, weitergeben
und verkaufen ist erlaubt, auch in geschlossener Software – Bedingung ist nur, dass
der Lizenztext mit dem Copyright-Hinweis in Kopien erhalten bleibt. Ohne Gewähr.

Die Wortlisten behalten ihre eigenen Lizenzen, siehe `tres0r/wordlists/LICENSES.md`
(EFF-Liste unter CC BY 3.0 US, deutsche Liste unter Unlicense/CC0/BSD-3).
Abhängigkeiten: cryptography (Apache-2.0/BSD), optional argon2-cffi (MIT),
zstandard (BSD), python-fido2 (BSD-2-Clause), fusepy (ISC).
