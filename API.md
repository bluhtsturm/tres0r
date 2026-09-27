# tres0r – Python-API (stabil, 1.x)

Diese Datei ist aus dem Code erzeugt (`python -m tres0r.docgen`); die Signaturen
sind zusätzlich per Test eingefroren (`tests/api_surface.json`).

## Stabilitätsversprechen

Stabil sind die Namen in `__all__` der Module unten. In allen 1.x-Versionen gilt:

* Keine öffentlichen Namen werden entfernt oder umbenannt; die Reihenfolge
  positioneller Parameter bleibt, neue Pflichtparameter gibt es nicht.
* Erlaubt sind neue Namen, neue optionale Schlüsselwort-Parameter und neue Felder
  (mit Standardwert) in Ergebnisklassen.
* Die Fehlerhierarchie bleibt; neue Unterklassen sind möglich. Alle Fehler erben
  von `Tres0rError`.
* Verhalten ändert sich nur bei Fehlerkorrekturen. Das Containerformat folgt
  FORMAT.md (Spezifikation 1.0).

**Intern** (ohne Zusage, auch in Unterversionen änderbar): alle übrigen Module
(`container`, `header`, `header2`, `stream`, `payload`, `sign`, `segments`,
`volumes`, `kdf`, `workers`, `portability`, `exclude`, `padding`, `rng`, `cli`,
`docgen`, `pwgen`, `tui`, `gui`) und alle Namen mit führendem `_`. Was davon gebraucht wird,
ist über `tres0r` erreichbar.

**Kommandozeile:** Befehle, Optionen und Exit-Codes sind ebenso stabil. Bei
`--json` behalten vorhandene Schlüssel ihre Bedeutung, neue können hinzukommen;
Fehler kommen als `{"error": {"type": …, "message": …}}`. Die menschenlesbare
Ausgabe ist nicht zum Auswerten gedacht.

**Threads und Fortschritt:** Lange Funktionen nehmen `progress=` (Funktion
`(erledigt, gesamt)` oder `Monitor`) und prüfen ein `CancelToken`. Mit mehreren
Threads können Ereignisse aus Arbeitsthreads kommen – Oberflächen reichen sie in
ihren eigenen Thread weiter.

## Gemeinsame Parameter

Diese Namen bedeuten in allen Funktionen dasselbe:

* `container` – Pfad des Containers (bei --split der Basisname oder ein Teil).
* `sources` – Pfade (Dateien/Ordner) oder ein `Plan` aus `scan`.
* `plan` – Ergebnis von `scan`.
* `output` – Zielpfad.
* `dest` – Zielordner; entsteht bei Bedarf.
* `path` – Pfad.
* `src` – Lesbares Binär-Dateiobjekt.
* `out` – Beschreibbares Binär-Dateiobjekt.
* `credentials` – Zugangsdaten: Passwort/Phrase (str, bytes) oder `Credentials` (Passwörter, Identitäten, Keyfiles, Anteile, FIDO2).
* `password` – Passwort für den neuen Passwort-Slot; `None` = keiner.
* `params` – Argon2id-Parameter (`KdfParams`, z. B. `LEVELS["normal"]`); `None` = Standard bzw. unverändert.
* `recipients` – Öffentliche X25519-Schlüssel; jeder bekommt einen eigenen Slot.
* `recovery` – Wiederherstellungsphrase (`keys.generate_recovery`) als eigener Slot.
* `keyfile` – Keyfile-Geheimnis (`keys.keyfile_secret`) – zweiter Faktor zum Passwort.
* `fido2` – `hwtoken.TokenProvider` – FIDO2-Token als zweiter Faktor zum Passwort.
* `threshold` – `(k, n)` – Schwellwert-Slot; die Anteile stehen im Ergebnis (`shares`).
* `compress` – Mit zstd komprimieren (Python 3.14 oder Paket `zstandard`).
* `pad` – Padmé-Padding: verbirgt die genaue Größe (Standard an).
* `sign_with` – Ed25519-Signaturschlüssel (`keys.generate_signing_key`).
* `signers` – Erwartete Prüfschlüssel: fehlt die Signatur oder passt keiner, folgt `SignatureError`.
* `overwrite` – Vorhandene Ausgabe ersetzen (sonst Fehler).
* `progress` – Fortschritt: Funktion `(erledigt, gesamt)` oder `Monitor` (Ereignisse, Abbruch).
* `exclude` – `ExcludeRules` (Muster, typische Junk-Dateien).
* `ignore_files` – `.tres0rignore`-Dateien in den Quellen beachten (Standard an).
* `strict_names` – Abbrechen statt warnen, wenn Namen nicht auf allen Systemen gültig sind.
* `check_space` – Freien Speicherplatz vorher prüfen (`InsufficientSpace`).
* `times` – Änderungszeiten speichern (`False`: Zeit 0, beim Entpacken die aktuelle Zeit).
* `xattrs` – Erweiterte Attribute `user.*` sichern bzw. wiederherstellen (Linux).
* `acls` – POSIX-ACLs sichern bzw. wiederherstellen (Linux).
* `threads` – Threads für SHA-256 und zstd; `None` = automatisch (Kerne, max. 8), `1` = aus.
* `split` – Teilgröße in Byte für `NAME.001 …`; `None` = eine Datei.
* `rename` – Kollidierende oder hier ungültige Namen umbenennen statt abbrechen.
* `only` – Muster: nur passende Einträge (samt Inhalt passender Ordner).
* `total` – Erwartete Größe in Byte – für Fortschritt und Restzeit.
* `passphrase` – Passphrase einer geschützten Schlüsseldatei.

## `tres0r`

### `SUFFIX`

`'.tres0r'`

### `scan(sources, *, exclude=None, ignore_files=True, output=None, progress=None)`

Quellen durchlaufen und festlegen, was in den Container kommt.

* ``exclude`` passt auf Pfade, wie ``tres0r list`` sie zeigt ("Projekt/build").
* Eine ``.tres0rignore`` direkt in einem Quellordner gilt relativ zu diesem.
* Explizit angegebene Quellen werden nie ausgeschlossen.

### `plan_sources(sources)`

Quellen prüfen und ihre Namen im Container bestimmen (ohne Durchlaufen).

### `estimate_size(plan, pad=True)`

Obere Schätzung der Containergröße in Byte (ohne Kompression gerechnet).

### `check_free_space(directory, needed, purpose)`

InsufficientSpace, wenn ``needed`` Byte (+ Reserve) nicht frei sind.

Netzlaufwerke oder Dateisysteme mit Kompression melden mitunter
unzuverlässige Werte – Frontends sollten die Prüfung abschaltbar machen.

``directory``: Ordner auf dem Zieldatenträger; ``needed``: Byte; ``purpose``: Text für die Fehlermeldung ("für …").

### `format_size(n)`

Bytezahl menschenlesbar (``1536`` -> ``"1.5 KiB"``).

### `atomic_output(path, *, overwrite=False, split=None)`

Datei (oder mit ``split`` einen Teilesatz) erst nach Erfolg an ihren Platz
bringen; bei Fehlern bleiben keine Reste. Beim Überschreiben verschwinden auch
Teile, die ein früherer, anders aufgeteilter Container hinterlassen hat.

### `create(sources, output, password, params=None, *, recipients=(), recovery=None, keyfile=None, threshold=None, fido2=None, compress=False, sign_with=None, overwrite=False, progress=None, exclude=None, pad=True, strict_names=False, check_space=True, times=True, xattrs=False, acls=False, threads=None, split=None)`

Dateien/Ordner in einen neuen verschlüsselten Container packen (Format v2).

``sources`` ist eine Pfadliste oder ein vorab erstellter ``Plan``. Keyslots:
``password`` (Argon2id mit ``params``), ``recovery`` (generierte Phrase,
siehe keys.generate_recovery) und beliebig viele X25519-``recipients``.

Metadaten: ``times=False`` speichert keine Änderungszeiten (0 = "unbekannt";
beim Entpacken gilt dann die aktuelle Zeit). ``xattrs``/``acls`` übernehmen
user.*-Attribute bzw. POSIX-ACLs (nur Linux). ``threads``: SHA-256 im
Hintergrund und zstd-Worker (None = automatisch, 1 = aus).
Geschrieben wird in eine temporäre Datei im Zielordner, die erst nach
vollständigem Erfolg per atomarem os.replace() umbenannt wird.

### `append(container, sources, credentials, *, exclude=None, ignore_files=True, compress=False, sign_with=None, pad=True, progress=None, strict_names=False, check_space=True, times=True, xattrs=False, acls=False, threads=None)`

Dateien als neues Segment an einen v2-Container anhängen – an Ort und Stelle.

Nur die neuen Daten werden verschlüsselt und geschrieben; der Bestand bleibt
unberührt. Gleiche Namen: die neue Fassung gilt (list/unpack/mount/diff).
Absturzsicher über ein Journal neben dem Container; bei einer Exception
(auch Abbruch) wird die Datei sofort auf den alten Stand gekürzt.

### `inspect(container)`

Header-Informationen lesen – ohne Passwort. Bei v2 sind die Angaben erst
nach dem Entsperren durch die Header-MAC bestätigt.

### `list_contents(container, credentials, *, progress=None)`

Inhaltsverzeichnis. Bei v2 aus dem Index – dafür werden nur die letzten
Chunks entschlüsselt. Vollständig prüft ``verify``.

### `verify(container, credentials, *, progress=None, signers=None, threads=None)`

Container vollständig prüfen, ohne etwas zu schreiben.

Authentifiziert jeden Chunk inkl. Padding und Index. Bei v2 mit Index wird
zusätzlich jeder tar-Eintrag mit dem Inhaltsverzeichnis abgeglichen
(Name, Typ, Größe, SHA-256). Ist der Container signiert, wird die Signatur
geprüft; ``signers`` verlangt zusätzlich einen dieser Unterzeichner.
Ohne Exception ist der Container intakt.

### `extract(container, dest, credentials, *, progress=None, rename=False, check_space=True, only=None, signers=None, xattrs=False, acls=False)`

Container in ``dest`` entpacken.

Entpackt wird zunächst in einen versteckten Staging-Ordner innerhalb von
``dest``; erst danach werden die Einträge an ihren Platz verschoben. Bei
jedem Fehler bleibt ``dest`` unverändert.

``only``: Muster (fnmatch) für Pfade; ein passender Ordner bringt seinen
Inhalt mit. Bei v2 springt tres0r über den Index direkt zu den Einträgen
und prüft dabei nur die gelesenen Chunks (plus den Abschluss) – für eine
Vollprüfung ``verify`` verwenden. Ohne ``only`` wird immer alles geprüft.

Namenskollisionen und (unter Windows) ungültige Namen führen zum Abbruch
(NameConflict) oder mit ``rename=True`` zum Umbenennen.

Signatur: Beim vollständigen Lesen wird sie geprüft, bevor irgendetwas im
Zielordner landet. ``signers`` verlangt einen dieser Unterzeichner – dann
wird auch mit ``only`` alles gelesen, weil nur so geprüft werden kann.

### `extract_stream(src, dest, credentials, *, progress=None, rename=False, only=None, signers=None, xattrs=False, acls=False)`

Container aus einem Datenstrom (Pipe, stdin) entpacken – mit denselben
Schutzmechanismen wie ``extract``: Staging-Ordner, Namensschutz, data-Filter,
Signaturprüfung vor dem Verschieben. Ohne wahlfreien Zugriff: kein
Inhaltsverzeichnis, keine Speicherplatzprüfung, ``only`` filtert beim Lesen.

### `diff(container, sources, credentials, *, exclude=None, ignore_files=True, quick=False, times=False, progress=None, threads=None)`

Container mit Ordnern/Dateien vergleichen – Aufruf wie bei ``create``.

Die Pfade werden genau wie beim Packen ermittelt (gleiche Namen, gleiche
Ausschlüsse), sodass "Projekt/a.txt" im Container auf "Projekt/a.txt" lokal
trifft. Dateien gleicher Größe werden per SHA-256 verglichen; ``quick``
begnügt sich wie rsync mit Größe und Änderungszeit. Reine Zeitunterschiede
meldet ``times``. Container ohne Zeitstempel (pack --no-times): ``quick``
hasht dann doch, ``times`` meldet nichts. ``threads``: Dateien parallel hashen.

### `encrypt_stream(src, out, password, params=None, *, recipients=(), recovery=None, compress=False, pad=True, sign_with=None, progress=None, total=None, threads=None, keyfile=None, threshold=None, fido2=None)`

Beliebigen Datenstrom verschlüsseln (Nutzdatentyp "roh"). Gibt die
Anzahl gelesener Bytes zurück. ``out`` bekommt den Container unmittelbar –
für Dateien mit atomic_output() kombinieren. ``total``: erwartete Größe
(für Fortschritt/Restzeit), falls bekannt.

### `decrypt_stream(src, out, credentials, *, signers=None, progress=None, total=None)`

Nutzdaten eines Containers ausgeben (roh; bei tar-Containern den tar-Stream).

Achtung bei Pipes: Die Daten fließen, bevor Abschluss und Signatur geprüft
sind. Erst ein Rücklauf ohne Exception (Exit-Code 0) bestätigt beides.

### `salvage(container, dest, credentials, *, rename=False, progress=None)`

Aus einem beschädigten Container retten, was intakt ist.

Voraussetzung: Der Header ist lesbar und lässt sich entsperren.

* Mit lesbarem Inhaltsverzeichnis (v2): jeder Eintrag einzeln über seinen
  Einstiegspunkt. Ein beschädigter Chunk kostet nur die Einträge, die ihn
  berühren; jede gerettete Datei wird per SHA-256 gegengeprüft.
* Sonst (v1, abgeschnittener Container): der Reihe nach bis zur ersten
  beschädigten Stelle; die Datei, in der sie liegt, wird verworfen.

Gerettet wird nur, was vollständig und authentisch ist. Wie bei extract
landet alles erst am Ende im Zielordner.

### `repair(container, credentials)`

Nach einem unterbrochenen Anhängen einen gültigen Stand herstellen.

* Tabelle am Ende gültig: Anhängen war fertig geschrieben – abschließen.
* Sonst mit Journal: auf den Stand davor zurücksetzen.
* Sonst: auf die letzte gültige Segmenttabelle kürzen.

### `upgrade(container, credentials, output=None, *, compress=False, pad=True, progress=None, check_space=True, threads=None, split=None)`

Container der Formatversion 1 in Version 2 umwandeln.

Läuft als Stream – es entsteht nie Klartext auf der Platte. Passwort und
Stufe bleiben gleich; neu sind Inhaltsverzeichnis, Header-MAC und optional
Kompression. Der alte Stream wird vollständig authentifiziert, bevor der neue
Container an seinen Platz kommt; ohne ``output`` wird atomar ersetzt.

### `add_keys(container, credentials, *, password=None, params=None, recovery=None, recipients=(), keyfile=None, fido2=None, check_space=True, progress=None)`

Weitere Keyslots hinzufügen. Gibt die Nummern der neuen Slots zurück.

### `add_threshold(container, credentials, k, n, *, check_space=True, progress=None)`

Schwellwert-Slot hinzufügen: k von n Anteilen öffnen den Container.
Gibt (Slotnummer, Anteile) zurück – die Anteile gibt es nur jetzt.

### `remove_key(container, credentials, slot_index, *, check_space=True, progress=None)`

Keyslot entfernen. Der letzte Slot lässt sich nicht entfernen.

``slot_index``: Nummer des Slots wie in ``inspect().slots``.

### `change_password(container, old_password, new_password, params=None, *, check_space=True, progress=None)`

Das Passwort ändern, mit dem entsperrt wurde – ohne Neuverschlüsselung.

Bei v2 wird genau der Passwort-Slot ersetzt, der zum alten Passwort passt;
ohne ``params`` behält er seine Stufe.

``old_password``: Zugangsdaten zum Entsperren (wie ``credentials``); ``new_password``: das neue Passwort. Ein zweiter Faktor (Keyfile, FIDO2) bleibt.

### `Plan` (Datenklasse)

Ergebnis von scan(): was in den Container käme.

* `entries: list[tuple[Path, str, os.stat_result]]`
* `skipped: list[str]`
* `excluded: int`
* `issues: list[portability.Issue]`

### `ContainerInfo` (Datenklasse)

ContainerInfo(path: 'Path', kdf: 'KdfParams | None', level: 'str | None', size: 'int', version: 'int' = 1, header_len: 'int' = 107, payload_type: 'str' = 'tar', compression: 'str | None' = None, has_index: 'bool' = False, slots: 'list[SlotInfo]' = <factory>, signed: 'bool' = False, volumes: 'int' = 1, segmented: 'bool' = False, interrupted: 'bool' = False)

* `path: Path`
* `kdf: KdfParams | None`
* `level: str | None`
* `size: int`
* `version: int`
* `header_len: int`
* `payload_type: str`
* `compression: str | None`
* `has_index: bool`
* `slots: list[SlotInfo]`
* `signed: bool`
* `volumes: int`
* `segmented: bool`
* `interrupted: bool`

### `SlotInfo` (Datenklasse)

SlotInfo(index: 'int', type: 'str', description: 'str', level: 'str | None' = None)

* `index: int`
* `type: str`
* `description: str`
* `level: str | None`

### `CreateResult` (Datenklasse)

CreateResult(path: 'Path', entries: 'int', size: 'int', padding: 'int' = 0, skipped: 'list[str]' = <factory>, excluded: 'int' = 0, issues: 'list[portability.Issue]' = <factory>, slots: 'list[str]' = <factory>, shares: 'list' = <factory>)

* `path: Path`
* `entries: int`
* `size: int`
* `padding: int`
* `skipped: list[str]`
* `excluded: int`
* `issues: list[portability.Issue]`
* `slots: list[str]`
* `shares: list`

### `AppendResult` (Datenklasse)

AppendResult(path: 'Path', segment: 'int', entries: 'int', size: 'int', added: 'int', skipped: 'list[tuple[str, str]]' = <factory>, excluded: 'int' = 0, issues: 'list[portability.Issue]' = <factory>)

* `path: Path`
* `segment: int`
* `entries: int`
* `size: int`
* `added: int`
* `skipped: list[tuple[str, str]]`
* `excluded: int`
* `issues: list[portability.Issue]`

### `Entry` (Datenklasse)

Entry(name: 'str', size: 'int', kind: 'str', mtime: 'int | None' = None, sha256: 'str | None' = None, segment: 'int' = 0)

* `name: str`
* `size: int`
* `kind: str`
* `mtime: int | None`
* `sha256: str | None`
* `segment: int`

### `VerifyResult` (Datenklasse)

VerifyResult(entries: 'int', files: 'int', bytes: 'int', checked_hashes: 'bool' = False, segments: 'int' = 1, signed: 'bool' = False, signer: 'str | None' = None)

* `entries: int`
* `files: int`
* `bytes: int`
* `checked_hashes: bool`
* `segments: int`
* `signed: bool`
* `signer: str | None`

### `ExtractResult` (Datenklasse)

ExtractResult(names: 'list[str]', entries: 'int', renamed: 'list[tuple[str, str]]' = <factory>, signed: 'bool' = False, signer: 'str | None' = None, warnings: 'list[str]' = <factory>)

* `names: list[str]`
* `entries: int`
* `renamed: list[tuple[str, str]]`
* `signed: bool`
* `signer: str | None`
* `warnings: list[str]`

### `EncryptResult` (Datenklasse)

EncryptResult(bytes: 'int', shares: 'list' = <factory>)

* `bytes: int`
* `shares: list`

### `DecryptResult` (Datenklasse)

DecryptResult(bytes: 'int', signed: 'bool' = False, signer: 'str | None' = None)

* `bytes: int`
* `signed: bool`
* `signer: str | None`

### `DiffEntry` (Datenklasse)

DiffEntry(name: 'str', status: 'str', detail: 'str' = '')

* `name: str`
* `status: str`
* `detail: str`

### `DiffResult` (Datenklasse)

DiffResult(changes: 'list[DiffEntry]' = <factory>, unchanged: 'int' = 0, hashed: 'int' = 0, quick: 'bool' = False)

* `changes: list[DiffEntry]`
* `unchanged: int`
* `hashed: int`
* `quick: bool`

### `SalvageResult` (Datenklasse)

SalvageResult(recovered: 'list[str]' = <factory>, damaged: 'list[tuple[str, str]]' = <factory>, names: 'list[str]' = <factory>, used_index: 'bool' = False, notes: 'list[str]' = <factory>, renamed: 'list[tuple[str, str]]' = <factory>)

* `recovered: list[str]`
* `damaged: list[tuple[str, str]]`
* `names: list[str]`
* `used_index: bool`
* `notes: list[str]`
* `renamed: list[tuple[str, str]]`

### `RepairResult` (Datenklasse)

RepairResult(action: 'str', size: 'int')

* `action: str`
* `size: int`

### `UpgradeResult` (Datenklasse)

UpgradeResult(path: 'Path', entries: 'int', size: 'int')

* `path: Path`
* `entries: int`
* `size: int`

### `Credentials` (Datenklasse)

Alles, womit ein Container entsperrt werden kann.

``prompt`` wird nur aufgerufen, wenn Identitäten nicht gereicht haben und
der Container Passwort- oder Wiederherstellungs-Slots hat.

* `passwords: list[str | bytes]`
* `identities: list[X25519PrivateKey]`
* `prompt: Callable[[], str] | None`
* `keyfiles: list[bytes]`
* `shares: list`
* `fido2: Callable | None`

### `KdfParams` (Datenklasse)

KdfParams(memory_kib: 'int', iterations: 'int', lanes: 'int')

* `memory_kib: int`
* `iterations: int`
* `lanes: int`

### `LEVELS`

`{'schnell': KdfParams(memory_kib=65536, iterations=3, lanes=4), 'normal': KdfParams(memory_kib=262144, iterations=4, lanes=4), 'stark': KdfParams(memory_kib=1048576, iterations=4, lanes=4)}`

### `LEVEL_HINTS`

`{'schnell': 'Öffnen in Sekundenbruchteilen, geringer RAM-Bedarf', 'normal': 'Guter Kompromiss für die meisten Rechner', 'stark': 'Maximaler Schutz gegen Passwort-Raten, braucht 1 GiB RAM beim Öffnen'}`

### `DEFAULT_LEVEL`

`'normal'`

### `calibrate(target_seconds=2.0, *, max_memory_kib=1048576, lanes=4, timer=<function measure>)`

Argon2id-Parameter für eine Zielzeit auf diesem Rechner ("-l auto").

Speicher zuerst, weil er gegen Grafikkarten-Angriffe am meisten hilft: so
viel wie möglich, aber höchstens ``max_memory_kib`` (Standard 1 GiB) und ein
Viertel des freien Arbeitsspeichers – der Rechner, der den Container später
öffnet, braucht genauso viel. Ist schon eine Iteration zu langsam, wird der
Speicher halbiert (nicht unter 64 MiB). Die Iterationen füllen dann die
Zielzeit auf.

Die Dauer folgt T(t) ≈ A + B·t: A ist ein fester Anteil (vor allem das
Bereitstellen des Speichers), B der Anteil je Iteration. Gemessen werden
t = 1 und t = 2 (nach einem kleinen Aufwärmlauf), daraus t = (Ziel − A) / B.
Nur mit t = 1 zu rechnen zählt A bei jeder Iteration mit und verfehlt das
Ziel nach unten (gemessen: 1,3 statt 2 s). Kostet etwa T(1) + T(2) Messzeit.

``target_seconds``: Zielzeit; ``max_memory_kib``: Speichergrenze; ``lanes``: Parallelität (p); ``timer``: Messfunktion (für Tests).

### `ExcludeRules(patterns=())`

Menge von Mustern; ``matches`` bekommt Pfade mit "/" als Trenner.

### `ProgressEvent` (Datenklasse)

ProgressEvent(phase: 'str', done: 'int', total: 'int | None', item: 'str | None' = None, rate: 'float | None' = None, eta: 'float | None' = None, unit: 'str' = 'bytes', finished: 'bool' = False)

* `phase: str`
* `done: int`
* `total: int | None`
* `item: str | None`
* `rate: float | None`
* `eta: float | None`
* `unit: str`
* `finished: bool`

### `Monitor(callback=None, cancel=None, interval=0.1)`

Empfängt Fortschrittsereignisse (gedrosselt) und trägt ein Abbruch-Token.

### `CancelToken()`

Threadsicheres Abbruchsignal.

### `Tres0rError(Exception)`

Basisklasse für alle erwarteten Fehler.

### `FormatError(Tres0rError)`

Keine tres0r-Datei oder Header strukturell ungültig.

### `UnsupportedVersion(FormatError)`

Formatversion wird von dieser Programmversion nicht unterstützt.

### `WrongPassword(Tres0rError)`

Falsches Passwort – oder der Header wurde manipuliert.

Beides ist kryptografisch nicht unterscheidbar: Der komplette Header ist
als Associated Data an den verschlüsselten Datenschlüssel gebunden.

### `IntegrityError(Tres0rError)`

Nutzdaten beschädigt, manipuliert, abgeschnitten oder verlängert.

### `SignatureError(IntegrityError)`

Signatur fehlt, ist ungültig oder stammt nicht vom erwarteten Schlüssel.

### `UnsafeArchive(Tres0rError)`

Archivinhalt würde außerhalb des Zielordners schreiben o. Ä.

### `Cancelled(Tres0rError)`

Vorgang wurde abgebrochen (Nutzer oder Progress-Callback).

### `HibpUnavailable(Tres0rError)`

Have-I-Been-Pwned-Abfrage nicht möglich (offline, Timeout, …).

### `NameConflict(Tres0rError)`

Namen würden beim Entpacken kollidieren oder sind auf diesem System ungültig.

### `InsufficientSpace(Tres0rError)`

Auf dem Zieldatenträger ist voraussichtlich nicht genug Platz.

### `InsufficientMemory(Tres0rError)`

Die Schlüsselableitung bräuchte mehr Arbeitsspeicher als verfügbar.

### `KeyFormatError(Tres0rError, ValueError)`

Schlüssel- oder Anteiltext ist ungültig (Tippfehler, falsches Präfix, falsche Länge).

## `tres0r.keys`

Schlüssel für Format v2: X25519-Identitäten, Empfänger, Signaturschlüssel,
Wiederherstellungsphrasen.

### `Credentials` (Datenklasse)

Alles, womit ein Container entsperrt werden kann.

``prompt`` wird nur aufgerufen, wenn Identitäten nicht gereicht haben und
der Container Passwort- oder Wiederherstellungs-Slots hat.

* `passwords: list[str | bytes]`
* `identities: list[X25519PrivateKey]`
* `prompt: Callable[[], str] | None`
* `keyfiles: list[bytes]`
* `shares: list`
* `fido2: Callable | None`

### `KeyFormatError(Tres0rError, ValueError)`

Schlüssel- oder Anteiltext ist ungültig (Tippfehler, falsches Präfix, falsche Länge).

### `KEYFILE_BYTES`

`64`

### `generate_identity()`

Neue X25519-Identität (privater Schlüssel zum Entschlüsseln).

### `generate_signing_key()`

Neuer Ed25519-Signaturschlüssel.

### `generate_recovery(lang='de')`

Neue Wiederherstellungsphrase (``lang``: Wortliste "de" oder "en").

### `generate_keyfile(path)`

Neues Keyfile (64 Byte Zufall, Rechte 0600) an ``path``; überschreibt nie.

### `encode_identity(key)`

Privaten X25519-Schlüssel (``key``) als ``TRES0R-SECRET-…`` kodieren.

### `encode_recipient(key)`

Öffentlichen X25519-Schlüssel (``key``) als ``tres0r-pub-…`` kodieren.

### `encode_signing_key(key)`

Ed25519-Signaturschlüssel (``key``) als Text kodieren.

### `encode_verify_key(key)`

Ed25519-Prüfschlüssel (``key``) als ``tres0r-sig-…`` kodieren.

### `parse_identity(text)`

``TRES0R-SECRET-…`` aus ``text`` lesen; ``KeyFormatError`` bei Tippfehlern.

### `parse_recipient(text)`

``tres0r-pub-…`` aus ``text`` lesen; ``KeyFormatError`` bei Tippfehlern.

### `parse_signing_key(text)`

Signaturschlüssel aus ``text`` lesen; ``KeyFormatError`` bei Tippfehlern.

### `parse_verify_key(text)`

``tres0r-sig-…`` aus ``text`` lesen; ``KeyFormatError`` bei Tippfehlern.

### `load_identities(path, passphrase=None)`

Alle X25519-Identitäten aus einer Identitätsdatei (ggf. mit ``passphrase``).

### `load_recipients(path, passphrase=None)`

Empfängerliste (ein Schlüssel pro Zeile) oder eine Identitätsdatei.

### `load_signing_keys(path, passphrase=None)`

Alle Signaturschlüssel aus einer Identitätsdatei (ggf. mit ``passphrase``).

### `load_verify_keys(path, passphrase=None)`

Liste von Prüfschlüsseln (tres0r-sig-…) oder eine Identitätsdatei mit Signaturschlüssel.

### `write_identity_file(path, keys, passphrase=None, params=None)`

Neue Identitätsdatei mit Rechten 0600 anlegen; überschreibt nie.

Mit ``passphrase`` wird sie als tres0r-Container verschlüsselt
(Standardstufe "stark", da die Datei genau gegen Offline-Raten schützen soll).

``keys``: ein oder mehrere private Schlüssel; ``params``: Argon2id für den Schutz mit ``passphrase``.

### `protect_identity_file(path, passphrase, params=None)`

Bestehende ungeschützte Identitätsdatei verschlüsseln (atomar ersetzt, 0600).

### `is_protected(path)`

Ist die Identitätsdatei mit einer Passphrase geschützt?

### `public_text(key)`

Öffentlicher Teil als Text – Empfänger- oder Prüfschlüssel.

``key``: privater X25519- oder Ed25519-Schlüssel.

### `keyfile_secret(path)`

K = SHA-256("tres0r keyfile" ‖ Dateiinhalt) – beliebige Dateien sind möglich,
empfohlen ist ein mit ``generate_keyfile`` erzeugtes (512 Bit Zufall).

### `keyfile_id(secret)`

Kennung im Keyslot: erkennt ein falsches Keyfile, bevor Argon2 läuft.

``secret``: Ergebnis von ``keyfile_secret``.

## `tres0r.shamir`

Schwellwert-Wiederherstellung: Shamirs Secret Sharing über GF(2⁸).

### `Share` (Datenklasse)

Share(set_id: 'bytes', k: 'int', n: 'int', x: 'int', y: 'bytes')

* `set_id: bytes`
* `k: int`
* `n: int`
* `x: int`
* `y: bytes`

### `split(secret, k, n, set_id=None)`

Geheimnis in n Anteile zerlegen, von denen k genügen.

``secret``: 32 Byte; ``k``/``n``: nötige/alle Anteile; ``set_id``: 8 Byte (sonst zufällig).

### `combine(shares)`

Geheimnis aus mindestens k Anteilen desselben Satzes (Lagrange an x = 0).

``shares``: mindestens k Anteile desselben Satzes; zu wenige -> ``WrongPassword``.

### `parse_share(text)`

Anteil ``tres0r-teil-…`` aus ``text`` lesen (Prüfsumme, kanonische Schreibweise).

### `PREFIX`

`'tres0r-teil-'`

### `SECRET_LEN`

`32`

### `MAX_SHARES`

`32`

## `tres0r.progress`

Fortschritt und Abbruch für lange Vorgänge (für CLI, TUI und GUI).

### `ProgressEvent` (Datenklasse)

ProgressEvent(phase: 'str', done: 'int', total: 'int | None', item: 'str | None' = None, rate: 'float | None' = None, eta: 'float | None' = None, unit: 'str' = 'bytes', finished: 'bool' = False)

* `phase: str`
* `done: int`
* `total: int | None`
* `item: str | None`
* `rate: float | None`
* `eta: float | None`
* `unit: str`
* `finished: bool`

### `CancelToken()`

Threadsicheres Abbruchsignal.

### `Monitor(callback=None, cancel=None, interval=0.1)`

Empfängt Fortschrittsereignisse (gedrosselt) und trägt ein Abbruch-Token.

### `Progress` (Typ)

`Callable[[int, int], None] | Monitor | None`

### `UNIT_BYTES`

`'bytes'`

### `UNIT_ENTRIES`

`'einträge'`

## `tres0r.errors`

Fehlerklassen von tres0r.

### `Tres0rError(Exception)`

Basisklasse für alle erwarteten Fehler.

### `FormatError(Tres0rError)`

Keine tres0r-Datei oder Header strukturell ungültig.

### `UnsupportedVersion(FormatError)`

Formatversion wird von dieser Programmversion nicht unterstützt.

### `WrongPassword(Tres0rError)`

Falsches Passwort – oder der Header wurde manipuliert.

Beides ist kryptografisch nicht unterscheidbar: Der komplette Header ist
als Associated Data an den verschlüsselten Datenschlüssel gebunden.

### `IntegrityError(Tres0rError)`

Nutzdaten beschädigt, manipuliert, abgeschnitten oder verlängert.

### `SignatureError(IntegrityError)`

Signatur fehlt, ist ungültig oder stammt nicht vom erwarteten Schlüssel.

### `UnsafeArchive(Tres0rError)`

Archivinhalt würde außerhalb des Zielordners schreiben o. Ä.

### `Cancelled(Tres0rError)`

Vorgang wurde abgebrochen (Nutzer oder Progress-Callback).

### `HibpUnavailable(Tres0rError)`

Have-I-Been-Pwned-Abfrage nicht möglich (offline, Timeout, …).

### `NameConflict(Tres0rError)`

Namen würden beim Entpacken kollidieren oder sind auf diesem System ungültig.

### `InsufficientSpace(Tres0rError)`

Auf dem Zieldatenträger ist voraussichtlich nicht genug Platz.

### `InsufficientMemory(Tres0rError)`

Die Schlüsselableitung bräuchte mehr Arbeitsspeicher als verfügbar.

### `KeyFormatError(Tres0rError, ValueError)`

Schlüssel- oder Anteiltext ist ungültig (Tippfehler, falsches Präfix, falsche Länge).

## `tres0r.passgen`

Anbindung von pwgen an tres0r.

### `Secret` (Datenklasse)

Secret(value: 'str', kind: 'str', entropy_bits: 'float')

* `value: str`
* `kind: str`
* `entropy_bits: float`

### `PasswordCheck` (Datenklasse)

PasswordCheck(length: 'int', classes: 'int', pwned: 'int | None' = None, hibp_error: 'str | None' = None, warnings: 'list[str]' = <factory>)

* `length: int`
* `classes: int`
* `pwned: int | None`
* `hibp_error: str | None`
* `warnings: list[str]`

### `generate_password(length=20, *, symbols=True, exclude_ambiguous=False)`

Wie pwgen: Klein-, Großbuchstaben und Ziffern immer, Sonderzeichen optional.

``length``: Zeichen; ``symbols``: Sonderzeichen verwenden; ``exclude_ambiguous``: Verwechselbares (0/O, 1/l/I) weglassen.

### `generate_passphrase(words=8, *, lang='de', separator='-', capitalize=False, append_digit=False, wordlist=None)`

Passphrase aus ``words`` Wörtern der Liste ``lang`` (oder ``wordlist``), getrennt durch ``separator``; optional ``capitalize``/``append_digit``.

### `check_password(password, *, online=False)`

Selbst gewähltes Passwort prüfen.

Bewusst ohne Entropie-Schätzung: Heuristiken wie "Länge × Zeichenvorrat"
überschätzen menschlich gewählte Passwörter massiv ("Sommer2026!" wirkt
nach 72 Bit, ist aber in Sekunden geraten). Stattdessen harte Kriterien
plus – nur wenn ``online`` – der Abgleich mit echten Datenlecks.

### `hibp_count(password)`

Treffer in der Pwned-Passwords-Datenbank (k-Anonymität, siehe pwgen).

### `load_wordlist(lang='de')`

Mitgelieferte Diceware-Liste über pwgen laden (je 7776 Wörter).

### `load_wordlist_file(path)`

Eigene Liste laden – gleiches Format wie pwgen ('würfel<TAB>wort' oder nur 'wort').

### `LANGUAGES`

`('en', 'de')`

### `AMBIGUOUS`

`['0', '1', 'I', 'O', 'l', '|']`

### `RECOMMENDED_BITS`

`80`

### `DEFAULT_SEPARATOR`

`'-'`

### `PASSWORD_MIN_LEN`

`8`

### `PASSWORD_MAX_LEN`

`128`

### `DEFAULT_PASSWORD_LEN`

`20`

### `PASSPHRASE_MIN_WORDS`

`8`

### `PASSPHRASE_MAX_WORDS`

`40`

### `DEFAULT_WORDS`

`8`

## `tres0r.hwtoken`

FIDO2-Token (YubiKey, Nitrokey, SoloKey …) als zweiter Faktor über hmac-secret.

### `TokenProvider(found=None, *, notify=None, pin=None)`

Für ``Credentials.fido2``: fragt angeschlossene Tokens nach dem Geheimnis.

Probiert jedes Gerät, bis eines den Credential kennt (fremde Geräte lehnen
ohne Berührung ab). Ergebnisse werden für diesen Vorgang zwischengespeichert,
damit z. B. ``passwd`` keine zweite Berührung braucht.

### `devices()`

Angeschlossene FIDO2-Geräte (USB-HID).

### `describe(device)`

Anzeigename eines Geräts (``device`` aus ``devices()``).

### `enroll(device, *, notify=None, pin=None)`

Neuen Credential mit hmac-secret anlegen; gibt die Credential-ID zurück.

``device``: Gerät aus ``devices()``; ``notify``: Hinweis-Funktion ("bitte berühren"); ``pin``: liefert die Token-PIN, falls verlangt.

### `secret(device, credential_id, salt, *, notify=None, pin=None)`

32-Byte-Geheimnis des Credentials für ``salt`` (Berührung nötig).

``device``: Gerät; ``credential_id``: aus ``enroll``; ``salt``: 32 Byte; ``notify``/``pin`` wie bei ``enroll``.

### `RP_ID`

`'tres0r.local'`

### `SALT_LEN`

`32`

## `tres0r.mount`

Container schreibgeschützt einhängen (FUSE).

### `ContainerFS(container, credentials)`

Schreibgeschützte Sicht auf einen entsperrten Container.

### `Node` (Datenklasse)

Node(kind: 'str', size: 'int' = 0, mtime: 'int' = 0, entry: 'payload.IndexEntry | None' = None, segment: 'int' = 0, link: 'str | None' = None, children: 'dict[str, Node]' = <factory>)

* `kind: str`
* `size: int`
* `mtime: int`
* `entry: payload.IndexEntry | None`
* `segment: int`
* `link: str | None`
* `children: dict[str, Node]`

### `mount(container, mountpoint, credentials, *, foreground=True, allow_other=False)`

Container einhängen; kehrt erst nach dem Aushängen zurück (Strg+C oder
``fusermount -u``). Braucht fusepy und libfuse (Linux) bzw. macFUSE (macOS).

``mountpoint``: leerer Ordner; ``foreground``: blockiert bis zum Aushängen; ``allow_other``: auch andere Benutzer dürfen lesen (FUSE-Option).

### `unmount(mountpoint)`

Eingehängten Container unter ``mountpoint`` aushängen (fusermount bzw. umount).
