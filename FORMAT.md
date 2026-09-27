# tres0r – Containerformat

**Spezifikation 1.0 – stabil.** Gilt für tres0r 1.x. Formatversion im Header: 2
(Version 1 nur lesen, Abschnitt 11). Änderungen sind ab hier nur noch
rückwärtskompatibel möglich (Abschnitt 13).

Diese Spezifikation beschreibt das Dateiformat von tres0r so genau, dass sich ein
Container ohne Kenntnis des Python-Codes lesen und schreiben lässt.
`tests/reference_decoder.py` ist ein unabhängiger Leser, der nur nach diesem
Dokument geschrieben ist; die Testvektoren in `tests/vectors/` prüfen beide.

Schlüsselwörter: **MUSS**/**DARF NICHT** sind verbindlich; ein Leser, der sie
verletzt, ist fehlerhaft. **SOLL** ist eine starke Empfehlung.

## 1. Notation und Bausteine

* Ganzzahlen sind vorzeichenlos und **big endian**: `u8`, `u16`, `u32`, `u64`.
* `a ‖ b` ist Verkettung, `0^n` sind n Nullbytes, `"…"` ist ASCII.

| Baustein | Definition |
|---|---|
| AEAD | ChaCha20-Poly1305 (RFC 8439), Schlüssel 32 B, Nonce 12 B, Tag 16 B |
| HKDF | HKDF-SHA256 (RFC 5869), Ausgabe immer 32 B: `HKDF(ikm, salt, info)` |
| HMAC | HMAC-SHA256 |
| Argon2id | RFC 9106, Version 0x13, Ausgabe 32 B, ohne Secret und ohne Associated Data |
| X25519 | RFC 7748 |
| Ed25519 | RFC 8032 (reines Ed25519, kein Prehash) |
| zstd | RFC 8878 (Frames); zlib: RFC 1950 |

## 2. Dateiaufbau

```
Datei = Header ‖ Payload
```

Die ersten 5 Byte sind immer `"TRS0"` ‖ `u8 version`. Leser **MÜSSEN** andere
Versionen als 1 und 2 mit einer eindeutigen Meldung ablehnen.

## 3. Header (Version 2)

| Offset | Länge | Feld | Werte |
|---:|---:|---|---|
| 0 | 4 | magic | `"TRS0"` |
| 4 | 1 | version | `2` |
| 5 | 2 | header_len | Gesamtlänge des Headers inkl. MAC, 59 … 65535 |
| 7 | 1 | payload_type | `0` = tar, `1` = roh |
| 8 | 1 | compression | `0` = keine, `1` = zstd |
| 9 | 1 | flags | Bit 0 = Inhaltsverzeichnis vorhanden, Bit 1 = signiert, Bit 2 = angehängte Segmente (9b; nur bei tar); alle anderen Bits 0 |
| 10 | 16 | stream_nonce | zufällig |
| 26 | 1 | slot_count | 1 … 16 |
| 27 | … | slots | `slot_count` × Keyslot |
| header_len − 32 | 32 | mac | siehe 4.2 |

Ein Keyslot ist `u8 type ‖ u16 body_len ‖ body`.

Ein Leser **MUSS** den Header ablehnen (Formatfehler), wenn

* `header_len` nicht exakt die Summe aus 27 B, allen Keyslots und 32 B MAC ist,
* `payload_type`, `compression` oder `flags` unbekannte Werte haben,
* `payload_type = 1` und Flag-Bit 0 gesetzt ist,
* `slot_count` außerhalb von 1 … 16 liegt oder mehr als 4 Slots vom Typ 1 existieren,
* ein Slot bekannten Typs die falsche `body_len` hat oder seine Argon2-Parameter
  außerhalb der Grenzen aus Abschnitt 10 liegen.

Diese Prüfungen **MÜSSEN** vor jeder teuren Berechnung (Argon2) erfolgen.
Alle Headerfelder sind bis zur erfolgreichen MAC-Prüfung (4.2) unbestätigt.

## 4. Schlüssel

### 4.1 Datenschlüssel und Keyslots

Jeder Container hat einen zufälligen 32-Byte-**Datenschlüssel** `DEK`. Jeder
Keyslot enthält `wrapped = AEAD_Encrypt(KEK, nonce = 0^12, plaintext = DEK, aad = u8 type ‖ params)`
(48 Byte). `params` ist der Slot-Inhalt ohne die letzten 48 Byte. Da jeder KEK
nur einmal vorkommt (zufälliges Salt bzw. ephemerer Schlüssel), ist die feste
Nonce zulässig.

| Typ | Name | body | KEK |
|---:|---|---|---|
| 1 | Passwort | `u8 kdf=1 ‖ u32 m_kib ‖ u32 t ‖ u8 p ‖ salt(16) ‖ wrapped(48)` (74 B) | `Argon2id(P, salt, m_kib, t, p)` |
| 2 | Schlüssel | `salt(16) ‖ wrapped(48)` (64 B) | `HKDF(C, salt, "tres0r v2 secret slot")` |
| 3 | X25519 | `epk(32) ‖ wrapped(48)` (80 B) | `HKDF(X25519(e, R), epk ‖ R, "tres0r v2 x25519 slot")` |
| 4 | reserviert | ML-KEM-768 + X25519 (Post-Quanten-Hybrid), noch nicht definiert | – |
| 5 | Passwort + Keyfile | `u8 kdf=1 ‖ u32 m_kib ‖ u32 t ‖ u8 p ‖ salt(16) ‖ kid(16) ‖ wrapped(48)` (90 B) | `HKDF(Argon2id(P, salt, m_kib, t, p) ‖ K, salt, "tres0r v2 password+keyfile slot")` |
| 6 | Schwellwert | `u8 k ‖ u8 n ‖ set_id(8) ‖ salt(16) ‖ wrapped(48)` (74 B) | `HKDF(S, salt, "tres0r v2 threshold slot")` |
| 7 | Passwort + FIDO2 | `u8 kdf=1 ‖ u32 m_kib ‖ u32 t ‖ u8 p ‖ salt(16) ‖ hsalt(32) ‖ u8 rp_len ‖ rp_id ‖ u16 cred_len ‖ cred_id ‖ wrapped(48)` (variabel) | `HKDF(Argon2id(P, salt, m_kib, t, p) ‖ H, salt, "tres0r v2 password+fido2 slot")` |

* **P** = Passwort: Unicode NFC, dann UTF-8. Nicht als UTF-8 kodierbare
  Codepunkte U+DC80…U+DCFF (Python „surrogateescape“) stehen für das Byte
  `codepoint − 0xDC00`.
* **C** = kanonische Form eines Schlüssel-Geheimnisses (5.2).
* **K** = `SHA256("tres0r keyfile" ‖ Inhalt der Keyfile-Datei)`; `kid = SHA256("tres0r keyfile id" ‖ K)[0:16]`
  – mit `kid` erkennt ein Leser ein falsches Keyfile vor der Argon2-Berechnung.
* **S** = 32-Byte-Geheimnis, aus mindestens k von n Anteilen rekonstruiert (5.3).
* **H** = hmac-secret (CTAP 2.1, 12.5) des FIDO2-Credentials `cred_id` (nicht resident,
  RP-ID `rp_id`, UTF-8, 1–255 Byte; `cred_id` 1–1023 Byte) für `salt1 = hsalt`, ohne
  User-Verification: 32 Byte, die nur der Token mit Berührung berechnen kann.
  Die Slot-Typen 1, 5 und 7 zählen gemeinsam zur Grenze von 4 Passwort-Slots.
* **e/epk** = ephemerer privater/öffentlicher X25519-Schlüssel, **R** = öffentlicher
  Schlüssel des Empfängers (32 B). Ergibt X25519 nur Nullbytes, **MUSS** der Slot
  als nicht passend gelten.

Typ 2 ist nur für generierte Geheimnisse mit mindestens 128 Bit Entropie
bestimmt (z. B. die Wiederherstellungsphrase, 5.2); Passwörter von Menschen
gehören in Typ 1.

Unbekannte Slot-Typen **MÜSSEN** beim Entsperren übersprungen und beim
Umschreiben des Headers unverändert übernommen werden.

### 4.2 Header-MAC und Key-Commitment

```
mac_key = HKDF(DEK, stream_nonce, "tres0r v2 header mac")
mac     = HMAC(mac_key, Header[0 : header_len − 32])
```

Ein Leser gilt erst dann als entsperrt, wenn ein Slot einen DEK liefert **und**
die MAC mit diesem DEK stimmt (Vergleich in konstanter Zeit). Stimmt sie nicht,
**MUSS** er abbrechen (Header manipuliert) und **DARF NICHT** weitere Slots
versuchen. Hintergrund: ChaCha20-Poly1305 ist nicht schlüsselbindend; ein
präparierter Slot kann unter mehreren KEKs „gültig“ entschlüsseln. Die MAC passt
höchstens zu einem dieser DEKs.

### 4.3 Reihenfolge beim Entsperren (empfohlen)

1. alle X25519-Identitäten gegen alle Slots vom Typ 3 (billig),
2. Anteile gegen Slots vom Typ 6 mit gleicher `set_id` (billig, ohne Passwort),
3. alle Passwort-Kandidaten gegen alle Slots vom Typ 2 (billig),
4. alle Passwort-Kandidaten gegen Typ 1 und – mit passendem Keyfile – Typ 5 (teuer),
5. mit angeschlossenem Token: Typ 7 (Berührung, dann Argon2 je Passwort-Kandidat).

## 5. Textformate

### 5.1 Schlüssel

```
Empfänger:          "tres0r-pub-"         ‖ base32(R ‖ check("pub", R))              klein
Identität:          "TRES0R-SECRET-"      ‖ base32(k ‖ check("secret", k))           groß
Prüfschlüssel:      "tres0r-sig-"         ‖ base32(V ‖ check("sign-pub", V))         klein
Signaturschlüssel:  "TRES0R-SIGN-SECRET-" ‖ base32(s ‖ check("sign-secret", s))      groß
check(kind, key) = SHA256("tres0r " ‖ kind ‖ " " ‖ key)[0:4]
```

(`k` = X25519-Privatschlüssel, `V`/`s` = Ed25519-Public-Key/-Seed, je 32 B.)

`base32` ist RFC 4648 ohne `=`-Padding (36 Byte → 58 Zeichen). Das Präfix ist
unabhängig von Groß-/Kleinschreibung. Leser **MÜSSEN** nur die kanonische
Kodierung akzeptieren: Die 2 ungenutzten Bits des letzten Zeichens **MÜSSEN**
0 sein, sonst gibt es mehrere Schreibweisen desselben Schlüssels.

Eine Identitätsdatei ist UTF-8-Text; leere Zeilen und Zeilen mit `#` am Anfang
sind Kommentare, jede andere Zeile ist ein privater Schlüssel (Identität oder
Signaturschlüssel). **Geschützte** Identitätsdateien beginnen mit `"TRS0"`: Sie
sind ein Container mit `payload_type = 1` (roh), dessen Nutzdaten diese Textform
sind; tres0r schützt sie mit einem Passwort-Slot.

### 5.2 Wiederherstellungsphrase und kanonische Form

tres0r erzeugt 20 zufällige Wörter aus einer der beiden Diceware-Listen mit je
7776 Einträgen (≈ 258 Bit). Die kanonische Form **C** eines Geheimnisses:

1. Unicode NFC, 2. Kleinschreibung (Unicode-Default-Case-Mapping), 3. erneut NFC,
4. jedes Zeichen, das weder Buchstabe (Kategorie L*) noch Zahl (Kategorie N*) ist,
   trennt Wörter, 5. die nicht leeren Wörter mit `-` verbinden, 6. UTF-8 wie bei P.

`"Wald  SEE-berg"` und `"wald-see-berg"` ergeben also dasselbe C.

### 5.3 Schwellwert-Anteile (Shamir)

S wird byteweise über GF(2⁸) mit dem Polynom x⁸+x⁴+x³+x+1 (0x11B) geteilt: Für
jedes Byte `S[j]` ein Polynom `f_j(x) = S[j] + a_j1·x + … + a_j(k−1)·x^(k−1)` mit
zufälligen Koeffizienten; Anteil i (i = 1 … n) ist `y = f_0(i) ‖ … ‖ f_31(i)`.
Rekonstruktion per Lagrange an x = 0: `S[j] = Σ y_i[j] · Π_(m≠i) x_m / (x_m ⊕ x_i)`.
Es gilt 2 ≤ k ≤ n ≤ 32.

```
Anteil: "tres0r-teil-" ‖ base32(set_id(8) ‖ u8 k ‖ u8 n ‖ u8 x ‖ y(32) ‖ check(4))   klein
check = SHA256("tres0r share " ‖ set_id ‖ k ‖ n ‖ x ‖ y)[0:4]
```

Wie bei Schlüsseln gilt nur die kanonische Base32-Kodierung; Leerzeichen und
Bindestriche nach dem Präfix dürfen beim Einlesen ignoriert werden.

## 6. Payload: Verschlüsselung

```
payload_key = HKDF(DEK, stream_nonce, "tres0r v2 payload key")
```

Der Klartext (Abschnitt 7) wird in Chunks zu 65536 Byte zerlegt; der letzte
Chunk ist 0 … 65536 Byte lang. Chunk i (ab 0) wird zu
`AEAD_Encrypt(payload_key, nonce_i, chunk_i, aad = leer)` mit

```
nonce_i = u88(i) ‖ u8(last)      last = 1 nur beim letzten Chunk, sonst 0
```

(`u88` = 11 Byte big endian.) Ein leerer letzter Chunk ist nur zulässig, wenn
er der einzige ist (Klartext der Länge 0). Folgerungen für Leser:

* Aus der Payload-Größe `S` folgt `n = ⌈S / 65552⌉` Chunks; ein Rest
  `0 < S mod 65552 < 16` ist ungültig. Die Klartextlänge ist `S − 16·n`.
* Ein Chunk von voller Länge ist genau dann der letzte, wenn danach keine
  Bytes mehr folgen.
* Jede Änderung, Vertauschung, Kürzung oder Verlängerung **MUSS** zu einem
  Integritätsfehler führen. Einzelne Chunks dürfen für wahlfreien Zugriff
  unabhängig entschlüsselt werden.

## 7. Payload: Klartext

```
Klartext = Blöcke ‖ Padding ‖ [Inhaltsverzeichnis] ‖ [Signaturanhang]
Blöcke   = { u32 len ‖ Daten(len) } ‖ u32 0          1 ≤ len
```

* Schreiber erzeugen Blöcke mit höchstens 1 MiB; Leser **MÜSSEN** Blöcke über
  4 MiB ablehnen. Die Verkettung aller Blockdaten ergibt den **Datenstrom**.
* **Padding:** Nullbytes, sodass die Klartextlänge `L` den Wert `padme(L) = L`
  erfüllt (Padmé, Nikitin et al. 2019):
  `E = ⌊log2 L⌋, S = ⌊log2 E⌋ + 1, z = max(0, E − S), padme(L) = ⌈L / 2^z⌉ · 2^z`
  (für L < 2: L). Padding ist optional; Leser **MÜSSEN** beliebig viele Nullbytes
  akzeptieren und ignorieren.
* **Inhaltsverzeichnis** (nur bei Flag-Bit 0): `blob ‖ u64 len(blob) ‖ "TRS0IDX\x01"`
  am Ende des Klartexts – bei gesetztem Flag-Bit 1 unmittelbar vor dem
  Signaturanhang –, siehe Abschnitt 9.
* **Signaturanhang** (nur bei Flag-Bit 1): die letzten 105 Byte des Klartexts,
  siehe Abschnitt 9a.

### 7.1 Datenstrom

* `compression = 0`: Der Datenstrom sind die Nutzdaten.
* `compression = 1`: Der Datenstrom ist eine Folge vollständiger zstd-Frames,
  deren Dekompression die Nutzdaten ergibt. Ein Frame, der vor dem Terminator
  endet, **MUSS** als Fehler gelten. Jeder Frame beginnt am Anfang eines Blocks.
* `payload_type = 0` (tar): Nutzdaten sind ein tar-Archiv (POSIX.1-2001/PAX).
  Schreiber setzen `uid = gid = 0` und `uname = gname = ""`. Eine Änderungszeit
  `mtime = 0` bedeutet „nicht gespeichert“; Leser **SOLLEN** dann die aktuelle Zeit
  verwenden. Erweiterte Attribute stehen als PAX-Einträge `SCHILY.xattr.<name>`
  (Konvention von star/GNU tar/bsdtar; Werte binär über `hdrcharset=BINARY`).
  Leser **DÜRFEN NICHT** Attribute außerhalb von `user.*` und
  `system.posix_acl_access`/`system.posix_acl_default` setzen – `security.*`
  (z. B. Datei-Capabilities) und `trusted.*` würden Rechte ausweiten. Leser **MÜSSEN**
  beim Entpacken mindestens die Regeln des Python-`data`-Filters durchsetzen:
  keine absoluten Pfade, kein Pfad außerhalb des Ziels, keine Links nach außen,
  keine Geräte-/FIFO-Einträge, keine setuid/setgid/sticky-Bits.
* `payload_type = 1` (roh): Nutzdaten sind ein beliebiger Bytestrom.

## 8. Einstiegspunkte (wahlfreier Zugriff)

Ein Einstiegspunkt ist ein Paar `(offset, skip)`: `offset` ist die Position eines
Blockanfangs im Klartext, `skip` die Zahl der ab dort **dekodierten** Bytes, die
zu überspringen sind. Unkomprimiert beginnt jeder tar-Eintrag (inkl. seiner
PAX-Erweiterung) in einem neuen Block, `skip = 0`. Komprimiert beginnt ein
neuer zstd-Frame am ersten Eintrag, nachdem der laufende Frame mindestens
1 MiB unkomprimierte Daten enthält; `offset` zeigt auf dessen Blockanfang.

## 8a. Aufgeteilte Container

Ein aufgeteilter Container (`NAME.001`, `NAME.002`, …, fortlaufend ab 1, mindestens
drei Ziffern) ist exakt die Byte-Folge eines normalen Containers, in Stücke
geschnitten. Leser hängen die Teile in Nummernfolge aneinander; eine Lücke ist ein
Fehler. Das Format selbst kennt keine Teile.

## 9. Inhaltsverzeichnis

`blob` ist zlib-komprimiertes JSON (ASCII; Nicht-ASCII-Zeichen und einzelne
Surrogate als `\uXXXX`). Ein hohes Surrogat direkt vor einem niedrigen würde als
ein Zeichen gelesen; Dateinamen enthalten diese Folge nie (unter Linux entstehen nur
niedrige Surrogate U+DC80–U+DCFF, Windows kombiniert UTF-16-Paare):

```json
{"v": 1, "entries": [
  {"n": "Projekt/notiz.txt", "t": "f", "s": 11, "m": 1790000000,
   "o": 0, "k": 0, "h": "<sha256 hex>"},
  {"n": "Projekt/verweis", "t": "l", "s": 0, "m": 1790000000, "o": 1557, "k": 0, "l": "notiz.txt"}
]}
```

| Feld | Typ | Bedeutung |
|---|---|---|
| `n` | String | Pfad im tar-Archiv |
| `t` | `f`/`d`/`l`/`h`/`o` | Datei, Ordner, Symlink, Hardlink, sonstiges |
| `s` | Integer ≥ 0 | Größe der Datei (sonst 0) |
| `m` | Integer | Änderungszeit (Unix-Sekunden) |
| `o`, `k` | Integer ≥ 0 | Einstiegspunkt (Abschnitt 8) |
| `h` | 64 Hex-Zeichen, optional | SHA-256 des Dateiinhalts |
| `l` | String, optional | Linkziel |

Die Einträge stehen in Archivreihenfolge, genau ein Eintrag je tar-Eintrag.
Leser **MÜSSEN** Typen und Wertebereiche prüfen und dürfen JSON-Tiefe und
Größe begrenzen (Abschnitt 10). Beim Einstieg über einen Eintrag **MUSS** der
Name im tar-Header mit `n` übereinstimmen.

## 9a. Signaturen

```
Signaturanhang = u8 alg (1 = Ed25519) ‖ V(32) ‖ sig(64) ‖ "TRS0SIG\x01"          (105 B)
M   = "tres0r v2 signature" ‖ 0x00 ‖ u8 payload_type ‖ u8 compression ‖ u8 flags
      ‖ stream_nonce(16) ‖ SHA256(Klartext[0 : L − 105])
sig = Ed25519_Sign(s, M)                         L = Länge des gesamten Klartexts
```

* Signiert wird der **gesamte** Klartext vor dem Anhang (Blöcke, Padding,
  Inhaltsverzeichnis). Ein anderer Empfänger desselben Containers kennt den DEK
  und könnte gültig neu verschlüsseln; er kann aber nichts ändern, ohne dass die
  Signatur bricht.
* **Nicht** signiert sind Keyslots und Header-MAC: Schlüssel lassen sich
  hinzufügen und entfernen, ohne die Signatur zu brechen. Die Signatur bestätigt
  den Inhalt, nicht die Liste der Empfänger.
* Der Anhang liegt innerhalb der Verschlüsselung; wer signiert hat, sehen nur
  Schlüsselinhaber.
* Leser **MÜSSEN** die Signatur prüfen, bevor sie ein vollständig gelesenes
  Ergebnis als gültig melden (bei Dateien: bevor etwas im Ziel landet). Ist das
  Flag gesetzt, der Anhang aber fehlerhaft, ist der Container ungültig.
* Ob eine Signatur *verlangt* wird und von welchem `V`, entscheidet der Leser.
  Wer das Flag entfernt (nur mit dem DEK möglich), erzeugt einen unsignierten
  Container – das fällt nur auf, wenn eine Signatur verlangt wird.
* Ein Leser, der nur Teile liest (Inhaltsverzeichnis, einzelne Einträge), kann
  die Signatur nicht prüfen und darf sie nicht als geprüft ausgeben.

## 9b. Angehängte Segmente

Bei gesetztem Flag-Bit 2 folgen nach dem Header mehrere eigenständige
Nutzdatenströme (Segmente), jeder aufgebaut wie in 6–9 beschrieben, und die Datei
endet mit einer Segmenttabelle:

```
Header | Segment 0 | [ältere Tabelle, entwertet] | Segment 1 | … | Tabelle
Tabelle   = table_nonce(16) ‖ ct ‖ u32 len(ct) ‖ "TRS0SEG\x01"
ct        = ChaCha20-Poly1305(K_T, 0^12, T, AAD = "tres0r v2 segment table" ‖ stream_nonce)
K_T       = HKDF(DEK, table_nonce, "tres0r v2 segment table")
T         = u8 version=1 ‖ u32 n ‖ n × (u64 offset ‖ u64 länge ‖ nonce(16) ‖ u8 compression ‖ u8 flags)
```

* `offset` zählt ab Nutzdatenbeginn (Header-Ende), `länge` in Chiffretext-Bytes.
  Segment i nutzt `K_P,i = HKDF(DEK, nonce_i, "tres0r v2 payload key")`; für
  Segment 0 sind Nonce, Kompression und Flags die des Headers (ohne Bit 2).
* Segment-`flags` kennen nur Bit 0 und Bit 1. Eine Signatur (9a) wird mit
  compression, flags und nonce **des Segments** gebildet.
* Gültig ist: 1 ≤ n ≤ 4096; Segment 0 beginnt bei offset 0; Segmente liegen
  aufsteigend, überschneiden sich nicht und enden vor der Tabelle. Zwischen
  Segmenten dürfen ältere, entwertete Tabellen liegen.
* Ansicht: Einträge späterer Segmente ersetzen gleichnamige früherer (auch bei
  anderem Typ). Wer mehrere Segmente prüft und Unterzeichner verlangt, verlangt
  sie für **jedes** Segment. Signaturen belegen Herkunft und Unversehrtheit je
  Segment, nicht die Vollständigkeit der Segmentliste gegenüber Mitempfängern,
  die den DEK kennen.
* Schreiber hängen an Ort und Stelle an: Segment und neue Tabelle ans Ende; danach
  beim ersten Anhängen Bit 2 im Header setzen (gleiche Länge, neuer MAC), sonst die
  Kennung `"TRS0SEG\x01"` der vorherigen Tabelle mit Nullbytes überschreiben –
  so ergibt ein Abschneiden auf einen früheren Stand keinen gültigen Container.

## 10. Grenzen

| Größe | Grenze |
|---|---|
| Argon2id Speicher `m_kib` | 8192 … 4194304 (8 MiB … 4 GiB) |
| Argon2id Iterationen `t` | 1 … 64 |
| Argon2id Parallelität `p` | 1 … 16 |
| Keyslots gesamt / davon Passwort | 16 / 4 |
| Header | 65535 Byte |
| Block (lesen) | 4 MiB |
| Inhaltsverzeichnis `blob` / entpackt | 256 MiB / 1 GiB |

Leser **SOLLEN** vor Argon2 prüfen, ob `m_kib` in den verfügbaren Arbeitsspeicher
passt, und sonst mit einer klaren Meldung abbrechen.

## 11. Formatversion 1 (nur lesen)

```
"TRS0" ‖ u8 1 ‖ u8 kdf=1 ‖ u32 m_kib ‖ u32 t ‖ u8 p ‖ salt(16) ‖ stream_nonce(16)
‖ wrap_nonce(12) ‖ wrapped(48)                                             (107 B)
KEK         = Argon2id(P, salt, m_kib, t, p)
DEK         = AEAD_Decrypt(KEK, wrap_nonce, wrapped, aad = Header[0:59])
payload_key = HKDF(DEK, stream_nonce, "tres0r v1 payload key")
```

Die Payload ist wie in Abschnitt 6 verschlüsselt; der Klartext ist direkt der
tar-Stream, gefolgt von optionalem Null-Padding (ohne Blöcke, ohne Kompression,
ohne Inhaltsverzeichnis). v1 kennt nur einen Passwort-Slot; Header-Manipulation
fällt über die AAD beim Entschlüsseln des DEK auf.

## 12. Testvektoren

`tests/vectors/*.json` enthalten vollständige Container (hex) samt Eingaben
(Passwort, Phrase, X25519-Identität), erwartetem DEK und erwarteten Nutzdaten.
Die Vektoren ohne Kompression sind byte-genau reproduzierbar
(`python tests/vectors/generate.py`); zstd- und tar-Ausgaben können sich
zwischen Bibliotheksversionen unterscheiden und werden deshalb nur gelesen.

Leser, die alle Vektoren lesen (bzw. mit der erwarteten Fehlerart ablehnen), gelten
als konform zu dieser Spezifikation.

## 13. Stabilität und Weiterentwicklung

Diese Spezifikation ist ab 1.0 eingefroren. Für Leser und Schreiber gilt:

* Was ein 1.0-Leser liest, MUSS jeder spätere 1.x-Leser genauso lesen. Bytes eines
  Containers werden nie umgedeutet.
* Neue Fähigkeiten kommen nur über **neue Werte** hinzu: neue Slot-Typen (4.1),
  neue Flag-Bits (3), neue Kompressions- oder Payload-Typen, neue Signatur- oder
  Tabellenversionen. Die Regeln aus 3 und 4 sorgen dafür, dass ältere Leser damit
  sicher umgehen:
  * Unbekannte Flags, Kompressions- oder Payload-Typen: Der Container wird
    abgelehnt (nie halb verstanden gelesen).
  * Unbekannte Slot-Typen: Sie werden übersprungen, der Header-MAC deckt sie
    trotzdem ab. Container mit zusätzlichen Slots bleiben also für alle Schlüssel
    lesbar, die der Leser kennt.
* Schreiber setzen nur Flags, die der Inhalt braucht (z. B. Bit 2 erst beim ersten
  Anhängen), damit ältere Leser so viele Container wie möglich öffnen können.
* Eine inkompatible Änderung erfordert eine neue Formatversion im Header (3) und
  eine neue Hauptversion dieser Spezifikation.
* Reserviert: Slot-Typ 4 (Post-Quanten-Hybrid ML-KEM-768 + X25519).

### Inhalt von 1.0

Formatversion 2 mit Header und MAC samt Key-Commitment (3), den Slot-Typen 1–3, 5
(Passwort + Keyfile), 6 (Schwellwert, 5.3) und 7 (Passwort + FIDO2), dem
verschlüsselten Datenstrom (6–7), Einstiegspunkten (8), aufgeteilten Containern
(8a), dem Inhaltsverzeichnis (9), Signaturen (9a) und angehängten Segmenten (9b);
dazu Formatversion 1 zum Lesen (11).
