# Sicherheit

## Schwachstellen melden

Bitte **nicht** als öffentliches Issue, sondern vertraulich über GitHub:
*Security* → *Report a vulnerability* in diesem Repository. Hilfreich sind eine
Beschreibung, betroffene Version und – wenn möglich – ein präparierter Container
oder ein Skript, das den Fehler zeigt.

## Unterstützte Versionen

Sicherheitskorrekturen gibt es für die jeweils neueste Version.

## Stand

* Eigenes Containerformat, vollständig beschrieben in `FORMAT.md` (Spezifikation 1.0).
* Alle kryptografischen Primitive stammen aus `cryptography` (ChaCha20-Poly1305,
  X25519, Ed25519, HKDF, Argon2id) bzw. `argon2-cffi`; nichts ist selbst implementiert.
* Geprüft durch automatische Tests, einen unabhängigen Referenz-Leser mit
  Testvektoren, Property-Tests und Fuzzing (Header, Text, ganze Container).
* **Kein externes Audit.** Wer tres0r für wichtige Daten einsetzt, sollte das wissen.
* FIDO2 ist gegen einen Software-Token getestet, nicht mit echter Hardware.
* Grenzen, die im Entwurf liegen (z. B. Schlüssel im RAM, Größenhinweise trotz
  Padding, kein Post-Quanten-Schutz für X25519-Empfänger), stehen in der README
  unter „Grenzen (ehrlich)“.
