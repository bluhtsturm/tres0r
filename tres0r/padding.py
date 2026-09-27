"""Padmé-Padding (Nikitin et al., "Reducing Metadata Leakage from Encrypted
Files and Communication with PURBs", PETS 2019).

Ohne Padding verrät die Containergröße die exakte Datenmenge. Padmé rundet
auf eine von wenigen möglichen Größen auf: Es bleiben nur O(log log n) Bit
Information übrig. Der Overhead liegt im Mittel bei ca. 1 %, maximal bei ca. 6 %
(kleine Container ab 1 KiB) bzw. ca. 3 % ab 64 KiB.

Aufgefüllt wird mit Nullbytes *nach* dem tar-Archivende. tar-Leser ignorieren
diese – deshalb ändert Padding das Containerformat nicht.
"""
from __future__ import annotations


def padme(length: int) -> int:
    if length < 2:
        return length
    e = length.bit_length() - 1  # floor(log2 L)
    s = e.bit_length()  # floor(log2 E) + 1
    mask = (1 << max(0, e - s)) - 1
    return (length + mask) & ~mask
