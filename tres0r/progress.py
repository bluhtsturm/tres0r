"""Fortschritt und Abbruch für lange Vorgänge (für CLI, TUI und GUI).

Alle langen Funktionen des Cores nehmen ``progress=`` entgegen, und zwar

* eine Funktion ``(erledigt, gesamt)`` – einfach, wie in früheren Versionen, oder
* einen ``Monitor``: bekommt ``ProgressEvent``s (Phase, aktuelle Datei,
  Durchsatz, Restzeit) und trägt ein ``CancelToken``.

Beispiel für eine GUI (Vorgang in einem Arbeits-Thread):

    token = CancelToken()
    monitor = Monitor(lambda ev: queue.put(ev), cancel=token)
    worker = threading.Thread(target=create, args=(...), kwargs={"progress": monitor})
    ...  # Abbrechen-Knopf:  token.cancel()

Ein Abbruch wirft ``Cancelled`` an der nächsten Prüfstelle (je Chunk bzw. je
Datei); Temporärdateien und Staging-Ordner werden wie bei jedem Fehler
aufgeräumt. Die Argon2-Schlüsselableitung selbst läuft in C und lässt sich
nicht unterbrechen – geprüft wird direkt davor und danach.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Union

from .errors import Cancelled

UNIT_BYTES = "bytes"
UNIT_ENTRIES = "einträge"


@dataclass(frozen=True)
class ProgressEvent:
    phase: str  # z. B. "durchsuchen", "schlüssel", "packen", "entpacken", "prüfen", "vergleichen"
    done: int
    total: int | None  # None = unbekannt (z. B. beim Lesen aus einer Pipe)
    item: str | None = None  # aktueller Eintrag
    rate: float | None = None  # Einheiten pro Sekunde
    eta: float | None = None  # Restzeit in Sekunden
    unit: str = UNIT_BYTES
    finished: bool = False

    @property
    def fraction(self) -> float | None:
        if not self.total:
            return 1.0 if self.finished else None
        return min(1.0, self.done / self.total)


class CancelToken:
    """Threadsicheres Abbruchsignal."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def check(self) -> None:
        if self._event.is_set():
            raise Cancelled("Abgebrochen.")


class Monitor:
    """Empfängt Fortschrittsereignisse (gedrosselt) und trägt ein Abbruch-Token."""

    def __init__(
        self,
        callback: Callable[[ProgressEvent], None] | None = None,
        cancel: CancelToken | None = None,
        interval: float = 0.1,
    ) -> None:
        self.callback = callback
        self.cancel = cancel or CancelToken()
        self.interval = interval


LegacyProgress = Callable[[int, int], None]
Progress = Union[LegacyProgress, Monitor, None]


class Tracker:
    """Intern: zählt Fortschritt einer Phase und meldet ihn passend weiter.

    Aufrufbar mit einer Anzahl (als ``on_bytes``-Callback für Lese-/Schreibschichten).
    Threadsicher: Bei parallelem Hashen (diff) können Meldungen aus Arbeitsthreads
    kommen – GUIs sollten Ereignisse ohnehin in ihren UI-Thread weiterreichen.
    """

    def __init__(self, progress: Progress, phase: str, total: int | None = None, unit: str = UNIT_BYTES,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._monitor = progress if isinstance(progress, Monitor) else None
        self._legacy = progress if callable(progress) and self._monitor is None else None
        self.phase, self.total, self.unit = phase, total, unit
        self.done = 0
        self._item: str | None = None
        self._clock = clock
        self._start = clock()
        self._last_emit = -1e9
        self._lock = threading.Lock()
        if self._monitor is not None:
            self._monitor.cancel.check()
            self._emit(force=True)

    # -- Zählen -----------------------------------------------------------
    def __call__(self, n: int) -> None:
        with self._lock:
            self.done += n
            if self._monitor is not None:
                self._monitor.cancel.check()
                self._emit()
            elif self._legacy is not None and self.total is not None:
                self._legacy(min(self.done, self.total), self.total)

    def item(self, name: str) -> None:
        with self._lock:
            self._item = name
            if self._monitor is not None:
                self._monitor.cancel.check()
                self._emit()

    def check(self) -> None:
        if self._monitor is not None:
            self._monitor.cancel.check()

    def finish(self) -> None:
        with self._lock:
            self._finish()

    def _finish(self) -> None:
        if self.total is not None:
            self.done = max(self.done, self.total)
        if self._monitor is not None:
            self._emit(force=True, finished=True)
        elif self._legacy is not None and self.total is not None:
            self._legacy(self.total, self.total)

    # -- Melden -----------------------------------------------------------
    def _emit(self, force: bool = False, finished: bool = False) -> None:
        if self._monitor.callback is None:
            return
        now = self._clock()
        if not force and now - self._last_emit < self._monitor.interval:
            return
        self._last_emit = now
        elapsed = now - self._start
        rate = self.done / elapsed if elapsed > 0.05 and self.done else None
        eta = None
        if rate and self.total is not None and not finished:
            eta = max(0.0, (self.total - self.done) / rate)
        self._monitor.callback(ProgressEvent(
            phase=self.phase, done=min(self.done, self.total) if self.total is not None else self.done,
            total=self.total, item=self._item, rate=rate, eta=eta, unit=self.unit, finished=finished,
        ))


def tracker(progress: Progress, phase: str, total: int | None = None, unit: str = UNIT_BYTES) -> Tracker | None:
    """Tracker nur anlegen, wenn jemand zuhört (spart Arbeit in heißen Schleifen)."""
    return None if progress is None else Tracker(progress, phase, total, unit)


__all__ = [
    "ProgressEvent",
    "CancelToken",
    "Monitor",
    "Progress",
    "UNIT_BYTES",
    "UNIT_ENTRIES",
]
