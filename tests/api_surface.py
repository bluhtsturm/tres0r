"""Stabile öffentliche API als Schnappschuss (tests/api_surface.json).

    python tests/api_surface.py            # Abweichungen anzeigen
    python tests/api_surface.py --update   # Änderung bewusst übernehmen

Jede Änderung an einer öffentlichen Signatur, einem Feld, einer Fehlerklasse oder
Konstante lässt test_api_surface.py fehlschlagen. In 1.x sind nur Ergänzungen
erlaubt (neue Namen, neue optionale Parameter am Ende bzw. als Schlüsselwort).
"""
from __future__ import annotations

import dataclasses
import enum
import importlib
import inspect
import json
import re
import sys
import typing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = Path(__file__).with_name("api_surface.json")
sys.path.insert(0, str(ROOT))
from tres0r.docgen import PUBLIC_MODULES as MODULES  # noqa: E402 – eine Quelle für "öffentlich"


def _value(value) -> str:
    if isinstance(value, (set, frozenset)):
        return f"{type(value).__name__}({sorted(value)!r})"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{k!r}: {_value(v)}" for k, v in sorted(value.items(), key=lambda kv: repr(kv[0]))) + "}"
    return repr(value)


def _signature(obj) -> str:
    try:
        text = str(inspect.signature(obj))
    except (TypeError, ValueError):
        return "(…)"
    return re.sub(r" at 0x[0-9a-fA-F]+", "", text)  # Speicheradressen (Windows: Großbuchstaben)


def _describe(obj) -> str:
    if inspect.ismodule(obj):
        return "module"
    if typing.get_origin(obj) is not None:  # Typ-Alias; Darstellung hängt von der Python-Version ab
        return "type alias"
    if inspect.isclass(obj):
        if issubclass(obj, BaseException):
            return "exception(" + ", ".join(b.__name__ for b in obj.__bases__) + ")"
        if issubclass(obj, enum.Enum):
            return "enum(" + ", ".join(m.name for m in obj) + ")"
        members = []
        for name, member in sorted(vars(obj).items()):
            if name.startswith("_"):
                continue
            if isinstance(member, property):
                members.append(f"{name} (property)")
            elif inspect.isfunction(member) or isinstance(member, (classmethod, staticmethod)):
                func = member.__func__ if isinstance(member, (classmethod, staticmethod)) else member
                members.append(f"{name}{_signature(func)}")
        if dataclasses.is_dataclass(obj):
            fields = []
            for f in dataclasses.fields(obj):
                default = ("" if f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING
                           else " = <factory>" if f.default is dataclasses.MISSING else f" = {_value(f.default)}")
                fields.append(f"{f.name}: {f.type}{default}")
            head = "dataclass(" + "; ".join(fields) + ")"
        else:
            head = "class" + _signature(obj.__init__)
        return head + (" | " + "; ".join(members) if members else "")
    if callable(obj):
        return "def" + _signature(obj)
    return _value(obj)


def surface() -> dict:
    sys.path.insert(0, str(ROOT))
    result = {}
    for name in MODULES:
        module = importlib.import_module(name)
        result[name] = {attr: "str (Versionsnummer)" if attr == "__version__" else _describe(getattr(module, attr))
                        for attr in sorted(module.__all__)}
    return result


def differences(old: dict, new: dict) -> list[str]:
    lines = []
    for module in sorted(set(old) | set(new)):
        a, b = old.get(module, {}), new.get(module, {})
        for name in sorted(set(a) | set(b)):
            if name not in b:
                lines.append(f"ENTFERNT  {module}.{name}")
            elif name not in a:
                lines.append(f"NEU       {module}.{name}: {b[name]}")
            elif a[name] != b[name]:
                lines.append(f"GEÄNDERT  {module}.{name}\n    vorher:  {a[name]}\n    jetzt:   {b[name]}")
    return lines


if __name__ == "__main__":
    current = surface()
    if "--update" in sys.argv:
        SNAPSHOT.write_text(json.dumps(current, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"{SNAPSHOT.name} aktualisiert ({sum(len(v) for v in current.values())} Namen).")
    else:
        found = differences(json.loads(SNAPSHOT.read_text(encoding="utf-8")), current)
        print("\n".join(found) or "keine Abweichungen")
