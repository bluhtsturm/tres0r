"""Manpage und Shell-Vervollständigung direkt aus dem CLI-Parser (veraltet nie).

    tres0r manpage > tres0r.1            tres0r completion bash|zsh
    python -m tres0r.docgen              # man/ und completions/ im Quellbaum neu schreiben

Die Ausgabe ist deterministisch (kein Datum), damit ein Test prüfen kann, dass die
Dateien im Repository zum Code passen.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from . import __version__

SUMMARY = "Dateien, Ordner und Datenströme verschlüsseln"
# Stabile öffentliche Module (1.x); alles andere ist intern.
PUBLIC_MODULES = ["tres0r", "tres0r.keys", "tres0r.shamir", "tres0r.progress", "tres0r.errors",
                  "tres0r.passgen", "tres0r.hwtoken", "tres0r.mount"]

API_INTRO = """# tres0r – Python-API (stabil, 1.x)

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
"""


# --- Parser auslesen ---------------------------------------------------------
def _subparsers(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def _summaries(parser: argparse.ArgumentParser) -> dict[str, str]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return {a.dest: a.help or "" for a in action._choices_actions}
    return {}


def _help(parser: argparse.ArgumentParser, action: argparse.Action) -> str:
    if not action.help or action.help == argparse.SUPPRESS:
        return ""
    return " ".join(parser._get_formatter()._expand_help(action).split())


def _options(parser: argparse.ArgumentParser) -> list[argparse.Action]:
    return [a for a in parser._actions if a.option_strings and a.help != argparse.SUPPRESS
            and not isinstance(a, argparse._HelpAction)]


def _positionals(parser: argparse.ArgumentParser) -> list[argparse.Action]:
    return [a for a in parser._actions if not a.option_strings and not isinstance(a, argparse._SubParsersAction)]


def _takes_value(action: argparse.Action) -> bool:
    return action.nargs != 0


def _metavar(action: argparse.Action) -> str:
    if action.metavar:
        return action.metavar if isinstance(action.metavar, str) else " ".join(action.metavar)
    return action.dest.upper()


def _commands(parser: argparse.ArgumentParser) -> list[tuple[str, argparse.ArgumentParser, str]]:
    """(Name, Parser, Kurzhilfe) – verschachtelte Befehle als "keys add-password"."""
    found = []
    summaries = _summaries(parser)
    for name, sub in _subparsers(parser).items():
        found.append((name, sub, summaries.get(name, "")))
        inner = _summaries(sub)
        for inner_name, inner_sub in _subparsers(sub).items():
            found.append((f"{name} {inner_name}", inner_sub, inner.get(inner_name, "")))
    return found


def _usage(sub: argparse.ArgumentParser) -> str:
    text = " ".join(sub.format_usage().split())
    return re.sub(r"^usage:\s*", "", text)


# --- Manpage -----------------------------------------------------------------
def _roff(text: str) -> str:
    text = text.replace("\\", "\\e").replace("-", "\\-")
    text = "".join(ch if ord(ch) < 128 else f"\\[u{ord(ch):04X}]" for ch in text)  # reines ASCII: überall lesbar
    return "\n".join(("\\&" + line) if line.startswith((".", "'")) else line for line in text.split("\n"))


def manpage(parser: argparse.ArgumentParser | None = None) -> str:
    from .cli import build_parser

    parser = parser or build_parser()
    out = [f'.TH TRES0R 1 "" "tres0r {__version__}" "Benutzerbefehle"', ".nh", ".ad l",
           ".SH NAME", f"tres0r \\- {_roff(SUMMARY)}",
           f".SH {_roff('ÜBERSICHT')}", ".B tres0r", ".I BEFEHL", ".RI [ OPTIONEN ]", ".br",
           ".B tres0r", ".RB [ \\-\\-version | \\-h ]",
           ".SH BESCHREIBUNG",
           _roff("tres0r verschlüsselt Dateien, Ordner und Datenströme in einen Container "
                 "(Argon2id, ChaCha20-Poly1305, optional zstd). Container können mehrere Schlüssel "
                 "haben (Passwörter, Wiederherstellungsphrase, Empfänger, Keyfile, FIDO2-Token, "
                 "Schwellwert-Anteile), signiert, aufgeteilt, eingehängt und erweitert werden. "
                 "Das Format ist in FORMAT.md beschrieben."),
           _roff("Alle Befehle kennen --json (maschinenlesbare Ausgabe auf stdout), -q und -v."),
           ".SH BEFEHLE"]
    for name, sub, summary in _commands(parser):
        if _subparsers(sub):
            out += [f'.SS "{_roff(name)}"', _roff(summary or ""), _roff("Unterbefehle siehe unten.")]
            continue
        out += [f'.SS "{_roff(name)}"', _roff(summary or sub.description or ""), ".PP",
                _roff(_usage(sub))]
        for action in _positionals(sub):
            text = _help(sub, action)
            if text:
                out += [".TP", f".I {_roff(_metavar(action))}", _roff(text)]
        for action in _options(sub):
            flags = ", ".join(action.option_strings)
            value = f" {_metavar(action)}" if _takes_value(action) else ""
            out += [".TP", f".B {_roff(flags)}{_roff(value)}", _roff(_help(sub, action))]
    codes = [("0", "Erfolg."), ("1", "Fehler oder Abbruch."), ("2", "Falsches Passwort bzw. kein passender Schlüssel."),
             ("3", "Container beschädigt, manipuliert oder unsicher; Signatur fehlt oder ist falsch."),
             ("4", "diff: Unterschiede gefunden."), ("130", "Abbruch mit Strg+C.")]
    out += [".SH EXIT\\-CODES"]
    for code, text in codes:
        out += [".TP", f".B {code}", _roff(text)]
    out += [".SH SIEHE AUCH", _roff("FORMAT.md (Containerformat 1.0), API.md (Python-API), README.md.")]
    return "\n".join(out) + "\n"


# --- Vervollständigung -------------------------------------------------------
def _shell_word(text: str) -> str:
    return text.replace("'", "")


def bash_completion(parser: argparse.ArgumentParser | None = None) -> str:
    """bash-Vervollständigung. Läuft auch mit bash 3.2 (macOS): keine assoziativen
    Arrays, kein extglob (verstellt sonst Optionen der Shell des Nutzers)."""
    from .cli import build_parser

    parser = parser or build_parser()
    top = list(_subparsers(parser))
    nested = {name: " ".join(_subparsers(sub)) for name, sub, _ in _commands(parser) if _subparsers(sub)}
    lines = ["# bash-Vervollständigung für tres0r – erzeugt von tres0r.docgen, nicht von Hand ändern",
             "_tres0r() {",
             '    local cur="${COMP_WORDS[COMP_CWORD]}" prev="${COMP_WORDS[COMP_CWORD-1]}"',
             '    local cmd="" sub="" nested="" i word opts="" values="" choices="" positional=""',
             "    for ((i = 1; i < COMP_CWORD; i++)); do",
             '        word="${COMP_WORDS[i]}"',
             '        [[ $word == -* ]] && continue',
             '        if [[ -z $cmd ]]; then',
             '            cmd="$word"',
             '            case "$cmd" in']
    lines += [f'                {name}) nested="{words}" ;;' for name, words in nested.items()]
    lines += ["            esac",
              '        elif [[ -z $sub && -n $nested ]]; then sub="$word"; fi',
              "    done",
              '    if [[ -z $cmd ]]; then',
              f'        COMPREPLY=($(compgen -W "{" ".join(top)} --help --version" -- "$cur")); return',
              "    fi",
              '    if [[ -n $nested && -z $sub ]]; then',
              '        COMPREPLY=($(compgen -W "$nested" -- "$cur")); return',
              "    fi",
              '    case "$cmd${sub:+ $sub}" in']
    for name, sub, _ in _commands(parser):
        if name in nested:
            continue
        options = _options(sub)
        flags = " ".join(f for a in options for f in a.option_strings)
        valued = "|".join(f for a in options if _takes_value(a) for f in a.option_strings)
        lines.append(f'        "{name}")')
        lines.append(f'            opts="{flags} --help"; values="{valued}"')
        fixed = [str(c) for a in _positionals(sub) if a.choices for c in a.choices]
        if fixed:
            lines.append(f'            positional="{" ".join(fixed)}"')
        with_choices = [a for a in options if a.choices]
        if with_choices:
            lines.append('            case "$prev" in')
            for action in with_choices:
                pattern = "|".join(action.option_strings)
                words = " ".join(str(c) for c in action.choices)
                lines.append(f'                {pattern}) choices="{words}" ;;')
            lines.append("            esac")
        lines.append("            ;;")
    lines += ["    esac",
              '    if [[ -n $choices ]]; then COMPREPLY=($(compgen -W "$choices" -- "$cur")); return; fi',
              # Dateinamen zeilenweise trennen – sonst zerfällt "Meine Datei" in zwei Vorschläge
              '    if [[ -n $values && "|$values|" == *"|$prev|"* ]]; then',
              "        local IFS=$'\\n'; COMPREPLY=($(compgen -f -- \"$cur\")); return",
              "    fi",
              '    if [[ $cur == -* ]]; then COMPREPLY=($(compgen -W "$opts" -- "$cur"))',
              '    elif [[ -n $positional ]]; then COMPREPLY=($(compgen -W "$positional" -- "$cur"))',
              "    else local IFS=$'\\n'; COMPREPLY=($(compgen -f -- \"$cur\")); fi",
              "}",
              "complete -o filenames -o bashdefault -F _tres0r tres0r"]
    return "\n".join(lines) + "\n"


def _zsh_text(text: str, limit: int = 70) -> str:
    text = text.replace("'", "’").replace("[", "(").replace("]", ")").replace(":", " –").replace("\\", "/")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _zsh_spec(sub: argparse.ArgumentParser, action: argparse.Action) -> str:
    flags = action.option_strings
    description = _zsh_text(_help(sub, action))
    repeat = "*" if isinstance(action, (argparse._AppendAction, argparse._CountAction)) else ""
    value = ""
    if _takes_value(action):
        target = "(" + " ".join(str(c) for c in action.choices) + ")" if action.choices else "_files"
        value = f":{_zsh_text(_metavar(action), 30)}:{target}"
    if len(flags) == 1:
        return f"'{repeat}{flags[0]}[{description}]{value}'"
    exclusive = "" if repeat else "(" + " ".join(flags) + ")"
    return f"'{repeat}{exclusive}'{{{','.join(flags)}}}'[{description}]{value}'"


def zsh_completion(parser: argparse.ArgumentParser | None = None) -> str:
    from .cli import build_parser

    parser = parser or build_parser()
    summaries = _summaries(parser)

    def describe(names: dict[str, str], label: str, indent: str) -> list[str]:
        return [f"{indent}local -a choices=(" + " ".join(f"'{n}:{_zsh_text(h, 50)}'" for n, h in names.items()) + ")",
                f"{indent}_describe '{label}' choices"]

    lines = ["#compdef tres0r", "# zsh-Vervollständigung für tres0r – erzeugt von tres0r.docgen, nicht von Hand ändern",
             "_tres0r() {", "  if (( CURRENT == 2 )); then",
             *describe(summaries, "Befehl", "    "), "    return", "  fi",
             "  local cmd=${words[2]}", "  shift words; (( CURRENT-- ))", "  case $cmd in"]
    for name, sub in _subparsers(parser).items():
        lines.append(f"    {name})")
        inner = _subparsers(sub)
        if inner:
            lines += ["      if (( CURRENT == 2 )); then", *describe(_summaries(sub), "Aktion", "        "),
                      "        return", "      fi", "      local action=${words[2]}", "      shift words; (( CURRENT-- ))",
                      "      case $action in"]
            for inner_name, inner_sub in inner.items():
                lines.append(f"        {inner_name}) _arguments -s {_zsh_arguments(inner_sub)} ;;")
            lines += ["      esac", "      ;;"]
        else:
            lines.append(f"      _arguments -s {_zsh_arguments(sub)} ;;")
    lines += ["  esac", "}", '_tres0r "$@"']
    return "\n".join(lines) + "\n"


def _zsh_arguments(sub: argparse.ArgumentParser) -> str:
    specs = [_zsh_spec(sub, a) for a in _options(sub)]
    for action in _positionals(sub):
        many = action.nargs in ("+", "*", argparse.REMAINDER)
        target = "(" + " ".join(str(c) for c in action.choices) + ")" if action.choices else "_files"
        specs.append(f"'{'*' if many else ''}:{_zsh_text(_metavar(action), 30)}:{target}'")
    return " \\\n          ".join(specs)


# --- API-Referenz -----------------------------------------------------------------
PARAMETERS = {
    "container": "Pfad des Containers (bei --split der Basisname oder ein Teil).",
    "sources": "Pfade (Dateien/Ordner) oder ein ``Plan`` aus ``scan``.",
    "plan": "Ergebnis von ``scan``.",
    "output": "Zielpfad.",
    "dest": "Zielordner; entsteht bei Bedarf.",
    "path": "Pfad.",
    "src": "Lesbares Binär-Dateiobjekt.",
    "out": "Beschreibbares Binär-Dateiobjekt.",
    "credentials": "Zugangsdaten: Passwort/Phrase (str, bytes) oder ``Credentials`` "
                   "(Passwörter, Identitäten, Keyfiles, Anteile, FIDO2).",
    "password": "Passwort für den neuen Passwort-Slot; ``None`` = keiner.",
    "params": "Argon2id-Parameter (``KdfParams``, z. B. ``LEVELS[\"normal\"]``); ``None`` = Standard bzw. unverändert.",
    "recipients": "Öffentliche X25519-Schlüssel; jeder bekommt einen eigenen Slot.",
    "recovery": "Wiederherstellungsphrase (``keys.generate_recovery``) als eigener Slot.",
    "keyfile": "Keyfile-Geheimnis (``keys.keyfile_secret``) – zweiter Faktor zum Passwort.",
    "fido2": "``hwtoken.TokenProvider`` – FIDO2-Token als zweiter Faktor zum Passwort.",
    "threshold": "``(k, n)`` – Schwellwert-Slot; die Anteile stehen im Ergebnis (``shares``).",
    "compress": "Mit zstd komprimieren (Python 3.14 oder Paket ``zstandard``).",
    "pad": "Padmé-Padding: verbirgt die genaue Größe (Standard an).",
    "sign_with": "Ed25519-Signaturschlüssel (``keys.generate_signing_key``).",
    "signers": "Erwartete Prüfschlüssel: fehlt die Signatur oder passt keiner, folgt ``SignatureError``.",
    "overwrite": "Vorhandene Ausgabe ersetzen (sonst Fehler).",
    "progress": "Fortschritt: Funktion ``(erledigt, gesamt)`` oder ``Monitor`` (Ereignisse, Abbruch).",
    "exclude": "``ExcludeRules`` (Muster, typische Junk-Dateien).",
    "ignore_files": "``.tres0rignore``-Dateien in den Quellen beachten (Standard an).",
    "strict_names": "Abbrechen statt warnen, wenn Namen nicht auf allen Systemen gültig sind.",
    "check_space": "Freien Speicherplatz vorher prüfen (``InsufficientSpace``).",
    "times": "Änderungszeiten speichern (``False``: Zeit 0, beim Entpacken die aktuelle Zeit).",
    "xattrs": "Erweiterte Attribute ``user.*`` sichern bzw. wiederherstellen (Linux).",
    "acls": "POSIX-ACLs sichern bzw. wiederherstellen (Linux).",
    "threads": "Threads für SHA-256 und zstd; ``None`` = automatisch (Kerne, max. 8), ``1`` = aus.",
    "split": "Teilgröße in Byte für ``NAME.001 …``; ``None`` = eine Datei.",
    "rename": "Kollidierende oder hier ungültige Namen umbenennen statt abbrechen.",
    "only": "Muster: nur passende Einträge (samt Inhalt passender Ordner).",
    "total": "Erwartete Größe in Byte – für Fortschritt und Restzeit.",
    "passphrase": "Passphrase einer geschützten Schlüsseldatei.",
}


def undocumented() -> list[str]:
    """Parameter öffentlicher Funktionen, die weder im Docstring noch in PARAMETERS stehen."""
    import importlib
    import inspect

    missing = []
    for module_name in PUBLIC_MODULES:
        module = importlib.import_module(module_name)
        for name in module.__all__:
            obj = getattr(module, name)
            if not inspect.isfunction(obj):
                continue
            doc = inspect.getdoc(obj) or ""
            if not doc:
                missing.append(f"{module_name}.{name}: kein Docstring")
                continue
            gaps = [p for p in inspect.signature(obj).parameters if p not in PARAMETERS and p not in doc]
            if gaps:
                missing.append(f"{module_name}.{name}: {', '.join(gaps)}")
    return missing

def _plain_signature(obj) -> str:
    import inspect

    try:
        signature = inspect.signature(obj)
    except (TypeError, ValueError):
        return "(…)"
    parameters = [p.replace(annotation=inspect.Parameter.empty) for p in signature.parameters.values()]
    text = str(signature.replace(parameters=parameters, return_annotation=inspect.Signature.empty))
    return re.sub(r" at 0x[0-9a-fA-F]+", "", text)  # Windows: Großbuchstaben


def _type_text(tp) -> str:
    """Typ lesbar und über Python-Versionen gleich (typing-Darstellung ändert sich mit 3.14)."""
    import collections.abc
    import types
    import typing

    origin, args = typing.get_origin(tp), typing.get_args(tp)
    if tp is type(None):
        return "None"
    if origin in (typing.Union, getattr(types, "UnionType", typing.Union)):
        return " | ".join(_type_text(a) for a in args)
    if origin is collections.abc.Callable:
        params, result = args
        inner = "..." if params is Ellipsis else ", ".join(_type_text(a) for a in params)
        return f"Callable[[{inner}], {_type_text(result)}]"
    if origin is not None:
        return f"{getattr(origin, '__name__', str(origin))}[{', '.join(_type_text(a) for a in args)}]"
    return getattr(tp, "__name__", str(tp))


def _doc(obj) -> str:
    import inspect

    text = inspect.getdoc(obj) or ""
    return text.strip()


def api_reference() -> str:
    import dataclasses
    import importlib
    import inspect
    import typing

    out = [API_INTRO, "## Gemeinsame Parameter\n",
           "Diese Namen bedeuten in allen Funktionen dasselbe:\n",
           "\n".join(f"* `{name}` – {text.replace('``', '`')}" for name, text in PARAMETERS.items()) + "\n"]
    for module_name in PUBLIC_MODULES:
        module = importlib.import_module(module_name)
        out.append(f"## `{module_name}`\n")
        if module_name != "tres0r":
            first = _doc(module).split("\n\n")[0]
            if first:
                out.append(first + "\n")
        for name in module.__all__:
            obj = getattr(module, name)
            if inspect.ismodule(obj) or name == "__version__":
                continue
            if typing.get_origin(obj) is not None:
                out.append(f"### `{name}` (Typ)\n\n`{_type_text(obj)}`\n")
                continue
            if inspect.isclass(obj) and issubclass(obj, BaseException):
                bases = ", ".join(b.__name__ for b in obj.__bases__)
                out.append(f"### `{name}({bases})`\n\n{_doc(obj)}\n")
            elif inspect.isclass(obj) and dataclasses.is_dataclass(obj):
                fields = "\n".join(f"* `{f.name}: {f.type}`" for f in dataclasses.fields(obj))
                out.append(f"### `{name}` (Datenklasse)\n\n{_doc(obj)}\n\n{fields}\n".replace("\n\n\n", "\n\n"))
            elif inspect.isclass(obj):
                out.append(f"### `{name}{_plain_signature(obj)}`\n\n{_doc(obj)}\n")
            elif callable(obj):
                out.append(f"### `{name}{_plain_signature(obj)}`\n\n{_doc(obj)}\n")
            else:
                value = sorted(obj) if isinstance(obj, (set, frozenset)) else obj
                out.append(f"### `{name}`\n\n`{value!r}`\n")
    text = "\n".join(out)
    return re.sub(r"\n{3,}", "\n\n", text).rstrip() + "\n"


# --- Dateien im Quellbaum --------------------------------------------------------
def outputs(root: Path) -> dict[Path, str]:
    return {root / "man" / "tres0r.1": manpage(), root / "completions" / "tres0r.bash": bash_completion(),
            root / "completions" / "_tres0r": zsh_completion(), root / "API.md": api_reference()}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    for path, text in outputs(root).items():
        path.parent.mkdir(exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"geschrieben: {path.relative_to(root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
