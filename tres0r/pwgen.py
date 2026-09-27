#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pwgen.py - Password and passphrase generator with Have I Been Pwned lookups.

Runs on Linux, macOS and Windows with Python 3.9+ and the standard library only.
Optional extra: pyperclip (clipboard support falls back to native OS tools).

License: MIT
"""

from __future__ import annotations

import argparse
import atexit
import getpass
import hashlib
import json
import locale
import math
import os
import re
import secrets
import string
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Sequence

__version__ = "1.0.0"

# --------------------------------------------------------------------------
# Configuration constants - adjust here if you want different bounds.
# --------------------------------------------------------------------------

MIN_PW_LENGTH = 8
MAX_PW_LENGTH = 128
DEFAULT_PW_LENGTH = 20

MIN_WORDS = 8
MAX_WORDS = 40
DEFAULT_WORDS = 8

# Characters that are easy to confuse in most fonts.
AMBIGUOUS_CHARS = "Il1|O0"

# Attacker capability used for the crack-time estimate (offline, fast hash).
GUESSES_PER_SECOND = 1e12

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"
HIBP_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
# The HIBP API rejects requests without a descriptive User-Agent.
# Replace this with your own project URL before publishing.
USER_AGENT = f"pwgen.py/{__version__} (password generator CLI)"
HTTP_TIMEOUT = 20

WORDLIST_FILES = {
    "en": "eff_large_wordlist_en.txt",
    "de": "de-7776-v1-diceware.txt",
}

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PWNED = 2

# --------------------------------------------------------------------------
# Localisation
# --------------------------------------------------------------------------

STRINGS: dict[str, dict[str, str]] = {
    "de": {
        "menu_title": "Passwort-Generator",
        "menu_1": "1) Passwort generieren",
        "menu_2": "2) Passphrase generieren",
        "menu_3": "3) Passwort gegen HIBP pruefen",
        "menu_4": "4) E-Mail-Adresse gegen HIBP pruefen",
        "menu_5": "5) Sprache wechseln (aktuell: {lang})",
        "menu_0": "0) Beenden",
        "prompt_choice": "Auswahl: ",
        "invalid_choice": "Ungueltige Auswahl.",
        "bye": "Tschuess.",
        "yes_no": "[j/n]",
        "yes_chars": "jy",
        "prompt_length": "Laenge ({min}-{max}) [{default}]: ",
        "prompt_symbols": "ASCII-Sonderzeichen verwenden? {yn} [j]: ",
        "prompt_ambiguous": "Mehrdeutige Zeichen ({chars}) ausschliessen? {yn} [n]: ",
        "prompt_count": "Wie viele erzeugen? [1]: ",
        "prompt_words": "Anzahl Woerter ({min}-{max}) [{default}]: ",
        "prompt_wordlist": "Wortliste - [d]eutsch oder [e]nglisch? [d]: ",
        "prompt_separator": "Trennzeichen [-]: ",
        "prompt_capitalize": "Woerter gross beginnen lassen? {yn} [n]: ",
        "prompt_digit": "Eine Ziffer anhaengen? {yn} [n]: ",
        "prompt_email": "E-Mail-Adresse: ",
        "prompt_password_hidden": "Passwort (Eingabe bleibt unsichtbar): ",
        "out_of_range": "Bitte eine Zahl zwischen {min} und {max} eingeben.",
        "not_a_number": "Das ist keine gueltige Zahl.",
        "result_header": "Ergebnis",
        "entropy": "Entropie: {bits} Bit (Zeichenvorrat: {charset})",
        "entropy_words": "Entropie: {bits} Bit ({charset} Woerter in der Liste)",
        "crack_time": "Geschaetzte Suchdauer: {value} (bei {rate} Versuchen/Sekunde)",
        "clipboard_ask": "In die Zwischenablage kopieren? {yn} [n]: ",
        "clipboard_ok": "Kopiert. Die Zwischenablage wird beim Beenden geleert.",
        "clipboard_fail": "Zwischenablage nicht verfuegbar: {err}",
        "hibp_checking": "Frage HIBP ab ...",
        "hibp_pw_clean": "Dieses Passwort taucht in keinem bekannten Leak auf.",
        "hibp_pw_pwned": "WARNUNG: Dieses Passwort taucht {count} mal in Leaks auf. Nicht verwenden.",
        "hibp_pw_note": "Hinweis: Es werden nur die ersten 5 Zeichen des SHA-1-Hashes uebertragen (k-Anonymitaet).",
        "hibp_email_clean": "Keine Treffer fuer diese Adresse.",
        "hibp_email_pwned": "Diese Adresse taucht in {count} Leak(s) auf:",
        "hibp_email_entry": "  - {title} ({date}), {pwn_count} Konten: {classes}",
        "hibp_no_key": (
            "Fuer die E-Mail-Abfrage wird ein HIBP-API-Key benoetigt (kostenpflichtiges Abo).\n"
            "Key hinterlegen in der Umgebungsvariable HIBP_API_KEY oder in der Datei:\n  {path}\n"
            "Key beziehen: https://haveibeenpwned.com/API/Key"
        ),
        "hibp_bad_key": "Der API-Key wurde abgelehnt (HTTP 401). Bitte pruefen.",
        "hibp_rate_limit": "Rate-Limit erreicht. Bitte {seconds} Sekunden warten.",
        "hibp_http_error": "HIBP-Fehler (HTTP {code}): {reason}",
        "hibp_network_error": "Netzwerkfehler: {err}",
        "invalid_email": "Das sieht nicht nach einer E-Mail-Adresse aus.",
        "wordlist_missing": (
            "Wortliste '{name}' nicht gefunden. Erwartet in einem dieser Verzeichnisse:\n{dirs}"
        ),
        "wordlist_loaded": "Wortliste: {name} ({count} Woerter)",
        "lang_switched": "Sprache: Deutsch",
        "generating_failed": "Konnte kein Passwort erzeugen, das alle Zeichenklassen enthaelt.",
        "no_charset": "Es wurde keine einzige Zeichenklasse ausgewaehlt.",
        "aborted": "Abgebrochen.",
        "unit_second": "Sekunden",
        "unit_minute": "Minuten",
        "unit_hour": "Stunden",
        "unit_day": "Tage",
        "unit_year": "Jahre",
        "unit_second_one": "Sekunde",
        "unit_minute_one": "Minute",
        "unit_hour_one": "Stunde",
        "unit_day_one": "Tag",
        "unit_year_one": "Jahr",
        "instant": "sofort",
    },
    "en": {
        "menu_title": "Password generator",
        "menu_1": "1) Generate a password",
        "menu_2": "2) Generate a passphrase",
        "menu_3": "3) Check a password against HIBP",
        "menu_4": "4) Check an email address against HIBP",
        "menu_5": "5) Switch language (current: {lang})",
        "menu_0": "0) Quit",
        "prompt_choice": "Choice: ",
        "invalid_choice": "Invalid choice.",
        "bye": "Bye.",
        "yes_no": "[y/n]",
        "yes_chars": "yj",
        "prompt_length": "Length ({min}-{max}) [{default}]: ",
        "prompt_symbols": "Include ASCII symbols? {yn} [y]: ",
        "prompt_ambiguous": "Exclude ambiguous characters ({chars})? {yn} [n]: ",
        "prompt_count": "How many should I generate? [1]: ",
        "prompt_words": "Number of words ({min}-{max}) [{default}]: ",
        "prompt_wordlist": "Wordlist - [g]erman or [e]nglish? [e]: ",
        "prompt_separator": "Separator [-]: ",
        "prompt_capitalize": "Capitalise each word? {yn} [n]: ",
        "prompt_digit": "Append a digit? {yn} [n]: ",
        "prompt_email": "Email address: ",
        "prompt_password_hidden": "Password (input stays hidden): ",
        "out_of_range": "Please enter a number between {min} and {max}.",
        "not_a_number": "That is not a valid number.",
        "result_header": "Result",
        "entropy": "Entropy: {bits} bits (character pool: {charset})",
        "entropy_words": "Entropy: {bits} bits ({charset} words in the list)",
        "crack_time": "Estimated search time: {value} (at {rate} guesses/second)",
        "clipboard_ask": "Copy to clipboard? {yn} [n]: ",
        "clipboard_ok": "Copied. The clipboard is cleared on exit.",
        "clipboard_fail": "Clipboard unavailable: {err}",
        "hibp_checking": "Querying HIBP ...",
        "hibp_pw_clean": "This password does not appear in any known breach.",
        "hibp_pw_pwned": "WARNING: this password appears {count} times in breaches. Do not use it.",
        "hibp_pw_note": "Note: only the first 5 characters of the SHA-1 hash are transmitted (k-anonymity).",
        "hibp_email_clean": "No hits for this address.",
        "hibp_email_pwned": "This address appears in {count} breach(es):",
        "hibp_email_entry": "  - {title} ({date}), {pwn_count} accounts: {classes}",
        "hibp_no_key": (
            "The email lookup requires a HIBP API key (paid subscription).\n"
            "Store the key in the HIBP_API_KEY environment variable or in the file:\n  {path}\n"
            "Get a key: https://haveibeenpwned.com/API/Key"
        ),
        "hibp_bad_key": "The API key was rejected (HTTP 401). Please check it.",
        "hibp_rate_limit": "Rate limit reached. Please wait {seconds} seconds.",
        "hibp_http_error": "HIBP error (HTTP {code}): {reason}",
        "hibp_network_error": "Network error: {err}",
        "invalid_email": "That does not look like an email address.",
        "wordlist_missing": (
            "Wordlist '{name}' not found. Expected in one of these directories:\n{dirs}"
        ),
        "wordlist_loaded": "Wordlist: {name} ({count} words)",
        "lang_switched": "Language: English",
        "generating_failed": "Could not generate a password containing all character classes.",
        "no_charset": "No character class was selected at all.",
        "aborted": "Aborted.",
        "unit_second": "seconds",
        "unit_minute": "minutes",
        "unit_hour": "hours",
        "unit_day": "days",
        "unit_year": "years",
        "unit_second_one": "second",
        "unit_minute_one": "minute",
        "unit_hour_one": "hour",
        "unit_day_one": "day",
        "unit_year_one": "year",
        "instant": "instantly",
    },
}

LANG = "en"


def t(key: str, **kwargs) -> str:
    """Look up a translated string and format it."""
    text = STRINGS.get(LANG, STRINGS["en"]).get(key) or STRINGS["en"].get(key, key)
    return text.format(**kwargs) if kwargs else text


def detect_language() -> str:
    """Guess the UI language from the environment, defaulting to English."""
    for var in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        value = os.environ.get(var)
        if value and value.lower().startswith("de"):
            return "de"
    try:
        code = locale.getdefaultlocale()[0] or ""
    except (ValueError, TypeError):
        code = ""
    return "de" if code.lower().startswith("de") else "en"


# --------------------------------------------------------------------------
# Terminal helpers
# --------------------------------------------------------------------------


def setup_stdio() -> None:
    """Force UTF-8 output so symbols survive the legacy Windows console."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def ask(prompt: str) -> str:
    """input() that turns Ctrl-C / Ctrl-D into a clean abort."""
    try:
        return input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        print()
        raise Abort()


def ask_yes_no(prompt: str, default: bool) -> bool:
    answer = ask(prompt).lower()
    if not answer:
        return default
    return answer[0] in t("yes_chars")


def ask_int(prompt: str, minimum: int, maximum: int, default: int) -> int:
    while True:
        raw = ask(prompt)
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print(t("not_a_number"))
            continue
        if minimum <= value <= maximum:
            return value
        print(t("out_of_range", min=minimum, max=maximum))


class Abort(Exception):
    """Raised when the user interrupts an interactive prompt."""


# --------------------------------------------------------------------------
# Clipboard (optional)
# --------------------------------------------------------------------------

_clipboard_value: str | None = None


def _clipboard_commands() -> list[list[str]]:
    if sys.platform == "darwin":
        return [["pbcopy"]]
    if sys.platform.startswith("win"):
        return [["clip"]]
    return [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]


def copy_to_clipboard(value: str) -> None:
    """Copy to clipboard via pyperclip if present, otherwise via native tools."""
    global _clipboard_value
    try:
        import pyperclip  # type: ignore

        pyperclip.copy(value)
        _clipboard_value = value
        return
    except ImportError:
        pass
    except Exception as exc:  # pyperclip raises its own error types
        raise RuntimeError(str(exc)) from exc

    errors = []
    for cmd in _clipboard_commands():
        try:
            subprocess.run(cmd, input=value.encode("utf-8"), check=True, timeout=10)
            _clipboard_value = value
            return
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"{cmd[0]}: {exc}")
    raise RuntimeError("; ".join(errors) or "no clipboard backend found")


@atexit.register
def _clear_clipboard() -> None:
    """Best-effort wipe so the secret does not linger after the program exits."""
    if _clipboard_value is None:
        return
    try:
        copy_to_clipboard(" ")
    except Exception:
        pass


# --------------------------------------------------------------------------
# Entropy reporting
# --------------------------------------------------------------------------


def fmt_decimal(value: float, digits: int = 1) -> str:
    """Decimal number with the separator the current UI language expects."""
    text = f"{value:.{digits}f}"
    return text.replace(".", ",") if LANG == "de" else text


def fmt_int(value: int) -> str:
    """Integer with a language-appropriate thousands separator."""
    text = f"{value:,}"
    if LANG == "de":
        return text.replace(",", ".")
    return text


def fmt_power(value: float) -> str:
    """Render a huge number as '2,2 x 10^43' instead of '2.2e+43'."""
    if value <= 0:
        return "0"
    exponent = math.floor(math.log10(value))
    mantissa = value / (10.0**exponent)
    if round(mantissa, 1) == 1.0:
        return f"10^{exponent}"
    return f"{fmt_decimal(mantissa)} x 10^{exponent}"


def fmt_unit(count: int, unit: str) -> str:
    """Number plus unit, using the singular form when the count is exactly one."""
    key = f"unit_{unit}_one" if count == 1 else f"unit_{unit}"
    return f"{fmt_int(count)} {t(key)}"


def format_crack_time(bits: float) -> str:
    """Average search time for a uniformly random secret of the given entropy."""
    try:
        seconds = (2.0 ** (bits - 1)) / GUESSES_PER_SECOND
    except OverflowError:
        return f"> 10^300 {t('unit_year')}"
    if seconds < 1:
        return t("instant")
    if seconds < 60:
        return fmt_unit(round(seconds), "second")
    if seconds < 3600:
        return fmt_unit(round(seconds / 60), "minute")
    if seconds < 86400:
        return fmt_unit(round(seconds / 3600), "hour")
    years = seconds / 31_557_600
    if years < 1:
        return fmt_unit(round(seconds / 86400), "day")
    if years < 1e6:
        return fmt_unit(round(years), "year")
    return f"{fmt_power(years)} {t('unit_year')}"


def report_secret(secret_value: str, bits: float, pool_size: int, is_words: bool) -> None:
    print()
    print(t("result_header") + ":")
    print("  " + secret_value)
    key = "entropy_words" if is_words else "entropy"
    print("  " + t(key, bits=fmt_decimal(bits), charset=fmt_int(pool_size)))
    print(
        "  "
        + t("crack_time", value=format_crack_time(bits), rate=fmt_power(GUESSES_PER_SECOND))
    )


# --------------------------------------------------------------------------
# Password generation
# --------------------------------------------------------------------------


def build_alphabet(use_symbols: bool, exclude_ambiguous: bool) -> list[str]:
    """Return the character classes that must each appear at least once."""
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if use_symbols:
        classes.append(string.punctuation)
    if exclude_ambiguous:
        classes = ["".join(c for c in cls if c not in AMBIGUOUS_CHARS) for cls in classes]
    return [cls for cls in classes if cls]


def generate_password(length: int, classes: Sequence[str]) -> str:
    """Uniform random password, resampled until every class is represented.

    Rejection sampling keeps the distribution uniform over all valid passwords.
    Placing one character per class at a fixed position would not.
    """
    if not classes:
        raise ValueError(t("no_charset"))
    alphabet = "".join(classes)
    for _ in range(10_000):
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(ch in cls for ch in candidate) for cls in classes):
            return candidate
    raise RuntimeError(t("generating_failed"))


# --------------------------------------------------------------------------
# Wordlists
# --------------------------------------------------------------------------


def wordlist_search_paths() -> list[Path]:
    here = Path(__file__).resolve().parent
    paths = [here / "wordlists", here]
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            paths.append(Path(appdata) / "pwgen" / "wordlists")
    else:
        xdg = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        paths.append(Path(xdg) / "pwgen" / "wordlists")
        paths.append(Path("/usr/local/share/pwgen/wordlists"))
        paths.append(Path("/usr/share/pwgen/wordlists"))
    return paths


def load_wordlist(lang: str) -> list[str]:
    """Load a Diceware-style wordlist. Accepts 'dice<TAB>word' and plain lines."""
    name = WORDLIST_FILES[lang]
    for directory in wordlist_search_paths():
        candidate = directory / name
        if candidate.is_file():
            words = []
            with candidate.open(encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    words.append(parts[-1])
            if words:
                return words
    dirs = "\n".join(f"  {d}" for d in wordlist_search_paths())
    raise FileNotFoundError(t("wordlist_missing", name=name, dirs=dirs))


def generate_passphrase(
    words: Sequence[str],
    count: int,
    separator: str,
    capitalize: bool,
    append_digit: bool,
) -> str:
    chosen = [secrets.choice(words) for _ in range(count)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = separator.join(chosen)
    if append_digit:
        phrase += separator + str(secrets.randbelow(10))
    return phrase


# --------------------------------------------------------------------------
# Have I Been Pwned
# --------------------------------------------------------------------------


def config_dir() -> Path:
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / "pwgen"
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(xdg) / "pwgen"


def load_api_key() -> str | None:
    key = os.environ.get("HIBP_API_KEY", "").strip()
    if key:
        return key
    key_file = config_dir() / "hibp_api_key"
    if key_file.is_file():
        content = key_file.read_text(encoding="utf-8").strip()
        if content:
            return content
    return None


def http_get(url: str, headers: dict[str, str]) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.status, response.read().decode(charset, errors="replace")


def check_password_pwned(password: str) -> int:
    """Return how often the password appears in HIBP. Uses k-anonymity.

    Only the first five characters of the SHA-1 hash leave this machine.
    'Add-Padding' makes HIBP pad the response so its size leaks nothing.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    _, body = http_get(HIBP_RANGE_URL.format(prefix), {"Add-Padding": "true"})
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip() == suffix:
            try:
                return int(count)
            except ValueError:
                return 0
    return 0


def check_email_pwned(email: str, api_key: str) -> list[dict]:
    """Return the list of breaches for an account. Requires a paid API key."""
    quoted = urllib.parse.quote(email, safe="")
    url = HIBP_ACCOUNT_URL.format(quoted) + "?truncateResponse=false"
    try:
        _, body = http_get(url, {"hibp-api-key": api_key})
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise
    return json.loads(body)


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --------------------------------------------------------------------------
# Interactive actions
# --------------------------------------------------------------------------


def action_password() -> None:
    length = ask_int(
        t("prompt_length", min=MIN_PW_LENGTH, max=MAX_PW_LENGTH, default=DEFAULT_PW_LENGTH),
        MIN_PW_LENGTH,
        MAX_PW_LENGTH,
        DEFAULT_PW_LENGTH,
    )
    use_symbols = ask_yes_no(t("prompt_symbols", yn=t("yes_no")), True)
    exclude_ambiguous = ask_yes_no(
        t("prompt_ambiguous", chars=AMBIGUOUS_CHARS, yn=t("yes_no")), False
    )
    count = ask_int(t("prompt_count"), 1, 50, 1)

    classes = build_alphabet(use_symbols, exclude_ambiguous)
    pool = len("".join(classes))
    bits = length * math.log2(pool)

    last = ""
    for _ in range(count):
        last = generate_password(length, classes)
        report_secret(last, bits, pool, is_words=False)

    if count == 1:
        offer_clipboard(last)


def action_passphrase(preset: str | None = None) -> None:
    if preset:
        lang = preset
    else:
        choice = ask(t("prompt_wordlist")).lower()
        if LANG == "de":
            lang = "en" if choice.startswith("e") else "de"
        else:
            lang = "de" if choice[:1] in ("g", "d") else "en"

    words = load_wordlist(lang)
    print(t("wordlist_loaded", name=WORDLIST_FILES[lang], count=len(words)))

    count = ask_int(
        t("prompt_words", min=MIN_WORDS, max=MAX_WORDS, default=DEFAULT_WORDS),
        MIN_WORDS,
        MAX_WORDS,
        DEFAULT_WORDS,
    )
    separator = ask(t("prompt_separator")) or "-"
    capitalize = ask_yes_no(t("prompt_capitalize", yn=t("yes_no")), False)
    append_digit = ask_yes_no(t("prompt_digit", yn=t("yes_no")), False)

    phrase = generate_passphrase(words, count, separator, capitalize, append_digit)
    bits = count * math.log2(len(words))
    report_secret(phrase, bits, len(words), is_words=True)
    offer_clipboard(phrase)


def offer_clipboard(value: str) -> None:
    if not ask_yes_no("  " + t("clipboard_ask", yn=t("yes_no")), False):
        return
    try:
        copy_to_clipboard(value)
        print("  " + t("clipboard_ok"))
    except RuntimeError as exc:
        print("  " + t("clipboard_fail", err=exc))


def action_check_password() -> None:
    print(t("hibp_pw_note"))
    try:
        password = getpass.getpass(t("prompt_password_hidden"))
    except (KeyboardInterrupt, EOFError):
        print()
        raise Abort()
    if not password:
        return
    print(t("hibp_checking"))
    try:
        count = check_password_pwned(password)
    except urllib.error.HTTPError as exc:
        print(t("hibp_http_error", code=exc.code, reason=exc.reason))
        return
    except urllib.error.URLError as exc:
        print(t("hibp_network_error", err=exc.reason))
        return
    if count:
        print(t("hibp_pw_pwned", count=fmt_int(count)))
    else:
        print(t("hibp_pw_clean"))


def action_check_email() -> None:
    api_key = load_api_key()
    if not api_key:
        print(t("hibp_no_key", path=config_dir() / "hibp_api_key"))
        return
    email = ask(t("prompt_email"))
    if not EMAIL_RE.match(email):
        print(t("invalid_email"))
        return
    print(t("hibp_checking"))
    try:
        breaches = check_email_pwned(email, api_key)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            print(t("hibp_bad_key"))
        elif exc.code == 429:
            print(t("hibp_rate_limit", seconds=exc.headers.get("Retry-After", "?")))
        else:
            print(t("hibp_http_error", code=exc.code, reason=exc.reason))
        return
    except urllib.error.URLError as exc:
        print(t("hibp_network_error", err=exc.reason))
        return

    if not breaches:
        print(t("hibp_email_clean"))
        return
    print(t("hibp_email_pwned", count=len(breaches)))
    for breach in breaches:
        print(
            t(
                "hibp_email_entry",
                title=breach.get("Title", breach.get("Name", "?")),
                date=breach.get("BreachDate", "?"),
                pwn_count=fmt_int(breach.get("PwnCount", 0)),
                classes=", ".join(breach.get("DataClasses", [])) or "-",
            )
        )


# --------------------------------------------------------------------------
# Main menu
# --------------------------------------------------------------------------


def print_menu() -> None:
    print()
    print("=" * 46)
    print(f"  {t('menu_title')} v{__version__}")
    print("=" * 46)
    for key in ("menu_1", "menu_2", "menu_3", "menu_4"):
        print(t(key))
    print(t("menu_5", lang="Deutsch" if LANG == "de" else "English"))
    print(t("menu_0"))


def main_menu(wordlist_preset: str | None = None) -> int:
    global LANG
    actions = {
        "1": action_password,
        "2": lambda: action_passphrase(wordlist_preset),
        "3": action_check_password,
        "4": action_check_email,
    }
    while True:
        print_menu()
        try:
            choice = ask(t("prompt_choice"))
        except Abort:
            print(t("bye"))
            return EXIT_OK
        if choice in ("0", "q", "quit", "exit"):
            print(t("bye"))
            return EXIT_OK
        if choice == "5":
            LANG = "en" if LANG == "de" else "de"
            print(t("lang_switched"))
            continue
        action = actions.get(choice)
        if not action:
            print(t("invalid_choice"))
            continue
        try:
            action()
        except Abort:
            print(t("aborted"))
        except (FileNotFoundError, ValueError, RuntimeError) as exc:
            print(str(exc))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pwgen.py",
        description="Password and passphrase generator with Have I Been Pwned lookups.",
    )
    parser.add_argument("--lang", choices=("de", "en"), help="UI language (default: auto-detect)")
    parser.add_argument(
        "--wordlist",
        choices=("de", "en"),
        help="Preselect the passphrase wordlist and skip that question",
    )
    parser.add_argument("--version", action="version", version=f"pwgen.py {__version__}")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    global LANG
    setup_stdio()
    args = parse_args(argv)
    LANG = args.lang or detect_language()

    return main_menu(args.wordlist)


if __name__ == "__main__":
    sys.exit(main())
