"""Textparser: Schlüssel, Phrasen, Ausschlussmuster, Portabilitäts-Check."""
import sys

import atheris

import _common

_common.PHRASE  # nur für den Suchpfad importiert (Nebenwirkung); so sieht pyflakes die Nutzung

with atheris.instrument_imports():
    from tres0r import keys, portability
    from tres0r.exclude import ExcludeRules


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(200) if fdp.ConsumeBool() else fdp.ConsumeUnicode(200)
    for parse, prefix in ((keys.parse_recipient, keys.PUB_PREFIX), (keys.parse_identity, keys.SECRET_PREFIX),
                          (keys.parse_verify_key, keys.SIGN_PUB_PREFIX),
                          (keys.parse_signing_key, keys.SIGN_SECRET_PREFIX)):
        for candidate in (text, prefix + text):
            try:
                parse(candidate)
            except keys.KeyFormatError:
                pass
    once = keys.canonical_secret(text)
    assert keys.canonical_secret(once) == once
    try:
        rules = ExcludeRules(text.split("\n"))
        rules.matches(text, fdp.ConsumeBool())
    except ValueError:
        pass
    items = [(part, bool(i % 2)) for i, part in enumerate(text.split("\x00")) if part]
    portability.check_names(items)
    for part in text.split("/"):
        if part:
            fixed = portability.sanitize_component(part)
            assert fixed in (".", "..") or portability.component_problem(fixed) is None, (part, fixed)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
