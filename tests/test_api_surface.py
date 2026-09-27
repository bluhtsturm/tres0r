import json

import api_surface


def test_public_api_matches_snapshot():
    """Die öffentliche API ist eingefroren – Änderungen nur bewusst:
    python tests/api_surface.py --update (und in CHANGELOG.md begründen)."""
    stored = json.loads(api_surface.SNAPSHOT.read_text(encoding="utf-8"))
    found = api_surface.differences(stored, api_surface.surface())
    assert not found, "Öffentliche API geändert:\n" + "\n".join(found)


def test_no_internal_names_exported():
    for module, names in api_surface.surface().items():
        assert not [n for n in names if n.startswith("_") and n != "__version__"], module
