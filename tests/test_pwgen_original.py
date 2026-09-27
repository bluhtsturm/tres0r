import hashlib
from pathlib import Path

# tres0r/pwgen.py ist Julians Original und bleibt unverändert – tres0r passt sich über
# tres0r/passgen.py an. Ändert sich die Prüfsumme, war das ein Versehen.
ORIGINAL_SHA256 = "2a85ed5ec5d286754c5e69cabc092501d5f409f619ffb0fd9debd44eeeb8cab9"


def test_pwgen_is_the_unchanged_original():
    path = Path(__file__).resolve().parents[1] / "tres0r" / "pwgen.py"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == ORIGINAL_SHA256
