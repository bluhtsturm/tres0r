"""Testvektoren für FORMAT.md erzeugen.

    python tests/vectors/generate.py        # schreibt tests/vectors/*.json

Die Zufallsquelle (tres0r.rng) wird durch eine feste Folge ersetzt:
    block_i = SHA256("tres0r-vektor:" ‖ Name ‖ ":" ‖ u64 i)
Nutzdaten der Rohdaten-Vektoren entstehen genauso (Label "daten").
Vektoren mit "reproducible": true müssen byte-genau wieder entstehen.
"""
from __future__ import annotations

import hashlib
import io
import itertools
import json
import os
import sys
import tarfile
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from tres0r import container, keys, payload, rng  # noqa: E402
from tres0r import header as v1  # noqa: E402
from tres0r.kdf import KdfParams  # noqa: E402
from tres0r.padding import padme  # noqa: E402
from tres0r.stream import EncryptingWriter  # noqa: E402

KDF = KdfParams(memory_kib=8192, iterations=1, lanes=1)
PASSWORD = "Korrekt Pferd Batterie Heftklammer"
RECOVERY = "wald-see-berg-tal-fluss-dorf-feld-hain-moor-heide-bach-quelle-hang-kamm-grat-sattel-gipfel-hütte-weide-alm"
RECOVERY_INPUT = "Wald See Berg Tal Fluss Dorf Feld Hain Moor Heide Bach Quelle Hang Kamm Grat Sattel Gipfel HÜTTE Weide Alm"


def data_for(spec: dict) -> bytes:
    """Nutzdaten eines Rohdaten-Vektors: pattern(label, length) × repeat."""
    return pattern(spec["label"], spec["length"]) * spec.get("repeat", 1)


def pattern(label: str, length: int) -> bytes:
    out = bytearray()
    for i in itertools.count():
        if len(out) >= length:
            return bytes(out[:length])
        out += hashlib.sha256(f"tres0r-vektor:{label}:".encode() + i.to_bytes(8, "big")).digest()


@contextmanager
def deterministic(name: str):
    counter = itertools.count()

    def random_bytes(n: int) -> bytes:
        return pattern(f"{name}/{next(counter)}", n)

    with mock.patch.object(rng, "random_bytes", random_bytes):
        yield


def identity(name: str):
    return keys.X25519PrivateKey.from_private_bytes(pattern(f"identitaet/{name}", 32))


def signing_key(name: str):
    return keys.Ed25519PrivateKey.from_private_bytes(pattern(f"signatur/{name}", 32))


def keyfile_bytes(name: str) -> bytes:
    return pattern(f"keyfile/{name}", 64)


class FixedToken:
    """Steht für einen FIDO2-Token: feste Registrierungsdaten und festes hmac-secret H."""

    def __init__(self, name: str) -> None:
        self.material = ("tres0r.local", pattern(f"fido2/{name}/cred", 64), pattern(f"fido2/{name}/salt", 32),
                         pattern(f"fido2/{name}/H", 32))

    def enroll(self):
        return self.material


def _raw(name, data, *, password=None, recovery=None, recipients=(), compress=False, sign=False,
         keyfile=False, threshold=None, fido2=False):
    out = io.BytesIO()
    with deterministic(name):
        result = container.encrypt_stream(
            io.BytesIO(data), out, password, KDF, recipients=recipients, recovery=recovery, compress=compress,
            sign_with=signing_key(name) if sign else None, threshold=threshold,
            fido2=FixedToken(name) if fido2 else None,
            keyfile=hashlib.sha256(b"tres0r keyfile" + keyfile_bytes(name)).digest() if keyfile else None)
    SHARES[name] = [s.text() for s in result.shares]
    return out.getvalue()


SHARES: dict = {}


def _tree(root: Path) -> None:
    (root / "Projekt" / "Unterordner").mkdir(parents=True)
    files = {"Projekt/notiz.txt": b"Hallo Welt\n", "Projekt/Überraschung ä ö ü ß.txt": "Umlaute".encode(),
             "Projekt/leer": b"", "Projekt/Unterordner/daten.bin": pattern("baum", 700) * 100}  # > 1 Chunk
    for rel, data in files.items():
        (root / rel).write_bytes(data)
        os.chmod(root / rel, 0o644)
    os.symlink("notiz.txt", root / "Projekt" / "verweis")
    for rel in ("Projekt/Unterordner", "Projekt"):
        os.chmod(root / rel, 0o755)
    for path in sorted(root.rglob("*"), reverse=True):
        os.utime(path, (1_790_000_000, 1_790_000_000), follow_symlinks=False)


def _tar(name, *, password=None, recovery=None, recipients=(), compress=False, sign=False, append=False):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _tree(root)
        out = root / "c.tres0r"
        with deterministic(name):
            container.create([root / "Projekt"], out, password, KDF, recipients=recipients,
                             recovery=recovery, compress=compress,
                             sign_with=signing_key(name) if sign else None)
            if append:  # Segment 1: ersetzt eine vorhandene Datei und bringt eine neue mit
                victim = sorted(p for p in (root / "Projekt").rglob("*") if p.is_file())[0]
                later = root / "nachtrag" / "Projekt"
                target = later / victim.relative_to(root / "Projekt")
                target.parent.mkdir(parents=True)
                target.write_bytes(pattern(f"{name}/neu", 700))
                (later / "nachgereicht.txt").write_bytes(b"angehaengt\n")
                container.append(out, [later], password, sign_with=signing_key(name) if sign else None,
                                 compress=True)
        return out.read_bytes()


def _v1(name):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for rel, data in (("alt/liesmich.txt", b"Formatversion 1\n"), ("alt/daten.bin", pattern("v1", 1000))):
            ti = tarfile.TarInfo(rel)
            ti.size, ti.mtime, ti.mode = len(data), 1_700_000_000, 0o644
            tar.addfile(ti, io.BytesIO(data))
    tar_bytes = buf.getvalue()
    counter = itertools.count()
    with mock.patch.object(v1.secrets, "token_bytes", lambda n: pattern(f"{name}/{next(counter)}", n)):
        header, dek = v1.Header.create(PASSWORD, KDF)
    out = io.BytesIO()
    out.write(header.to_bytes())
    enc = EncryptingWriter(out, header.payload_key(dek))
    enc.write(tar_bytes)
    enc.write_zeros(padme(len(tar_bytes)) - len(tar_bytes))
    enc.finish()
    return out.getvalue()


def _entries_of(blob: bytes, creds) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "c.tres0r"
        path.write_bytes(blob)
        return [{"name": e.name, "kind": e.kind, "size": e.size, "sha256": e.sha256}
                for e in container.list_contents(path, creds)]


def build(name: str) -> dict:
    """Einen Vektor erzeugen (ohne 'expected' – das ergänzt main aus dem Ergebnis)."""
    ident = identity(name)
    ident_text = keys.encode_identity(ident)
    specs = {
        "v2-roh-alle-slots": dict(kind="raw", reproducible=True, data={"label": "daten", "length": 70_000},
                                  args=dict(password=PASSWORD, recovery=RECOVERY, recipients=[ident.public_key()]),
                                  unlock={"password": 0, "recovery": 1, "identity": 2}),
        "v2-roh-leer-empfaenger": dict(kind="raw", reproducible=True, data={"label": "leer", "length": 0},
                                       args=dict(recipients=[ident.public_key()]), unlock={"identity": 0}),
        "v2-tar-passwort": dict(kind="tar", reproducible=False, args=dict(password=PASSWORD),
                                unlock={"password": 0}),
        "v2-tar-zstd-phrase": dict(kind="tar", reproducible=False, args=dict(recovery=RECOVERY, compress=True),
                                   unlock={"recovery": 0}),
        "v2-roh-zstd-empfaenger": dict(kind="raw", reproducible=False, data={"label": "zstd", "length": 2000, "repeat": 100},
                                       args=dict(recipients=[ident.public_key()], compress=True),
                                       unlock={"identity": 0}),
        "v1-passwort": dict(kind="v1", reproducible=False, unlock={"password": 0}),
        "v2-roh-signiert": dict(kind="raw", reproducible=True, data={"label": "signiert", "length": 70_000},
                                args=dict(password=PASSWORD, sign=True), unlock={"password": 0}),
        "v2-tar-signiert": dict(kind="tar", reproducible=False, args=dict(password=PASSWORD, sign=True),
                                unlock={"password": 0}),
        "v2-roh-fido2": dict(kind="raw", reproducible=True, data={"label": "fido2", "length": 1000},
                             args=dict(password=PASSWORD, fido2=True), unlock={"password+fido2": 0}),
        "v2-tar-angehaengt-zstd": dict(kind="tar", reproducible=False, args=dict(password=PASSWORD, append=True,
                                                                            sign=True),
                                  unlock={"password": 0}),
        "v2-roh-keyfile": dict(kind="raw", reproducible=True, data={"label": "keyfile", "length": 1000},
                               args=dict(password=PASSWORD, keyfile=True), unlock={"password+keyfile": 0}),
        "v2-roh-schwellwert": dict(kind="raw", reproducible=True, data={"label": "schwellwert", "length": 1000},
                                   args=dict(password=PASSWORD, threshold=(2, 3)),
                                   unlock={"password": 0, "shares": 1}),
    }
    spec = specs[name]
    if spec["kind"] == "raw":
        blob = _raw(name, data_for(spec["data"]), **spec["args"])
    elif spec["kind"] == "tar":
        blob = _tar(name, **spec["args"])
    else:
        blob = _v1(name)
    vector = {
        "name": name,
        "format_version": blob[4],
        "reproducible": spec["reproducible"],
        "inputs": {"password": PASSWORD, "recovery": RECOVERY_INPUT, "identity": ident_text,
                   "kdf": {"m_kib": KDF.memory_kib, "t": KDF.iterations, "p": KDF.lanes}},
        "unlock": spec["unlock"],
        "container_hex": blob.hex(),
    }
    if spec["kind"] == "raw":
        vector["data"] = spec["data"]
    if spec.get("args", {}).get("keyfile"):
        vector["inputs"]["keyfile_hex"] = keyfile_bytes(name).hex()
    if spec.get("args", {}).get("fido2"):
        vector["inputs"]["fido2_secret_hex"] = FixedToken(name).material[3].hex()
    if spec.get("args", {}).get("threshold"):
        vector["inputs"]["shares"] = [SHARES[name][0], SHARES[name][2]]  # 2 von 3 genügen
    if spec.get("args", {}).get("sign"):
        vector["inputs"]["signing_key"] = keys.encode_signing_key(signing_key(name))
        vector["signer"] = keys.encode_verify_key(signing_key(name).public_key())
    return vector


NAMES = ["v2-roh-alle-slots", "v2-roh-leer-empfaenger", "v2-tar-passwort", "v2-tar-zstd-phrase",
         "v2-roh-zstd-empfaenger", "v1-passwort", "v2-roh-signiert", "v2-tar-signiert",
         "v2-roh-keyfile", "v2-roh-schwellwert", "v2-tar-angehaengt-zstd", "v2-roh-fido2"]


def main() -> None:
    for name in NAMES:
        if "zstd" in name and payload.zstd_backend() is None:
            print(f"übersprungen (kein zstd): {name}")
            continue
        vector = build(name)
        blob = bytes.fromhex(vector["container_hex"])
        creds = keys.Credentials(passwords=[PASSWORD, RECOVERY_INPUT], identities=[identity(name)],
                                 keyfiles=[hashlib.sha256(b"tres0r keyfile" + keyfile_bytes(name)).digest()],
                                 fido2=lambda rp, cid, salt: FixedToken(name).material[3])
        header = container.read_header(io.BytesIO(blob))
        dek = header.unlock(creds)[0] if header.version == 2 else header.unlock(PASSWORD)
        expected = {"dek_hex": dek.hex()}
        if "data" in vector:
            data = data_for(vector["data"])
            expected["data_sha256"] = hashlib.sha256(data).hexdigest()
        else:
            expected["entries"] = _entries_of(blob, creds)
        vector["expected"] = expected
        path = HERE / f"{name}.json"
        path.write_text(json.dumps(vector, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"{path.name}: {len(blob)} Byte")


if __name__ == "__main__":
    main()
