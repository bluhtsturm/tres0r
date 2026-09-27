"""Startkorpus erzeugen: echte Header, echte Nutzdaten-Klartexte, Beispieltexte.

    python fuzz/make_seeds.py        -> fuzz/corpus/<harness>/
"""
import io
import os
import tarfile
import tempfile

import _common

from tres0r import container, keys, payload
from tres0r import header2 as h2
from tres0r.kdf import KdfParams

HERE = os.path.dirname(__file__)
FAST = KdfParams(8 * 1024, 1, 1)


def write(harness: str, name: str, data: bytes) -> None:
    folder = os.path.join(HERE, "corpus", harness)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, name), "wb") as f:
        f.write(data)


def plaintext_of(path: str) -> bytes:
    with container._open(__import__("pathlib").Path(path), "pw") as op:
        access = op.random_access()
        return access.pread(0, access.plaintext_size)


def main() -> None:
    _common.fast_kdf()
    dek = bytes(32)
    ident = keys.X25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    slots = [h2.password_slot(dek, "pw", FAST), h2.secret_slot(dek, _common.PHRASE), h2.x25519_slot(dek, ident.public_key())]
    write("header", "v2", h2.HeaderV2.create(dek, slots, flags=h2.FLAG_INDEX).to_bytes())
    # Schwellwert-Slot passend zu den Anteilen in fuzz_header.py (Geheimnis 0^32, Satz-ID 0^8)
    salt = bytes(range(16))
    threshold = h2._wrap(h2.SLOT_THRESHOLD, h2._THRESHOLD.pack(2, 2, bytes(8), salt),
                         h2._hkdf(bytes(32), salt, h2._INFO_THRESHOLD), dek)
    fido2 = h2.password_fido2_slot(dek, "pw", FAST, "tres0r.local", bytes(40), bytes(32), bytes(range(32, 64)))
    extra = [h2.password_keyfile_slot(dek, "pw", bytes(range(32)), FAST), threshold, fido2]
    write("header", "v2-faktoren", h2.HeaderV2.create(dek, extra).to_bytes())
    from tres0r import header as v1
    write("header", "v1", v1.Header.create("pw", FAST)[0].to_bytes())

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "a")
        os.makedirs(os.path.join(src, "b"))
        with open(os.path.join(src, "x.txt"), "w") as f:
            f.write("hallo")
        os.symlink("x.txt", os.path.join(src, "verweis"))
        for i, compress in enumerate([False, True] if payload.zstd_backend() else [False]):
            out = os.path.join(tmp, f"c{i}.tres0r")
            container.create([src], out, "pw", FAST, compress=compress)
            mode = 1 | (2 if compress else 0)
            write("container", f"tar{i}", bytes([mode]) + plaintext_of(out))
            first = plaintext_of(out)  # zwei Segmente: gleicher Inhalt zweimal
            write("container", f"segmente{i}", bytes([mode | 32]) + len(first).to_bytes(2, "big") + b"\0"
                  + first + first)
        # Modus 0 (ohne Index, ohne Kompression): Blöcke von Hand – [Länge][tar][0]
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            ti = tarfile.TarInfo("a/datei")
            ti.size = 3
            tar.addfile(ti, io.BytesIO(b"abc"))
        tar_bytes = buf.getvalue()
        write("container", "raw-tar", bytes([0]) + len(tar_bytes).to_bytes(4, "big") + tar_bytes + bytes(4))
    # Signierter tar-Klartext: Modus 1|8 -> der Harness signiert selbst gültig
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "a")
        os.makedirs(src)
        with open(os.path.join(src, "x.txt"), "w") as f:
            f.write("signiert")
        out = os.path.join(tmp, "s.tres0r")
        container.create([src], out, "pw", FAST)
        write("container", "signiert", bytes([1 | 8]) + plaintext_of(out))
    write("text", "pub", keys.encode_recipient(ident.public_key()).encode())
    write("text", "sig", keys.encode_verify_key(keys.Ed25519PrivateKey.from_private_bytes(bytes(32)).public_key()).encode())
    write("text", "muster", b"*.tmp\nbuild/\n/wurzel\nCON.txt\n")


if __name__ == "__main__":
    main()
