"""Alles hinter der Kryptografie: Die Fuzz-Eingabe wird als GÜLTIG verschlüsselte
Nutzdaten in einen v2-Container gepackt – so, wie es ein böswilliger Absender
mit bekanntem Passwort bzw. über einen öffentlichen Schlüssel könnte. Danach
laufen list, verify und extract darauf.

Erwartung: nur Tres0rError; nie Dateien außerhalb des Zielordners.
Das erste Byte wählt: Bit 0 Index, Bit 1 zstd, Bit 2 Formatversion 1,
Bit 3 signiert (Harness hängt eine GÜLTIGE Signatur an – so erreicht der Fuzzer
auch alles nach der Prüfung), Bit 4 signiert ohne Anhang (kaputte Anhänge).
"""
import io
import os
import shutil
import sys
import tempfile

import atheris

import _common

with atheris.instrument_imports():
    import hashlib

    from tres0r import container, keys, payload, sign
    from tres0r import header as v1
    from tres0r import header2 as h2
    from tres0r.kdf import KdfParams
    from tres0r.errors import Tres0rError
    from tres0r.stream import EncryptingWriter

_common.fast_kdf()  # v1-Container entsperren sonst jedes Mal per Argon2
DEK = bytes(range(32))
# Mehrere Kerne vortäuschen: Hintergrund-Dekodierer, Hash- und zstd-Worker laufen mit
# (die Ein-Kern-Pfade haben frühere Runden abgedeckt).
os.cpu_count = lambda: int(os.environ.get("TRES0R_FUZZ_CPUS", "4"))
XATTRS = hasattr(os, "listxattr")  # Wiederherstellung erweiterter Attribute (nur Linux)
SIGNER = keys.Ed25519PrivateKey.from_private_bytes(bytes(range(40, 72)))
HEADERS = {}
V1 = {}
ZSTD = payload.zstd_backend() is not None


def header_for(mode: int) -> h2.HeaderV2:
    if mode not in HEADERS:
        compression = h2.COMPRESS_ZSTD if (mode & 2 and ZSTD) else h2.COMPRESS_NONE
        flags = (h2.FLAG_INDEX if mode & 1 else 0) | (h2.FLAG_SIGNED if mode & 24 else 0)
        HEADERS[mode] = h2.HeaderV2.create(DEK, [h2.secret_slot(DEK, _common.PHRASE)],
                                           compression=compression, flags=flags)
    return HEADERS[mode]


def v1_header():
    """v1 kennt nur Passwort-Slots; der KDF-Platzhalter aus _common hält das schnell."""
    if "h" not in V1:
        V1["h"], V1["dek"] = v1.Header.create("pw", KdfParams(8192, 1, 1))
    return V1["h"], V1["dek"]


def decrypt(path: str, secret: str) -> None:
    with open(path, "rb") as f:
        container.decrypt_stream(f, io.BytesIO(), secret)


def write_segmented(path: str, header, plain: bytes) -> None:
    """Zwei Segmente mit gültig verschlüsselter, aber vom Fuzzer verbogener Tabelle.

    plain = u16 Schnitt ‖ u8 Verbiegen ‖ Klartext Segment 0 ‖ Klartext Segment 1
    """
    from tres0r import segments
    from tres0r.header2 import FLAG_SEGMENTS, payload_key_for

    cut = int.from_bytes(plain[:2].ljust(2, b"\0"), "big")
    tweak = plain[2] if len(plain) > 2 else 0
    body = plain[3:]
    first, second = body[:cut], body[cut:]
    flagged = header.with_flags(DEK, header.flags | FLAG_SEGMENTS)
    nonce = bytes(range(16, 32))
    with open(path, "wb") as f:
        f.write(flagged.to_bytes())
        for key, part in ((header.payload_key(DEK), first), (payload_key_for(DEK, nonce), second)):
            enc = EncryptingWriter(f, key)
            enc.write(part)
            enc.finish()
            if key == header.payload_key(DEK):
                length0 = f.tell() - flagged.header_len
        length1 = f.tell() - flagged.header_len - length0
        delta = (tweak & 0x0F) - 8 if tweak & 0x80 else 0  # Grenzen verbiegen
        entries = [
            segments.SegmentEntry(0, length0, header.stream_nonce, header.compression, header.flags & 3),
            segments.SegmentEntry(max(0, length0 + delta), max(0, length1 - (delta if tweak & 0x40 else 0)), nonce,
                                  (tweak >> 4) & 1 if tweak & 0x20 else header.compression,
                                  tweak & 0x07 if tweak & 0x08 else 1),
        ]
        f.write(segments.encode_table(DEK, header.stream_nonce, entries))


def browse(path: str, secret: str) -> None:
    """Wie ein eingehängter Container: Baum ablaufen, jede Datei ganz lesen."""
    from tres0r.mount import ContainerFS

    fs = ContainerFS(path, secret)
    try:
        pending = ["/"]
        while pending:
            current = pending.pop()
            for name in fs.listdir(current):
                child = current.rstrip("/") + "/" + name
                kind = fs.attributes(child)["st_mode"] & 0o170000
                if kind == 0o040000:
                    pending.append(child)
                elif kind == 0o100000:
                    handle = fs.open(child)
                    handle.read(0, 1 << 16)
                    handle.read(3, 10)  # Sprung zurück
                else:
                    fs.readlink(child)
    finally:
        fs.close()


def extract_from_pipe(path: str, dest: str, secret: str) -> None:
    with open(path, "rb") as f:  # wie "unpack -": ohne Index, ohne wahlfreien Zugriff
        container.extract_stream(io.BufferedReader(io.BytesIO(f.read())), dest, secret)


def inside(root: str) -> None:
    real_root = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            target = os.path.realpath(path)
            assert target == real_root or target.startswith(real_root + os.sep), (path, target)


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    work = tempfile.mkdtemp(prefix="tres0r-fuzz-")
    try:
        path = os.path.join(work, "c.tres0r")
        if data[0] & 4:
            header, dek, secret = *v1_header(), "pw"
        else:
            header, dek, secret = header_for(data[0] & 27), DEK, _common.PHRASE
        plain = data[1:]
        if data[0] & 32 and not data[0] & 4:  # angehängte Segmente
            write_segmented(path, header, plain)
        else:
            if not data[0] & 4 and data[0] & 8:  # gültig signieren
                plain += sign.trailer(SIGNER, header, hashlib.sha256(plain).digest())
            with open(path, "wb") as f:
                f.write(header.to_bytes())
                enc = EncryptingWriter(f, header.payload_key(dek))
                enc.write(plain)
                enc.finish()
        for action in (lambda: container.list_contents(path, secret),
                       lambda: container.verify(path, secret),
                       lambda: container.verify(path, secret, signers=[SIGNER.public_key()]),
                       lambda: container.extract(path, os.path.join(work, "ziel"), secret, check_space=False),
                       lambda: container.extract(path, os.path.join(work, "attr"), secret, check_space=False,
                                                 xattrs=XATTRS, acls=XATTRS),
                       lambda: container.extract(path, os.path.join(work, "teil"), secret,
                                                 check_space=False, only=["a*"]),
                       lambda: container.salvage(path, os.path.join(work, "rettung"), secret),
                       lambda: decrypt(path, secret),
                       lambda: extract_from_pipe(path, os.path.join(work, "pipe"), secret),
                       lambda: browse(path, secret),
                       lambda: container.upgrade(path, secret, os.path.join(work, "neu.tres0r"),
                                                 check_space=False)):
            try:
                action()
            except Tres0rError:
                pass
        try:  # zuletzt: repair verändert die Datei
            container.repair(path, secret)
            container.verify(path, secret)
        except Tres0rError:
            pass
        inside(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
