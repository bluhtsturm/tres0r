"""Unabhängiger Referenz-Leser für tres0r-Container.

Nur nach FORMAT.md geschrieben und importiert bewusst NICHTS aus tres0r – er
prüft, dass die Spezifikation vollständig ist und Code und Dokument
übereinstimmen. Bewusst schlicht: alles im Speicher, keine Optimierungen.
Abschnittsnummern verweisen auf FORMAT.md.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import struct
import tarfile
import unicodedata
import zlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class ReferenceError_(Exception):
    pass


# --- 1. Bausteine -----------------------------------------------------------
def hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def argon2id(password: bytes, salt: bytes, m_kib: int, t: int, p: int) -> bytes:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    return Argon2id(salt=salt, length=32, iterations=t, lanes=p, memory_cost=m_kib).derive(password)


def aead_open(key: bytes, nonce: bytes, data: bytes, aad: bytes | None) -> bytes | None:
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, data, aad)
    except Exception:
        return None


def encode_p(text: str) -> bytes:  # 4.1 "P"
    return unicodedata.normalize("NFC", text).encode("utf-8", "surrogateescape")


def canonical_c(text: str) -> bytes:  # 5.2
    s = unicodedata.normalize("NFC", unicodedata.normalize("NFC", text).lower())
    words, current = [], []
    for ch in s:
        if unicodedata.category(ch)[0] in "LN":
            current.append(ch)
        elif current:
            words.append("".join(current))
            current = []
    if current:
        words.append("".join(current))
    return "-".join(words).encode("utf-8", "surrogateescape")


# --- 5.3 Anteile (bewusst anders implementiert: Multiplikation per Schieben) ----
def gf_mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return result


def gf_inv(a: int) -> int:
    result, power = 1, a  # a^254 = a^(-1) in GF(2⁸)
    exponent = 254
    while exponent:
        if exponent & 1:
            result = gf_mul(result, power)
        power = gf_mul(power, power)
        exponent >>= 1
    return result


def parse_share(text: str) -> dict:
    import base64

    body = "".join(ch for ch in text.strip()[len("tres0r-teil-"):] if ch not in " -").upper()
    raw = base64.b32decode(body + "=" * (-len(body) % 8))
    data, check = raw[:-4], raw[-4:]
    if hashlib.sha256(b"tres0r share " + data).digest()[:4] != check:
        raise ReferenceError_("Prüfsumme des Anteils falsch")
    return {"set_id": data[:8], "k": data[8], "n": data[9], "x": data[10], "y": data[11:43]}


def combine(shares: list[dict]) -> bytes:
    use = {s["x"]: s for s in shares}
    points = list(use.values())[: shares[0]["k"]]
    secret = bytearray(32)
    for i, si in enumerate(points):
        weight = 1
        for j, sj in enumerate(points):
            if i != j:
                weight = gf_mul(weight, gf_mul(sj["x"], gf_inv(sj["x"] ^ si["x"])))
        for b in range(32):
            secret[b] ^= gf_mul(si["y"][b], weight)
    return bytes(secret)


# --- 6. Payload entschlüsseln -----------------------------------------------
def decrypt_payload(key: bytes, payload: bytes) -> bytes:
    enc_chunk = 65536 + 16
    n = -(-len(payload) // enc_chunk)
    if len(payload) < 16 or 0 < len(payload) % enc_chunk < 16:
        raise ReferenceError_("Payload-Länge ungültig")
    out = []
    for i in range(n):
        chunk = payload[i * enc_chunk:(i + 1) * enc_chunk]
        last = i == n - 1
        plain = aead_open(key, i.to_bytes(11, "big") + bytes([last]), chunk, None)
        if plain is None:
            raise ReferenceError_(f"Chunk {i} ungültig")
        if last and not plain and i > 0:
            raise ReferenceError_("leerer Abschluss-Chunk")
        out.append(plain)
    return b"".join(out)


# --- 3./4. Header v2 --------------------------------------------------------
def parse_v2(data: bytes) -> dict:
    magic, version, header_len, ptype, comp, flags, nonce, count = struct.unpack_from(">4sBHBBB16sB", data)
    assert magic == b"TRS0" and version == 2
    header = data[:header_len]
    pos, slots = 27, []
    for _ in range(count):
        stype, blen = struct.unpack_from(">BH", header, pos)
        slots.append((stype, header[pos + 3:pos + 3 + blen]))
        pos += 3 + blen
    if pos != header_len - 32:
        raise ReferenceError_("Header-Länge passt nicht zu den Slots")
    return {"header": header, "ptype": ptype, "comp": comp, "flags": flags, "nonce": nonce,
            "slots": slots, "mac": header[-32:], "payload": data[header_len:]}


def unlock_v2(h: dict, passwords=(), identities=(), keyfiles=(), shares=(), fido2=()) -> tuple[bytes, int]:
    def accept(dek: bytes, index: int):
        mac_key = hkdf(dek, h["nonce"], b"tres0r v2 header mac")
        if not hmac.compare_digest(hmac.new(mac_key, h["header"][:-32], "sha256").digest(), h["mac"]):
            raise ReferenceError_("Header-MAC falsch")
        return dek, index

    def unwrap(stype: int, body: bytes, kek: bytes):
        return aead_open(kek, bytes(12), body[-48:], bytes([stype]) + body[:-48])

    for raw_identity in identities:
        private = X25519PrivateKey.from_private_bytes(raw_identity)
        own = private.public_key().public_bytes_raw()
        for i, (stype, body) in enumerate(h["slots"]):
            if stype != 3:
                continue
            try:
                shared = private.exchange(X25519PublicKey.from_public_bytes(body[:32]))
            except ValueError:
                continue
            dek = unwrap(3, body, hkdf(shared, body[:32] + own, b"tres0r v2 x25519 slot"))
            if dek is not None:
                return accept(dek, i)
    parsed = [parse_share(t) for t in shares]
    for i, (stype, body) in enumerate(h["slots"]):
        if stype == 6 and parsed:
            k, n, set_id, salt = struct.unpack(">BB8s16s", body[:26])
            matching = [p for p in parsed if p["set_id"] == set_id]
            if len({p["x"] for p in matching}) >= k:
                dek = unwrap(6, body, hkdf(combine(matching), salt, b"tres0r v2 threshold slot"))
                if dek is not None:
                    return accept(dek, i)
    for text in passwords:
        for i, (stype, body) in enumerate(h["slots"]):
            if stype == 2:
                dek = unwrap(2, body, hkdf(canonical_c(text), body[:16], b"tres0r v2 secret slot"))
                if dek is not None:
                    return accept(dek, i)
    keyfile_secrets = [hashlib.sha256(b"tres0r keyfile" + content).digest() for content in keyfiles]
    for text in passwords:
        for i, (stype, body) in enumerate(h["slots"]):
            if stype == 1:
                kdf, m, t, p, salt = struct.unpack(">BIIB16s", body[:26])
                assert kdf == 1
                dek = unwrap(1, body, argon2id(encode_p(text), salt, m, t, p))
                if dek is not None:
                    return accept(dek, i)
            if stype == 7:  # H kommt vom Token; hier als Liste bekannter Werte
                kdf, m, t, p, salt = struct.unpack(">BIIB16s", body[:26])
                rp_len = body[26 + 32]
                cred_len = struct.unpack(">H", body[27 + 32 + rp_len:29 + 32 + rp_len])[0]
                if 29 + 32 + rp_len + cred_len + 48 != len(body):
                    raise ReferenceError_("FIDO2-Slot hat die falsche Länge")
                for secret in fido2:
                    stretched = argon2id(encode_p(text), salt, m, t, p)
                    dek = unwrap(7, body, hkdf(stretched + secret, salt, b"tres0r v2 password+fido2 slot"))
                    if dek is not None:
                        return accept(dek, i)
            if stype == 5:
                kdf, m, t, p, salt = struct.unpack(">BIIB16s", body[:26])
                kid = body[26:42]
                for secret in keyfile_secrets:
                    if hashlib.sha256(b"tres0r keyfile id" + secret).digest()[:16] != kid:
                        continue
                    stretched = argon2id(encode_p(text), salt, m, t, p)
                    dek = unwrap(5, body, hkdf(stretched + secret, salt, b"tres0r v2 password+keyfile slot"))
                    if dek is not None:
                        return accept(dek, i)
    raise ReferenceError_("kein Slot passt")


# --- 7.–9. Klartext ---------------------------------------------------------
def check_signature(h: dict, plain: bytes) -> bytes:
    """9a – gibt den Prüfschlüssel V (32 B) zurück."""
    if len(plain) < 105:
        raise ReferenceError_("Signaturanhang fehlt")
    alg, public, sig, magic = struct.unpack(">B32s64s8s", plain[-105:])
    if magic != b"TRS0SIG\x01" or alg != 1:
        raise ReferenceError_("Signaturanhang ungültig")
    message = (b"tres0r v2 signature\x00" + bytes([h["ptype"], h["comp"], h["flags"]]) + h["nonce"]
               + hashlib.sha256(plain[:-105]).digest())
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(sig, message)
    except InvalidSignature:
        raise ReferenceError_("Signatur ungültig") from None
    return public


def split_plaintext(plain: bytes, flags: int) -> tuple[bytes, list | None]:
    if flags & 2:  # 7 / 9a: Signaturanhang am Ende abtrennen
        plain = plain[:-105]
    stream, pos = [], 0
    while True:
        (length,) = struct.unpack_from(">I", plain, pos)
        pos += 4
        if length == 0:
            break
        if length > 4 << 20:
            raise ReferenceError_("Block zu groß")
        stream.append(plain[pos:pos + length])
        pos += length
    index = None
    if flags & 1:
        blob_len, magic = struct.unpack(">Q8s", plain[-16:])
        assert magic == b"TRS0IDX\x01"
        doc = json.loads(zlib.decompress(plain[-16 - blob_len:-16]))
        assert doc["v"] == 1
        index = doc["entries"]
    return b"".join(stream), index


def zstd_frames(data: bytes) -> bytes:
    try:
        from compression import zstd

        new = zstd.ZstdDecompressor
    except ImportError:
        import zstandard

        def new():
            return zstandard.ZstdDecompressor().decompressobj()
    out, rest = [], data
    while rest:
        d = new()
        out.append(d.decompress(rest))
        if not d.eof:
            raise ReferenceError_("zstd-Frame unvollständig")
        rest = bytes(d.unused_data)
    return b"".join(out)


def read_tar(data: bytes) -> list[dict]:
    entries = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        for ti in tar:
            entry = {"name": ti.name, "size": ti.size if ti.isreg() else 0}
            if ti.isreg():
                entry["sha256"] = hashlib.sha256(tar.extractfile(ti).read()).hexdigest()
            entries.append(entry)
    return entries


# --- Einstieg ---------------------------------------------------------------
def open_container(data: bytes, passwords=(), identities=(), keyfiles=(), shares=(), fido2=()) -> dict:
    """Entsperren, entschlüsseln, dekodieren. Ergebnis: dek, slot, payload_type,
    compression, data (Nutzdaten), index (oder None)."""
    if data[:4] != b"TRS0":
        raise ReferenceError_("keine tres0r-Datei")
    if data[4] == 1:  # Abschnitt 11
        _, _, kdf, m, t, p, salt, nonce, wrap_nonce = struct.unpack_from(">4sBBIIB16s16s12s", data)
        header, wrapped = data[:59], data[59:107]
        for text in passwords:
            dek = aead_open(argon2id(encode_p(text), salt, m, t, p), wrap_nonce, wrapped, header)
            if dek is not None:
                plain = decrypt_payload(hkdf(dek, nonce, b"tres0r v1 payload key"), data[107:])
                return {"dek": dek, "slot": 0, "payload_type": "tar", "compression": None,
                        "data": plain, "index": None, "signer": None}
        raise ReferenceError_("Passwort passt nicht")
    h = parse_v2(data)
    dek, slot = unlock_v2(h, passwords, identities, keyfiles, shares, fido2)
    if h["flags"] & 4:  # 9b: angehängte Segmente
        segs = open_segments(h, dek, h["payload"])
        files: dict = {}
        for seg in segs:  # spätere ersetzen frühere
            for entry in read_tar(seg["data"]):
                files.pop(entry["name"], None)
                files[entry["name"]] = entry
        return {"dek": dek, "slot": slot, "payload_type": "tar", "compression": None, "data": None,
                "index": None, "signer": None, "segments": segs, "files": files}
    plain = decrypt_payload(hkdf(dek, h["nonce"], b"tres0r v2 payload key"), h["payload"])
    signer = check_signature(h, plain) if h["flags"] & 2 else None
    stream, index = split_plaintext(plain, h["flags"])
    if h["comp"] == 1:
        stream = zstd_frames(stream)
    return {"dek": dek, "slot": slot, "payload_type": "tar" if h["ptype"] == 0 else "roh",
            "compression": "zstd" if h["comp"] == 1 else None, "data": stream, "index": index,
            "signer": signer}


def open_segments(h: dict, dek: bytes, payload: bytes) -> list[dict]:
    """9b – Segmenttabelle am Ende lesen, jedes Segment wie 6–9 entschlüsseln."""
    if payload[-8:] != b"TRS0SEG\x01":
        raise ReferenceError_("Segmenttabelle fehlt")
    ct_len = struct.unpack(">I", payload[-12:-8])[0]
    start = len(payload) - 12 - ct_len - 16
    table_nonce, ct = payload[start:start + 16], payload[start + 16:start + 16 + ct_len]
    table = aead_open(hkdf(dek, table_nonce, b"tres0r v2 segment table"), bytes(12), ct,
                      b"tres0r v2 segment table" + h["nonce"])
    if table is None or table[0] != 1:
        raise ReferenceError_("Segmenttabelle ungültig")
    count = struct.unpack(">I", table[1:5])[0]
    segs = []
    for i in range(count):
        offset, length, nonce, comp, flags = struct.unpack_from(">QQ16sBB", table, 5 + 34 * i)
        plain = decrypt_payload(hkdf(dek, nonce, b"tres0r v2 payload key"), payload[offset:offset + length])
        view = dict(h, comp=comp, flags=flags, nonce=nonce)
        signer = check_signature(view, plain) if flags & 2 else None
        stream, index = split_plaintext(plain, flags)
        if comp == 1:
            stream = zstd_frames(stream)
        segs.append({"data": stream, "index": index, "signer": signer, "compression": comp})
    return segs


def decode_identity(text: str) -> bytes:
    """5.1 – privater Schlüssel aus "TRES0R-SECRET-…"."""
    import base64

    body = text.strip()[len("TRES0R-SECRET-"):].upper()
    raw = base64.b32decode(body + "=" * (-len(body) % 8))
    key, check = raw[:32], raw[32:]
    if hashlib.sha256(b"tres0r secret " + key).digest()[:4] != check:
        raise ReferenceError_("Prüfsumme falsch")
    return key
