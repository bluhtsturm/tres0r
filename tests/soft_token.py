"""Software-FIDO2-Token für Tests – spricht CTAP2 (CBOR) mit hmac-secret.

Nur Testgerüst: Die Gegenseite ist die echte python-fido2-Bibliothek (Fido2Client,
ClientPin, HmacSecretExtension), so wie sie mit einem YubiKey arbeiten würde.
Geprüft wird damit das Zusammenspiel mit der Bibliothek; ungeprüft bleiben die
USB-Übertragung (CTAPHID) und Eigenheiten echter Geräte.

CTAP 2.1, Abschnitte 6.1 (makeCredential), 6.2 (getAssertion), 6.4 (getInfo),
6.5 (clientPin: getKeyAgreement) und 12.5 (hmac-secret).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.ctap import CtapDevice, CtapError
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.hid import CAPABILITY, CTAPHID

AAGUID = bytes.fromhex("7e57ab1e00000000000000000000beef")
_PROTOCOLS = {1: PinProtocolV1(), 2: PinProtocolV2()}


class SoftToken(CtapDevice):
    def __init__(self, deny_touch: bool = False, protocols=(2, 1), pin: str | None = None,
                 make_cred_uv_not_required: bool = False) -> None:
        self.pin = pin  # gesetzte Geräte-PIN (None = keine)
        self.pin_retries = 8
        self.pin_prompts_seen = 0
        self.make_cred_uv_not_required = make_cred_uv_not_required
        self._pin_token: bytes | None = None
        self.credentials: dict[bytes, dict] = {}
        self.touches = 0
        self.deny_touch = deny_touch
        self.protocols = list(protocols)
        self._agreement = ec.generate_private_key(ec.SECP256R1())
        self._counter = 0

    # -- CtapDevice ----------------------------------------------------------
    @property
    def capabilities(self) -> int:
        return CAPABILITY.CBOR | CAPABILITY.NMSG

    @classmethod
    def list_devices(cls):
        return iter(())

    def close(self) -> None:
        pass

    def call(self, cmd, data=b"", event=None, on_keepalive=None) -> bytes:
        if cmd != CTAPHID.CBOR:
            raise CtapError(CtapError.ERR.INVALID_COMMAND)
        command, params = data[0], cbor.decode(data[1:]) if len(data) > 1 else {}
        handler = {0x04: self._info, 0x06: self._client_pin, 0x01: self._make_credential,
                   0x02: self._get_assertion}.get(command)
        if handler is None:
            return bytes([CtapError.ERR.INVALID_COMMAND])
        try:
            response = handler(params)
        except CtapError as e:
            return bytes([e.code])
        return b"\x00" + cbor.encode(response)

    # -- Befehle ---------------------------------------------------------------
    def _info(self, params):
        options = {"rk": False, "up": True, "plat": False, "clientPin": self.pin is not None,
                   "pinUvAuthToken": True}
        if self.make_cred_uv_not_required:
            options["makeCredUvNotRqd"] = True
        return {1: ["FIDO_2_0", "FIDO_2_1"], 2: ["hmac-secret"], 3: AAGUID, 4: options, 5: 1200, 6: self.protocols}

    def _shared(self, protocol, peer):
        peer_key = ec.EllipticCurvePublicNumbers(int.from_bytes(peer[-2], "big"), int.from_bytes(peer[-3], "big"),
                                                 ec.SECP256R1()).public_key()
        return protocol.kdf(self._agreement.exchange(ec.ECDH(), peer_key))

    def _client_pin(self, params):
        sub = params.get(2)
        if sub == 0x01:  # getPINRetries
            return {3: self.pin_retries}
        if sub == 0x02:  # getKeyAgreement
            cose = ES256.from_cryptography_key(self._agreement.public_key())
            return {1: {1: 2, 3: -25, -1: 1, -2: cose[-2], -3: cose[-3]}}
        if sub in (0x05, 0x09):  # getPinToken (alt) / getPinUvAuthTokenUsingPinWithPermissions
            if self.pin is None:
                raise CtapError(CtapError.ERR.PIN_NOT_SET)
            if self.pin_retries <= 0:
                raise CtapError(CtapError.ERR.PIN_BLOCKED)
            protocol = _PROTOCOLS[params[1]]
            shared = self._shared(protocol, params[3])
            self.pin_prompts_seen += 1
            if protocol.decrypt(shared, params[6]) != hashlib.sha256(self.pin.encode()).digest()[:16]:
                self.pin_retries -= 1
                self._agreement = ec.generate_private_key(ec.SECP256R1())  # CTAP: neuer Schlüssel nach Fehlversuch
                raise CtapError(CtapError.ERR.PIN_INVALID)
            self.pin_retries = 8
            self._pin_token = os.urandom(32)
            return {2: protocol.encrypt(shared, self._pin_token)}
        raise CtapError(CtapError.ERR.INVALID_SUBCOMMAND)

    def _touch(self) -> None:
        self.touches += 1
        if self.deny_touch:
            raise CtapError(CtapError.ERR.OPERATION_DENIED)

    def _make_credential(self, params):
        rp_id = params[2]["id"]
        if not any(p.get("alg") == -7 for p in params[4]):
            raise CtapError(CtapError.ERR.UNSUPPORTED_ALGORITHM)
        if self.pin is not None and not self.make_cred_uv_not_required:  # PIN-Nachweis nötig
            proof, version = params.get(8), params.get(9)
            if proof is None or self._pin_token is None:
                raise CtapError(CtapError.ERR.PUAT_REQUIRED)
            if not hmac.compare_digest(_PROTOCOLS[version].authenticate(self._pin_token, params[1]), proof):
                raise CtapError(CtapError.ERR.PIN_AUTH_INVALID)
        self._touch()
        key = ec.generate_private_key(ec.SECP256R1())
        cred_id = os.urandom(48)
        self.credentials[cred_id] = {"rp": hashlib.sha256(rp_id.encode()).digest(), "key": key,
                                     "random": os.urandom(32), "random_uv": os.urandom(32)}
        public = cbor.encode(dict(ES256.from_cryptography_key(key.public_key())))
        extensions = {}
        if (params.get(6) or {}).get("hmac-secret") is True:
            extensions["hmac-secret"] = True
        flags = 0x01 | 0x40 | (0x80 if extensions else 0)
        auth_data = (hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self._counter)
                     + AAGUID + struct.pack(">H", len(cred_id)) + cred_id + public
                     + (cbor.encode(extensions) if extensions else b""))
        return {1: "none", 2: auth_data, 3: {}}

    def _get_assertion(self, params):
        rp_hash = hashlib.sha256(params[1].encode()).digest()
        allowed = [c["id"] for c in params.get(3) or []]
        found = next((cid for cid in allowed if cid in self.credentials
                      and self.credentials[cid]["rp"] == rp_hash), None)
        if found is None:
            raise CtapError(CtapError.ERR.NO_CREDENTIALS)
        if (params.get(5) or {}).get("up", True):  # Vorabprüfungen (up=False) ohne Berührung
            self._touch()
        cred = self.credentials[found]
        extensions = {}
        request = (params.get(4) or {}).get("hmac-secret")
        if request is not None:
            protocol = _PROTOCOLS[request.get(4, 1)]
            shared = self._shared(protocol, request[1])
            if not hmac.compare_digest(protocol.authenticate(shared, request[2]), request[3]):
                raise CtapError(CtapError.ERR.INVALID_PARAMETER)  # saltAuth falsch
            salts = protocol.decrypt(shared, request[2])
            if len(salts) not in (32, 64):
                raise CtapError(CtapError.ERR.INVALID_LENGTH)
            uv = bool((params.get(5) or {}).get("uv"))
            secret = cred["random_uv"] if uv else cred["random"]
            output = b"".join(hmac.new(secret, salts[i:i + 32], hashlib.sha256).digest()
                              for i in range(0, len(salts), 32))
            extensions["hmac-secret"] = protocol.encrypt(shared, output)
        self._counter += 1
        flags = 0x01 | (0x80 if extensions else 0)
        auth_data = (rp_hash + bytes([flags]) + struct.pack(">I", self._counter)
                     + (cbor.encode(extensions) if extensions else b""))
        signature = cred["key"].sign(auth_data + params[2], ec.ECDSA(hashes.SHA256()))
        return {1: {"type": "public-key", "id": found}, 2: auth_data, 3: signature}
