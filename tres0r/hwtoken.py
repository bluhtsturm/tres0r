"""FIDO2-Token (YubiKey, Nitrokey, SoloKey …) als zweiter Faktor über hmac-secret.

Registrierung: ein nicht residenter Credential für die RP-ID ``tres0r.local``
(makeCredential mit hmac-secret). Entsperren: getAssertion mit dem im Keyslot
gespeicherten Credential und einem Salt; der Token liefert
``HMAC-SHA256(geheimes Zufallsgeheimnis des Credentials, Salt)`` – 32 Byte, die
den Token nie im Klartext verlassen, ohne ihn nicht berechenbar sind und nur mit
Berührung herausgegeben werden. Die Kryptografie auf dem Weg (Schlüsselaustausch,
verschlüsselte Salts) erledigt python-fido2 (Extra ``tres0r-crypt[fido2]``).

User-Verification bleibt "discouraged": Es zählt die Berührung, die Token-PIN wird
nur abgefragt, wenn der Token sie selbst verlangt. hmac-secret liefert mit und ohne
UV verschiedene Geheimnisse – deshalb bei allen Vorgängen gleich.
"""
from __future__ import annotations

import os
from typing import Callable

from .errors import Tres0rError, WrongPassword

RP_ID = "tres0r.local"
ORIGIN = "https://tres0r.local"
SALT_LEN = 32

Notify = Callable[[str], None]


def _library():
    try:
        from fido2 import webauthn
        from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client, UserInteraction
        from fido2.ctap2.extensions import HmacSecretExtension
        from fido2.utils import websafe_decode
    except ImportError:
        raise Tres0rError("FIDO2 braucht python-fido2: pip install 'tres0r-crypt[fido2]'") from None
    return webauthn, ClientError, DefaultClientDataCollector, Fido2Client, UserInteraction, HmacSecretExtension, \
        websafe_decode


def devices() -> list:
    """Angeschlossene FIDO2-Geräte (USB-HID)."""
    try:
        from fido2.hid import CtapHidDevice
    except ImportError:
        raise Tres0rError("FIDO2 braucht python-fido2: pip install 'tres0r-crypt[fido2]'") from None
    return list(CtapHidDevice.list_devices())


def describe(device) -> str:
    """Anzeigename eines Geräts (``device`` aus ``devices()``)."""
    descriptor = getattr(device, "descriptor", None)
    name = getattr(descriptor, "product_name", None) or type(device).__name__
    return f"{name} ({getattr(descriptor, 'path', '?')})" if descriptor else name


def _client(device, notify: Notify | None, pin: Callable[[], str] | None):
    webauthn, _, Collector, Client, Interaction, Hmac, _ = _library()

    class _Asks(Interaction):
        def prompt_up(self) -> None:  # nur bei Geräten, die per Keepalive warten
            pass

        def request_pin(self, permissions, rp_id):
            if pin is None:
                raise Tres0rError("Der Token verlangt seine PIN, aber es ist keine Abfrage möglich.")
            return pin()

        def request_uv(self, permissions, rp_id) -> bool:
            return True

    return Client(device, client_data_collector=Collector(ORIGIN), user_interaction=_Asks(),
                  extensions=[Hmac(allow_hmac_secret=True)])


def _explain(error: Exception) -> Tres0rError:
    text = str(error)
    if "NO_CREDENTIALS" in text or "DEVICE_INELIGIBLE" in text:
        return WrongPassword("Dieser FIDO2-Token passt nicht zum Container.")
    if "OPERATION_DENIED" in text or "ACTION_TIMEOUT" in text or "TIMEOUT" in text:
        return WrongPassword("Keine Berührung am Token – abgebrochen.")
    if "PIN_INVALID" in text:
        return WrongPassword("Falsche PIN für den FIDO2-Token.")
    if "PIN_AUTH_BLOCKED" in text:
        return WrongPassword("Zu viele falsche PINs – Token einmal abziehen und wieder einstecken.")
    if "PIN_BLOCKED" in text:
        return WrongPassword("Die PIN des Tokens ist nach zu vielen Fehlversuchen gesperrt. "
                             "Der Token muss zurückgesetzt werden – dabei gehen seine Schlüssel verloren.")
    if "PIN" in text:
        return WrongPassword("Der FIDO2-Token hat die PIN nicht angenommen.")
    return Tres0rError(f"FIDO2-Token meldet einen Fehler: {text}")


def enroll(device, *, notify: Notify | None = None, pin: Callable[[], str] | None = None) -> bytes:
    """Neuen Credential mit hmac-secret anlegen; gibt die Credential-ID zurück.

    ``device``: Gerät aus ``devices()``; ``notify``: Hinweis-Funktion ("bitte berühren"); ``pin``: liefert die Token-PIN, falls verlangt.
    """
    webauthn, ClientError, *_ = _library()
    if notify:
        notify("Bitte FIDO2-Token berühren (Registrierung) …")
    try:
        created = _client(device, notify, pin).make_credential(webauthn.PublicKeyCredentialCreationOptions(
            rp=webauthn.PublicKeyCredentialRpEntity(id=RP_ID, name="tres0r"),
            user=webauthn.PublicKeyCredentialUserEntity(id=os.urandom(16), name="tres0r"),
            challenge=os.urandom(32),
            pub_key_cred_params=[webauthn.PublicKeyCredentialParameters(
                type=webauthn.PublicKeyCredentialType.PUBLIC_KEY, alg=-7),
                webauthn.PublicKeyCredentialParameters(type=webauthn.PublicKeyCredentialType.PUBLIC_KEY, alg=-8)],
            authenticator_selection=webauthn.AuthenticatorSelectionCriteria(
                user_verification=webauthn.UserVerificationRequirement.DISCOURAGED),
            extensions={"hmacCreateSecret": True}))
    except (ClientError, OSError) as e:
        raise _explain(e) from None
    if not (created.client_extension_results or {}).get("hmacCreateSecret"):
        raise Tres0rError("Dieser Token unterstützt hmac-secret nicht und eignet sich nicht als zweiter Faktor.")
    return bytes(created.raw_id)


def secret(device, credential_id: bytes, salt: bytes, *, notify: Notify | None = None,
           pin: Callable[[], str] | None = None) -> bytes:
    """32-Byte-Geheimnis des Credentials für ``salt`` (Berührung nötig).

    ``device``: Gerät; ``credential_id``: aus ``enroll``; ``salt``: 32 Byte; ``notify``/``pin`` wie bei ``enroll``.
    """
    webauthn, ClientError, *_, websafe_decode = _library()
    if len(salt) != SALT_LEN:
        raise ValueError("Salt muss 32 Byte lang sein.")
    if notify:
        notify("Bitte FIDO2-Token berühren …")
    try:
        result = _client(device, notify, pin).get_assertion(webauthn.PublicKeyCredentialRequestOptions(
            challenge=os.urandom(32), rp_id=RP_ID,
            allow_credentials=[webauthn.PublicKeyCredentialDescriptor(
                type=webauthn.PublicKeyCredentialType.PUBLIC_KEY, id=credential_id)],
            user_verification=webauthn.UserVerificationRequirement.DISCOURAGED,
            extensions={"hmacGetSecret": {"salt1": salt}}))
    except (ClientError, OSError) as e:
        raise _explain(e) from None
    outputs = dict(result.get_response(0).client_extension_results or {}).get("hmacGetSecret") or {}
    value = outputs.get("output1")
    if value is None:
        raise Tres0rError("Der Token hat kein hmac-secret geliefert.")
    raw = websafe_decode(value) if isinstance(value, str) else bytes(value)  # 2.x: base64url
    if len(raw) != 32:
        raise Tres0rError("Der Token hat ein hmac-secret unerwarteter Länge geliefert.")
    return raw


class TokenProvider:
    """Für ``Credentials.fido2``: fragt angeschlossene Tokens nach dem Geheimnis.

    Probiert jedes Gerät, bis eines den Credential kennt (fremde Geräte lehnen
    ohne Berührung ab). Ergebnisse werden für diesen Vorgang zwischengespeichert,
    damit z. B. ``passwd`` keine zweite Berührung braucht.
    """

    def __init__(self, found: list | None = None, *, notify: Notify | None = None,
                 pin: Callable[[], str] | None = None) -> None:
        self._devices = found
        self.notify, self.pin = notify, pin
        self.cache: dict[tuple[bytes, bytes], bytes] = {}

    @property
    def devices(self) -> list:
        if self._devices is None:
            self._devices = devices()
        if not self._devices:
            raise WrongPassword("Kein FIDO2-Token gefunden – bitte einstecken.")
        return self._devices

    def __call__(self, rp_id: str, credential_id: bytes, salt: bytes) -> bytes:
        if rp_id != RP_ID:
            raise Tres0rError(f"Unbekannte FIDO2-RP-ID '{rp_id}'.")
        key = (credential_id, salt)
        if key not in self.cache:
            last: Exception | None = None
            for device in self.devices:
                try:
                    self.cache[key] = secret(device, credential_id, salt, notify=self.notify, pin=self.pin)
                    break
                except WrongPassword as e:
                    last = e
            else:
                raise last or WrongPassword("Kein passender FIDO2-Token gefunden.")
        return self.cache[key]

    def enroll(self) -> tuple[str, bytes, bytes, bytes]:
        """Für einen neuen Keyslot: (rp_id, Credential-ID, Salt, Geheimnis) – zwei Berührungen."""
        if len(self.devices) > 1:
            raise Tres0rError("Mehrere FIDO2-Tokens gefunden – für die Registrierung bitte nur einen einstecken.")
        device = self.devices[0]
        credential_id = enroll(device, notify=self.notify, pin=self.pin)
        salt = os.urandom(SALT_LEN)
        value = secret(device, credential_id, salt, notify=self.notify, pin=self.pin)
        self.cache[(credential_id, salt)] = value
        return RP_ID, credential_id, salt, value


__all__ = [
    "TokenProvider",
    "devices",
    "describe",
    "enroll",
    "secret",
    "RP_ID",
    "SALT_LEN",
]
