"""Header-Parser und Entsperren (v1 und v2) mit beliebigen Bytes."""
import io
import sys

import atheris

import _common

with atheris.instrument_imports():
    from tres0r import header2, keys
    from tres0r.errors import Tres0rError

_common.fast_kdf()
IDENTITY = keys.X25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
_SHARES = header2.shamir.split(bytes(32), 2, 2, set_id=bytes(8))  # passend zu make_seeds.py
CREDS = keys.Credentials(passwords=["pw", _common.PHRASE], identities=[IDENTITY],
                         keyfiles=[bytes(range(32))], shares=_SHARES,
                         fido2=lambda rp, cid, salt: bytes(range(32, 64)))


def TestOneInput(data: bytes) -> None:
    try:
        header = header2.read_header(io.BytesIO(data))
        if header.version == 2:
            header.unlock(CREDS)
        else:
            header.unlock("pw")
    except Tres0rError:
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
