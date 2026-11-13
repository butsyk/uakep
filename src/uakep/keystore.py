"""Private keys from the containers Ukrainian CAs issue.

IIT Key-6.dat holds a PKCS#8 private key encrypted with ГОСТ 28147-89 (ECB) under a key derived
from the password by 10 000 ГОСТ 34.311 hashes, plus a 4-byte ГОСТ MAC of the plaintext. The
plaintext usually carries a second key in IIT attributes: its curve parameters big-endian, its
private scalar as a bit-reversed BIT STRING.
"""

from __future__ import annotations

from collections.abc import Iterator

from asn1crypto import core

from . import asn1
from .asn1 import UnsupportedError
from .dstu4145 import PrivateKey
from .gost28147 import GOST28147
from .gost34311 import gost34311, key6_kdf

_KEY_ALGORITHMS = {asn1.DSTU4145_LE, asn1.DSTU4145_KUPYNA}


class KeyFileError(ValueError):
    """A key container that cannot be read."""


class WrongPasswordError(KeyFileError):
    """The password does not open the key container."""


def password_candidates(password: str | bytes) -> Iterator[bytes]:
    """Byte forms of a password to try, most likely first.

    Bytes are used as given. An ASCII string has one form; any other string is tried in
    Windows-1251 (IIT's Windows software) and then UTF-8.
    """
    if isinstance(password, bytes | bytearray):
        yield bytes(password)
        return
    if password.isascii():
        yield password.encode("ascii")
        return
    for encoding in ("cp1251", "utf-8"):
        try:
            encoded = password.encode(encoding)
        except UnicodeEncodeError:
            continue
        yield encoded


def key_identifier(key: PrivateKey) -> bytes:
    """ГОСТ 34.311 hash of the DER OCTET STRING of the compressed public key (little-endian).

    CAs put this value in the certificate's subjectKeyIdentifier; IIT key containers store it
    beside each key.
    """
    pub = key.public_key()
    raw = pub.compressed().to_bytes((key.curve.m + 7) // 8, "little")
    return gost34311(core.OctetString(raw).dump())


def read_key6(data: bytes, password: str | bytes) -> list[PrivateKey]:
    """All private keys in an IIT Key-6.dat container."""
    try:
        store = asn1.IitStore.load(data)
        if store["header"]["type"].dotted != asn1.IIT_STORE:
            raise KeyFileError("not an IIT key container")
        params = store["header"]["params"]
        mac = params["mac"].native
        pad = params["pad"].native or b""
        body = store["data"].native
    except (ValueError, TypeError, KeyError) as exc:
        if isinstance(exc, KeyFileError):
            raise
        raise KeyFileError("not an IIT key container") from exc
    if len(mac) != 4 or (len(body) + len(pad)) % 8:
        raise KeyFileError("damaged IIT key container")

    for candidate in password_candidates(password):
        cipher = GOST28147(key6_kdf(candidate))
        plain = cipher.decrypt_ecb(body + pad)[: len(body)]
        if cipher.mac(plain) == mac:
            return private_keys_from_pkcs8(plain)
    raise WrongPasswordError("wrong password, or the key file is damaged")


def private_keys_from_pkcs8(der: bytes) -> list[PrivateKey]:
    """The key of a ДСТУ 4145 PrivateKeyInfo, then the second key from IIT attributes, if any."""
    try:
        info = asn1.DstuPrivateKey.load(der, strict=False)
        algorithm = info["algorithm"]["algorithm"].dotted
        if algorithm not in _KEY_ALGORITHMS:
            raise UnsupportedError(f"not a ДСТУ 4145 private key ({algorithm})")
        curve = asn1.curve_from_spec(info["algorithm"]["parameters"]["curve"])
        keys = [PrivateKey(curve, int.from_bytes(info["private_key"].native, "little"))]
        second = _attribute_key(info["attributes"])
    except (UnsupportedError, KeyFileError):
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise KeyFileError(f"cannot read the private key: {exc}") from exc
    if second is not None:
        keys.append(second)
    return keys


def _attribute_key(attributes) -> PrivateKey | None:
    found = {a["type"].dotted: a["values"][0] for a in attributes if len(a["values"])}
    bits_value = found.get(asn1.IIT_KEY_BITS)
    curve_value = found.get(asn1.IIT_KEY_CURVE)
    if bits_value is None or curve_value is None:
        return None
    bits = core.BitString.load(bits_value.dump()).contents[1:]
    d = int.from_bytes(bits, "big")
    d = int(format(d, f"0{8 * len(bits)}b")[::-1], 2)  # the bit string is stored reversed
    spec = asn1.DstuParams.load(curve_value.dump())
    curve = asn1.curve_from_spec(spec["curve"], little_endian=False)
    return PrivateKey(curve, d)
