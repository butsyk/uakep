"""Private keys from the containers Ukrainian CAs issue.

IIT Key-6.dat holds a PKCS#8 private key encrypted with ГОСТ 28147-89 (ECB) under a key derived
from the password by 10 000 ГОСТ 34.311 hashes, plus a 4-byte ГОСТ MAC of the plaintext. The
plaintext usually carries a second key in IIT attributes: its curve parameters big-endian, its
private scalar as a bit-reversed BIT STRING.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from pathlib import Path

from asn1crypto import core

from . import asn1
from .asn1 import UnsupportedError
from .cades import SigningKey
from .certificate import Certificate, CertificateError
from .dstu4145 import PrivateKey
from .gost28147 import DEFAULT_SBOX, GOST28147
from .gost34311 import gost34311, key6_kdf, pbkdf2

_KEY_ALGORITHMS = {asn1.DSTU4145_LE, asn1.DSTU4145_KUPYNA}


class KeyFileError(ValueError):
    """A key container that cannot be read."""


class WrongPasswordError(KeyFileError):
    """The password does not open the key container."""


def password_candidates(password: str | bytes, *, prefer_utf8: bool = False) -> Iterator[bytes]:
    """Byte forms of a password to try, most likely first.

    Bytes are used as given. An ASCII string has one form. Any other string is tried in
    Windows-1251 (IIT's Windows software) and UTF-8, UTF-8 first for PKCS#8 containers.
    """
    if isinstance(password, bytes | bytearray):
        yield bytes(password)
        return
    if password.isascii():
        yield password.encode("ascii")
        return
    for encoding in ("utf-8", "cp1251") if prefer_utf8 else ("cp1251", "utf-8"):
        try:
            encoded = password.encode(encoding)
        except UnicodeEncodeError:
            continue
        yield encoded


def key_identifier(key: PrivateKey) -> bytes:
    """ГОСТ 34.311 hash of the public key's DER OCTET STRING, as IIT stores it beside each key."""
    return gost34311(key.public_key().to_octet_string())


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
    except ValueError as exc:
        raise KeyFileError(f"cannot read the private key: {exc}") from exc
    return _keys_from_info(info)


def _keys_from_info(info: asn1.DstuPrivateKey) -> list[PrivateKey]:
    try:
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


# -- PBES2, PKCS#12 and Java KeyStore --------------------------------------------------------


def _pbes2_decrypt(algorithm: asn1.AlgorithmIdentifier, data: bytes, password: bytes) -> bytes:
    """PBES2 with PBKDF2-HMAC-ГОСТ 34.311 and ГОСТ 28147-89 CFB, the scheme of ДСТУ containers."""
    if algorithm["algorithm"].dotted != asn1.PBES2:
        raise UnsupportedError(f"key encryption {algorithm['algorithm'].dotted}")
    params = algorithm["parameters"].parse(asn1.Pbes2Params)
    kdf = params["key_derivation_func"]
    if kdf["algorithm"].dotted != asn1.PBKDF2:
        raise UnsupportedError(f"key derivation {kdf['algorithm'].dotted}")
    kdf_params = kdf["parameters"].parse(asn1.Pbkdf2Params)
    prf = kdf_params["prf"]
    if isinstance(prf, core.Void) or prf["algorithm"].dotted != asn1.GOST34311_HMAC:
        raise UnsupportedError("PBKDF2 without HMAC-ГОСТ 34.311 (Kalyna containers come later)")
    scheme = params["encryption_scheme"]
    if scheme["algorithm"].dotted != asn1.GOST28147_CFB:
        raise UnsupportedError(f"cipher {scheme['algorithm'].dotted}")
    cipher_params = scheme["parameters"].parse(asn1.Gost28147Params)
    sbox = cipher_params["dke"].native or DEFAULT_SBOX
    key = pbkdf2(password, kdf_params["salt"].native, kdf_params["iteration_count"].native)
    return GOST28147(key, sbox).decrypt_cfb(cipher_params["iv"].native, data)


def _decrypt_key(algorithm: asn1.AlgorithmIdentifier, data: bytes, password) -> list[PrivateKey]:
    """Keys from an encrypted PKCS#8 body, trying each byte form of the password."""
    for candidate in password_candidates(password, prefer_utf8=True):
        plain = _pbes2_decrypt(algorithm, data, candidate)
        try:
            return private_keys_from_pkcs8(plain)
        except KeyFileError:
            continue  # garbage: most likely the wrong password
    raise WrongPasswordError("wrong password, or the key file is damaged")


def read_pfx(data: bytes, password: str | bytes) -> tuple[list[PrivateKey], list[bytes]]:
    """Private keys and DER certificates in a PKCS#12 (.pfx, .p12) file."""
    try:
        pfx = asn1.Pfx.load(data)
        auth_safe = pfx["auth_safe"]["content"].parse(core.OctetString).native
        safes = asn1.AuthenticatedSafe.load(auth_safe)
        keys: list[PrivateKey] = []
        certs: list[bytes] = []
        for content_info in safes:
            kind = content_info["content_type"].dotted
            if kind == asn1.ID_DATA:
                bags = content_info["content"].parse(core.OctetString).native
            elif kind == asn1.ID_ENCRYPTED_DATA:
                enc = content_info["content"].parse(asn1.EncryptedData)["encrypted_content_info"]
                bags = _decrypt_any(
                    enc["content_encryption_algorithm"], enc["encrypted_content"].native, password
                )
            else:
                continue
            _read_bags(asn1.SafeContents.load(bags), password, keys, certs)
    except (KeyFileError, UnsupportedError):
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise KeyFileError(f"cannot read the PKCS#12 file: {exc}") from exc
    return keys, certs


def _decrypt_any(algorithm, data: bytes, password) -> bytes:
    for candidate in password_candidates(password, prefer_utf8=True):
        plain = _pbes2_decrypt(algorithm, data, candidate)
        if plain[:1] == b"\x30":
            return plain
    raise WrongPasswordError("wrong password, or the key file is damaged")


def _read_bags(bags: asn1.SafeContents, password, keys: list, certs: list) -> None:
    for bag in bags:
        kind = bag["bag_id"].dotted
        if kind == asn1.SHROUDED_KEY_BAG:
            info = bag["bag_value"].parse(asn1.EncryptedPrivateKeyInfo)
            keys.extend(
                _decrypt_key(info["encryption_algorithm"], info["encrypted_data"].native, password)
            )
        elif kind == asn1.KEY_BAG:
            keys.extend(_keys_from_info(bag["bag_value"].parse(asn1.DstuPrivateKey)))
        elif kind == asn1.CERT_BAG:
            cert_bag = bag["bag_value"].parse(asn1.CertBag)
            if cert_bag["cert_id"].dotted == asn1.X509_CERTIFICATE:
                certs.append(cert_bag["cert_value"].native)
        elif kind == asn1.SAFE_CONTENTS_BAG:
            _read_bags(bag["bag_value"].parse(asn1.SafeContents), password, keys, certs)


_JKS_MAGIC = b"\xfe\xed\xfe\xed"


def read_jks(data: bytes, password: str | bytes) -> tuple[list[PrivateKey], list[bytes]]:
    """Private keys and DER certificates in a Java KeyStore (PrivatBank's .jks).

    The key password opens the keys; the store's own integrity digest is not checked.
    """
    if data[:1] == b"Q" and data[6:10] == _JKS_MAGIC:
        data = data[6:]  # a 6-byte prefix some key files carry
    reader = _Reader(data)
    try:
        if reader.take(4) != _JKS_MAGIC:
            raise KeyFileError("not a Java KeyStore")
        if reader.u32() != 2:
            raise UnsupportedError("only version 2 Java KeyStores are supported")
        text = password.decode("utf-8") if isinstance(password, bytes | bytearray) else password
        keys: list[PrivateKey] = []
        certs: list[bytes] = []
        for _ in range(reader.u32()):
            tag = reader.u32()
            reader.utf()  # alias
            reader.take(8)  # creation time
            if tag == 1:
                protected = reader.take(reader.u32())
                for _ in range(reader.u32()):
                    certs.append(reader.certificate())
                keys.extend(_jks_key(protected, text))
            elif tag == 2:
                certs.append(reader.certificate())
            else:
                raise KeyFileError(f"unknown Java KeyStore entry {tag}")
    except (KeyFileError, UnsupportedError):
        raise
    except (ValueError, TypeError, KeyError, IndexError, UnicodeDecodeError) as exc:
        raise KeyFileError(f"cannot read the Java KeyStore: {exc}") from exc
    return keys, certs


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise KeyFileError("truncated Java KeyStore")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def utf(self) -> str:
        return self.take(int.from_bytes(self.take(2), "big")).decode("utf-8")

    def certificate(self) -> bytes:
        kind = self.utf()
        der = self.take(self.u32())
        if kind not in ("X.509", "X509"):
            raise UnsupportedError(f"certificate type {kind}")
        return der


def _jks_key(protected: bytes, password: str) -> list[PrivateKey]:
    """Sun's key protector: SHA-1 keystream from the UTF-16BE password, SHA-1 check."""
    info = asn1.EncryptedPrivateKeyInfo.load(protected)
    if info["encryption_algorithm"]["algorithm"].dotted != asn1.JKS_KEY_PROTECTOR:
        raise UnsupportedError("Java KeyStore key protection other than Sun's key protector")
    blob = info["encrypted_data"].native
    if len(blob) < 40:
        raise KeyFileError("damaged Java KeyStore key")
    iv, body, check = blob[:20], blob[20:-20], blob[-20:]
    pw = password.encode("utf-16-be")
    stream = bytearray()
    block = iv
    while len(stream) < len(body):
        block = hashlib.sha1(pw + block).digest()
        stream += block
    plain = bytes(a ^ b for a, b in zip(body, stream, strict=False))
    if hashlib.sha1(pw + plain).digest() != check:
        raise WrongPasswordError("wrong password, or the key file is damaged")
    return private_keys_from_pkcs8(plain)


def read_key_file(data: bytes, password: str | bytes) -> tuple[list[PrivateKey], list[bytes]]:
    """Keys and DER certificates from any supported container, recognised by its contents."""
    data = bytes(data)
    if data[:4] == _JKS_MAGIC or (data[:1] == b"Q" and data[6:10] == _JKS_MAGIC):
        return read_jks(data, password)
    try:
        outer = core.Sequence.load(data, strict=False)
        first = outer[0]
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise KeyFileError("not a key file uakep can read") from exc
    if isinstance(first, core.Integer):
        if first.native == 3:
            return read_pfx(data, password)
        return private_keys_from_pkcs8(data), []  # unencrypted PKCS#8
    if (
        isinstance(first, core.Sequence)
        and len(first)
        and isinstance(first[0], core.ObjectIdentifier)
    ):
        if first[0].dotted == asn1.IIT_STORE:
            return read_key6(data, password), []
        if first[0].dotted == asn1.PBES2:
            info = asn1.EncryptedPrivateKeyInfo.load(data)
            return _decrypt_key(
                info["encryption_algorithm"], info["encrypted_data"].native, password
            ), []
    raise KeyFileError("not a key file uakep can read")


def _read(source: str | os.PathLike | bytes) -> bytes:
    if isinstance(source, bytes | bytearray):
        return bytes(source)
    return Path(source).read_bytes()


def load_key(
    key_file: str | os.PathLike | bytes,
    password: str | bytes,
    certificate: str | os.PathLike | bytes | Certificate | None = None,
) -> SigningKey:
    """The signing key in a key file, paired with its certificate.

    Reads IIT Key-6.dat, PKCS#12 (.pfx, .p12), Java KeyStore (.jks) and PKCS#8 files. Key-6.dat
    holds no certificate, so pass the signing certificate (a path, bytes or a Certificate);
    the other formats usually carry it. The certificate must allow signing.
    """
    keys, cert_ders = read_key_file(_read(key_file), password)
    if certificate is not None:
        cert = (
            certificate
            if isinstance(certificate, Certificate)
            else Certificate.load(_read(certificate))
        )
        if not cert.can_sign:
            raise KeyFileError("this certificate is not for signing (see its key usage)")
        candidates = [cert]
    else:
        candidates = []
        for der in cert_ders:
            try:
                cert = Certificate(der)
            except CertificateError:
                continue
            if cert.can_sign:
                candidates.append(cert)
        if not candidates:
            raise KeyFileError("the key file holds no signing certificate; pass certificate=")
    public_keys = [(key, key.public_key()) for key in keys]
    for cert in candidates:
        try:
            wanted = cert.public_key
        except UnsupportedError:
            continue
        for key, public in public_keys:
            if public == wanted:
                return SigningKey(key, cert)
    raise KeyFileError("no key in the key file matches the signing certificate")
