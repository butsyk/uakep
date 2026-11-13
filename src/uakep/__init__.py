"""uakep: Ukrainian qualified electronic signatures (КЕП, ДСТУ 4145-2002) in pure Python.

from uakep import load_key, sign, unwrap

key = load_key("Key-6.dat", password="…", certificate="signer.cer")
signed = sign(receipt_xml_cp1251, key)   # CAdES, data attached, signer certificate inside
content = unwrap(signed)                 # checks the signature, returns the data
"""

from importlib.metadata import PackageNotFoundError, version

from .asn1 import UnsupportedError
from .cades import SignatureError, SigningKey, Verified, sign, verify
from .certificate import Certificate, CertificateError
from .keystore import KeyFileError, WrongPasswordError, load_key

try:
    __version__ = version("uakep")
except PackageNotFoundError:  # running from a source tree that is not installed
    __version__ = "0+unknown"


def unwrap(signed: bytes, *, detached_content: bytes | None = None) -> bytes:
    """Check the ДСТУ 4145 signature on CAdES signed data and return the signed data.

    Raises SignatureError when the signature does not verify. Certificate chains, revocation
    and time-stamps are not checked.
    """
    return verify(signed, detached_content=detached_content).content


__all__ = [
    "Certificate",
    "CertificateError",
    "KeyFileError",
    "SignatureError",
    "SigningKey",
    "UnsupportedError",
    "Verified",
    "WrongPasswordError",
    "__version__",
    "load_key",
    "sign",
    "unwrap",
    "verify",
]
