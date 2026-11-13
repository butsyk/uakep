"""uakep: Ukrainian qualified electronic signatures (КЕП, ДСТУ 4145-2002) in pure Python.

from uakep import load_key, sign, unwrap

key = load_key("Key-6.dat", password="…", certificate="signer.cer")
signed = sign(receipt_xml_cp1251, key, timestamp=post)  # CAdES with a signature time-stamp
content = unwrap(signed)                                # checks the signature, returns the data

``post(url, request) -> bytes`` is yours: it POSTs the time-stamp request to the TSA named in
the signer's certificate. Async callers use ``await sign_async(..., timestamp=async_post)``.
Offline documents are signed without ``timestamp``.
"""

from importlib.metadata import PackageNotFoundError, version

from .asn1 import UnsupportedError
from .cades import SignatureError, SigningKey, Verified, sign, sign_async, verify
from .certificate import Certificate, CertificateError
from .keystore import KeyFileError, WrongPasswordError, load_key
from .tsp import TimeStamp, TimeStampError

try:
    __version__ = version("uakep")
except PackageNotFoundError:  # running from a source tree that is not installed
    __version__ = "0+unknown"


def unwrap(signed: bytes, *, detached_content: bytes | None = None) -> bytes:
    """Check the ДСТУ 4145 signature on CAdES signed data and return the signed data.

    Raises SignatureError when the signature, or a signature time-stamp, does not verify.
    Certificate chains and revocation are not checked.
    """
    return verify(signed, detached_content=detached_content).content


__all__ = [
    "Certificate",
    "CertificateError",
    "KeyFileError",
    "SignatureError",
    "SigningKey",
    "TimeStamp",
    "TimeStampError",
    "UnsupportedError",
    "Verified",
    "WrongPasswordError",
    "__version__",
    "load_key",
    "sign",
    "sign_async",
    "unwrap",
    "verify",
]
