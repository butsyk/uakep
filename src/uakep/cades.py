"""CAdES signed data with ДСТУ 4145 signatures, in the layout the fiscal server accepts.

The layout follows the tax service's signed samples («Приклади з КЕП»): SignedData version 1,
the signer's certificate inside, the data attached, the signer named by its key identifier
as [0] EXPLICIT OCTET STRING, and three signed attributes in this order: messageDigest,
contentType, signingCertificateV2. Hash and signature algorithms carry no parameters.

Online documents also carry a signature time-stamp (RFC 3161) in the unsigned attributes: a
token over the hash of the signature value, in the signature's digest family. uakep makes no
network calls; the caller passes the function that posts the request to the TSA.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime

from asn1crypto import core, x509

from . import asn1, tsp
from .asn1 import UnsupportedError
from .certificate import Certificate
from .dstu4145 import PrivateKey
from .gost34311 import gost34311
from .kupyna import kupyna
from .tsp import TimeStamp, TimeStampError

KUPYNA_256 = "1.2.804.2.1.1.1.1.2.2.1"
_DIGESTS: dict[str, Callable[[bytes], bytes]] = {
    asn1.GOST34311: gost34311,
    KUPYNA_256: lambda data: kupyna(data, 32),
    "1.2.804.2.1.1.1.1.2.2.2": lambda data: kupyna(data, 48),
    "1.2.804.2.1.1.1.1.2.2.3": lambda data: kupyna(data, 64),
}
_SIGNATURE_ALGORITHMS = {asn1.DSTU4145_LE, asn1.DSTU4145_KUPYNA}

Post = Callable[[str, bytes], bytes]
"""``post(url, request) -> response``: POST the request to the TSA, return the response body."""
AsyncPost = Callable[[str, bytes], Awaitable[bytes]]


class SignatureError(ValueError):
    """Signed data that does not verify, or is not signed data uakep can check."""


class _SignerNotFound(SignatureError):
    pass


# What malformed bytes can raise while they are read, here or in asn1crypto.
_MALFORMED = (ValueError, TypeError, KeyError, IndexError)


@dataclass(frozen=True)
class SigningKey:
    """A private key and the certificate issued for it."""

    private_key: PrivateKey
    certificate: Certificate

    def __post_init__(self) -> None:
        if self.certificate.public_key != self.private_key.public_key():
            raise ValueError("the certificate was not issued for this private key")


@dataclass(frozen=True)
class Verified:
    """What a valid signature vouches for."""

    content: bytes
    certificate: Certificate
    digest_algorithm: str
    signing_time: datetime | None
    timestamp: TimeStamp | None = None


def _digest_for(certificate: Certificate) -> tuple[str, str]:
    """(digest OID, signature OID) for a signer.

    A certificate its CA signed with ДСТУ 4145 over Купина belongs to the Купина family and
    signs Купина-256 digests, as ЦЗО's Купина examples do; every other one uses ГОСТ 34.311,
    as the tax service's samples do.
    """
    if asn1.DSTU4145_KUPYNA in (certificate.signature_algorithm, certificate.public_key_algorithm):
        return KUPYNA_256, asn1.DSTU4145_KUPYNA
    return asn1.GOST34311, asn1.DSTU4145_LE


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def _attribute(oid: str, value: core.Asn1Value) -> bytes:
    return asn1.Attribute({"type": oid, "values": [value]}).dump()


def signed_attributes(content: bytes, certificate: Certificate) -> bytes:
    """The signed attributes as a DER SET, in the samples' order (not sorted)."""
    digest_oid, _ = _digest_for(certificate)
    digest = _DIGESTS[digest_oid]
    ess = asn1.SigningCertificateV2(
        {
            "certs": [
                {
                    "hash_algorithm": {"algorithm": digest_oid},
                    "cert_hash": digest(certificate.der),
                    "issuer_serial": {
                        "issuer": [
                            x509.GeneralName(
                                name="directory_name", value=x509.Name.load(certificate.issuer_der)
                            )
                        ],
                        "serial_number": certificate.serial_number,
                    },
                }
            ]
        }
    )
    attrs = (
        _attribute(asn1.ID_MESSAGE_DIGEST, core.OctetString(digest(content)))
        + _attribute(asn1.ID_CONTENT_TYPE, core.ObjectIdentifier(asn1.ID_DATA))
        + _attribute(asn1.ID_SIGNING_CERTIFICATE_V2, ess)
    )
    return _der(0x31, attrs)


def _seq(*parts: bytes) -> bytes:
    return _der(0x30, b"".join(parts))


def _algorithm(oid: str) -> bytes:
    return _seq(core.ObjectIdentifier(oid).dump())  # no parameters, as in the samples


class _Signing:
    """A signature in the samples' layout, made before its time-stamp is fetched."""

    def __init__(
        self, content: bytes, certificate: Certificate, sign_digest: Callable[[bytes], bytes]
    ) -> None:
        if certificate.subject_key_identifier is None:
            raise ValueError("the certificate has no subjectKeyIdentifier to name the signer")
        self.content = content
        self.certificate = certificate
        self.digest_oid, self.signature_oid = _digest_for(certificate)
        self.attrs = signed_attributes(content, certificate)
        self.signature = sign_digest(_DIGESTS[self.digest_oid](self.attrs))

    def timestamp_request(self) -> tuple[str, bytes]:
        """(TSA URL, DER request) for a signature time-stamp from the signer's own TSA."""
        url = self.certificate.tsp_url
        if url is None:
            raise TimeStampError("the signer's certificate names no time-stamping service")
        return url, tsp.request(self.digest_oid, _DIGESTS[self.digest_oid](self.signature))

    def signed_data(self, timestamp_response: bytes | None = None) -> bytes:
        """ContentInfo(SignedData), with the TSA's token if its response is given."""
        if timestamp_response is None:
            return self._assemble(b"")
        token = tsp.token_from_response(timestamp_response)
        check_timestamp(token, self.signature)
        return self._assemble(_der(0xA1, timestamp_attribute(token)))

    def _assemble(self, unsigned_attrs: bytes) -> bytes:
        """Built field by field so that the order and tagging match the tax samples exactly."""
        sid = _der(0xA0, core.OctetString(self.certificate.subject_key_identifier).dump())
        signer_info = _seq(
            core.Integer(1).dump(),
            sid,
            _algorithm(self.digest_oid),
            b"\xa0" + self.attrs[1:],  # [0] IMPLICIT SET OF Attribute
            _algorithm(self.signature_oid),
            core.OctetString(self.signature).dump(),
            unsigned_attrs,  # [1] IMPLICIT SET OF Attribute, or nothing
        )
        signed_data = _seq(
            core.Integer(1).dump(),
            _der(0x31, _algorithm(self.digest_oid)),
            _seq(
                core.ObjectIdentifier(asn1.ID_DATA).dump(),
                _der(0xA0, core.OctetString(self.content).dump()),
            ),
            _der(0xA0, self.certificate.der),
            _der(0x31, signer_info),
        )
        return _seq(core.ObjectIdentifier(asn1.ID_SIGNED_DATA).dump(), _der(0xA0, signed_data))


def timestamp_attribute(token: bytes) -> bytes:
    """The signature-time-stamp Attribute holding ``token``, as DER."""
    return _seq(core.ObjectIdentifier(asn1.ID_SIGNATURE_TIMESTAMP).dump(), _der(0x31, token))


def build_signed_data(
    content: bytes, certificate: Certificate, sign_digest: Callable[[bytes], bytes]
) -> bytes:
    """ContentInfo(SignedData) over ``content``; ``sign_digest`` maps a hash to ``r || s``."""
    return _Signing(content, certificate, sign_digest).signed_data()


def sign(content: bytes, key: SigningKey, *, timestamp: Post | None = None) -> bytes:
    """Sign ``content`` (attached) as CAdES.

    Online documents need a signature time-stamp: pass ``timestamp``, a function that POSTs a
    request to a TSA with Content-Type ``application/timestamp-query`` and returns the response
    body. It is called once, with the URL of the TSA named in the signer's certificate.
    Offline documents go without one.
    """
    signing = _Signing(bytes(content), key.certificate, key.private_key.sign)
    if timestamp is None:
        return signing.signed_data()
    return signing.signed_data(timestamp(*signing.timestamp_request()))


async def sign_async(
    content: bytes, key: SigningKey, *, timestamp: AsyncPost | None = None
) -> bytes:
    """``sign`` for async callers: ``timestamp`` is awaited. Signing itself runs inline."""
    signing = _Signing(bytes(content), key.certificate, key.private_key.sign)
    if timestamp is None:
        return signing.signed_data()
    return signing.signed_data(await timestamp(*signing.timestamp_request()))


def _signer_identifier(sid: core.Any) -> tuple[str, object]:
    """('ski', bytes) or ('issuer_serial', (issuer DER, serial)) from the raw signer id."""
    for spec in (asn1.SignerIdExplicit, asn1.SignerIdImplicit):
        try:
            choice = sid.parse(spec)
        except ValueError:
            continue
        if choice.name == "subject_key_identifier":
            return "ski", choice.chosen.native
        ias = choice.chosen
        return "issuer_serial", (ias["issuer"].dump(), ias["serial_number"].native)
    raise SignatureError("unknown signer identifier")


def _certificates(signed_data: asn1.SignedData):
    for item in signed_data["certificates"]:
        try:
            yield Certificate(item.dump())
        except (ValueError, TypeError):  # not an X.509 certificate (attribute certs and such)
            continue


def _find_signer(signed_data: asn1.SignedData, signer_info: asn1.SignerInfo) -> Certificate:
    kind, value = _signer_identifier(signer_info["sid"])
    for cert in _certificates(signed_data):
        if kind == "ski" and cert.subject_key_identifier == value:
            return cert
        if kind == "issuer_serial" and (cert.issuer_der, cert.serial_number) == value:
            return cert
    raise _SignerNotFound("the signer's certificate is not in the signed data")


def verify(signed: bytes, *, detached_content: bytes | None = None) -> Verified:
    """Check a CAdES signature made with ДСТУ 4145; raise SignatureError if it fails.

    Signed data that cannot be read is a SignatureError too, however it is damaged. Only an
    algorithm uakep does not have raises something else, an UnsupportedError.

    A signature time-stamp is checked too. It is reported in ``timestamp`` when its token
    carries the TSA's certificate; without that certificate the token cannot be checked, and
    ``timestamp`` is None. Certificate chains and revocation are not checked.
    """
    return _verify(signed, detached_content, timestamps=True)


def _verify(signed: bytes, detached_content: bytes | None, *, timestamps: bool) -> Verified:
    """Whatever is wrong with ``signed``, the caller sees a SignatureError.

    asn1crypto parses lazily, so malformed bytes can surface at any step: in an attribute's
    value, in the signer's public key. All of it is caught here, in one place.
    """
    try:
        return _verify_signed_data(signed, detached_content, timestamps=timestamps)
    except (SignatureError, UnsupportedError):
        raise
    except _MALFORMED as exc:
        raise SignatureError(f"cannot read the signed data: {exc}") from exc


def _verify_signed_data(
    signed: bytes, detached_content: bytes | None, *, timestamps: bool
) -> Verified:
    info = asn1.ContentInfo.load(bytes(signed))
    if info["content_type"].dotted != asn1.ID_SIGNED_DATA:
        raise SignatureError("not signed data")
    signed_data = info["content"]
    if len(signed_data["signer_infos"]) != 1:
        raise SignatureError("expected exactly one signature")
    signer_info = signed_data["signer_infos"][0]
    econtent = signed_data["encap_content_info"]
    content = econtent["content"].native
    content_type = econtent["content_type"].dotted
    certificate = _find_signer(signed_data, signer_info)
    digest_oid = signer_info["digest_algorithm"]["algorithm"].dotted
    signature_oid = signer_info["signature_algorithm"]["algorithm"].dotted
    attrs = signer_info["signed_attrs"]
    found = {a["type"].dotted: a["values"] for a in attrs}
    signed_attrs_der = None if isinstance(attrs, core.Void) else attrs.dump()
    signature = signer_info["signature"].native
    tokens = [
        value.dump()
        for attr in signer_info["unsigned_attrs"]
        if attr["type"].dotted == asn1.ID_SIGNATURE_TIMESTAMP
        for value in attr["values"]
    ]

    if content is None:
        if detached_content is None:
            raise SignatureError("the data is not attached; pass it as detached_content")
        content = bytes(detached_content)
    digest = _DIGESTS.get(digest_oid)
    if digest is None:
        raise UnsupportedError(f"digest algorithm {digest_oid}")
    if signature_oid not in _SIGNATURE_ALGORITHMS:
        raise UnsupportedError(f"signature algorithm {signature_oid}")

    signing_time = None
    if signed_attrs_der is None:
        message = content
    else:
        _check_attributes(found, content, content_type, certificate, digest)
        if asn1.ID_SIGNING_TIME in found:
            signing_time = x509.Time.load(found[asn1.ID_SIGNING_TIME][0].dump()).native
        message = b"\x31" + signed_attrs_der[1:]  # the [0] IMPLICIT tag back to SET

    if not certificate.public_key.verify(digest(message), signature):
        raise SignatureError("the signature does not match")
    stamp = _signature_timestamp(tokens, signature) if timestamps else None
    return Verified(content, certificate, digest_oid, signing_time, stamp)


def _signature_timestamp(tokens: list[bytes], signature: bytes) -> TimeStamp | None:
    """The earliest signature time-stamp that can be checked; any that fails is an error."""
    stamps = []
    for token in tokens:
        try:
            stamp = check_timestamp(token, signature, require_certificate=False)
        except TimeStampError as exc:
            raise SignatureError(f"the signature time-stamp does not check out: {exc}") from exc
        if stamp is not None:
            stamps.append(stamp)
    return min(stamps, key=lambda stamp: stamp.time, default=None)


def check_timestamp(
    token: bytes, data: bytes, *, require_certificate: bool = True
) -> TimeStamp | None:
    """Check an RFC 3161 token over ``data``; raise TimeStampError if it does not hold.

    The token's imprint must be the hash of ``data``, and the token must be signed by a TSA
    whose certificate is attached, is meant for time-stamping and was valid at the stamped
    time. With ``require_certificate=False``, a token without its TSA's certificate returns
    None once its imprint is checked.
    """
    try:
        return _check_timestamp(token, data, require_certificate=require_certificate)
    except (TimeStampError, UnsupportedError):
        raise
    except _MALFORMED as exc:
        raise TimeStampError(f"cannot read the token: {exc}") from exc


def _check_timestamp(token: bytes, data: bytes, *, require_certificate: bool) -> TimeStamp | None:
    info = asn1.ContentInfo.load(bytes(token))
    if info["content_type"].dotted != asn1.ID_SIGNED_DATA:
        raise TimeStampError("the token is not signed data")
    econtent = info["content"]["encap_content_info"]
    content_type = econtent["content_type"].dotted
    tst_der = econtent["content"].native
    if content_type != asn1.ID_TST_INFO or tst_der is None:
        raise TimeStampError("the token holds no TSTInfo")
    tst = tsp.read_tst_info(tst_der)
    digest = _DIGESTS.get(tst.digest_algorithm)
    if digest is None:
        raise UnsupportedError(f"time-stamp digest algorithm {tst.digest_algorithm}")
    if tst.imprint != digest(bytes(data)):
        raise TimeStampError("the time-stamp is for other data")
    try:
        tsa = _verify(token, None, timestamps=False).certificate
    except _SignerNotFound as exc:
        if require_certificate:
            raise TimeStampError("the TSA's certificate is not in the token") from exc
        return None
    except SignatureError as exc:
        raise TimeStampError(f"the TSA's signature: {exc}") from exc
    if tsp.ID_KP_TIME_STAMPING not in tsa.extended_key_usage:
        raise TimeStampError("the token's signer is not a time-stamping authority")
    if not tsa.is_valid_at(tst.time):
        raise TimeStampError("the TSA's certificate was not valid at the stamped time")
    return TimeStamp(tst.time, tst.serial_number, tst.policy, tst.digest_algorithm, tsa)


def _check_attributes(found, content, content_type, certificate, digest) -> None:
    if asn1.ID_MESSAGE_DIGEST not in found:
        raise SignatureError("signed attributes lack messageDigest")
    if core.OctetString.load(found[asn1.ID_MESSAGE_DIGEST][0].dump()).native != digest(content):
        raise SignatureError("the data does not match its messageDigest")
    if asn1.ID_CONTENT_TYPE in found:
        declared = core.ObjectIdentifier.load(found[asn1.ID_CONTENT_TYPE][0].dump()).dotted
        if declared != content_type:
            raise SignatureError("contentType attribute does not match the content")
    if asn1.ID_SIGNING_CERTIFICATE_V2 in found:
        ess = asn1.SigningCertificateV2.load(found[asn1.ID_SIGNING_CERTIFICATE_V2][0].dump())
        first = ess["certs"][0]
        algorithm = first["hash_algorithm"]
        hash_oid = algorithm["algorithm"].dotted if algorithm.native else "2.16.840.1.101.3.4.2.1"
        cert_digest = _DIGESTS.get(hash_oid)
        if cert_digest is None:
            raise UnsupportedError(f"signingCertificateV2 hash {hash_oid}")
        if first["cert_hash"].native != cert_digest(certificate.der):
            raise SignatureError("signingCertificateV2 names another certificate")
