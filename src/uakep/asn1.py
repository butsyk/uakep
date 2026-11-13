"""ASN.1 structures for ДСТУ 4145 keys, parameters and key containers (on asn1crypto).

Curve parameters follow ДСТУ 4145-2002, Appendix Б: a named curve OID or an explicit binary
curve, optionally with a substitution table (ДКЕ). In certificates and private keys the
coefficient ``b`` and the compressed base point are little-endian octet strings; inside IIT's
key attributes they are big-endian.
"""

from __future__ import annotations

from asn1crypto import core, tsp, x509

from .curve import NAMED_CURVES, Curve

# Algorithms
DSTU4145_LE = "1.2.804.2.1.1.1.1.3.1.1"
DSTU4145_KUPYNA = "1.2.804.2.1.1.1.1.3.6.1.1"
GOST34311 = "1.2.804.2.1.1.1.1.2.1"
GOST34311_HMAC = "1.2.804.2.1.1.1.1.1.2"
GOST28147_CFB = "1.2.804.2.1.1.1.1.1.1.3"
PBES2 = "1.2.840.113549.1.5.13"
PBKDF2 = "1.2.840.113549.1.5.12"

# IIT key containers (Key-6.dat) and the attributes carrying a second key
IIT_STORE = "1.3.6.1.4.1.19398.1.1.1.2"
IIT_KEY_CURVE = "1.3.6.1.4.1.19398.1.1.2.2"
IIT_KEY_BITS = "1.3.6.1.4.1.19398.1.1.2.3"

# Named curves: the ten curves of ДСТУ 4145-2002 under the ГОСТ 34.311 and Купина arcs.
_CURVE_SIZES = (163, 167, 173, 179, 191, 233, 257, 307, 367, 431)
CURVE_OIDS: dict[str, str] = {}
for _arc in ("1.2.804.2.1.1.1.1.3.1.1.2", "1.2.804.2.1.1.1.1.3.6.1.1.2"):
    for _i, _m in enumerate(_CURVE_SIZES):
        CURVE_OIDS[f"{_arc}.{_i}"] = f"DSTU_PB_{_m}"


class UnsupportedError(ValueError):
    """Valid input that this version of uakep cannot handle (an unbundled curve, a cipher)."""


class Pentanomial(core.Sequence):
    _fields = [("k", core.Integer), ("j", core.Integer), ("l", core.Integer)]


class Polynomial(core.Choice):
    _alternatives = [("trinomial", core.Integer), ("pentanomial", Pentanomial)]


class FieldSpec(core.Sequence):
    _fields = [("m", core.Integer), ("poly", Polynomial)]


class ECBinary(core.Sequence):
    _fields = [
        ("version", core.Integer, {"explicit": 0, "default": 0}),
        ("field", FieldSpec),
        ("a", core.Integer),
        ("b", core.OctetString),
        ("n", core.Integer),
        ("bp", core.OctetString),
    ]


class CurveSpec(core.Choice):
    _alternatives = [("explicit", ECBinary), ("named", core.ObjectIdentifier)]


class DstuParams(core.Sequence):
    """Algorithm parameters of a ДСТУ 4145 key: the curve and the optional ДКЕ."""

    _fields = [
        ("curve", CurveSpec),
        ("dke", core.OctetString, {"optional": True}),
        ("dke2", core.OctetString, {"optional": True}),
    ]


class DstuAlgorithm(core.Sequence):
    _fields = [("algorithm", core.ObjectIdentifier), ("parameters", DstuParams, {"optional": True})]


class KeyAttribute(core.Sequence):
    _fields = [("type", core.ObjectIdentifier), ("values", core.SetOf, {"spec": core.Any})]


class KeyAttributes(core.SetOf):
    _child_spec = KeyAttribute


class DstuPrivateKey(core.Sequence):
    """PKCS#8 PrivateKeyInfo as ДСТУ 4145 key containers hold it; d is little-endian."""

    _fields = [
        ("version", core.Integer),
        ("algorithm", DstuAlgorithm),
        ("private_key", core.OctetString),
        ("attributes", KeyAttributes, {"implicit": 0, "optional": True}),
    ]


class IitStoreParams(core.Sequence):
    _fields = [("mac", core.OctetString), ("pad", core.OctetString, {"optional": True})]


class IitStoreHeader(core.Sequence):
    _fields = [("type", core.ObjectIdentifier), ("params", IitStoreParams)]


class IitStore(core.Sequence):
    """IIT Key-6.dat: a private key encrypted with ГОСТ 28147-89 in ECB mode."""

    _fields = [("header", IitStoreHeader), ("data", core.OctetString)]


class AlgorithmIdentifier(core.Sequence):
    _fields = [("algorithm", core.ObjectIdentifier), ("parameters", core.Any, {"optional": True})]


class SubjectPublicKeyInfo(core.Sequence):
    """X.509 public key info with the parameters left raw (asn1crypto rejects ДСТУ keys)."""

    _fields = [("algorithm", AlgorithmIdentifier), ("public_key", core.BitString)]


class TbsCertificate(core.Sequence):
    _fields = [
        ("version", x509.Version, {"explicit": 0, "default": "v1"}),
        ("serial_number", core.Integer),
        ("signature", AlgorithmIdentifier),
        ("issuer", x509.Name),
        ("validity", x509.Validity),
        ("subject", x509.Name),
        ("subject_public_key_info", SubjectPublicKeyInfo),
        ("issuer_unique_id", core.BitString, {"implicit": 1, "optional": True}),
        ("subject_unique_id", core.BitString, {"implicit": 2, "optional": True}),
        ("extensions", x509.Extensions, {"explicit": 3, "optional": True}),
    ]


class Certificate(core.Sequence):
    _fields = [
        ("tbs_certificate", TbsCertificate),
        ("signature_algorithm", AlgorithmIdentifier),
        ("signature_value", core.BitString),
    ]


class DirectoryAttribute(core.Sequence):
    _fields = [("type", core.ObjectIdentifier), ("values", core.SetOf, {"spec": core.Any})]


class DirectoryAttributes(core.SequenceOf):
    """subjectDirectoryAttributes, where Ukrainian CAs put РНОКПП and ЄДРПОУ."""

    _child_spec = DirectoryAttribute


class AccessDescription(core.Sequence):
    _fields = [("access_method", core.ObjectIdentifier), ("access_location", x509.GeneralName)]


class InfoAccess(core.SequenceOf):
    """authorityInfoAccess and subjectInfoAccess."""

    _child_spec = AccessDescription


# CMS (RFC 5652) as Ukrainian software writes it. The signer identifier is kept raw: the tax
# service's samples encode subjectKeyIdentifier as [0] EXPLICIT OCTET STRING, where RFC 5652
# has [0] IMPLICIT.

ID_DATA = "1.2.840.113549.1.7.1"
ID_SIGNED_DATA = "1.2.840.113549.1.7.2"
ID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
ID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
ID_SIGNING_TIME = "1.2.840.113549.1.9.5"
ID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"
ID_CONTENT_TIMESTAMP = "1.2.840.113549.1.9.16.2.20"
ID_SIGNATURE_TIMESTAMP = "1.2.840.113549.1.9.16.2.14"


class Attribute(core.Sequence):
    _fields = [("type", core.ObjectIdentifier), ("values", core.SetOf, {"spec": core.Any})]


class Attributes(core.SetOf):
    _child_spec = Attribute


class IssuerAndSerialNumber(core.Sequence):
    _fields = [("issuer", x509.Name), ("serial_number", core.Integer)]


class SignerIdExplicit(core.Choice):
    """The signer id as the tax samples write it: [0] EXPLICIT OCTET STRING for a key id."""

    _alternatives = [
        ("issuer_and_serial_number", IssuerAndSerialNumber),
        ("subject_key_identifier", core.OctetString, {"explicit": 0}),
    ]


class SignerIdImplicit(core.Choice):
    """The signer id as RFC 5652 defines it: [0] IMPLICIT for a key id."""

    _alternatives = [
        ("issuer_and_serial_number", IssuerAndSerialNumber),
        ("subject_key_identifier", core.OctetString, {"implicit": 0}),
    ]


class SignerInfo(core.Sequence):
    _fields = [
        ("version", core.Integer),
        ("sid", core.Any),
        ("digest_algorithm", AlgorithmIdentifier),
        ("signed_attrs", Attributes, {"implicit": 0, "optional": True}),
        ("signature_algorithm", AlgorithmIdentifier),
        ("signature", core.OctetString),
        ("unsigned_attrs", Attributes, {"implicit": 1, "optional": True}),
    ]


class SignerInfos(core.SetOf):
    _child_spec = SignerInfo


class DigestAlgorithms(core.SetOf):
    _child_spec = AlgorithmIdentifier


class CertificateSet(core.SetOf):
    _child_spec = core.Any


class EncapsulatedContentInfo(core.Sequence):
    _fields = [
        ("content_type", core.ObjectIdentifier),
        ("content", core.OctetString, {"explicit": 0, "optional": True}),
    ]


class SignedData(core.Sequence):
    _fields = [
        ("version", core.Integer),
        ("digest_algorithms", DigestAlgorithms),
        ("encap_content_info", EncapsulatedContentInfo),
        ("certificates", CertificateSet, {"implicit": 0, "optional": True}),
        ("crls", CertificateSet, {"implicit": 1, "optional": True}),
        ("signer_infos", SignerInfos),
    ]


class ContentInfo(core.Sequence):
    _fields = [
        ("content_type", core.ObjectIdentifier),
        ("content", core.Any, {"explicit": 0, "optional": True}),
    ]
    _oid_pair = ("content_type", "content")
    _oid_specs = {ID_SIGNED_DATA: SignedData}


# Password-protected keys: PKCS#8 EncryptedPrivateKeyInfo with PBES2 (RFC 8018), PKCS#12 (RFC 7292)

ID_ENCRYPTED_DATA = "1.2.840.113549.1.7.6"
KEY_BAG = "1.2.840.113549.1.12.10.1.1"
SHROUDED_KEY_BAG = "1.2.840.113549.1.12.10.1.2"
CERT_BAG = "1.2.840.113549.1.12.10.1.3"
SAFE_CONTENTS_BAG = "1.2.840.113549.1.12.10.1.6"
X509_CERTIFICATE = "1.2.840.113549.1.9.22.1"
JKS_KEY_PROTECTOR = "1.3.6.1.4.1.42.2.17.1.1"


class EncryptedPrivateKeyInfo(core.Sequence):
    _fields = [("encryption_algorithm", AlgorithmIdentifier), ("encrypted_data", core.OctetString)]


class Pbes2Params(core.Sequence):
    _fields = [
        ("key_derivation_func", AlgorithmIdentifier),
        ("encryption_scheme", AlgorithmIdentifier),
    ]


class Pbkdf2Params(core.Sequence):
    _fields = [
        ("salt", core.OctetString),
        ("iteration_count", core.Integer),
        ("key_length", core.Integer, {"optional": True}),
        ("prf", AlgorithmIdentifier, {"optional": True}),
    ]


class Gost28147Params(core.Sequence):
    _fields = [("iv", core.OctetString), ("dke", core.OctetString, {"optional": True})]


class SafeBag(core.Sequence):
    _fields = [
        ("bag_id", core.ObjectIdentifier),
        ("bag_value", core.Any, {"explicit": 0}),
        ("bag_attributes", Attributes, {"optional": True}),
    ]


class SafeContents(core.SequenceOf):
    _child_spec = SafeBag


class CertBag(core.Sequence):
    _fields = [
        ("cert_id", core.ObjectIdentifier),
        ("cert_value", core.OctetString, {"explicit": 0}),
    ]


class EncryptedContentInfo(core.Sequence):
    _fields = [
        ("content_type", core.ObjectIdentifier),
        ("content_encryption_algorithm", AlgorithmIdentifier),
        ("encrypted_content", core.OctetString, {"implicit": 0, "optional": True}),
    ]


class EncryptedData(core.Sequence):
    _fields = [("version", core.Integer), ("encrypted_content_info", EncryptedContentInfo)]


class AuthenticatedSafe(core.SequenceOf):
    _child_spec = ContentInfo


class Pfx(core.Sequence):
    _fields = [
        ("version", core.Integer),
        ("auth_safe", ContentInfo),
        ("mac_data", core.Any, {"optional": True}),
    ]


class GeneralNames(core.SequenceOf):
    _child_spec = x509.GeneralName


class IssuerSerial(core.Sequence):
    _fields = [("issuer", GeneralNames), ("serial_number", core.Integer)]


class ESSCertIDv2(core.Sequence):
    """RFC 5035; the hash algorithm is always written, as SHA-256 is never used here."""

    _fields = [
        ("hash_algorithm", AlgorithmIdentifier, {"optional": True}),
        ("cert_hash", core.OctetString),
        ("issuer_serial", IssuerSerial, {"optional": True}),
    ]


class ESSCertIDsV2(core.SequenceOf):
    _child_spec = ESSCertIDv2


class SigningCertificateV2(core.Sequence):
    _fields = [("certs", ESSCertIDsV2), ("policies", core.Any, {"optional": True})]


class TimeStampResp(core.Sequence):
    """RFC 3161 TimeStampResp with the token kept raw: it is CMS signed data with ДСТУ keys."""

    _fields = [
        ("status", tsp.PKIStatusInfo),
        ("time_stamp_token", core.Any, {"optional": True}),
    ]


def curve_from_spec(spec: CurveSpec, *, little_endian: bool = True) -> Curve:
    """The curve a parameter block names or spells out."""
    if spec.name == "named":
        oid = spec.chosen.dotted
        name = CURVE_OIDS.get(oid)
        if name is None:
            raise UnsupportedError(f"unknown curve OID {oid}")
        if name not in NAMED_CURVES:
            raise UnsupportedError(f"curve {name} is not bundled with uakep")
        return NAMED_CURVES[name]
    ec = spec.chosen
    poly = ec["field"]["poly"]
    if poly.name == "trinomial":
        ks: tuple[int, ...] = (poly.chosen.native,)
    else:
        p = poly.chosen
        ks = (p["k"].native, p["j"].native, p["l"].native)
    order = "little" if little_endian else "big"
    curve = Curve.from_params(
        ec["field"]["m"].native,
        ks,
        ec["a"].native,
        int.from_bytes(ec["b"].native, order),
        ec["n"].native,
        int.from_bytes(ec["bp"].native, order),
    )
    for named in NAMED_CURVES.values():
        if named == curve:
            return named
    return curve
