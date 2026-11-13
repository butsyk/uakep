"""Layer 7: certificates.

Ground truth: real certificates in the tax service's samples and ЦЗО's test examples. Their
subjectKeyIdentifier is the CA's ГОСТ 34.311 hash of the public key, and ЦЗО's test root and CA
certificates (inside the CAdES-X Long-Full example) carry real ДСТУ 4145 signatures over the
whole chain, on both the 257-bit and 431-bit curves.
"""

import base64
from datetime import UTC, datetime

import pytest
from asn1crypto import core

from uakep import asn1
from uakep.asn1 import UnsupportedError
from uakep.certificate import Certificate, CertificateError
from uakep.curve import DSTU_PB_257, DSTU_PB_431
from uakep.gost28147 import DEFAULT_SBOX, pack_sbox
from uakep.gost34311 import gost34311

from .conftest import data_file


def _signed_data(*path):
    return asn1.ContentInfo.load(data_file(*path))["content"]


def _gost_key_id(cert: Certificate) -> bytes:
    pub = cert.public_key
    raw = pub.compressed().to_bytes((pub.curve.m + 7) // 8, "little")
    return gost34311(core.OctetString(raw).dump())


@pytest.fixture(scope="module")
def tax_signer():
    return Certificate(_signed_data("tax", "receipt.xml.signed")["certificates"][0].dump())


@pytest.fixture(scope="module")
def tax_tsa():
    sd = _signed_data("tax", "receipt.xml.signed")
    token = sd["signer_infos"][0]["unsigned_attrs"][0]["values"][0]
    return Certificate(asn1.ContentInfo.load(token.dump())["content"]["certificates"][0].dump())


@pytest.fixture(scope="module")
def czo_chain():
    """(signer, CA, root) from ЦЗО's CAdES-X Long-Full example."""
    sd = _signed_data("czo", "DSTU_CAdES-X_Long-Full.p7s")
    signer = Certificate(sd["certificates"][0].dump())
    values = next(
        a["values"][0]
        for a in sd["signer_infos"][0]["unsigned_attrs"]
        if a["type"].dotted == "1.2.840.113549.1.9.16.2.23"  # certificateValues
    )
    ca, root = (Certificate(c.dump()) for c in core.SequenceOf.load(values.dump(), spec=core.Any))
    return signer, ca, root


def test_tax_signer_certificate(tax_signer):
    c = tax_signer
    assert c.owner_name == "Симоненко Валентина Андреевна"
    assert c.drfo == "1089999992"
    assert c.edrpou == "10899999"
    assert c.subject["title"] == "Головний бухгалтер"
    assert c.issuer["common_name"] == 'АЦСК ТОВ "Центр сертифікації ключів "Україна"'
    assert c.serial_number == 0x52DB1D0700000000000000000000000000000001
    assert c.not_before == datetime(2019, 12, 19, 10, 15, 55, tzinfo=UTC)
    assert c.not_after == datetime(2021, 12, 18, 21, 59, 59, tzinfo=UTC)
    assert c.is_valid_at(datetime(2020, 7, 21, tzinfo=UTC))
    assert not c.is_valid_at(datetime(2026, 1, 1, tzinfo=UTC))
    assert c.key_usage == {"digital_signature", "non_repudiation"} and c.can_sign
    assert c.extended_key_usage == {"1.2.804.2.1.1.1.11.36865753.2"}
    assert c.tsp_url == "http://uakey.com.ua/services/tsp/"
    assert c.ocsp_url == "http://uakey.com.ua/services/ocsp/"
    assert c.public_key_algorithm == asn1.DSTU4145_LE
    assert c.signature_algorithm == asn1.DSTU4145_LE
    assert c.public_key.curve is DSTU_PB_257
    assert c.dke is None
    assert c.authority_key_identifier.hex().startswith("94c65777724dab0c")
    # The CA computed this identifier from the key; uakep must decode the same key.
    assert c.subject_key_identifier == _gost_key_id(c)
    assert (
        c.subject_key_identifier.hex()
        == "49e704cb0cac46f4f9ab4d8d1ec3c62ae9010a0cce07d7d5eeee06daed0de862"
    )


def test_tsa_certificate_with_explicit_curve_and_dke(tax_tsa):
    assert tax_tsa.public_key.curve is DSTU_PB_257  # explicit parameters, recognised
    assert tax_tsa.dke == pack_sbox(DEFAULT_SBOX)
    assert tax_tsa.extended_key_usage == {"1.3.6.1.5.5.7.3.8"}  # id-kp-timeStamping
    assert tax_tsa.subject_key_identifier == _gost_key_id(tax_tsa)
    assert tax_tsa.drfo is None and tax_tsa.edrpou is None


@pytest.mark.parametrize(
    ("name", "curve", "usage"),
    [
        ("DSTU_sign.cer", DSTU_PB_257, {"digital_signature", "non_repudiation"}),
        ("DSTU_encryption.cer", DSTU_PB_431, {"key_agreement"}),
    ],
)
def test_czo_owner_certificates(name, curve, usage):
    c = Certificate.load(data_file("czo", name))
    assert c.owner_name == "ТЕСТ Тестовий Тест Тестович"
    assert c.public_key.curve is curve
    assert c.key_usage == usage
    assert c.can_sign == ("digital_signature" in usage)
    assert c.tsp_url == "http://ca-test.czo.gov.ua/services/tsp/"
    assert c.subject_key_identifier == _gost_key_id(c)
    assert c.drfo is None and c.edrpou is None


def test_certificate_chain_signatures(czo_chain):
    signer, ca, root = czo_chain
    assert ca.owner_name == "Адміністратор ІТС ЦЗО (CA TEST)"
    assert root.owner_name == "Центральний засвідчувальний орган (ROOT TEST)"
    assert (ca.public_key.curve, root.public_key.curve) == (DSTU_PB_257, DSTU_PB_431)
    assert signer.authority_key_identifier == ca.subject_key_identifier
    assert ca.authority_key_identifier == root.subject_key_identifier

    def signed_by(cert, issuer):
        return issuer.public_key.verify(gost34311(cert.tbs_der), cert.signature)

    assert signed_by(signer, ca)
    assert signed_by(ca, root)
    assert signed_by(root, root)  # self-signed, 431-bit curve
    assert not signed_by(signer, root)
    tampered = bytearray(signer.tbs_der)
    tampered[-40] ^= 1
    assert not ca.public_key.verify(gost34311(bytes(tampered)), signer.signature)


def test_load_der_pem_and_base64():
    der = data_file("czo", "DSTU_sign.cer")
    b64 = base64.b64encode(der)
    pem = b"-----BEGIN CERTIFICATE-----\n" + b64 + b"\n-----END CERTIFICATE-----\n"
    assert Certificate.load(der) == Certificate.load(pem) == Certificate.load(b64)
    assert Certificate.load(b"  " + b64[:40] + b"\r\n" + b64[40:] + b"\n") == Certificate.load(der)
    # ЦЗО serves its current ДСТУ 7564 certificates as bare base64
    kupyna = Certificate.load(data_file("czo", "DSTU-7564_sign.cer"))
    assert kupyna.signature_algorithm == asn1.DSTU4145_KUPYNA
    assert kupyna.owner_name == "TEST TEST Testov Test"
    assert hash(kupyna) == hash(Certificate.load(data_file("czo", "DSTU-7564_sign.cer")))
    assert kupyna != Certificate.load(der) and kupyna != "certificate"


@pytest.mark.parametrize("data", [b"", b"not a certificate!", b"\x30\x03\x02\x01\x00", b"%%%%"])
def test_rejects_garbage(data):
    with pytest.raises(CertificateError):
        Certificate.load(data)


def _edited(der: bytes, edit) -> bytes:
    cert = asn1.Certificate.load(der)
    edit(cert["tbs_certificate"])
    cert["tbs_certificate"] = asn1.TbsCertificate.load(cert["tbs_certificate"].dump())
    return asn1.Certificate(
        {k: cert[k] for k in ("tbs_certificate", "signature_algorithm", "signature_value")}
    ).dump()


def test_certificate_without_extensions():
    def drop(tbs):
        tbs["extensions"] = None

    c = Certificate(_edited(data_file("czo", "DSTU_sign.cer"), drop))
    assert c.key_usage == frozenset() and not c.can_sign
    assert c.extended_key_usage == frozenset()
    assert c.subject_key_identifier is None and c.authority_key_identifier is None
    assert c.tsp_url is None and c.ocsp_url is None
    assert c.drfo is None and c.edrpou is None


def test_tax_numbers_from_the_subject():
    """Newer profiles carry РНОКПП and ЄДРПОУ in the subject (TINUA-/NTRUA- prefixes)."""
    from asn1crypto import x509

    def rename(tbs):
        tbs["subject"] = x509.Name.build(
            {
                "common_name": "Тест",
                "serial_number": "TINUA-1234567890",
                "organization_identifier": "NTRUA-12345678",
            }
        )

    c = Certificate(_edited(data_file("czo", "DSTU_sign.cer"), rename))
    assert (c.drfo, c.edrpou) == ("1234567890", "12345678")
    assert repr(c).startswith("Certificate(owner='Тест', serial=")


def test_non_dstu_key_is_unsupported():
    def ecdsa(tbs):
        tbs["subject_public_key_info"]["algorithm"]["algorithm"] = "1.2.840.10045.2.1"

    c = Certificate(_edited(data_file("czo", "DSTU_sign.cer"), ecdsa))
    with pytest.raises(UnsupportedError):
        c.public_key  # noqa: B018
    with pytest.raises(UnsupportedError):
        c.dke  # noqa: B018


def test_issuer_der_is_the_issuers_subject_bytes(czo_chain):
    signer, ca, _ = czo_chain
    assert signer.issuer_der == asn1.Certificate.load(ca.der)["tbs_certificate"]["subject"].dump()


class _PlainExtension(core.Sequence):
    _fields = [("extn_id", core.ObjectIdentifier), ("extn_value", core.OctetString)]  # noqa: RUF012


def _with_extension(tbs, oid: str, value: bytes) -> None:
    from asn1crypto import x509

    added = x509.Extension.load(_PlainExtension({"extn_id": oid, "extn_value": value}).dump())
    kept = [e for e in tbs["extensions"] if e["extn_id"].dotted != oid]
    tbs["extensions"] = x509.Extensions([*kept, added])


def test_info_access_without_the_wanted_method():
    from asn1crypto import x509

    repository = asn1.InfoAccess(
        [
            {
                "access_method": "1.3.6.1.5.5.7.48.5",  # caRepository
                "access_location": x509.GeneralName(
                    name="uniform_resource_identifier", value="http://example.com/"
                ),
            }
        ]
    ).dump()

    def edit(tbs):
        _with_extension(tbs, "1.3.6.1.5.5.7.1.11", repository)

    c = Certificate(_edited(data_file("czo", "DSTU_sign.cer"), edit))
    assert c.tsp_url is None


def test_directory_attributes_skip_empty_values():
    attrs = asn1.DirectoryAttributes(
        [
            {"type": "1.2.804.2.1.1.1.11.1.4.2.1", "values": []},
            {"type": "1.2.804.2.1.1.1.11.1.4.7.1", "values": [core.PrintableString("2222222222")]},
        ]
    ).dump()

    def edit(tbs):
        _with_extension(tbs, "2.5.29.9", attrs)

    c = Certificate(_edited(data_file("czo", "DSTU_sign.cer"), edit))
    assert c.drfo == "2222222222"  # the second РНОКПП OID
    assert c.edrpou is None
