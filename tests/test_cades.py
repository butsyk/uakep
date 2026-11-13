"""Layers 8 and 9: CAdES signed data, built and verified.

Ground truth: the tax service's signed samples and ЦЗО's CAdES examples must verify; the
builder must rebuild the tax service's signed JSON sample byte for byte from its content,
certificate and signature value, and its signed attributes for the receipt and Z-report.
"""

from datetime import UTC, datetime

import pytest
from asn1crypto import core, x509

from uakep import asn1, cades
from uakep.asn1 import UnsupportedError
from uakep.cades import SignatureError, SigningKey, Verified
from uakep.certificate import Certificate
from uakep.curve import DSTU_PB_257
from uakep.dstu4145 import PrivateKey
from uakep.gost34311 import gost34311

from .conftest import certificate_for, data_file

TAX = ["receipt.xml.signed", "zreport.xml.signed", "state-request.json.signed"]
CZO_ENVELOPED = [
    f"{alg}_CAdES-{fmt}.p7s"
    for alg in ("DSTU", "DSTU-7564")
    for fmt in ("BES", "T", "C", "X_Long", "X_Long-Full")
]
KEY = PrivateKey(DSTU_PB_257, 0x2A45EAFE4CD469F811737780C57253360FBCC58E134C9A1FDCD10B0E4529A143)
CERT = certificate_for(KEY)
SID = cades._der(0xA0, core.OctetString(CERT.subject_key_identifier).dump())


def _parts(name: str):
    sd = asn1.ContentInfo.load(data_file("tax", name))["content"]
    return (
        sd["encap_content_info"]["content"].native,
        Certificate(sd["certificates"][0].dump()),
        sd["signer_infos"][0],
    )


def _signer_info(
    attrs: bytes | None, *, sid=SID, digest=asn1.GOST34311, signature=asn1.DSTU4145_LE
):
    message = attrs if attrs is not None else b"content"
    return cades._seq(
        core.Integer(1).dump(),
        sid,
        cades._algorithm(digest),
        b"" if attrs is None else b"\xa0" + attrs[1:],
        cades._algorithm(signature),
        core.OctetString(KEY.sign(gost34311(message))).dump(),
    )


def _signed_data(signer_infos: bytes, certificates: bytes = CERT.der, content: bytes = b"content"):
    sd = cades._seq(
        core.Integer(1).dump(),
        cades._der(0x31, cades._algorithm(asn1.GOST34311)),
        cades._seq(
            core.ObjectIdentifier(asn1.ID_DATA).dump(),
            cades._der(0xA0, core.OctetString(content).dump()),
        ),
        cades._der(0xA0, certificates),
        cades._der(0x31, signer_infos),
    )
    return cades._seq(core.ObjectIdentifier(asn1.ID_SIGNED_DATA).dump(), cades._der(0xA0, sd))


def _attrs(*items) -> bytes:
    return cades._der(0x31, b"".join(cades._attribute(oid, value) for oid, value in items))


DIGEST_ATTR = (asn1.ID_MESSAGE_DIGEST, core.OctetString(gost34311(b"content")))


# -- the official samples ----------------------------------------------------------------


@pytest.mark.parametrize("name", TAX)
def test_tax_samples_verify(name):
    result = cades.verify(data_file("tax", name))
    assert result.certificate.owner_name == "Симоненко Валентина Андреевна"
    assert result.digest_algorithm == asn1.GOST34311
    assert result.signing_time is None  # the samples carry no signingTime
    start = b"<?xml" if name.endswith(".xml.signed") else b'{"NumFiscal"'
    assert result.content.startswith(start)


@pytest.mark.parametrize("name", CZO_ENVELOPED)
def test_czo_examples_verify(name):
    result = cades.verify(data_file("czo", name))
    assert result.content == b"Test\r\n"
    assert result.certificate.owner_name == "ТЕСТ Тестовий Тест Тестович"
    expected = cades.KUPYNA_256 if name.startswith("DSTU-7564") else asn1.GOST34311
    assert result.digest_algorithm == expected
    assert result.signing_time.year == 2024


def test_czo_detached_example():
    signed = data_file("czo", "DSTU_CAdES-BES_detached.p7s")
    result = cades.verify(signed, detached_content=data_file("czo", "test.txt"))
    assert result.content == b"Test\r\n"
    with pytest.raises(SignatureError, match="not attached"):
        cades.verify(signed)
    with pytest.raises(SignatureError, match="messageDigest"):
        cades.verify(signed, detached_content=b"Test\n")


def test_json_sample_rebuilt_byte_for_byte():
    content, cert, signer_info = _parts("state-request.json.signed")
    signature = signer_info["signature"].native
    rebuilt = cades.build_signed_data(content, cert, lambda _digest: signature)
    assert rebuilt == data_file("tax", "state-request.json.signed")


@pytest.mark.parametrize("name", TAX)
def test_signed_attributes_match_the_samples(name):
    content, cert, signer_info = _parts(name)
    sample = signer_info["signed_attrs"].dump()
    assert cades.signed_attributes(content, cert) == b"\x31" + sample[1:]


# -- signing ---------------------------------------------------------------------------


def test_sign_and_verify_round_trip():
    key = SigningKey(KEY, CERT)
    signed = cades.sign(b"<CHECK/>", key)
    result = cades.verify(signed)
    assert isinstance(result, Verified)
    assert result.content == b"<CHECK/>"
    assert result.certificate == CERT
    assert result.digest_algorithm == asn1.GOST34311
    # The samples' layout: rebuilding with this signature value gives the same bytes.
    signature = asn1.ContentInfo.load(signed)["content"]["signer_infos"][0]["signature"].native
    assert cades.build_signed_data(b"<CHECK/>", CERT, lambda _d: signature) == signed


def test_kupyna_family_certificate_signs_kupyna():
    key = SigningKey(KEY, certificate_for(KEY, "DSTU-7564_sign.cer"))
    assert cades.verify(cades.sign(b"data", key)).digest_algorithm == cades.KUPYNA_256


def test_signing_key_must_match_its_certificate():
    with pytest.raises(ValueError, match="not issued for this private key"):
        SigningKey(KEY, certificate_for(PrivateKey(DSTU_PB_257, 777)))


def test_certificate_without_key_id_cannot_sign():
    cert = asn1.Certificate.load(CERT.der)
    tbs = cert["tbs_certificate"]
    tbs["extensions"] = x509.Extensions(
        [e for e in tbs["extensions"] if e["extn_id"].dotted != "2.5.29.14"]
    )
    fields = ("tbs_certificate", "signature_algorithm", "signature_value")
    no_ski = Certificate(asn1.Certificate({k: cert[k] for k in fields}).dump())
    with pytest.raises(ValueError, match="subjectKeyIdentifier"):
        cades.build_signed_data(b"x", no_ski, KEY.sign)


# -- verification failures -------------------------------------------------------------


def _flip(data: bytes, needle: bytes) -> bytes:
    i = data.index(needle)
    return data[:i] + bytes([needle[0] ^ 1]) + needle[1:] + data[i + len(needle) :]


def test_tampering_is_detected():
    signed = cades.sign(b"<CHECK>25.00</CHECK>", SigningKey(KEY, CERT))
    with pytest.raises(SignatureError, match="messageDigest"):
        cades.verify(_flip(signed, b"25.00"))
    signature = asn1.ContentInfo.load(signed)["content"]["signer_infos"][0]["signature"].native
    with pytest.raises(SignatureError, match="does not match"):
        cades.verify(_flip(signed, signature[:8]))


def test_wrong_or_missing_certificate():
    other = certificate_for(PrivateKey(DSTU_PB_257, 4242))
    with pytest.raises(SignatureError, match="does not match"):
        cades.verify(cades.build_signed_data(b"x", other, KEY.sign))  # names `other`
    stranger = cades._der(0xA0, core.OctetString(b"\x00" * 32).dump())
    with pytest.raises(SignatureError, match="not in the signed data"):
        cades.verify(_signed_data(_signer_info(_attrs(DIGEST_ATTR), sid=stranger)))


def test_signer_identifier_forms():
    ias = asn1.IssuerAndSerialNumber(
        {
            "issuer": asn1.Certificate.load(CERT.der)["tbs_certificate"]["issuer"],
            "serial_number": CERT.serial_number,
        }
    ).dump()
    implicit = cades._der(0x80, CERT.subject_key_identifier)  # RFC 5652's form
    for sid in (SID, ias, implicit):
        assert cades.verify(_signed_data(_signer_info(_attrs(DIGEST_ATTR), sid=sid))).content
    with pytest.raises(SignatureError, match="unknown signer identifier"):
        cades.verify(_signed_data(_signer_info(_attrs(DIGEST_ATTR), sid=cades._der(0x81, b"\x01"))))


def test_without_signed_attributes_the_content_is_signed():
    assert cades.verify(_signed_data(_signer_info(None))).content == b"content"


def test_attribute_checks():
    def verify(*items):
        return cades.verify(_signed_data(_signer_info(_attrs(*items))))

    with pytest.raises(SignatureError, match="lack messageDigest"):
        verify((asn1.ID_CONTENT_TYPE, core.ObjectIdentifier(asn1.ID_DATA)))
    with pytest.raises(SignatureError, match="contentType"):
        verify(DIGEST_ATTR, (asn1.ID_CONTENT_TYPE, core.ObjectIdentifier("1.2.3")))
    when = x509.Time(name="utc_time", value=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC))
    assert verify(DIGEST_ATTR, (asn1.ID_SIGNING_TIME, when)).signing_time == datetime(
        2026, 1, 2, 3, 4, 5, tzinfo=UTC
    )
    other = certificate_for(PrivateKey(DSTU_PB_257, 99))
    ess_other = asn1.Attributes.load(cades.signed_attributes(b"content", other))[2]["values"][0]
    with pytest.raises(SignatureError, match="another certificate"):
        verify(DIGEST_ATTR, (asn1.ID_SIGNING_CERTIFICATE_V2, ess_other))
    sha256_default = asn1.SigningCertificateV2({"certs": [{"cert_hash": b"\x00" * 32}]})
    with pytest.raises(UnsupportedError, match="signingCertificateV2"):
        verify(DIGEST_ATTR, (asn1.ID_SIGNING_CERTIFICATE_V2, sha256_default))


def test_unsupported_algorithms():
    attrs = _attrs(DIGEST_ATTR)
    with pytest.raises(UnsupportedError, match="digest algorithm"):
        cades.verify(_signed_data(_signer_info(attrs, digest="1.2.804.2.1.1.1.1.2.9")))
    with pytest.raises(UnsupportedError, match="signature algorithm"):
        cades.verify(_signed_data(_signer_info(attrs, signature="1.2.840.10045.4.3.2")))


def test_rejects_what_is_not_exactly_one_signature():
    for garbage in (b"", b"\x30\x03\x02\x01\x00"):
        with pytest.raises(SignatureError, match="cannot read"):
            cades.verify(garbage)
    data_info = asn1.ContentInfo(
        {"content_type": asn1.ID_DATA, "content": core.OctetString(b"x")}
    ).dump()
    with pytest.raises(SignatureError, match="not signed data"):
        cades.verify(data_info)
    one = _signer_info(_attrs(DIGEST_ATTR))
    with pytest.raises(SignatureError, match="exactly one"):
        cades.verify(_signed_data(one + one))


def test_skips_entries_that_are_not_certificates():
    attribute_cert = cades._der(0xA1, b"\x05\x00")  # [1]: an attribute certificate slot
    signed = _signed_data(_signer_info(_attrs(DIGEST_ATTR)), certificates=attribute_cert + CERT.der)
    assert cades.verify(signed).certificate == CERT
