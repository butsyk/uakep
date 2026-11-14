"""Layer 12: signature time-stamps in CAdES, checked and added.

Ground truth: the receipt and Z-report samples carry real tokens with their TSA's certificate,
and ЦЗО's X_Long-Full examples carry tokens in both families with theirs. The builder must
rebuild the receipt and Z-report samples byte for byte, token included.
"""

import asyncio
from datetime import UTC, datetime

import pytest
from asn1crypto import core, x509
from asn1crypto import tsp as tsp_asn1

from uakep import asn1, cades, tsp
from uakep.asn1 import UnsupportedError
from uakep.cades import SignatureError, SigningKey
from uakep.certificate import Certificate
from uakep.curve import DSTU_PB_257
from uakep.dstu4145 import PrivateKey
from uakep.gost34311 import gost34311
from uakep.kupyna import kupyna256
from uakep.tsp import TimeStamp, TimeStampError

from .conftest import (
    SAMPLE_STAMP_TIME,
    TEST_TSA_POLICY,
    LocalTsa,
    certificate_for,
    data_file,
    timestamp_response,
    tst_info,
)

KEY = PrivateKey(DSTU_PB_257, 0x2A45EAFE4CD469F811737780C57253360FBCC58E134C9A1FDCD10B0E4529A143)
CERT = certificate_for(KEY)  # names ЦЗО's test TSA in subjectInfoAccess
TSA_KEY = PrivateKey(
    DSTU_PB_257, 0x5D1C0A7B3E29F4686C10B8E6F3A2D4C1B0E9F8A7D6C5B4A39281706F5E4D3C2B
)
CZO_TSA_URL = "http://ca-test.czo.gov.ua/services/tsp/"
UKRAINE_TSA = 'TSP-сервер АЦСК ТОВ "Центр сертифікації ключів "Україна"'
CZO_TSA = "TSP-сервер Адміністратора ІТС ЦЗО (CA TEST)"


def _sample(name: str):
    """(content, certificate, signature value, token) of a tax sample."""
    sd = asn1.ContentInfo.load(data_file("tax", name))["content"]
    signer_info = sd["signer_infos"][0]
    return (
        sd["encap_content_info"]["content"].native,
        Certificate(sd["certificates"][0].dump()),
        signer_info["signature"].native,
        signer_info["unsigned_attrs"][0]["values"][0].dump(),
    )


def _signature(signed: bytes) -> bytes:
    return asn1.ContentInfo.load(signed)["content"]["signer_infos"][0]["signature"].native


SIGNING = cades._Signing(b"content", CERT, KEY.sign)


def _with_tokens(*tokens: bytes) -> bytes:
    """CAdES over b"content" by KEY, carrying ``tokens`` as signature time-stamps."""
    attrs = b"".join(cades.timestamp_attribute(token) for token in tokens)
    return SIGNING._assemble(cades._der(0xA1, attrs))


# -- the official samples ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "when", "serial"),
    [
        ("receipt.xml.signed", datetime(2020, 7, 21, 7, 37, 28, tzinfo=UTC), 0xCC173A26),
        ("zreport.xml.signed", datetime(2020, 7, 21, 7, 44, 1, tzinfo=UTC), 0xC6643A26),
    ],
)
def test_tax_samples_carry_a_checked_timestamp(name, when, serial):
    stamp = cades.verify(data_file("tax", name)).timestamp
    assert stamp.time == when
    assert stamp.serial_number == serial
    assert stamp.policy == "1.3.6.1.5.5.7.3.8"
    assert stamp.digest_algorithm == asn1.GOST34311
    assert stamp.certificate.owner_name == UKRAINE_TSA


def test_json_sample_has_no_timestamp():
    assert cades.verify(data_file("tax", "state-request.json.signed")).timestamp is None


@pytest.mark.parametrize(
    ("name", "when", "digest"),
    [
        ("DSTU_CAdES-X_Long-Full.p7s", datetime(2024, 3, 4, 8, 20, 41, tzinfo=UTC), asn1.GOST34311),
        (
            "DSTU-7564_CAdES-X_Long-Full.p7s",
            datetime(2024, 3, 4, 9, 57, 42, tzinfo=UTC),
            cades.KUPYNA_256,
        ),
    ],
)
def test_czo_tokens_with_their_tsa_certificate(name, when, digest):
    stamp = cades.verify(data_file("czo", name)).timestamp
    assert (stamp.time, stamp.digest_algorithm) == (when, digest)
    assert stamp.certificate.owner_name == CZO_TSA


@pytest.mark.parametrize(
    "name",
    [f"{alg}_CAdES-{fmt}.p7s" for alg in ("DSTU", "DSTU-7564") for fmt in ("T", "C", "X_Long")],
)
def test_czo_tokens_without_their_tsa_certificate_are_not_reported(name):
    assert cades.verify(data_file("czo", name)).timestamp is None


@pytest.mark.parametrize("name", ["receipt.xml.signed", "zreport.xml.signed"])
def test_tax_samples_rebuilt_byte_for_byte_with_their_tokens(name):
    content, cert, signature, token = _sample(name)
    signing = cades._Signing(content, cert, lambda _digest: signature)
    url, request = signing.timestamp_request()
    assert url == "http://uakey.com.ua/services/tsp/" == cert.tsp_url
    assert request == tsp.request(asn1.GOST34311, gost34311(signature))
    assert signing.signed_data(timestamp_response(token)) == data_file("tax", name)


def test_check_timestamp_on_a_sample_token():
    _, _, signature, token = _sample("receipt.xml.signed")
    stamp = cades.check_timestamp(token, signature)
    assert stamp == cades.verify(data_file("tax", "receipt.xml.signed")).timestamp
    with pytest.raises(TimeStampError, match=r"^the time-stamp is for other data$"):
        cades.check_timestamp(token, signature[:-1])


# -- signing with a time-stamp -----------------------------------------------------------


def test_sign_with_a_timestamp():
    tsa = LocalTsa(TSA_KEY)
    signed = cades.sign(b"<CHECK/>", SigningKey(KEY, CERT), timestamp=tsa)
    signature = _signature(signed)
    assert tsa.requests == [(CZO_TSA_URL, tsp.request(asn1.GOST34311, gost34311(signature)))]
    result = cades.verify(signed)
    assert result.content == b"<CHECK/>"
    assert result.timestamp == TimeStamp(
        SAMPLE_STAMP_TIME, 1, TEST_TSA_POLICY, asn1.GOST34311, tsa.certificate
    )


def test_sign_async_with_a_timestamp():
    tsa = LocalTsa(TSA_KEY)

    async def post(url, request):
        await asyncio.sleep(0)
        return tsa(url, request)

    signed = asyncio.run(cades.sign_async(b"<ZREP/>", SigningKey(KEY, CERT), timestamp=post))
    assert len(tsa.requests) == 1
    assert cades.verify(signed).timestamp.certificate == tsa.certificate
    unstamped = asyncio.run(cades.sign_async(b"<ZREP/>", SigningKey(KEY, CERT)))
    assert cades.verify(unstamped).timestamp is None


def test_offline_documents_get_no_timestamp():
    signed = cades.sign(b"<CHECK/>", SigningKey(KEY, CERT))
    signer_info = asn1.ContentInfo.load(signed)["content"]["signer_infos"][0]
    assert isinstance(signer_info["unsigned_attrs"], core.Void)
    assert cades.verify(signed).timestamp is None


def test_kupyna_family_signature_gets_a_kupyna_timestamp():
    cert = certificate_for(KEY, "DSTU-7564_sign.cer")
    tsa = LocalTsa(TSA_KEY)
    signed = cades.sign(b"data", SigningKey(KEY, cert), timestamp=tsa)
    expected = tsp.request(cades.KUPYNA_256, kupyna256(_signature(signed)))
    assert tsa.requests == [(cert.tsp_url, expected)]
    assert cades.verify(signed).timestamp.digest_algorithm == cades.KUPYNA_256


def _without_extension(cert: Certificate, oid: str) -> Certificate:
    parsed = asn1.Certificate.load(cert.der)
    tbs = parsed["tbs_certificate"]
    tbs["extensions"] = x509.Extensions(
        [e for e in tbs["extensions"] if e["extn_id"].dotted != oid]
    )
    fields = ("tbs_certificate", "signature_algorithm", "signature_value")
    return Certificate(asn1.Certificate({k: parsed[k] for k in fields}).dump())


def test_no_timestamp_without_a_tsa_in_the_certificate():
    cert = _without_extension(CERT, "1.3.6.1.5.5.7.1.11")
    tsa = LocalTsa(TSA_KEY)
    with pytest.raises(TimeStampError, match="names no time-stamping service"):
        cades.sign(b"x", SigningKey(KEY, cert), timestamp=tsa)
    assert tsa.requests == []


def test_signing_fails_when_the_tsa_refuses():
    with pytest.raises(TimeStampError, match="refused the request: rejection"):
        cades.sign(
            b"x", SigningKey(KEY, CERT), timestamp=lambda *_: timestamp_response(None, "rejection")
        )


def test_signing_checks_the_tsa_token():
    tsa = LocalTsa(TSA_KEY)
    other = timestamp_response(tsa.stamp(asn1.GOST34311, b"another signature"))
    with pytest.raises(TimeStampError, match="for other data"):
        cades.sign(b"x", SigningKey(KEY, CERT), timestamp=lambda *_: other)

    deaf = LocalTsa(TSA_KEY, attach_certificate=False)  # ignores certReq
    with pytest.raises(TimeStampError, match="certificate is not in the token"):
        cades.sign(b"x", SigningKey(KEY, CERT), timestamp=deaf)
    assert len(deaf.requests) == 1


# -- token checks ------------------------------------------------------------------------


def test_token_failures():
    tsa = LocalTsa(TSA_KEY)
    data = b"signature value"
    good_tst = tst_info(asn1.GOST34311, gost34311(data))

    def check(token, **options):
        return cades.check_timestamp(token, data, **options)

    assert check(tsa.token(good_tst)).certificate == tsa.certificate
    with pytest.raises(TimeStampError, match=r"^cannot read the token"):
        check(b"")
    data_info = asn1.ContentInfo({"content_type": asn1.ID_DATA, "content": core.OctetString(b"x")})
    with pytest.raises(TimeStampError, match=r"^the token is not signed data$"):
        check(data_info.dump())
    with pytest.raises(TimeStampError, match="holds no TSTInfo"):
        check(tsa.token(good_tst, content_type=asn1.ID_DATA))
    with pytest.raises(TimeStampError, match="holds no TSTInfo"):
        check(tsa.token(good_tst, econtent=False))
    sha256 = tst_info("2.16.840.1.101.3.4.2.1", b"\x00" * 32)
    with pytest.raises(UnsupportedError, match=r"time-stamp digest algorithm 2.16.840"):
        check(tsa.token(sha256))
    with pytest.raises(TimeStampError, match=r"^the time-stamp is for other data$"):
        check(tsa.token(tst_info(asn1.GOST34311, gost34311(b"other"))))

    no_cert = tsa.token(good_tst, attach_certificate=False)
    with pytest.raises(TimeStampError, match="certificate is not in the token"):
        check(no_cert)
    assert check(no_cert, require_certificate=False) is None
    assert check(tsa.token(good_tst), require_certificate=False) is not None

    impostor = LocalTsa(PrivateKey(DSTU_PB_257, 31337), certificate=tsa.certificate)
    with pytest.raises(TimeStampError, match=r"^the TSA's signature: the signature does not match"):
        check(impostor.token(good_tst))

    not_a_tsa = LocalTsa(TSA_KEY, certificate=certificate_for(TSA_KEY))
    with pytest.raises(TimeStampError, match="not a time-stamping authority"):
        check(
            not_a_tsa.token(
                tst_info(asn1.GOST34311, gost34311(data), when=datetime(2025, 1, 1, tzinfo=UTC))
            )
        )

    for when in (
        datetime(2017, 11, 1, 14, 48, tzinfo=UTC),
        datetime(2022, 11, 1, 14, 50, tzinfo=UTC),
    ):
        with pytest.raises(TimeStampError, match="not valid at the stamped time"):
            check(tsa.token(tst_info(asn1.GOST34311, gost34311(data), when=when)))


def test_malformed_tokens_are_timestamp_errors():
    """What a token holds is parsed late too; it must surface as a TimeStampError."""
    tsa = LocalTsa(TSA_KEY)
    signature = SIGNING.signature
    imprint = gost34311(signature)

    # genTime without a time zone cannot be compared with the certificate's validity
    local_time = tsp_asn1.TSTInfo(
        {
            "version": "v1",
            "policy": TEST_TSA_POLICY,
            "message_imprint": {
                "hash_algorithm": {"algorithm": asn1.GOST34311},
                "hashed_message": imprint,
            },
            "serial_number": 1,
            "gen_time": core.GeneralizedTime.load(b"\x18\x0e20200721073728"),
        }
    ).dump()
    with pytest.raises(TimeStampError, match=r"^cannot read the token: can't compare"):
        cades.check_timestamp(tsa.token(local_time), signature)

    # a messageDigest attribute holding an INTEGER where the hash should be
    good = tsa.stamp(asn1.GOST34311, signature)
    digest_value = core.OctetString(gost34311(tst_info(asn1.GOST34311, imprint))).dump()
    assert good.count(digest_value) == 1
    bad = good.replace(digest_value, b"\x02" + digest_value[1:])
    with pytest.raises(TimeStampError, match=r"^the TSA's signature: cannot read the signed data"):
        cades.check_timestamp(bad, signature)
    with pytest.raises(SignatureError, match=r"^the signature time-stamp does not check out: "):
        cades.verify(_with_tokens(bad))


# -- time-stamps found by verify() -------------------------------------------------------


def test_verify_rejects_a_timestamp_that_does_not_check_out():
    tsa = LocalTsa(TSA_KEY)
    with pytest.raises(
        SignatureError, match="signature time-stamp does not check out: the time-stamp is for other"
    ):
        cades.verify(_with_tokens(tsa.stamp(asn1.GOST34311, b"something else")))


def test_verify_reports_the_earliest_checked_timestamp():
    signature = SIGNING.signature
    later = LocalTsa(TSA_KEY, when=datetime(2021, 5, 5, tzinfo=UTC))
    earlier = LocalTsa(TSA_KEY, when=datetime(2020, 1, 1, tzinfo=UTC))
    unchecked = earlier.stamp(asn1.GOST34311, signature, attach_certificate=False)
    signed = _with_tokens(
        later.stamp(asn1.GOST34311, signature),
        unchecked,
        earlier.stamp(asn1.GOST34311, signature),
    )
    assert cades.verify(signed).timestamp.time == datetime(2020, 1, 1, tzinfo=UTC)
    assert cades.verify(_with_tokens(unchecked)).timestamp is None


def test_time_stamps_inside_a_token_are_not_followed():
    tsa = LocalTsa(TSA_KEY)
    signature = SIGNING.signature
    junk = cades._der(0xA1, cades.timestamp_attribute(b"\x30\x00"))
    token = tsa.stamp(asn1.GOST34311, signature, unsigned_attrs=junk)
    assert cades.verify(_with_tokens(token)).timestamp is not None
