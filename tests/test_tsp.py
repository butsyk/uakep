"""Layer 11: RFC 3161 requests, TSA responses and TSTInfo.

Ground truth: a TSA copies the request's MessageImprint into its token, so the request for a
tax sample's signature must hold exactly the MessageImprint found in that sample's token.
"""

from datetime import UTC, datetime

import pytest
from asn1crypto import core
from asn1crypto import tsp as rfc3161

from uakep import asn1, tsp
from uakep.gost34311 import gost34311
from uakep.tsp import TimeStampError

from .conftest import data_file


def _sample(name: str):
    """(signature value, token, TSTInfo DER) of a tax sample."""
    signer_info = asn1.ContentInfo.load(data_file("tax", name))["content"]["signer_infos"][0]
    token = signer_info["unsigned_attrs"][0]["values"][0].dump()
    tst = asn1.ContentInfo.load(token)["content"]["encap_content_info"]["content"].native
    return signer_info["signature"].native, token, tst


def _response(status: str, token: bytes | None = None, **extra) -> bytes:
    value = {"status": {"status": status, **extra}}
    if token is not None:
        value["time_stamp_token"] = core.Any.load(token)
    return asn1.TimeStampResp(value).dump()


@pytest.mark.parametrize("name", ["receipt.xml.signed", "zreport.xml.signed"])
def test_request_holds_the_imprint_the_tsa_copied(name):
    signature, _, tst = _sample(name)
    request = tsp.request(asn1.GOST34311, gost34311(signature))
    imprint = rfc3161.TSTInfo.load(tst)["message_imprint"].dump()
    assert request == (
        b"\x30\x38"
        + core.Integer(1).dump()
        + imprint
        + b"\x01\x01\xff"  # certReq TRUE; no policy, no nonce
    )


def test_request_fields():
    request = rfc3161.TimeStampReq.load(tsp.request("1.2.804.2.1.1.1.1.2.2.1", b"\x07" * 32))
    assert request["version"].native == "v1"
    imprint = request["message_imprint"]
    assert imprint["hash_algorithm"]["algorithm"].dotted == "1.2.804.2.1.1.1.1.2.2.1"
    assert imprint["hash_algorithm"]["parameters"].native is None
    assert imprint["hashed_message"].native == b"\x07" * 32
    assert request["cert_req"].native is True
    assert request["nonce"].native is None
    assert request["req_policy"].native is None


@pytest.mark.parametrize("status", ["granted", "granted_with_mods"])
def test_granted_response_gives_the_token(status):
    _, token, _ = _sample("receipt.xml.signed")
    assert tsp.token_from_response(_response(status, token)) == token


def test_refused_response():
    refused = _response(
        "rejection",
        status_string=["bad hash", "try again"],
        fail_info={"bad_alg", "bad_request"},
    )
    with pytest.raises(TimeStampError) as info:
        tsp.token_from_response(refused)
    message = str(info.value)
    assert (
        message
        == "the TSA refused the request: rejection (bad hash; try again, bad_alg, bad_request)"
    )
    with pytest.raises(TimeStampError, match=r"refused the request: waiting$"):
        tsp.token_from_response(_response("waiting"))
    with pytest.raises(TimeStampError, match=r"rejection \(system_failure\)$"):
        tsp.token_from_response(_response("rejection", fail_info={"system_failure"}))


def test_granted_without_token():
    with pytest.raises(TimeStampError, match="sent no token"):
        tsp.token_from_response(_response("granted"))


@pytest.mark.parametrize("garbage", [b"", b"<html>Bad Gateway</html>", b"\x30\x03\x02\x01\x00"])
def test_unreadable_response(garbage):
    with pytest.raises(TimeStampError, match="cannot read the TSA's response"):
        tsp.token_from_response(garbage)


def test_read_tst_info_of_the_receipt_sample():
    _, _, tst = _sample("receipt.xml.signed")
    info = tsp.read_tst_info(tst)
    assert info.digest_algorithm == asn1.GOST34311
    assert info.imprint == bytes.fromhex(
        "bfef1f8d3a2ee0d69ba1ff00a882ee713ca4b8bb8fe49efc6b18d2ef53cf6f40"
    )
    assert info.time == datetime(2020, 7, 21, 7, 37, 28, tzinfo=UTC)
    assert info.serial_number == 0xCC173A26
    assert info.policy == "1.3.6.1.5.5.7.3.8"


def test_read_tst_info_rejects_other_versions_and_garbage():
    _, _, tst = _sample("receipt.xml.signed")
    info = rfc3161.TSTInfo.load(tst)
    for version in (0, 2, 3):
        info["version"] = version
        with pytest.raises(TimeStampError, match=f"unknown TSTInfo version v{version}"):
            tsp.read_tst_info(info.dump(force=True))
    with pytest.raises(TimeStampError, match="cannot read the token's TSTInfo"):
        tsp.read_tst_info(b"\x30\x00")
