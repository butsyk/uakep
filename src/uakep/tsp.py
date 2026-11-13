"""RFC 3161 time-stamps: the request to a TSA, its response, and the token's TSTInfo.

No network here: the caller sends the request. A request goes to the TSA as an HTTP POST with
Content-Type ``application/timestamp-query``; the answer is the response body.

Requests follow the tax service's signed samples, whose tokens carry the TSA's certificate and
no nonce: the request asks for the certificate and sends no nonce or policy. A nonce adds
nothing here, as the imprint is the hash of a fresh signature value.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from asn1crypto import core, tsp

from . import asn1
from .certificate import Certificate

REQUEST_CONTENT_TYPE = "application/timestamp-query"
ID_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
_GRANTED = ("granted", "granted_with_mods")


class TimeStampError(ValueError):
    """A time-stamp the TSA refused, or a token that does not check out."""


@dataclass(frozen=True)
class TimeStamp:
    """A checked time-stamp: when the TSA saw the data, and which TSA it was."""

    time: datetime
    serial_number: int
    policy: str
    digest_algorithm: str
    certificate: Certificate


@dataclass(frozen=True)
class TstInfo:
    """The parts of a token's TSTInfo that uakep checks or reports."""

    digest_algorithm: str
    imprint: bytes
    time: datetime
    serial_number: int
    policy: str


def request(digest_algorithm: str, digest: bytes) -> bytes:
    """A DER TimeStampReq for ``digest``, made with ``digest_algorithm`` (an OID)."""
    return tsp.TimeStampReq(
        {
            "version": "v1",
            "message_imprint": {
                "hash_algorithm": {"algorithm": digest_algorithm},  # no parameters
                "hashed_message": bytes(digest),
            },
            "cert_req": True,
        }
    ).dump()


def token_from_response(response: bytes) -> bytes:
    """The token from a TSA's DER TimeStampResp; raise TimeStampError if it was refused."""
    try:
        resp = asn1.TimeStampResp.load(bytes(response))
        info = resp["status"]
        status = info["status"].native
        text = "; ".join(info["status_string"].native or [])
        failures = sorted(info["fail_info"].native or [])
        token = resp["time_stamp_token"]
        token_der = None if isinstance(token, core.Void) else token.dump()
    except (ValueError, TypeError, KeyError) as exc:
        raise TimeStampError(f"cannot read the TSA's response: {exc}") from exc
    if status not in _GRANTED:
        details = ", ".join(str(part) for part in (text, *failures) if part)
        raise TimeStampError(
            f"the TSA refused the request: {status}" + (f" ({details})" if details else "")
        )
    if token_der is None:
        raise TimeStampError("the TSA granted the request but sent no token")
    return token_der


def read_tst_info(der: bytes) -> TstInfo:
    """The checked parts of a DER TSTInfo."""
    try:
        info = tsp.TSTInfo.load(bytes(der))
        version = info["version"].native
        imprint = info["message_imprint"]
        result = TstInfo(
            digest_algorithm=imprint["hash_algorithm"]["algorithm"].dotted,
            imprint=imprint["hashed_message"].native,
            time=info["gen_time"].native,
            serial_number=info["serial_number"].native,
            policy=info["policy"].dotted,
        )
    except (ValueError, TypeError, KeyError) as exc:
        raise TimeStampError(f"cannot read the token's TSTInfo: {exc}") from exc
    if version != "v1":
        raise TimeStampError(f"unknown TSTInfo version {version}")
    return result
