"""Shared fixtures: test data paths and the JavaScript peer in interop/.

The peer is a compatibility check, not a source of truth.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(__file__).resolve().parent / "data"
INTEROP = ROOT / "interop"


def data_file(*parts: str) -> bytes:
    return DATA.joinpath(*parts).read_bytes()


class PeerHarness:
    """A running ``node interop/harness.mjs``; one JSON request and answer per line."""

    def __init__(self) -> None:
        self._proc = subprocess.Popen(
            ["node", str(INTEROP / "harness.mjs")],
            cwd=INTEROP,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def call(self, op: str, **kwargs: object) -> dict:
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(json.dumps({"op": op, **kwargs}) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            raise RuntimeError("peer harness exited")
        answer = json.loads(line)
        if "error" in answer:
            raise RuntimeError(f"peer harness: {answer['error']}")
        return answer

    def close(self) -> None:
        if self._proc.stdin:
            self._proc.stdin.close()
        self._proc.wait(timeout=10)


def _node_packages_installed() -> bool:
    packages = json.loads((INTEROP / "package.json").read_text())["dependencies"]
    return all((INTEROP / "node_modules" / name).is_dir() for name in packages)


@pytest.fixture(scope="session")
def peer():
    if shutil.which("node") is None:
        pytest.fail("node is not installed")
    if not _node_packages_installed():
        pytest.fail("the JavaScript peer is not installed: run `npm ci --prefix interop`")
    harness = PeerHarness()
    yield harness
    harness.close()


@pytest.fixture(scope="session")
def interop_rounds() -> int:
    return int(os.environ.get("UAKEP_INTEROP_ROUNDS", "30"))


def certificate_for(key, template="DSTU_sign.cer"):
    """A copy of a certificate carrying ``key``'s public key and key identifier.

    ``template`` names a ЦЗО test certificate, or is a Certificate. The issuer's signature on
    the copy no longer matches; CMS signing and verification do not look at it. The ДСТУ 7564
    template gives a Купина certificate.
    """
    from asn1crypto import core, x509

    from uakep import asn1
    from uakep.certificate import Certificate
    from uakep.gost34311 import gost34311
    from uakep.kupyna import kupyna256

    if isinstance(template, str):
        source = Certificate.load(data_file("czo", template))
        kupyna_id = "7564" in template
    else:
        source, kupyna_id = template, False
    cert = asn1.Certificate.load(source.der)
    tbs = cert["tbs_certificate"]
    octets = key.public_key().to_octet_string()
    spki = tbs["subject_public_key_info"]
    tbs["subject_public_key_info"] = asn1.SubjectPublicKeyInfo(
        {
            "algorithm": spki["algorithm"],
            "public_key": core.BitString.load(bytes([0x03, len(octets) + 1, 0]) + octets),
        }
    )
    key_id = kupyna256(octets) if kupyna_id else gost34311(octets)

    class _Extension(core.Sequence):
        _fields = [("extn_id", core.ObjectIdentifier), ("extn_value", core.OctetString)]  # noqa: RUF012

    ski = x509.Extension.load(
        _Extension({"extn_id": "2.5.29.14", "extn_value": core.OctetString(key_id).dump()}).dump()
    )
    others = [e for e in tbs["extensions"] if e["extn_id"].dotted != "2.5.29.14"]
    tbs["extensions"] = x509.Extensions([*others, ski])
    fields = ("tbs_certificate", "signature_algorithm", "signature_value")
    cert = asn1.Certificate({name: cert[name] for name in fields})
    return Certificate(cert.dump())


def sample_tsa_certificate():
    """The TSA certificate inside the tax receipt sample's time-stamp token."""
    from uakep import asn1
    from uakep.certificate import Certificate

    sd = asn1.ContentInfo.load(data_file("tax", "receipt.xml.signed"))["content"]
    token = asn1.ContentInfo.load(sd["signer_infos"][0]["unsigned_attrs"][0]["values"][0].dump())
    return Certificate(token["content"]["certificates"][0].dump())


SAMPLE_STAMP_TIME = datetime(2020, 7, 21, 7, 37, 28, tzinfo=UTC)
TEST_TSA_POLICY = "1.2.804.2.1.1.1.2.3.1"


def tst_info(digest_oid, imprint, *, when=SAMPLE_STAMP_TIME, serial=1):
    """A DER TSTInfo for ``imprint``."""
    from asn1crypto import tsp

    return tsp.TSTInfo(
        {
            "version": "v1",
            "policy": TEST_TSA_POLICY,
            "message_imprint": {
                "hash_algorithm": {"algorithm": digest_oid},
                "hashed_message": imprint,
            },
            "serial_number": serial,
            "gen_time": when,
        }
    ).dump()


def timestamp_response(token, status="granted"):
    from asn1crypto import core

    from uakep import asn1

    value = {"status": {"status": status}}
    if token is not None:
        value["time_stamp_token"] = core.Any.load(token)
    return asn1.TimeStampResp(value).dump()


class LocalTsa:
    """A time-stamping authority for tests, signing with a known key; call it as ``post``.

    By default its certificate is a copy of the tax samples' TSA certificate (time-stamping
    only, valid 2017-11-01 to 2022-11-01) carrying the test key. Like ЦЗО's TSA, it signs a
    token in the family of the requested imprint.
    """

    def __init__(self, key, certificate=None, *, when=SAMPLE_STAMP_TIME, attach_certificate=None):
        self.key = key
        self.certificate = certificate or certificate_for(key, sample_tsa_certificate())
        self.when = when
        self.attach_certificate = attach_certificate  # None: as the request asks
        self.requests: list[tuple[str, bytes]] = []

    def token(
        self,
        tst,
        *,
        digest_oid=None,
        attach_certificate=True,
        content_type=None,
        econtent=True,
        unsigned_attrs=b"",
    ):
        """A DER token over the DER TSTInfo ``tst``."""
        from asn1crypto import core

        from uakep import asn1, cades

        digest_oid = digest_oid or asn1.GOST34311
        content_type = content_type or asn1.ID_TST_INFO
        signature_oid = asn1.DSTU4145_LE if digest_oid == asn1.GOST34311 else asn1.DSTU4145_KUPYNA
        digest = cades._DIGESTS[digest_oid]
        attrs = cades._der(
            0x31,
            cades._attribute(asn1.ID_CONTENT_TYPE, core.ObjectIdentifier(content_type))
            + cades._attribute(asn1.ID_MESSAGE_DIGEST, core.OctetString(digest(tst))),
        )
        sid = cades._der(0xA0, core.OctetString(self.certificate.subject_key_identifier).dump())
        signer_info = cades._seq(
            core.Integer(1).dump(),
            sid,
            cades._algorithm(digest_oid),
            b"\xa0" + attrs[1:],
            cades._algorithm(signature_oid),
            core.OctetString(self.key.sign(digest(attrs))).dump(),
            unsigned_attrs,
        )
        econtent_der = cades._der(0xA0, core.OctetString(tst).dump()) if econtent else b""
        signed_data = cades._seq(
            core.Integer(3).dump(),
            cades._der(0x31, cades._algorithm(digest_oid)),
            cades._seq(core.ObjectIdentifier(content_type).dump(), econtent_der),
            cades._der(0xA0, self.certificate.der) if attach_certificate else b"",
            cades._der(0x31, signer_info),
        )
        return cades._seq(
            core.ObjectIdentifier(asn1.ID_SIGNED_DATA).dump(), cades._der(0xA0, signed_data)
        )

    def stamp(self, digest_oid, data, **options):
        """A token over ``data``, hashed with ``digest_oid``."""
        from uakep import cades

        imprint = cades._DIGESTS[digest_oid](data)
        return self.token(
            tst_info(digest_oid, imprint, when=self.when), digest_oid=digest_oid, **options
        )

    def __call__(self, url, request):
        from asn1crypto import tsp

        self.requests.append((url, request))
        parsed = tsp.TimeStampReq.load(request)
        imprint = parsed["message_imprint"]
        digest_oid = imprint["hash_algorithm"]["algorithm"].dotted
        tst = tst_info(digest_oid, imprint["hashed_message"].native, when=self.when)
        attach = self.attach_certificate
        if attach is None:
            attach = parsed["cert_req"].native
        return timestamp_response(self.token(tst, digest_oid=digest_oid, attach_certificate=attach))
