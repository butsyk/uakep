"""Shared fixtures: test data paths and the JavaScript peer in interop/.

The peer is a compatibility check, not a source of truth.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
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
    reason = None
    if shutil.which("node") is None:
        reason = "node is not installed"
    elif not _node_packages_installed():
        reason = "the JavaScript peer is not installed: run `npm ci --prefix interop`"
    if reason:
        if os.environ.get("UAKEP_REQUIRE_INTEROP"):
            pytest.fail(reason)
        pytest.skip(reason)
    harness = PeerHarness()
    yield harness
    harness.close()


@pytest.fixture(scope="session")
def interop_rounds() -> int:
    return int(os.environ.get("UAKEP_INTEROP_ROUNDS", "30"))


def certificate_for(key, template: str = "DSTU_sign.cer"):
    """A copy of a ЦЗО test certificate carrying ``key``'s public key and key identifier.

    The issuer's signature on it no longer matches; CMS signing and verification do not
    look at it. The ДСТУ 7564 template gives a Купина certificate.
    """
    from asn1crypto import core, x509

    from uakep import asn1
    from uakep.certificate import Certificate
    from uakep.gost34311 import gost34311
    from uakep.kupyna import kupyna256

    cert = asn1.Certificate.load(Certificate.load(data_file("czo", template)).der)
    tbs = cert["tbs_certificate"]
    octets = key.public_key().to_octet_string()
    spki = tbs["subject_public_key_info"]
    tbs["subject_public_key_info"] = asn1.SubjectPublicKeyInfo(
        {
            "algorithm": spki["algorithm"],
            "public_key": core.BitString.load(bytes([0x03, len(octets) + 1, 0]) + octets),
        }
    )
    key_id = kupyna256(octets) if "7564" in template else gost34311(octets)

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
