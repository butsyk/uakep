"""Compatibility: the JavaScript peer in interop/ verifies uakep's signed data and the other way
round. A disagreement needs a look at the standards and the official samples; neither side is
the source of truth.
"""

import random

import pytest

from uakep import cades
from uakep.cades import SigningKey
from uakep.curve import DSTU_PB_257
from uakep.dstu4145 import PrivateKey

from .conftest import certificate_for

pytestmark = pytest.mark.interop


@pytest.mark.parametrize("template", ["DSTU_sign.cer", "DSTU-7564_sign.cer"])
def test_peer_verifies_uakep_signed_data(peer, interop_rounds, template):
    rng = random.Random(template)
    for _ in range(max(3, interop_rounds // 10)):
        key = PrivateKey(DSTU_PB_257, rng.randrange(1, DSTU_PB_257.order))
        content = rng.randbytes(rng.randrange(1, 3000))
        signed = cades.sign(content, SigningKey(key, certificate_for(key, template)))
        answer = peer.call("cms_verify", data=signed.hex())
        assert answer["ok"], answer
        assert bytes.fromhex(answer["content"]) == content
        tampered = signed.replace(content[:16], bytes(b ^ 1 for b in content[:16]), 1)
        assert not peer.call("cms_verify", data=tampered.hex())["ok"]


def test_uakep_verifies_peer_signed_data(peer, interop_rounds):
    rng = random.Random(7)
    for _ in range(max(3, interop_rounds // 10)):
        key = PrivateKey(DSTU_PB_257, rng.randrange(1, DSTU_PB_257.order))
        cert = certificate_for(key)
        content = rng.randbytes(rng.randrange(1, 3000))
        answer = peer.call(
            "cms_sign", curve="DSTU_PB_257", d=f"{key.d:x}", cert=cert.der.hex(), data=content.hex()
        )
        result = cades.verify(bytes.fromhex(answer["signed"]))
        assert result.content == content
        assert result.certificate == cert
