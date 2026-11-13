"""Differential tests: uakep and the reference implementation in interop/ check each
other's ДСТУ 4145 signatures.

Rounds come from UAKEP_INTEROP_ROUNDS (default 30; CI runs more). Each failure message carries
the seed (UAKEP_INTEROP_SEED) so a run can be replayed.
"""

import os
import random

import pytest

from uakep.curve import DSTU_PB_191, DSTU_PB_257, DSTU_PB_431
from uakep.dstu4145 import PrivateKey, PublicKey

pytestmark = pytest.mark.interop

CURVES = [DSTU_PB_191, DSTU_PB_257, DSTU_PB_257, DSTU_PB_257, DSTU_PB_431]
SEED = int(os.environ.get("UAKEP_INTEROP_SEED", random.SystemRandom().randrange(1 << 32)))


def test_harness_rejects_unknown_ops(reference):
    with pytest.raises(RuntimeError, match="unknown op"):
        reference.call("no-such-op")


def test_signatures_cross_verify(reference, interop_rounds):
    rng = random.Random(SEED)
    for i in range(interop_rounds):
        curve = rng.choice(CURVES)
        key = PrivateKey(curve, rng.randrange(1, curve.order))
        digest = rng.randbytes(rng.choice([32, 32, 32, 1, 20, 48, 64]))
        where = f"seed={SEED} round={i} curve={curve.name} d={key.d:x} hash={digest.hex()}"
        common = {"curve": curve.name, "hash": digest.hex()}

        pub = key.public_key()
        theirs = int(reference.call("pub", curve=curve.name, d=f"{key.d:x}")["pub"], 16)
        assert pub.compressed() == theirs, where
        assert PublicKey.from_compressed(curve, theirs) == pub, where

        their_sig = bytes.fromhex(reference.call("sign", d=f"{key.d:x}", **common)["sig"])
        assert pub.verify(digest, their_sig), f"uakep rejects the reference signature: {where}"

        our_sig = key.sign(digest)
        answer = reference.call("verify", pub=f"{theirs:x}", sig=our_sig.hex(), **common)
        assert answer["ok"], f"the reference rejects uakep's signature ({answer}): {where}"

        bad = bytearray(our_sig)
        bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
        answer = reference.call("verify", pub=f"{theirs:x}", sig=bad.hex(), **common)
        assert not answer["ok"], f"the reference accepts a damaged signature: {where}"
        assert not pub.verify(digest, bytes(bad)), f"uakep accepts a damaged signature: {where}"
