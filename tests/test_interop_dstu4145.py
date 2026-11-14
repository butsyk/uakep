"""Compatibility: uakep and the JavaScript peer in interop/ check each other's ДСТУ 4145
signatures. A disagreement needs a look at the standard; neither side is the source of truth.

Rounds come from UAKEP_INTEROP_ROUNDS (default 30). Each failure message carries
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


def test_harness_rejects_unknown_ops(peer):
    with pytest.raises(RuntimeError, match="unknown op"):
        peer.call("no-such-op")


def test_signatures_cross_verify(peer, interop_rounds):
    rng = random.Random(SEED)
    for i in range(interop_rounds):
        curve = rng.choice(CURVES)
        key = PrivateKey(curve, rng.randrange(1, curve.order))
        digest = rng.randbytes(rng.choice([32, 32, 32, 1, 20, 48, 64]))
        if int.from_bytes(digest, "little") & curve.field.mask == 0:
            # ДСТУ 4145-2002 signs such a hash as h = 1 (test_digest_to_field); the peer
            # refuses to sign it, so it is no common ground. One 1-byte hash in 256 hits this.
            continue
        where = f"seed={SEED} round={i} curve={curve.name} d={key.d:x} hash={digest.hex()}"
        common = {"curve": curve.name, "hash": digest.hex()}

        pub = key.public_key()
        theirs = int(peer.call("pub", curve=curve.name, d=f"{key.d:x}")["pub"], 16)
        assert pub.compressed() == theirs, where
        assert PublicKey.from_compressed(curve, theirs) == pub, where

        their_sig = bytes.fromhex(peer.call("sign", d=f"{key.d:x}", **common)["sig"])
        assert pub.verify(digest, their_sig), f"uakep rejects the peer's signature: {where}"

        our_sig = key.sign(digest)
        answer = peer.call("verify", pub=f"{theirs:x}", sig=our_sig.hex(), **common)
        assert answer["ok"], f"the peer rejects uakep's signature ({answer}): {where}"

        bad = bytearray(our_sig)
        bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
        answer = peer.call("verify", pub=f"{theirs:x}", sig=bad.hex(), **common)
        assert not answer["ok"], f"the peer accepts a damaged signature: {where}"
        assert not pub.verify(digest, bytes(bad)), f"uakep accepts a damaged signature: {where}"
