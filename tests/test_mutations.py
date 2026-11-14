"""Layer 13: damaged signed data fails cleanly.

Each official sample is damaged at random a few hundred times: a bit flipped, a byte replaced,
bytes cut out, the end cut off. Whatever comes out, verify() must answer in time, and with a
result, a SignatureError or an UnsupportedError: nothing else may escape. The damage is drawn
from a fixed seed, so a failure can be replayed; UAKEP_MUTATION_ROUNDS sets how many per sample.
"""

import os
import random

import pytest

from uakep import SignatureError, UnsupportedError, verify

from .conftest import data_file, time_limit

ROUNDS = int(os.environ.get("UAKEP_MUTATION_ROUNDS", "250"))
SAMPLES = [
    ("tax", "receipt.xml.signed"),
    ("tax", "zreport.xml.signed"),
    ("tax", "state-request.json.signed"),
    ("czo", "DSTU_CAdES-X_Long-Full.p7s"),
    ("czo", "DSTU-7564_CAdES-X_Long-Full.p7s"),
]


def _damage(data: bytes, at: int, rng: random.Random) -> tuple[str, bytes]:
    damaged = bytearray(data)
    kind = rng.choice(("flip", "replace", "cut", "truncate"))
    if kind == "flip":
        damaged[at] ^= 1 << rng.randrange(8)
    elif kind == "replace":
        damaged[at] = rng.randrange(256)
    elif kind == "cut":
        del damaged[at : at + rng.randrange(1, 4)]
    else:
        del damaged[at:]
    return kind, bytes(damaged)


@pytest.mark.parametrize(("folder", "name"), SAMPLES)
def test_damaged_samples_fail_cleanly(folder, name):
    good = data_file(folder, name)
    rng = random.Random(name)
    # Leave the document itself alone: damage there only changes its hash.
    document = verify(good).content
    start = good.index(document)
    places = [*range(start), *range(start + len(document), len(good))]
    verified = refused = 0
    for round_number in range(ROUNDS):
        at = rng.choice(places)
        kind, damaged = _damage(good, at, rng)
        try:
            with time_limit(10):
                verify(damaged)
            verified += 1
        except (SignatureError, UnsupportedError):
            refused += 1
        except BaseException as exc:
            where = f"{name}, round {round_number}, {kind} at byte {at}"
            pytest.fail(f"{where}: {type(exc).__name__}: {exc}")
    # Damage is refused almost always; what still verifies sits in parts nothing signs.
    assert refused > verified, (refused, verified)
