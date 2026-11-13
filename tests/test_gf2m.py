"""Layer 1: GF(2^m) arithmetic.

Known answers are published vectors for reduction, multiplication, inversion and trace
in GF(2^257) and GF(2^191).
"""

import random

import pytest

from uakep.gf2m import BinaryField, clmul

F257 = BinaryField(257, (12,))
F191 = BinaryField(191, (9,))
F431 = BinaryField(431, (1, 3, 5))
FIELDS = [F191, F257, F431]


def words(*ws: int) -> int:
    """Little-endian 32-bit words, the layout of the published vectors."""
    return sum(w << (32 * i) for i, w in enumerate(ws))


BASE_PB_257 = words(
    2868794628, 3546471302, 1984461146, 2266653769, 1477709477, 2213487392, 1124848366, 927226002
)
BASE_PB_257_INV = words(
    2212782975, 784404366, 3639274527, 2383088420, 2863133559, 3083282239, 1915462745, 2352840975
)
BASE_PB_191 = words(3672863017, 3271360118, 2891495861, 2031265490, 1660092234, 1900090551)
BASE_PB_191_INV = words(588100965, 4266588766, 614862865, 900202323, 3844403428, 685512842)

VALUE = 0xAFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A65890
VALUE_REDUCED = 0xFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A60895


def test_modulus_bits():
    assert F257.modulus == (1 << 257) | (1 << 12) | 1
    assert F431.modulus == (1 << 431) | 0b101011
    assert F257.modulus.bit_length() == 258


def test_reduce_known_value():
    a = words(
        0x29A65890, 0x87025056, 0x90F62BA8, 0x94AA6314, 0xDE5742E1, 0x85849E20, 0xB4292849,
        0xFF3EE09C, 0xA,
    )  # fmt: skip
    expected = words(
        0x29A60895, 0x87025056, 0x90F62BA8, 0x94AA6314, 0xDE5742E1, 0x85849E20, 0xB4292849,
        0xFF3EE09C,
    )  # fmt: skip
    assert F257.reduce(a) == expected
    assert F257.reduce(VALUE) == VALUE_REDUCED


def test_mul_known_value():
    b = 0x01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C
    expected = 0x157B8E91C8B225469821FC836045A7C09C30D9FDEE54B680C8247821F8C4E3352
    assert F257.mul(F257.reduce(VALUE), b) == expected


def test_inv_known_values():
    assert F257.inv(VALUE) == 0xF5AE84D0C4DC2E7E89C670FB2083D124BE50B413EFB6863705BD63A5168352E0
    assert F257.inv(BASE_PB_257) == BASE_PB_257_INV
    assert F257.inv(BASE_PB_257_INV) == BASE_PB_257
    # PB 191 is where word-based binary inversion is known to loop.
    assert F191.inv(BASE_PB_191) == BASE_PB_191_INV
    assert F191.inv(BASE_PB_191_INV) == BASE_PB_191


@pytest.mark.parametrize(("a", "expected"), [(2, 5), (3, 6), (4, 7), (5, 2), (6, 3), (7, 4)])
def test_inv_small_field(a, expected):
    # GF(2^3) with t^3 + t + 1
    assert BinaryField(3, (1,)).inv(a) == expected


def test_inv_zero_raises():
    with pytest.raises(ZeroDivisionError):
        F257.inv(0)
    with pytest.raises(ZeroDivisionError):
        F257.inv(F257.modulus)  # reduces to zero


def test_trace_known_value():
    x = 0x2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6
    assert F257.trace(x) == 1
    assert F257.trace_slow(x) == 1


@pytest.mark.parametrize("f", FIELDS, ids=lambda f: str(f.m))
def test_trace_mask_matches_definition(f):
    rng = random.Random(f.m)
    for i in [0, 1, 2, *f.ks, f.m - 1]:
        assert f.trace(1 << i) == f.trace_slow(1 << i), i
    for _ in range(20):
        a = rng.getrandbits(f.m)
        assert f.trace(a) == f.trace_slow(a)


@pytest.mark.parametrize("f", FIELDS, ids=lambda f: str(f.m))
def test_field_laws(f):
    rng = random.Random(1000 + f.m)
    for _ in range(25):
        a, b, c = (rng.getrandbits(f.m) for _ in range(3))
        assert f.mul(a, b) == f.mul(b, a)
        assert f.mul(a, b ^ c) == f.mul(a, b) ^ f.mul(a, c)
        assert f.mul(f.mul(a, b), c) == f.mul(a, f.mul(b, c))
        assert f.sqr(a) == f.mul(a, a)
        assert f.mul(a, 1) == a
        if a:
            assert f.mul(a, f.inv(a)) == 1
            assert f.div(f.mul(a, b), a) == b
        assert f.sqr(f.sqrt(a)) == a
        assert f.sqr_n(a, 3) == f.sqr(f.sqr(f.sqr(a)))


def test_clmul_matches_schoolbook():
    def schoolbook(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a <<= 1
            b >>= 1
        return r

    rng = random.Random(7)
    for bits_a, bits_b in [(1, 1), (5, 300), (257, 257), (431, 3), (64, 64)]:
        a, b = rng.getrandbits(bits_a) | 1, rng.getrandbits(bits_b) | 1
        assert clmul(a, b) == schoolbook(a, b)
    assert clmul(0, 5) == 0
    assert clmul(5, 0) == 0


def test_sqr_zero_and_one():
    assert F257.sqr(0) == 0
    assert F257.sqr(1) == 1


@pytest.mark.parametrize("f", FIELDS, ids=lambda f: str(f.m))
def test_half_trace_solves_quadratic(f):
    rng = random.Random(2000 + f.m)
    solved = unsolvable = 0
    while solved < 5 or unsolvable < 5:
        c = rng.getrandbits(f.m)
        if f.trace(c) == 0:
            z = f.solve_quadratic(c)
            assert f.sqr(z) ^ z == c
            solved += 1
        else:
            with pytest.raises(ValueError):
                f.solve_quadratic(c)
            unsolvable += 1


def test_half_trace_needs_odd_degree():
    with pytest.raises(ValueError):
        BinaryField(4, (1,)).half_trace(3)


@pytest.mark.parametrize("ks", [(), (1, 2), (0,), (257,), (1, 2, 3, 4)])
def test_rejects_bad_polynomials(ks):
    with pytest.raises(ValueError):
        BinaryField(257, ks)


def test_equality_and_repr():
    assert BinaryField(257, [12]) == F257
    assert hash(BinaryField(257, [12])) == hash(F257)
    assert F257 != F191
    assert F257 != "F257"
    assert repr(F431) == "BinaryField(m=431, ks=(1, 3, 5))"
