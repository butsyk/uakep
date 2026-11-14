"""Layer 2: binary curves, point arithmetic, compression.

Known answers are published vectors for point addition, multiplication, compression and
decompression on DSTU_PB_257.
"""

import random

import pytest

from uakep.curve import (
    DSTU_PB_191,
    DSTU_PB_257,
    DSTU_PB_431,
    NAMED_CURVES,
    Curve,
    InvalidPointError,
)
from uakep.gf2m import BinaryField

from .conftest import time_limit

CURVES = [DSTU_PB_191, DSTU_PB_257, DSTU_PB_431]
C257 = DSTU_PB_257

PUB_X = 0x00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589
PUB_Y = 0x01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C
RAND_E = 0x7A32849E569C8888F25DE6F69A839D75057383F473ACF559ABD3C5D683294CEB


@pytest.mark.parametrize("curve", CURVES, ids=lambda c: c.name)
def test_named_curve_parameters_are_consistent(curve):
    assert curve.contains(curve.base)
    assert curve.mul(curve.order, curve.base) is None
    assert curve.is_valid_public_point(curve.base)
    assert NAMED_CURVES[curve.name] is curve


def test_contains_known_point():
    assert C257.contains((PUB_X, PUB_Y))
    assert not C257.contains((PUB_X, PUB_Y ^ 1))
    # Same point modulo the field polynomial, but the coordinates do not fit the field.
    modulus = C257.field.modulus
    assert not C257.contains((PUB_X ^ modulus, PUB_Y))
    assert not C257.contains((PUB_X, PUB_Y ^ modulus))
    assert C257.contains(None)


def test_double_known_point():
    expected = (
        0x176DBDE19773DFD335665597E8D6A0AB678721A5BB7030F25DC4C48B809EF3520,
        0x6E75301556EA5D571403086691030F024C026907C8E818B2EEDD9184D12040EE,
    )
    assert C257.add((PUB_X, PUB_Y), (PUB_X, PUB_Y)) == expected
    assert C257.double((PUB_X, PUB_Y)) == expected


def test_mul_known_point():
    expected = (
        0xF26DF77CA4C807C6B94F5C577415A1FCE603A85AE7678717E16CB9A78DE32D15,
        0x1785FDED2804BEA15B02C4FD785FD3E98AB2435B8D78DA44E195A9A088D3FC2D4,
    )
    assert C257.mul(RAND_E, (PUB_X, PUB_Y)) == expected


def test_compress_base_point():
    assert (
        C257.compress(C257.base)
        == 0x2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6
    )


@pytest.mark.parametrize(
    ("compressed", "x", "y"),
    [
        # two tax service public keys and a point that once broke decompression
        (
            0x01A77131A7C14F9AA6EA8C760D39673D5F0330FAB1118D55B55B7AF0735975485F,
            0x01A77131A7C14F9AA6EA8C760D39673D5F0330FAB1118D55B55B7AF0735975485F,
            0xDC058ADA665D99084038B5F914FB9CF7214760A4865B49CAF7F4BE7379F3A395,
        ),
        (
            0x2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6,
            0x2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7,
            0x010686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF,
        ),
        (
            0x76CD4555AD63455529755E5C3F3066C3BCB957CC63D00E22C6DD1E9ED316B419,
            0x76CD4555AD63455529755E5C3F3066C3BCB957CC63D00E22C6DD1E9ED316B418,
            0x12B20103548F45DCBED5486022DFCB244B2D996E0D3D761ABAF73BA16EA26E0D3,
        ),
    ],
)
def test_decompress_known_points(compressed, x, y):
    assert C257.decompress(compressed) == (x, y)
    assert C257.compress((x, y)) == compressed


def test_decompress_zero_gives_order_two_point():
    p = C257.decompress(0)
    assert p[0] == 0
    assert C257.contains(p)
    assert C257.double(p) is None
    assert C257.mul(3, p) == p
    assert C257.mul(2, p) is None
    assert not C257.is_valid_public_point(p)


def test_decompress_x_equal_one_with_trace_bit():
    # x = 1 compressed with bit 0 cleared becomes 0 after taking the trace bit out,
    # then gets bit 0 restored from the curve's a; check it lands on the curve or raises.
    for compressed in (1, 2, 3):
        try:
            p = C257.decompress(compressed)
        except InvalidPointError:
            continue
        assert C257.contains(p)


def test_decompress_rejects_bad_input():
    with pytest.raises(InvalidPointError):
        C257.decompress(1 << 257)
    with pytest.raises(InvalidPointError):
        C257.decompress(-1)
    rng = random.Random(5)
    rejected = 0
    for _ in range(40):
        x = rng.getrandbits(257)
        try:
            p = C257.decompress(x)
        except InvalidPointError:
            rejected += 1
            continue
        assert C257.contains(p)
        assert C257.compress(p) == x
    assert rejected > 0  # about half of all x have no point


def test_compress_rejects_x_zero():
    with pytest.raises(InvalidPointError):
        C257.compress((0, 5))


@pytest.mark.parametrize("curve", CURVES, ids=lambda c: c.name)
def test_ladder_matches_affine_double_and_add(curve):
    rng = random.Random(curve.m)
    p = curve.mul(rng.getrandbits(64) | 1, curve.base)

    def affine_mul(k, q):
        acc = None
        for bit in bin(k)[2:]:
            acc = curve.double(acc)
            if bit == "1":
                acc = curve.add(acc, q)
        return acc

    for k in [1, 2, 3, 4, 5, 255, 256, rng.getrandbits(40), rng.getrandbits(curve.m)]:
        assert curve.mul(k, p) == affine_mul(k, p), k


@pytest.mark.parametrize("curve", CURVES, ids=lambda c: c.name)
def test_group_laws(curve):
    rng = random.Random(10 + curve.m)
    g = curve.base
    a, b = rng.randrange(1, curve.order), rng.randrange(1, curve.order)
    pa, pb = curve.mul(a, g), curve.mul(b, g)
    assert curve.add(pa, pb) == curve.mul(a + b, g)
    assert curve.add(pa, pb) == curve.add(pb, pa)
    assert curve.mul(b, pa) == curve.mul(a * b % curve.order, g)
    assert curve.add(pa, curve.negate(pa)) is None
    assert curve.mul(-a, g) == curve.negate(pa)
    assert curve.mul(curve.order - 1, g) == curve.negate(g)
    assert curve.mul(0, g) is None
    assert curve.mul(5, None) is None
    assert curve.add(None, pa) == pa
    assert curve.add(pa, None) == pa
    assert curve.negate(None) is None
    assert curve.double(None) is None
    assert curve.mul_base(a) == pa
    # compression round trip
    assert curve.decompress(curve.compress(pa)) == pa


def test_mul_reaching_minus_p_in_ladder():
    # (n-1)*P makes the ladder's second register hit infinity (z2 == 0).
    p = C257.mul(12345, C257.base)
    assert C257.mul(C257.order - 1, p) == C257.negate(p)
    assert C257.mul(C257.order + 1, p) == p


def test_pad_scalar_has_fixed_length_and_same_point():
    n = C257.order
    for k in [1, 2, n - 1, n // 2, (1 << 200) + 7, 0x10]:
        padded = C257.pad_scalar(k)
        assert padded.bit_length() == n.bit_length() + 1
        assert padded % n == k % n
    assert C257.mul(C257.pad_scalar(7), C257.base) == C257.mul(7, C257.base)


def test_from_params_matches_named_curve():
    c = Curve.from_params(
        257,
        [12],
        0,
        C257.b,
        C257.order,
        C257.compress(C257.base),
    )
    assert c == C257
    assert hash(c) == hash(C257)
    assert c.m == 257
    assert c.ks == (12,)
    assert c != DSTU_PB_191
    assert (c == "curve") is False


def test_rejects_bad_curves():
    f = BinaryField(257, (12,))
    with pytest.raises(ValueError):
        Curve(f, a=2, b=C257.b, order=C257.order, base=C257.base)
    with pytest.raises(InvalidPointError):
        Curve(f, a=0, b=C257.b, order=C257.order, base=(C257.base[0], C257.base[1] ^ 1))
    for b in (0, 1 << 257, -C257.b):
        with pytest.raises(ValueError, match="coefficient b"):
            Curve(f, a=0, b=b, order=C257.order, base=C257.base)
    for order in (1, 1 << 258, -C257.order):
        with pytest.raises(ValueError, match="order does not fit"):
            Curve(f, a=0, b=C257.b, order=order, base=C257.base)
    # the largest b and order that pass: b then fails on the base point, the order is taken
    with pytest.raises(InvalidPointError):
        Curve(f, a=0, b=(1 << 257) - 1, order=C257.order, base=C257.base)
    assert Curve(f, a=0, b=C257.b, order=(1 << 258) - 1, base=C257.base).order.bit_length() == 258


def test_from_params_checks_the_numbers_before_using_them():
    base = C257.compress(C257.base)
    with pytest.raises(ValueError, match="a = 0 or a = 1"):
        Curve.from_params(257, [12], 2, C257.b, C257.order, base)
    # reducing a number this long by the field polynomial would take minutes
    with pytest.raises(ValueError, match="coefficient b"), time_limit(5):
        Curve.from_params(257, [12], 0, 1 << 16_000_000, C257.order, base)
    with pytest.raises(ValueError, match="order does not fit"):
        Curve.from_params(257, [12], 0, C257.b, 1 << 258, base)


def test_is_valid_public_point_rejects_off_curve_and_infinity():
    assert not C257.is_valid_public_point(None)
    assert not C257.is_valid_public_point((PUB_X, PUB_Y ^ 1))
    assert C257.is_valid_public_point((PUB_X, PUB_Y))


def test_add_points_with_same_x_different_y_is_infinity():
    p = C257.mul(99, C257.base)
    assert C257.add(p, C257.negate(p)) is None
