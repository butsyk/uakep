"""Binary elliptic curves y^2 + xy = x^3 + a*x^2 + b over GF(2^m) (ДСТУ 4145-2002).

Points are affine ``(x, y)`` tuples of field elements; ``None`` is the point at infinity.
Scalar multiplication uses the López–Dahab Montgomery ladder (Hankerson, Menezes, Vanstone,
*Guide to Elliptic Curve Cryptography*, algorithm 3.40), which does the same field operations
for every scalar bit.
"""

from __future__ import annotations

from dataclasses import dataclass

from .gf2m import BinaryField

Point = tuple[int, int]


class InvalidPointError(ValueError):
    """Bytes or coordinates that do not describe a usable point on the curve."""


@dataclass(frozen=True, eq=False)
class Curve:
    """A ДСТУ 4145 curve: field, coefficients a (0 or 1) and b, base point and its order."""

    field: BinaryField
    a: int
    b: int
    order: int
    base: Point
    name: str | None = None

    def __post_init__(self) -> None:
        _check_parameters(self.field, self.a, self.b, self.order)
        if not self.contains(self.base):
            raise InvalidPointError("base point is not on the curve")

    @classmethod
    def from_params(
        cls,
        m: int,
        ks: tuple[int, ...] | list[int],
        a: int,
        b: int,
        order: int,
        base_compressed: int,
        name: str | None = None,
    ) -> Curve:
        """Build a curve from parameters as stored in certificates and key files."""
        f = BinaryField(m, ks)
        _check_parameters(f, a, b, order)  # before any arithmetic with them
        stub = _CurveMath(f, a, b)
        return cls(f, a, b, order, stub.decompress(base_compressed), name)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Curve):
            return NotImplemented
        return (
            self.field == other.field
            and self.a == other.a
            and self.b == other.b
            and self.order == other.order
            and self.base == other.base
        )

    def __hash__(self) -> int:
        return hash((self.field, self.a, self.b, self.order, self.base))

    @property
    def m(self) -> int:
        return self.field.m

    @property
    def ks(self) -> tuple[int, ...]:
        return self.field.ks

    @property
    def _math(self) -> _CurveMath:
        return _CurveMath(self.field, self.a, self.b)

    def contains(self, p: Point | None) -> bool:
        return self._math.contains(p)

    def add(self, p: Point | None, q: Point | None) -> Point | None:
        return self._math.add(p, q)

    def double(self, p: Point | None) -> Point | None:
        return self._math.add(p, p)

    def negate(self, p: Point | None) -> Point | None:
        return None if p is None else (p[0], p[0] ^ p[1])

    def mul(self, k: int, p: Point | None) -> Point | None:
        """k*P for any integer k."""
        if p is None or k == 0:
            return None
        if k < 0:
            return self.mul(-k, self.negate(p))
        return self._math.ladder(k, p)

    def mul_base(self, k: int) -> Point | None:
        return self.mul(k, self.base)

    def pad_scalar(self, k: int) -> int:
        """k + t*n with exactly ``order.bit_length() + 1`` bits; (k + t*n)*G = k*G.

        Scalar multiplication time then does not depend on the bit length of a secret
        scalar, a countermeasure against Minerva/TPM-FAIL style timing attacks.
        """
        n = self.order
        padded = k + n
        if padded.bit_length() == n.bit_length():
            padded += n
        return padded

    def compress(self, p: Point) -> int:
        return self._math.compress(p)

    def decompress(self, x: int) -> Point:
        return self._math.decompress(x)

    def is_valid_public_point(self, p: Point | None) -> bool:
        """On the curve, not infinity, and of order ``self.order``."""
        return p is not None and self.contains(p) and self.mul(self.order, p) is None


def _check_parameters(field: BinaryField, a: int, b: int, order: int) -> None:
    """Reject numbers that are no curve; they may come from a certificate or key file."""
    if a not in (0, 1):
        raise ValueError("ДСТУ 4145 curves have a = 0 or a = 1")
    if not 0 < b <= field.mask:
        raise ValueError("the coefficient b is not a non-zero field element")
    # A subgroup's order divides the curve's, which is below 2^(m+1) by Hasse's bound.
    if not 1 < order < 2 << field.m:
        raise ValueError("the base point's order does not fit the curve")


@dataclass(frozen=True)
class _CurveMath:
    f: BinaryField
    a: int
    b: int

    def contains(self, p: Point | None) -> bool:
        if p is None:
            return True
        f = self.f
        x, y = p
        if x >> f.m or y >> f.m:
            return False
        # y^2 + xy = x^3 + a x^2 + b
        x2 = f.sqr(x)
        lhs = f.sqr(y) ^ f.mul(x, y)
        rhs = f.mul(x2, x) ^ (x2 if self.a else 0) ^ self.b
        return lhs == rhs

    def add(self, p: Point | None, q: Point | None) -> Point | None:
        """Affine addition and doubling."""
        if p is None:
            return q
        if q is None:
            return p
        f = self.f
        x0, y0 = p
        x1, y1 = q
        if x0 != x1:
            lam = f.div(y0 ^ y1, x0 ^ x1)
            x2 = f.sqr(lam) ^ lam ^ x0 ^ x1 ^ self.a
        else:
            if y0 != y1 or x1 == 0:
                return None
            lam = x1 ^ f.div(y1, x1)
            x2 = f.sqr(lam) ^ lam ^ self.a
        y2 = f.mul(lam, x1 ^ x2) ^ x2 ^ y1
        return (x2, y2)

    def ladder(self, k: int, p: Point) -> Point | None:
        f = self.f
        mul, sqr = f.mul, f.sqr
        b = self.b
        x, y = p
        if x == 0:
            # (0, sqrt(b)) has order 2.
            return p if k & 1 else None
        x1, z1 = x, 1
        xx = sqr(x)
        x2, z2 = sqr(xx) ^ b, xx  # (x^4 + b, x^2) is 2P
        for i in range(k.bit_length() - 2, -1, -1):
            if (k >> i) & 1:
                t1, t2 = mul(x1, z2), mul(x2, z1)
                z1 = sqr(t1 ^ t2)
                x1 = mul(x, z1) ^ mul(t1, t2)
                xx, zz = sqr(x2), sqr(z2)
                x2, z2 = sqr(xx) ^ mul(b, sqr(zz)), mul(xx, zz)
            else:
                t1, t2 = mul(x2, z1), mul(x1, z2)
                z2 = sqr(t1 ^ t2)
                x2 = mul(x, z2) ^ mul(t1, t2)
                xx, zz = sqr(x1), sqr(z1)
                x1, z1 = sqr(xx) ^ mul(b, sqr(zz)), mul(xx, zz)
        if z1 == 0:
            return None
        if z2 == 0:
            return (x, x ^ y)
        # Recover y (algorithm 3.40, step 4).
        x3 = f.div(x1, z1)
        z1z2 = mul(z1, z2)
        t = mul(x1 ^ mul(x, z1), x2 ^ mul(x, z2)) ^ mul(sqr(x) ^ y, z1z2)
        y3 = mul(mul(x ^ x3, t), f.inv(mul(x, z1z2))) ^ y
        return (x3, y3)

    def compress(self, p: Point) -> int:
        """x with its lowest bit replaced by Tr(y/x) (ДСТУ 4145-2002, 6.9)."""
        x, y = p
        if x == 0:
            raise InvalidPointError("cannot compress a point with x = 0")
        return (x & ~1) | self.f.trace(self.f.div(y, x))

    def decompress(self, compressed: int) -> Point:
        """Inverse of :meth:`compress` (ДСТУ 4145-2002, 6.10)."""
        f = self.f
        if compressed < 0 or compressed >> f.m:
            raise InvalidPointError("compressed point does not fit the field")
        if compressed == 0:
            return (0, f.sqrt(self.b))
        k = compressed & 1
        x = compressed & ~1
        if f.trace(x) != self.a:
            x |= 1
        if x == 0:
            return (0, f.sqrt(self.b))
        x2 = f.sqr(x)
        w = x ^ self.a ^ f.div(self.b, x2)  # (x^3 + a x^2 + b) / x^2
        try:
            z = f.solve_quadratic(w)
        except ValueError:
            raise InvalidPointError("compressed point is not on the curve") from None
        if f.trace(z) != k:
            z ^= 1
        return (x, f.mul(z, x))


def _h(text: str) -> int:
    return int(text.replace(" ", ""), 16)


# Named curves of ДСТУ 4145-2002 used in Ukrainian certificates.
DSTU_PB_191 = Curve(
    BinaryField(191, (9,)),
    a=1,
    b=_h("7bc86e2102902ec4d5890e8b6b4981ff27e0482750fefc03"),
    order=_h("40000000000000000000000069a779cac1dabc6788f7474f"),
    base=(
        _h("714114b762f2ff4a7912a6d2ac58b9b5c2fcfe76daeb7129"),
        _h("29c41e568b77c617efe5902f11db96fa9613cd8d03db08da"),
    ),
    name="DSTU_PB_191",
)

DSTU_PB_257 = Curve(
    BinaryField(257, (12,)),
    a=0,
    b=_h("01 CEF49472 0115657E 18F938D7 A7942394 FF9425C1 458C5786 1F9EEA6A DBE3BE10"),
    order=_h("80000000 00000000 00000000 00000000 6759213A F182E987 D3E17714 907D470D"),
    base=(
        _h("2A29EF20 7D0E9B6C 55CD260B 306C7E00 7AC491CA 1B10C623 34A9E8DC D8D20FB7"),
        _h("01 0686D41F F744D444 9FCCF6D8 EEA03102 E6812C93 A9D60B97 8B702CF1 56D814EF"),
    ),
    name="DSTU_PB_257",
)

DSTU_PB_431 = Curve(
    BinaryField(431, (1, 3, 5)),
    a=1,
    b=_h(
        "03CE 10490F6A 708FC26D FE8C3D27 C4F94E69 0134D5BF F988D8D2 8AAEAEDE 975936C6 "
        "6BAC536B 18AE2DC3 12CA4931 17DAA469 C640CAF3"
    ),
    order=_h(
        "3FFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFBA3175 458009A8 "
        "C0A724F0 2F81AA8A 1FCBAF80 D90C7A95 110504CF"
    ),
    base=(
        _h(
            "1A62 BA79D981 33A16BBA E7ED9A8E 03C32E08 24D57AEF 72F88986 874E5AAE 49C27BED "
            "49A2A950 58068426 C2171E99 FD3B43C5 947C857D"
        ),
        _h(
            "70B5 E1E14031 C1F70BBE FE96BDDE 66F45175 4B4CA5F4 8DA241F3 31AA396B 8D1839A8 "
            "55C1769B 1EA14BA5 3308B5E2 723724E0 90E02DB9"
        ),
    ),
    name="DSTU_PB_431",
)

NAMED_CURVES: dict[str, Curve] = {c.name: c for c in (DSTU_PB_191, DSTU_PB_257, DSTU_PB_431)}  # type: ignore[misc]
