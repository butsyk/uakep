"""Arithmetic in GF(2^m) with a polynomial basis (ДСТУ 4145-2002, section 5).

An element is a Python ``int``: bit ``i`` is the coefficient of ``t**i``. The field is set by
its degree ``m`` and the middle exponents of a trinomial ``t^m + t^k + 1`` or a pentanomial
``t^m + t^k3 + t^k2 + t^k1 + 1``.
"""

from __future__ import annotations

from functools import reduce

# Squaring spreads the bits of each hex digit over two hex digits: 0b1011 -> 0b01000101.
_SQUARE_HEX = {ord(c): format(int(format(int(c, 16), "04b"), 4), "02x") for c in "0123456789abcdef"}


class BinaryField:
    """GF(2^m) defined by a trinomial or pentanomial."""

    __slots__ = ("_trace_mask", "ks", "m", "mask", "modulus")

    def __init__(self, m: int, ks: tuple[int, ...] | list[int]) -> None:
        ks = tuple(sorted(int(k) for k in ks))
        if len(ks) not in (1, 3) or not ks[0] > 0 or ks[-1] >= m:
            raise ValueError(f"unsupported field polynomial m={m}, ks={ks}")
        self.m = m
        self.ks = ks
        self.modulus = reduce(lambda acc, k: acc | (1 << k), ks, (1 << m) | 1)
        self.mask = (1 << m) - 1
        self._trace_mask = self._compute_trace_mask()

    def __repr__(self) -> str:
        return f"BinaryField(m={self.m}, ks={self.ks})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, BinaryField) and self.modulus == other.modulus

    def __hash__(self) -> int:
        return hash(self.modulus)

    # -- reduction and products ------------------------------------------------------------

    def reduce(self, c: int) -> int:
        """Reduce a polynomial of any degree modulo the field polynomial."""
        m, mask, ks = self.m, self.mask, self.ks
        while c >> m:
            hi = c >> m
            c = (c & mask) ^ hi
            for k in ks:
                c ^= hi << k
        return c

    def mul(self, a: int, b: int) -> int:
        return self.reduce(clmul(a, b))

    def sqr(self, a: int) -> int:
        if not a:
            return 0
        return self.reduce(int(format(a, "x").translate(_SQUARE_HEX), 16))

    def inv(self, a: int) -> int:
        """Multiplicative inverse by the extended Euclidean algorithm for binary polynomials."""
        a = self.reduce(a)
        if a == 0:
            raise ZeroDivisionError("zero has no inverse in GF(2^m)")
        u, v = a, self.modulus
        g1, g2 = 1, 0
        while u != 1:
            j = u.bit_length() - v.bit_length()
            if j < 0:
                u, v, g1, g2, j = v, u, g2, g1, -j
            u ^= v << j
            g1 ^= g2 << j
        return self.reduce(g1)

    def div(self, a: int, b: int) -> int:
        return self.mul(a, self.inv(b))

    def sqr_n(self, a: int, n: int) -> int:
        for _ in range(n):
            a = self.sqr(a)
        return a

    # -- trace, half-trace, square root -----------------------------------------------------

    def _compute_trace_mask(self) -> int:
        """Bit i of the mask is Tr(t^i), found with Newton's identities for power sums.

        Tr(t^i) is the i-th power sum of the roots of the field polynomial. Over GF(2) the
        identity reads p_i = sum_{j=1}^{i-1} e_j p_{i-j} + i*e_i, where e_j is the coefficient
        of t^(m-j).
        """
        m = self.m
        e = [0] * (m + 1)
        for k in (0, *self.ks):
            e[m - k] = 1
        p = [m & 1] + [0] * (m - 1)
        nonzero = [j for j in range(1, m) if e[j]]
        for i in range(1, m):
            s = (i & 1) & e[i]
            for j in nonzero:
                if j < i:
                    s ^= p[i - j]
            p[i] = s
        return sum(bit << i for i, bit in enumerate(p))

    def trace(self, a: int) -> int:
        return (a & self._trace_mask).bit_count() & 1

    def trace_slow(self, a: int) -> int:
        """Tr(a) = a + a^2 + ... + a^(2^(m-1)); kept for tests of :meth:`trace`."""
        acc, x = a, a
        for _ in range(self.m - 1):
            x = self.sqr(x)
            acc ^= x
        return acc

    def half_trace(self, c: int) -> int:
        """H(c) = sum of c^(2^(2i)) for i in 0..(m-1)/2; solves z^2 + z = c when Tr(c) = 0."""
        if not self.m & 1:
            raise ValueError("half-trace needs an odd field degree")
        z = c
        for _ in range((self.m - 1) // 2):
            z = self.sqr(self.sqr(z)) ^ c
        return z

    def solve_quadratic(self, c: int) -> int:
        """Return z with z^2 + z = c, or raise ValueError when Tr(c) = 1 (no solution)."""
        z = self.half_trace(c)
        if self.sqr(z) ^ z != c:
            raise ValueError("z^2 + z = c has no solution")
        return z

    def sqrt(self, a: int) -> int:
        """Square root: a^(2^(m-1))."""
        return self.sqr_n(a, self.m - 1)


def clmul(a: int, b: int) -> int:
    """Carry-less product of two binary polynomials (4-bit window, most significant first)."""
    if a == 0 or b == 0:
        return 0
    if a.bit_length() < b.bit_length():
        a, b = b, a
    a2 = a << 1
    a4 = a << 2
    a8 = a << 3
    a3 = a2 ^ a
    a5 = a4 ^ a
    a6 = a4 ^ a2
    a7 = a6 ^ a
    table = (
        0, a, a2, a3, a4, a5, a6, a7,
        a8, a8 ^ a, a8 ^ a2, a8 ^ a3, a8 ^ a4, a8 ^ a5, a8 ^ a6, a8 ^ a7,
    )  # fmt: skip
    r = 0
    for digit in format(b, "x"):
        r = (r << 4) ^ table[_HEX[digit]]
    return r


_HEX = {c: int(c, 16) for c in "0123456789abcdef"}
