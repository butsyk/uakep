"""ГОСТ 34.311-95 hash function and the password-based key derivations built on it.

The step function encrypts the four 64-bit words of the chaining value with ГОСТ 28147-89
under keys derived from the message block, then mixes with the ψ shift register. Bytes are
read little-endian throughout; the cipher uses the default substitution table.
"""

from __future__ import annotations

from .gost28147 import DEFAULT_SBOX, _rounds, _tables

_M32 = 0xFFFFFFFF
_M64 = (1 << 64) - 1
_M256 = (1 << 256) - 1
_C3 = sum(0xFF << (8 * i) for i in (1, 3, 5, 7, 8, 10, 12, 14, 17, 18, 20, 23, 24, 28, 29, 31))
_ENC_ORDER = (0, 1, 2, 3, 4, 5, 6, 7) * 3 + (7, 6, 5, 4, 3, 2, 1, 0)
_SBOX_TABLES = _tables(DEFAULT_SBOX)


def _a(x: int) -> int:
    """A(y4 || y3 || y2 || y1) = (y1 ^ y2) || y4 || y3 || y2 on 64-bit words."""
    return (x >> 64) | (((x ^ (x >> 64)) & _M64) << 192)


def _psi(x: int) -> int:
    """One step of the ψ shift register on 16-bit words."""
    fb = (x ^ (x >> 16) ^ (x >> 32) ^ (x >> 48) ^ (x >> 192) ^ (x >> 240)) & 0xFFFF
    return (x >> 16) | (fb << 240)


def _byte_tables(images: list[int]) -> tuple[tuple[int, ...], ...]:
    """Lookup tables for a linear map on 256 bits, one table per input byte."""
    tables = []
    for pos in range(32):
        table = [0] * 256
        for v in range(1, 256):
            low = v & -v
            table[v] = table[v ^ low] ^ images[8 * pos + low.bit_length() - 1]
        tables.append(tuple(table))
    return tuple(tables)


_LINEAR: tuple | None = None


def _linear_maps():
    """ψ^61, ψ^62 and ψ^74 as byte tables, built on first use."""
    global _LINEAR
    if _LINEAR is None:
        img61, img62, img74 = [], [], []
        for bit in range(256):
            x = 1 << bit
            for _ in range(61):
                x = _psi(x)
            img61.append(x)
            x = _psi(x)
            img62.append(x)
            for _ in range(12):
                x = _psi(x)
            img74.append(x)
        _LINEAR = (_byte_tables(img61), _byte_tables(img62), _byte_tables(img74))
    return _LINEAR


def _apply(tables, x: int) -> int:
    r = 0
    for table, v in zip(tables, x.to_bytes(32, "little"), strict=True):
        r ^= table[v]
    return r


def _encrypt64(w: int, block: int) -> int:
    """Encrypt one 64-bit word under the key obtained from w by the P permutation."""
    wb = w.to_bytes(32, "little")
    k = [wb[t] | wb[8 + t] << 8 | wb[16 + t] << 16 | wb[24 + t] << 24 for t in range(8)]
    n0, n1 = _rounds(_SBOX_TABLES, [k[i] for i in _ENC_ORDER], block & _M32, block >> 32)
    return n1 | (n0 << 32)


def _step(h: int, m: int) -> int:
    """H(i+1) = f(H(i), M(i)) for 256-bit little-endian integers."""
    s = _encrypt64(h ^ m, h & _M64)
    u, v = _a(h), _a(_a(m))
    s |= _encrypt64(u ^ v, (h >> 64) & _M64) << 64
    u, v = _a(u) ^ _C3, _a(_a(v))
    s |= _encrypt64(u ^ v, (h >> 128) & _M64) << 128
    u, v = _a(u), _a(_a(v))
    s |= _encrypt64(u ^ v, h >> 192) << 192
    # ψ^61(H ^ ψ(M ^ ψ^12(S))) expanded by linearity.
    l61, l62, l74 = _linear_maps()
    return _apply(l74, s) ^ _apply(l62, m) ^ _apply(l61, h)


class GOST34311:
    """Incremental ГОСТ 34.311-95 hash with a zero initial value, hashlib-style."""

    name = "gost34311"
    digest_size = 32
    block_size = 32

    def __init__(self, data: bytes = b"") -> None:
        self._h = 0
        self._sum = 0
        self._length = 0
        self._pending = b""
        if data:
            self.update(data)

    def update(self, data: bytes) -> None:
        buf = self._pending + bytes(data)
        whole = len(buf) - len(buf) % 32
        h, total = self._h, self._sum
        for off in range(0, whole, 32):
            m = int.from_bytes(buf[off : off + 32], "little")
            h = _step(h, m)
            total = (total + m) & _M256
        self._h, self._sum = h, total
        self._length += whole
        self._pending = buf[whole:]

    def copy(self) -> GOST34311:
        other = GOST34311()
        other._h, other._sum, other._length, other._pending = (
            self._h,
            self._sum,
            self._length,
            self._pending,
        )
        return other

    def digest(self) -> bytes:
        h, total, length = self._h, self._sum, self._length
        if self._pending:
            m = int.from_bytes(self._pending.ljust(32, b"\0"), "little")
            h = _step(h, m)
            total = (total + m) & _M256
            length += len(self._pending)
        h = _step(h, (length * 8) & _M256)
        h = _step(h, total)
        return h.to_bytes(32, "little")

    def hexdigest(self) -> str:
        return self.digest().hex()


def gost34311(data: bytes) -> bytes:
    return GOST34311(data).digest()


def _hash_block(h0: int, sum0: int, length0: int, block: bytes) -> bytes:
    """Finish a hash whose state is (h0, sum0, length0) after one more 32-byte block."""
    m = int.from_bytes(block, "little")
    h = _step(h0, m)
    h = _step(h, ((length0 + 32) * 8) & _M256)
    return _step(h, (sum0 + m) & _M256).to_bytes(32, "little")


def key6_kdf(password: bytes, iterations: int = 10000) -> bytes:
    """Key for IIT Key-6.dat containers: the password hashed, then the hash re-hashed.

    ``iterations`` counts every hash, the first one included.
    """
    key = gost34311(password)
    for _ in range(iterations - 1):
        key = _hash_block(0, 0, 0, key)
    return key


def pbkdf2(password: bytes, salt: bytes, iterations: int) -> bytes:
    """PBKDF2 with HMAC-ГОСТ 34.311 (RFC 8018), one 32-byte output block.

    The HMAC key is the password zero-padded to the 32-byte hash block. Longer passwords are
    cut to 32 bytes, as the key containers this library reads were made with that rule.
    """
    key = bytes(password[:32]).ljust(32, b"\0")
    inner = GOST34311(bytes(b ^ 0x36 for b in key))
    outer = GOST34311(bytes(b ^ 0x5C for b in key))
    i_state = (inner._h, inner._sum, inner._length)
    o_state = (outer._h, outer._sum, outer._length)

    first = inner.copy()
    first.update(salt + b"\x00\x00\x00\x01")
    u = _hash_block(*o_state, first.digest())
    result = int.from_bytes(u, "little")
    for _ in range(iterations - 1):
        u = _hash_block(*o_state, _hash_block(*i_state, u))
        result ^= int.from_bytes(u, "little")
    return result.to_bytes(32, "little")
