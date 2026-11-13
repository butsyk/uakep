"""ГОСТ 28147-89 block cipher (ДСТУ ГОСТ 28147:2009): ECB, CFB and MAC modes.

Byte order and substitution tables follow the Ukrainian convention: blocks and keys are read
as little-endian 32-bit words, and the substitution table (ДКЕ) is given either unpacked, as 128
nibbles in eight rows from k8 down to k1, or packed into the 64 bytes found in certificates and
key containers.
"""

from __future__ import annotations

import struct
from functools import lru_cache

# The default substitution table (ДКЕ) of Ukrainian ГОСТ 28147-89 and ГОСТ 34.311-95
# software, unpacked (rows k8 ... k1).
DEFAULT_SBOX = bytes.fromhex(
    "0102030E060D0B080F0A0C050709000403080B0506040E0A020C0107090F0D00"
    "02080907050F000B0C010D0E0A0306040F080E090702000D0C0601050B04030A"
    "03080D09060B0F0002050C0A040E01070F0605080E0B0A040C0003070209010D"
    "08000C040906070B0203010F050E0A0D0A090D060E0B04050F01030C07000802"
)

_M32 = 0xFFFFFFFF
_ENC_ORDER = (0, 1, 2, 3, 4, 5, 6, 7) * 3 + (7, 6, 5, 4, 3, 2, 1, 0)
_DEC_ORDER = (0, 1, 2, 3, 4, 5, 6, 7) + (7, 6, 5, 4, 3, 2, 1, 0) * 3
_MAC_ORDER = (0, 1, 2, 3, 4, 5, 6, 7) * 2


def pack_sbox(unpacked: bytes) -> bytes:
    """128 nibbles (one per byte) -> 64 bytes, rows reversed, as stored in ASN.1 (ДКЕ)."""
    if len(unpacked) != 128 or any(b > 15 for b in unpacked):
        raise ValueError("an unpacked s-box is 128 values from 0 to 15")
    out = bytearray(64)
    for row in range(8):
        for col in range(0, 16, 2):
            hi, lo = unpacked[row * 16 + col], unpacked[row * 16 + col + 1]
            out[(7 - row) * 8 + col // 2] = hi << 4 | lo
    return bytes(out)


def unpack_sbox(packed: bytes) -> bytes:
    """Inverse of :func:`pack_sbox`."""
    if len(packed) != 64:
        raise ValueError("a packed s-box is 64 bytes")
    out = bytearray(128)
    for row in range(8):
        for col in range(0, 16, 2):
            byte = packed[(7 - row) * 8 + col // 2]
            out[row * 16 + col] = byte >> 4
            out[row * 16 + col + 1] = byte & 0x0F
    return bytes(out)


@lru_cache(maxsize=8)
def _tables(sbox: bytes) -> tuple[tuple[int, ...], ...]:
    """Four 256-entry tables: substitution of one byte pair of nibbles, then rotation by 11."""
    rows = [sbox[i * 16 : (i + 1) * 16] for i in range(8)]  # k8, k7, ..., k1
    k8, k7, k6, k5, k4, k3, k2, k1 = rows

    def rot11(x: int) -> int:
        return ((x << 11) | (x >> 21)) & _M32

    t3 = tuple(rot11((k8[i >> 4] << 4 | k7[i & 15]) << 24) for i in range(256))
    t2 = tuple(rot11((k6[i >> 4] << 4 | k5[i & 15]) << 16) for i in range(256))
    t1 = tuple(rot11((k4[i >> 4] << 4 | k3[i & 15]) << 8) for i in range(256))
    t0 = tuple(rot11(k2[i >> 4] << 4 | k1[i & 15]) for i in range(256))
    return t0, t1, t2, t3


def _rounds(tables, subkeys, n0: int, n1: int) -> tuple[int, int]:
    """Run Feistel rounds in pairs; returns the two halves without the final swap."""
    t0, t1, t2, t3 = tables
    for i in range(0, len(subkeys), 2):
        x = (n0 + subkeys[i]) & _M32
        n1 ^= t3[x >> 24] ^ t2[(x >> 16) & 255] ^ t1[(x >> 8) & 255] ^ t0[x & 255]
        x = (n1 + subkeys[i + 1]) & _M32
        n0 ^= t3[x >> 24] ^ t2[(x >> 16) & 255] ^ t1[(x >> 8) & 255] ^ t0[x & 255]
    return n0, n1


def _resolve_sbox(sbox: bytes) -> bytes:
    sbox = bytes(sbox)
    if len(sbox) == 64:
        return unpack_sbox(sbox)
    if len(sbox) == 128 and all(b < 16 for b in sbox):
        return sbox
    raise ValueError("s-box must be 64 packed or 128 unpacked bytes")


class GOST28147:
    """The cipher with a fixed key and substitution table."""

    block_size = 8

    def __init__(self, key: bytes, sbox: bytes = DEFAULT_SBOX) -> None:
        if len(key) != 32:
            raise ValueError("ГОСТ 28147-89 keys are 32 bytes")
        self._tables = _tables(_resolve_sbox(sbox))
        k = struct.unpack("<8I", key)
        self._enc = tuple(k[i] for i in _ENC_ORDER)
        self._dec = tuple(k[i] for i in _DEC_ORDER)
        self._mac = tuple(k[i] for i in _MAC_ORDER)

    def encrypt_block(self, block: bytes) -> bytes:
        n0, n1 = _rounds(self._tables, self._enc, *struct.unpack("<2I", block))
        return struct.pack("<2I", n1, n0)

    def decrypt_block(self, block: bytes) -> bytes:
        n0, n1 = _rounds(self._tables, self._dec, *struct.unpack("<2I", block))
        return struct.pack("<2I", n1, n0)

    def encrypt_ecb(self, data: bytes) -> bytes:
        return b"".join(self.encrypt_block(b) for b in _blocks(data))

    def decrypt_ecb(self, data: bytes) -> bytes:
        return b"".join(self.decrypt_block(b) for b in _blocks(data))

    def encrypt_cfb(self, iv: bytes, data: bytes) -> bytes:
        out = bytearray()
        feedback = _check_iv(iv)
        for off in range(0, len(data), 8):
            chunk = data[off : off + 8]
            gamma = self.encrypt_block(feedback)
            feedback = bytes(a ^ b for a, b in zip(chunk, gamma, strict=False))
            out += feedback
        return bytes(out)

    def decrypt_cfb(self, iv: bytes, data: bytes) -> bytes:
        out = bytearray()
        feedback = _check_iv(iv)
        for off in range(0, len(data), 8):
            chunk = data[off : off + 8]
            gamma = self.encrypt_block(feedback)
            out += bytes(a ^ b for a, b in zip(chunk, gamma, strict=False))
            feedback = chunk
        return bytes(out)

    def mac(self, data: bytes) -> bytes:
        """32-bit imitovstavka: 16-round chaining over zero-padded blocks.

        A message of exactly one block gets a second, all-zero block, so that every input
        goes through at least two encryptions.
        """
        n0 = n1 = 0
        blocks = [data[i : i + 8].ljust(8, b"\0") for i in range(0, len(data), 8)]
        if len(data) == 8:
            blocks.append(bytes(8))
        for block in blocks:
            b0, b1 = struct.unpack("<2I", block)
            n0, n1 = _rounds(self._tables, self._mac, n0 ^ b0, n1 ^ b1)
        return struct.pack("<I", n0)


def _check_iv(iv: bytes) -> bytes:
    if len(iv) != 8:
        raise ValueError("ГОСТ 28147-89 IV is 8 bytes")
    return bytes(iv)


def _blocks(data: bytes):
    if len(data) % 8:
        raise ValueError("ECB data must be a whole number of 8-byte blocks")
    return (data[i : i + 8] for i in range(0, len(data), 8))
