"""ДСТУ 7564:2014 «Купина» hash function, 256-, 384- and 512-bit outputs.

The state is 8 rows by 8 columns of bytes (16 columns for outputs over 256 bits), each column a
little-endian 64-bit word. A block is compressed as h' = h ^ T⊕(h ^ m) ^ T+(m); the T-tables
fold SubBytes and MixColumns into one lookup per byte.
"""

from __future__ import annotations

from functools import lru_cache

_M64 = (1 << 64) - 1

# The four substitution tables π0..π3 of ДСТУ 7564:2014 (shared with ДСТУ 7624:2014).
_SBOXES = tuple(
    bytes.fromhex(h)
    for h in (
        "a8435f066b756c5971df879517f0d8096df31dcbc94d2caf79e097fd6f4b45393edda34fb4b69a0e1fbf15e149d293c6"
        "92729e61d163faeef419d5ad58a4bba1dcf2833742e47a329cccab4a8f6e04272ee7e25a9616232bc265660fbca94741"
        "3448fcb76a88a55386f95bdb387bc31e2233242836c7b23b8e77baf5149f08559b4cfe605cda1846cd7d21b03f1b89ff"
        "eb84693a9dd7d3706740b5de5d3091b1781101e5006898a0c502a6742d0ba276b3becebdaee98a311cecf19994aaf626"
        "2fefe88c3503d47ffb05c15e90203d82f7ea0a0d7ef8501ac40757b83c62e3c8ac526410d0d9130c122951b9cfd6738d"
        "8154c0ed4e44a72a8525e6ca7c8b5680",
        "cebbeb92eacb13c1e93ad6b2d29017f8421556b4651c8843c55c36baf557678d31f664589ef422aa750f02b1df6d734d"
        "7c262ef7085d443e9f14c8ae5410d8bc1a6b69f3bd33abfad19b684e169591ee4c638e5bcc3c19a181497bd96f3760ca"
        "e72b48fd9645fc41120d79e5898ce32030dcb76c4ab53f97d4622d06a4a5835f2adac9007ea255bf11d59ccf0e0a3d51"
        "7d931bfec44709860b8f9d6a07b9b0981832714bef3b70a0e440ffc3a9e678f98b46801e38e1b8a8e00c23761d252405"
        "f16e94289a84e8a34f77d385e252f282507a2f7453b361af3935decd1f99acad722cddd087be5ea6ec04c60334fbdb59"
        "b6c201f05aeda766217f8a27c7c029d7",
        "93d99ab5982245fcba6adf029fdc51594a172bc294f4bba362e471d4cd7016e1493cc0d85c9bad8553a17ac82de0d172"
        "a62cc4e37678b7b4093b0e414cdeb29025a5d7031100c32e92ef4e129d7dcb3510d54f9e4da955c6d07b1897d336e648"
        "56818f77cc9cb9e2acb82f15a47cda381e0b05d6146e6c7e66fdb1e560af5e3387c9f05d6d3f888dc7f71de9eced8029"
        "27cf99a8500f3724283095d23e5b4083b369571f071c8abc20ebce8eabee31a273f9ca3a1afb0dc1fefaf26fbd96dd43"
        "52b608f3aebe19893226b0ea4b6484826bf579bf015f75631b233d682a65e891f6ff1358f1470a7fc5a7e7615a064644"
        "4204a0db398654aa8c34218bf80c7467",
        "688dca4d734b4e2ad45226b3541e191f2203463d2d4a5383138ab7d52579f5bd582f0d02ed519e11f23e555ed1163c66"
        "705df34540cce8945608ce1a3ad2e1dfb5386e0ee5f4f986e94fd68523cf32993114aeeec848d330a19241b118c42c71"
        "724415fd37be5faa9b88d8ab899cfa60eabc620c24a6a8ec6720db7c28ddac5b347e10f17b8f63a0059a437721bf2709"
        "c39fb6d729c2ebc0a48b8c1dfbffc1b2972ef865f67507044933e4d9b9d042c76c90008e6f5001c5da473fcd69a2e27a"
        "a7c6930f0a06e62b96a31caf6a128439e7b082f7fe9d875c8135deb4a5fc80efcbbb6b76ba5a7d780b95e3ad74983b36"
        "646ddcf059a94c177f91b8c9571be061",
    )
)
_MDS_ROW = (0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04)


def _gf_mul(x: int, y: int) -> int:
    """Product in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1."""
    r = 0
    while y:
        if y & 1:
            r ^= x
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
        y >>= 1
    return r


@lru_cache(maxsize=1)
def _t_tables() -> tuple[tuple[int, ...], ...]:
    """T[i][v]: the column that byte v in row i contributes after SubBytes and MixColumns."""
    tables = []
    for i in range(8):
        sbox = _SBOXES[i % 4]
        table = []
        for v in range(256):
            s = sbox[v]
            word = 0
            for row in range(8):
                coeff = _MDS_ROW[(i - row) % 8]  # the MDS matrix is circulant
                word |= _gf_mul(s, coeff) << (8 * row)
            table.append(word)
        tables.append(tuple(table))
    return tuple(tables)


def _rounds(state: list[int], q: bool) -> list[int]:
    """T⊕ (q=False) or T+ (q=True) on a state of 8 or 16 columns."""
    t0, t1, t2, t3, t4, t5, t6, t7 = _t_tables()
    cols = len(state)
    last_shift = 7 if cols == 8 else 11
    shifts = (0, 1, 2, 3, 4, 5, 6, last_shift)
    for rnd in range(10 if cols == 8 else 14):
        if q:
            state = [
                (w + (0x00F0F0F0F0F0F0F3 ^ ((((cols - j - 1) << 4) ^ rnd) << 56))) & _M64
                for j, w in enumerate(state)
            ]
        else:
            state = [w ^ ((j << 4) ^ rnd) for j, w in enumerate(state)]
        src = [[state[(c - s) % cols] for c in range(cols)] for s in shifts]
        state = [
            t0[src[0][c] & 0xFF]
            ^ t1[(src[1][c] >> 8) & 0xFF]
            ^ t2[(src[2][c] >> 16) & 0xFF]
            ^ t3[(src[3][c] >> 24) & 0xFF]
            ^ t4[(src[4][c] >> 32) & 0xFF]
            ^ t5[(src[5][c] >> 40) & 0xFF]
            ^ t6[(src[6][c] >> 48) & 0xFF]
            ^ t7[src[7][c] >> 56]
            for c in range(cols)
        ]
    return state


def kupyna(data: bytes, digest_size: int = 32) -> bytes:
    """Купина hash of ``data``; ``digest_size`` is 32, 48 or 64 bytes."""
    if digest_size not in (32, 48, 64):
        raise ValueError("Купина digests are 32, 48 or 64 bytes")
    cols = 8 if digest_size <= 32 else 16
    block = 8 * cols
    state = [0] * cols
    state[0] = block  # IV: the state size in bytes in the first byte
    data = bytes(data)
    # a 1 bit, zeros, then the length in bits as 96 bits little-endian, to whole blocks
    length = (8 * len(data)).to_bytes(12, "little")
    padded = data + b"\x80" + bytes(-(len(data) + 13) % block) + length
    for off in range(0, len(padded), block):
        m = [int.from_bytes(padded[off + 8 * j : off + 8 * j + 8], "little") for j in range(cols)]
        p = _rounds([h ^ x for h, x in zip(state, m, strict=True)], q=False)
        q = _rounds(m, q=True)
        state = [h ^ a ^ b for h, a, b in zip(state, p, q, strict=True)]
    final = _rounds(state, q=False)
    out = b"".join((h ^ f).to_bytes(8, "little") for h, f in zip(state, final, strict=True))
    return out[-digest_size:]


def kupyna256(data: bytes) -> bytes:
    return kupyna(data, 32)
