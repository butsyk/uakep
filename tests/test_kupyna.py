"""Layer 4b: ДСТУ 7564:2014 «Купина».

Ground truth: the standard's example (Купина-256 of the bytes 00..3F) and further published
vectors; ЦЗО's Купина CAdES example, whose messageDigest attribute is Купина-256 of «Test\\r\\n»;
ЦЗО's Купина certificates, whose subjectKeyIdentifier is Купина-256 of the public key.
A literal, slow implementation of the round operations checks the table-driven one.
"""

import random

import pytest

from uakep import asn1
from uakep.certificate import Certificate
from uakep.kupyna import _MDS_ROW, _SBOXES, _gf_mul, kupyna, kupyna256

from .conftest import data_file


@pytest.mark.parametrize(
    ("data", "size", "expected"),
    [
        (
            bytes(range(64)),
            32,
            "08f4ee6f1be6903b324c4e27990cb24ef69dd58dbe84813ee0a52f6631239875",
        ),
        (
            b"",
            64,
            "656b2f4cd71462388b64a37043ea55dbe445d452aecd46c3298343314ef04019"
            "bcfa3f04265a9857f91be91fce197096187ceda78c9c1c021c294a0689198538",
        ),
        (
            bytes.fromhex(
                "2d20726f6c65206469726563746f72206661696c757265206f6e206d697373696e67206564"
                "7220636f64653b0a2d20706572662070726f66696c652063747820616e642063757276652"
                "06f626a65637420636f6e7465787420696e6974696c69736174696f6e3b0a2d206f757470"
                "757420756e636f6d70726573736564206b6579733b0a2d207368617265206b6579207061"
                "636b2f756e7061636b20616e6420776e6166206361636865206163726f73732064696666"
                "6572656e74206b6579732028636f6e7374616e742074696d653f3f3f292e0a"
            ),
            32,
            "9398e9eb82463b9b33da1fb96dca35d1aff8a9d186dc3b801c1092c3715e4994",
        ),
    ],
)
def test_published_vectors(data, size, expected):
    assert kupyna(data, size).hex() == expected


def test_czo_message_digest():
    sd = asn1.ContentInfo.load(data_file("czo", "DSTU-7564_CAdES-BES.p7s"))["content"]
    signer_info = sd["signer_infos"][0]
    assert signer_info["digest_algorithm"]["algorithm"].dotted == "1.2.804.2.1.1.1.1.2.2.1"
    digest = next(
        a["values"][0].contents
        for a in signer_info["signed_attrs"]
        if a["type"].dotted == asn1.ID_MESSAGE_DIGEST
    )
    assert digest == kupyna256(b"Test\r\n")


@pytest.mark.parametrize("name", ["DSTU-7564_sign.cer", "DSTU-7564_encryption.cer"])
def test_czo_key_identifiers(name):
    cert = Certificate.load(data_file("czo", name))
    assert cert.subject_key_identifier == kupyna256(cert.public_key.to_octet_string())


# -- a literal implementation of the standard, byte by byte ----------------------------------


def _reference(data: bytes, size: int) -> bytes:
    cols = 8 if size <= 32 else 16
    rounds = 10 if cols == 8 else 14
    block = 8 * cols

    def to_state(b):  # state[row][col], bytes taken column by column
        return [[b[8 * c + r] for c in range(cols)] for r in range(8)]

    def to_bytes(s):
        return bytes(s[r][c] for c in range(cols) for r in range(8))

    def permute(s, q):
        s = [row[:] for row in s]
        for rnd in range(rounds):
            for c in range(cols):
                if q:  # add 0x00F0F0F0F0F0F0F3 ^ (const << 56) to the column, mod 2^64
                    word = int.from_bytes(bytes(s[r][c] for r in range(8)), "little")
                    const = 0x00F0F0F0F0F0F0F3 ^ (((((cols - c - 1) << 4) ^ rnd) & 0xFF) << 56)
                    word = (word + const) % (1 << 64)
                    for r in range(8):
                        s[r][c] = (word >> (8 * r)) & 0xFF
                else:
                    s[0][c] ^= ((c << 4) ^ rnd) & 0xFF
            s = [[_SBOXES[r % 4][s[r][c]] for c in range(cols)] for r in range(8)]
            shifted = [[0] * cols for _ in range(8)]
            for r in range(8):
                shift = 11 if (r == 7 and cols == 16) else r
                for c in range(cols):
                    shifted[r][(c + shift) % cols] = s[r][c]
            s = shifted
            mixed = [[0] * cols for _ in range(8)]
            for c in range(cols):
                for r in range(8):
                    acc = 0
                    for b in range(8):
                        acc ^= _gf_mul(s[b][c], _MDS_ROW[(b - r) % 8])
                    mixed[r][c] = acc
            s = mixed
        return s

    state = bytearray(block)
    state[0] = block
    h = to_state(bytes(state))
    bits = 8 * len(data)
    data = data + b"\x80"
    while len(data) % block != block - 12:
        data += b"\x00"
    data += bits.to_bytes(12, "little")
    for off in range(0, len(data), block):
        m = to_state(data[off : off + block])
        p = permute([[h[r][c] ^ m[r][c] for c in range(cols)] for r in range(8)], q=False)
        q = permute(m, q=True)
        h = [[h[r][c] ^ p[r][c] ^ q[r][c] for c in range(cols)] for r in range(8)]
    t = permute(h, q=False)
    return to_bytes([[h[r][c] ^ t[r][c] for c in range(cols)] for r in range(8)])[-size:]


def test_reference_agrees_on_the_standard_example():
    assert _reference(bytes(range(64)), 32) == kupyna(bytes(range(64)), 32)


@pytest.mark.parametrize("size", [32, 64])
def test_tables_match_the_literal_rounds(size):
    rng = random.Random(size)
    block = 64 if size == 32 else 128
    lengths = [0, 1, block - 14, block - 13, block - 12, block - 1, block, block + 1]
    for length in lengths:
        data = rng.randbytes(length)
        assert kupyna(data, size) == _reference(data, size), length


def test_384_is_the_512_state_truncated():
    data = b"uakep"
    assert kupyna(data, 48) == _reference(data, 48)
    assert len(kupyna(data, 48)) == 48


@pytest.mark.parametrize("size", [0, 16, 33, 128])
def test_rejects_other_sizes(size):
    with pytest.raises(ValueError):
        kupyna(b"", size)
