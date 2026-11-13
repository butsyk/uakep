"""Layers 4 and 5: ГОСТ 34.311-95 hash, ГОСТ 28147-89 cipher, password-based KDFs.

Known answers:
* published ГОСТ 34.311 and ГОСТ 28147 vectors (ECB, CFB) with the default table;
* dstu-engine's test suite (an OpenSSL engine in C), tests/test.cpp: hash and CFB vectors;
* the tax service's signed samples (prro_docs): the messageDigest attribute of a signed
  command, and the imprint of a time-stamp token over a signature value.
"""

import hmac
import random

import pytest

from uakep.gost28147 import DEFAULT_SBOX, GOST28147, pack_sbox, unpack_sbox
from uakep.gost34311 import GOST34311, _psi, _step, gost34311, key6_kdf, pbkdf2

KEY = bytes(range(32))

HASH_VECTORS = [
    (
        b"12345678901234567890123456789011",
        "7686f3f4b113aadc97bca9ea054f41821f0676c5c28ffb987e41797a568e1ed4",
    ),
    (bytes(range(32)), "811cb06a8ee423182d9cc9d281f783908f4cfbaf47a68be8415d3499674a3063"),
    (b"123123", "34d4da2c04e9c1ceb933282069c864617d94ed7cc5c0a9840c0c1a99629df637"),
    (
        b"IGNORE THIS FILE. This file does nothing, contains no useful data, and might go away "
        b"in future releases.  Do not depend on this file or its contents.",
        "e9312d13d0e0d39aa4a00c77dcfb661883dd0ed8218af48a146168fc60f014dc",
    ),
    # dstu-engine tests/test.cpp
    (b"123456", "9648e3650b970d6239bc76cd4ca5944c2c9c27692402f4d4870588992be37d5d"),
    (
        b"abcdefghijklmnopqrstuvwxyz012345",
        "39e1eae583ce45bbfd328d9220e78185aaf9db324bdfbcaa83b6bf99657b9375",
    ),
    (
        b"abcdefghijklmnopqrstuvwxyz0123456789",
        "0bcec7202d925bc957935a09f3cfa1354fb8713cfc3634557c1de50c5e8c1251",
    ),
    # Tax service sample «запит_стану_РРО.json.signed»: content and its messageDigest attribute
    (
        b'{"NumFiscal":4000000001,"OfflineSessionId":null,"OfflineSeed":null,'
        b'"Command":"TransactionsRegistrarState"}',
        "b2a1a769ae40385103d2adcffdb58953e94f5e6521550267bee8eba5277c5ab5",
    ),
    # Tax service sample «чек.xml.signed»: signature value and its time-stamp token's imprint
    (
        bytes.fromhex(
            "0360AF0A9DE392CE15B575AB0759DC74069E12CC90D07A683C8FC64C8E4EC93F"
            "4CABF161E7DC5069ADC2E7E4D53A58C5175307FBBB943B70FB43E95DD9DDFA09"
        ),
        "bfef1f8d3a2ee0d69ba1ff00a882ee713ca4b8bb8fe49efc6b18d2ef53cf6f40",
    ),
]


@pytest.mark.parametrize(("data", "expected"), HASH_VECTORS)
def test_hash_known_answers(data, expected):
    assert gost34311(data).hex() == expected


def test_hash_incremental_matches_one_shot():
    rng = random.Random(3)
    data = rng.randbytes(200)
    for cut in [0, 1, 31, 32, 33, 64, 150, 200]:
        h = GOST34311(data[:cut])
        h.update(data[cut:])
        assert h.digest() == gost34311(data), cut
    h = GOST34311()
    for i in range(0, 200, 7):
        h.update(data[i : i + 7])
    assert h.hexdigest() == gost34311(data).hex()


def test_hash_digest_does_not_consume_state():
    h = GOST34311(b"abc")
    first = h.digest()
    assert h.digest() == first
    clone = h.copy()
    h.update(b"def")
    assert clone.digest() == first
    assert h.digest() == gost34311(b"abcdef")


def test_hash_empty_message_is_stable():
    assert gost34311(b"") == GOST34311().digest()
    assert len(gost34311(b"")) == 32


def test_step_tables_match_direct_psi():
    # The ψ tables replace 74 ψ steps; check them against the direct definition.
    rng = random.Random(9)
    for _ in range(3):
        h, m, s = rng.getrandbits(256), rng.getrandbits(256), rng.getrandbits(256)
        direct = s
        for _ in range(12):
            direct = _psi(direct)
        direct = _psi(direct ^ m) ^ h
        for _ in range(61):
            direct = _psi(direct)
        from uakep import gost34311 as mod

        l61, l62, l74 = mod._linear_maps()
        assert mod._apply(l74, s) ^ mod._apply(l62, m) ^ mod._apply(l61, h) == direct
    assert _step(0, 0) == _step(0, 0)  # deterministic


def test_hmac_matches_stdlib_construction():
    # Python's hmac module builds RFC 2104 HMAC from any hashlib-style class.
    for key, msg in [(b"password", b"salt"), (b"k" * 32, b"m" * 100), (b"", b"")]:
        reference = hmac.new(key, msg, digestmod=GOST34311).digest()
        inner = GOST34311(bytes(b ^ 0x36 for b in key.ljust(32, b"\0")) + msg).digest()
        ours = GOST34311(bytes(b ^ 0x5C for b in key.ljust(32, b"\0")) + inner).digest()
        assert ours == reference


def _pbkdf2_reference(password: bytes, salt: bytes, iterations: int) -> bytes:
    """RFC 8018 PBKDF2 on top of stdlib hmac, one block."""
    u = hmac.new(password, salt + b"\x00\x00\x00\x01", digestmod=GOST34311).digest()
    out = bytearray(u)
    for _ in range(iterations - 1):
        u = hmac.new(password, u, digestmod=GOST34311).digest()
        out = bytearray(a ^ b for a, b in zip(out, u, strict=True))
    return bytes(out)


@pytest.mark.parametrize("iterations", [1, 2, 5])
def test_pbkdf2_matches_rfc8018(iterations):
    salt = bytes.fromhex("31a58dc1462981189cf6c701e276c7553a5ab5f6e36d8418e4aa40c930cf3876")
    for password in [b"password", b"p" * 32, b""]:
        assert pbkdf2(password, salt, iterations) == _pbkdf2_reference(password, salt, iterations)


def test_pbkdf2_cuts_long_passwords_to_the_hash_block():
    salt = b"s" * 32
    assert pbkdf2(b"x" * 40, salt, 2) == pbkdf2(b"x" * 32, salt, 2)


def test_key6_kdf_counts_every_hash():
    h1 = gost34311(b"tect4")
    assert key6_kdf(b"tect4", 1) == h1
    assert key6_kdf(b"tect4", 3) == gost34311(gost34311(h1))


# -- ГОСТ 28147-89 ---------------------------------------------------------------------------


def test_ecb_known_answer():
    cipher = GOST28147(KEY)
    clear = bytes.fromhex("0001020304050607f1f2f3f4f5f6f7f8")
    expected = bytes.fromhex("e393a17df2b6de6f2086d8230c277432")
    assert cipher.encrypt_ecb(clear) == expected
    assert cipher.decrypt_ecb(expected) == clear


def test_cfb_known_answer():
    cipher = GOST28147(KEY)
    iv = bytes.fromhex("F1F2F3F4F5F6F7F8")
    clear = bytes.fromhex("0001020304050607f1f2f3f4f5f6f7f8")
    expected = bytes.fromhex("2087da2008227235a919d76142e8ce65")
    assert cipher.encrypt_cfb(iv, clear) == expected
    assert cipher.decrypt_cfb(iv, expected) == clear


@pytest.mark.parametrize(
    ("clear", "expected"),
    [
        # dstu-engine tests/test.cpp, key 00..1F, IV 07 06 05 04 03 02 01 00
        (b"123456", "23a8382932ae"),
        (b"abcdefgh", "73f8687962fe53c9"),
        (b'ZXCVBNM<>?ASDFGHJKL:"|', "48c2484b45d6799d0da011cdd22b1b2881aea4f4124f"),
    ],
)
def test_cfb_partial_blocks(clear, expected):
    cipher = GOST28147(KEY)
    iv = bytes([7, 6, 5, 4, 3, 2, 1, 0])
    assert cipher.encrypt_cfb(iv, clear).hex() == expected
    assert cipher.decrypt_cfb(iv, bytes.fromhex(expected)) == clear


def test_round_trips_with_other_sbox():
    sbox = DEFAULT_SBOX[::-1]
    rng = random.Random(11)
    key, iv, data = rng.randbytes(32), rng.randbytes(8), rng.randbytes(45)
    cipher = GOST28147(key, sbox)
    default = GOST28147(key)
    assert cipher.decrypt_cfb(iv, cipher.encrypt_cfb(iv, data)) == data
    assert cipher.encrypt_cfb(iv, data) != default.encrypt_cfb(iv, data)
    block = data[:8]
    assert cipher.decrypt_block(cipher.encrypt_block(block)) == block
    assert GOST28147(key, pack_sbox(sbox)).encrypt_block(block) == cipher.encrypt_block(block)


def test_sbox_packing():
    packed = pack_sbox(DEFAULT_SBOX)
    # The packed default table as it appears in certificates (DKE parameter).
    assert packed.hex() == (
        "a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17"
        "f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904"
    )
    assert unpack_sbox(packed) == DEFAULT_SBOX
    rng = random.Random(1)
    for _ in range(20):
        table = bytes(rng.randrange(16) for _ in range(128))
        assert unpack_sbox(pack_sbox(table)) == table


@pytest.mark.parametrize("bad", [b"\x00" * 63, b"\x10" * 128, b"\x00" * 100])
def test_rejects_bad_sbox(bad):
    with pytest.raises(ValueError):
        GOST28147(KEY, bad)


def test_rejects_bad_sizes():
    with pytest.raises(ValueError):
        pack_sbox(b"\x00" * 127)
    with pytest.raises(ValueError):
        unpack_sbox(b"\x00" * 65)
    with pytest.raises(ValueError):
        GOST28147(KEY[:31])
    with pytest.raises(ValueError):
        GOST28147(KEY).encrypt_ecb(b"1234567")
    with pytest.raises(ValueError):
        GOST28147(KEY).encrypt_cfb(b"1234567", b"data")


def _mac_chain(cipher: GOST28147, blocks: list[bytes]) -> bytes:
    """By definition: n = E16(n ^ block) per block, where E16 is the first 16 rounds of
    encryption (whose key order the ECB vectors pin down), without the final swap."""
    import struct

    from uakep.gost28147 import _rounds

    n0 = n1 = 0
    for block in blocks:
        b0, b1 = struct.unpack("<2I", block)
        n0, n1 = _rounds(cipher._tables, cipher._enc[:16], n0 ^ b0, n1 ^ b1)
    return struct.pack("<I", n0)


def test_mac_structure():
    cipher = GOST28147(KEY)
    assert cipher.mac(b"") == bytes(4)
    # Exactly one block gets a second, all-zero block.
    assert cipher.mac(b"12345678") == _mac_chain(cipher, [b"12345678", bytes(8)])
    assert cipher.mac(b"12345678") == cipher.mac(b"12345678" + bytes(8))
    # A short last block is zero-padded and gets no extra block.
    assert cipher.mac(b"1234567") == _mac_chain(cipher, [b"1234567\0"])
    assert cipher.mac(b"1234567") != cipher.mac(b"1234567\0")
    data = bytes(range(20))
    assert cipher.mac(data) == _mac_chain(cipher, [data[:8], data[8:16], data[16:] + bytes(4)])
    assert cipher.mac(data) != cipher.mac(data + b"\1")
