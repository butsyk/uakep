"""Layer 3: ДСТУ 4145-2002 signing and verification.

Known answers:
* the worked example of ДСТУ 4145-2002 (163-bit curve) and four more vectors, as published in
  BouncyCastle's DSTU4145Test (core/src/test/java/org/bouncycastle/crypto/test), which reads
  hash bytes little-endian like the software used by Ukrainian CAs;
* published DSTU_PB_257 vectors for signing with a known nonce, signature encoding and parsing.
"""

import random

import pytest

from uakep.curve import DSTU_PB_191, DSTU_PB_257, DSTU_PB_431, Curve, InvalidPointError
from uakep.dstu4145 import (
    PrivateKey,
    PublicKey,
    decode_signature,
    digest_to_field,
    encode_signature,
    signature_size,
)
from uakep.gf2m import BinaryField

C257 = DSTU_PB_257

# DSTU_PB_257 known answers
KAT_D = 0x2A45EAFE4CD469F811737780C57253360FBCC58E134C9A1FDCD10B0E4529A143
KAT_H = 0x6845214B63288A832A772E1FE6CB6C7D3528569E29A8B3584370FDC65F474242
KAT_E = 0x7A32849E569C8888F25DE6F69A839D75057383F473ACF559ABD3C5D683294CEB
KAT_S = 0xCCC6816453A903A1B641DF999011177DF420D21A72236D798532AEF42E224AB
KAT_R = 0x491FA1EF75EAEF75E1F20CF3918993AB37E06005EA8E204BC009A1FA61BB0FB2
KAT_PUB = (
    0x00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589,
    0x01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C,
)
KAT_SHORT = bytes.fromhex(
    "0440b20fbb61faa109c04b208eea0560e037ab938991f30cf2e175efea75efa11f49"
    "ab24e242ef2a5398d73622a7210d42df77110199f91d641b3a903a451668cc0c"
)


def test_kat_public_key():
    assert PrivateKey(C257, KAT_D).public_key().point == KAT_PUB


def test_kat_sign_known_nonce():
    r, s = PrivateKey(C257, KAT_D).sign_rs(KAT_H, nonce=KAT_E)
    assert (r, s) == (KAT_R, KAT_S)
    assert PublicKey(C257, KAT_PUB).verify_rs(KAT_H, r, s)


def test_kat_signature_encoding():
    assert encode_signature(C257, KAT_R, KAT_S) == KAT_SHORT[2:]
    assert decode_signature(KAT_SHORT[2:]) == (KAT_R, KAT_S)


def test_kat_verify_saved_signature():
    digest = bytes.fromhex("6845214B63288A832A772E1FE6CB6C7D3528569E29A8B3584370FDC65F474242")
    signature = bytes.fromhex(
        "044091d08086a623d7fc292418636f634e82e52f8f989d423dae6c64878699cc2f11d0332bfe45c2374"
        "21a41c2eb99e230f2629881c8e0c90be88610880e8c269d23"
    )
    pub = PrivateKey(C257, KAT_D).public_key()
    assert pub.verify(digest, signature[2:])
    assert not pub.verify(digest[:-1] + b"\x43", signature[2:])


def _bc_nonce(stream_hex: str, n: int) -> int:
    """The nonce BouncyCastle draws from its fixed test stream: L(n)-1 random bits."""
    bits = n.bit_length() - 1
    raw = bytes.fromhex(stream_hex)[: (bits + 7) // 8]
    return int.from_bytes(raw, "big") & ((1 << bits) - 1)


def _curve(m, ks, a, b, x, y, n):
    return Curve(BinaryField(m, ks), a, b, n, (x, y))


STANDARD_163 = _curve(
    163, (3, 6, 7), 1,
    0x5FF6108462A2DC8210AB403925E638A19C1455D21,
    0x72D867F93A93AC27DF9FF01AFFE74885C8C540420,
    0x0224A9C3947852B97C5599D5F4AB81122ADC3FD9B,
    0x400000000000000000002BEC12BE2262D39BCF14D,
)  # fmt: skip
CURVE_173 = _curve(
    173, (1, 2, 10), 0,
    0x108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9,
    0xBE6628EC3E67A91A4E470894FBA72B52C515F8AEE9,
    0xD9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C,
    0x800000000000000000000189B4E67606E3825BB2831,
)  # fmt: skip
CURVE_283 = _curve(
    283, (5, 7, 12), 1,
    0x27B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5,
    0x4D95820ACE761110824CE425C8089129487389B7F0E0A9D043DDC0BB0A4CC9EB25,
    0x954C9C4029B2C62DE35C2B9C2A164984BF1101951E3A68ED03DF234DDE5BB2013152F2,
    0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307,
)  # fmt: skip
CURVE_431 = Curve(
    DSTU_PB_431.field,
    1,
    DSTU_PB_431.b,
    DSTU_PB_431.order,
    (
        0x9548BCDF314CEEEAF099C780FFEFBF93F9FE5B5F55547603C9C8FC1A2774170882B3BE35E892C6D4296B8DEA282EC30FB344272791,
        0x4C6CBD7C62A8EEEFDE17A8B5E196E49A22CE6DE128ABD9FBD81FA4411AD5A38E2A810BEDE09A7C6226BCDCB4A4A5DA37B4725E00AA74,
    ),
)
BC_HASH = "0137187EA862117EF1484289470ECAC802C5A651FDA8"
STREAM_431 = (
    "0000C4224DBBD800988DBAA39DE838294C345CDA5F5929D1174AA8D9340A5E79D10ACADE6B53CF873E7301A3"
    "871C2073AD75AB530457"
)

BC_VECTORS = [
    pytest.param(
        STANDARD_163,
        0x183F60FDF7951FF47D67193F8D073790C1C9B5A3E,
        # ДСТУ 4145-2002 prints H(T) as a big-endian number; signers read hash bytes
        # little-endian, so the bytes handed to sign() are reversed.
        bytes.fromhex("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff")[::-1],
        0x1025E40BD97DB012B7A1D79DE8E12932D247F61C6,
        0x274EA2C0CAA014A0D80A424F59ADE7A93068D08A7,
        0x2100D86957331832B8E8C230F5BD6A332B3615ACA,
        id="dstu4145-2002-example-163",
    ),
    pytest.param(
        CURVE_173,
        0x955CD7E344303D1034E66933DC21C8044D42ADB8,
        bytes.fromhex(BC_HASH)[::-1],
        _bc_nonce("0000137449348C1249971759D99C252FFE1E14D8B31F", CURVE_173.order),
        0x13AE89746386709CDBD237CC5EC20CA30004A82EAD8,
        0x3597912CDD093B3E711CCB74A79D3C4AB4C7CCCDC60,
        id="bc-173",
    ),
    pytest.param(
        CURVE_283,
        0xB844EEAF15213E4BAD4FB84796D68F2448DB8EB7B4621EC0D51929874892C43E,
        bytes.fromhex(BC_HASH)[::-1],
        _bc_nonce(
            "00000000245383CB3AD41BF30F5F7E8FBA858509B2D5558C92D539A6D994BFA98BC6940E",
            CURVE_283.order,
        ),
        0x12A5EDCC38D92208FF23036D75B000C7E4BC0F9AF2D40B35F15D6FD15E01234E67781A8,
        0x2DE0775577F75B643CF5AFC80D4FE10B21100690F17E2CAB7BDC9B50EC87C5727AEB515,
        id="bc-283",
    ),
    pytest.param(
        CURVE_431,
        0xD0F97354E314191FD773E2404F478C8AEE0FF5109F39E6F37D1FEEC8B2ED1691D84C9882CC729E716A71CC013F66CAC60E29E22C,
        bytes.fromhex(BC_HASH)[::-1],
        _bc_nonce(STREAM_431, CURVE_431.order),
        0x1911FEFB1F494BEBCF8DFFDF5276946FF9C9F662192EE18C718DB47310A439C784FE07577B16E1EDBE16179876E0792A634F1C9C3A2E,
        0x3852170EE801C2083C52F1EA77B987A5432ACECD9C654F064E87BF179E0A397151EDBCA430082E43BD38A67B55424B5BBC7F2713F620,
        id="bc-431",
    ),
    pytest.param(
        CURVE_173,
        0x955CD7E344303D1034E66933DC21C8044D42ADB8,
        b"\xff" * 26,  # longer than the field: truncated to m bits
        _bc_nonce(STREAM_431, CURVE_173.order),
        0x6BB5C0CB82E5067485458EBFE81025F03B687C63A27,
        0x34D6B1868969B86ECF934167C8FE352C63D1074BD,
        id="bc-truncation",
    ),
]


@pytest.mark.parametrize(("curve", "d", "digest", "nonce", "r", "s"), BC_VECTORS)
def test_known_answers(curve, d, digest, nonce, r, s):
    key = PrivateKey(curve, d)
    signature = key.sign(digest, nonce=nonce)
    assert decode_signature(signature) == (r, s)
    assert key.public_key().verify(digest, signature)


def test_standard_example_intermediate_point():
    # ДСТУ 4145-2002 worked example: e*P for the example nonce.
    assert STANDARD_163.mul(0x1025E40BD97DB012B7A1D79DE8E12932D247F61C6, STANDARD_163.base) == (
        0x42A7D756D70E1C9BA62D2CB43707C35204EF3C67C,
        0x5310AE5E560464A95DC80286F17EB762EC544B15B,
    )


@pytest.mark.parametrize("curve", [DSTU_PB_191, DSTU_PB_257, DSTU_PB_431], ids=lambda c: c.name)
def test_round_trip_and_tampering(curve):
    rng = random.Random(curve.m)
    key = PrivateKey.generate(curve)
    pub = key.public_key()
    other = PrivateKey.generate(curve).public_key()
    for _ in range(3):
        digest = rng.randbytes(32)
        signature = key.sign(digest)
        assert len(signature) == signature_size(curve)
        assert pub.verify(digest, signature)
        assert not other.verify(digest, signature)
        assert not pub.verify(bytes([digest[0] ^ 1]) + digest[1:], signature)
        flipped = bytearray(signature)
        flipped[len(flipped) // 2 - 1] ^= 0x10
        assert not pub.verify(digest, bytes(flipped))


def test_signature_sizes():
    assert signature_size(DSTU_PB_191) == 48
    assert signature_size(DSTU_PB_257) == 64
    assert signature_size(DSTU_PB_431) == 108


def test_verify_rejects_out_of_range_components():
    pub = PublicKey(C257, KAT_PUB)
    n = C257.order
    assert not pub.verify_rs(KAT_H, 0, KAT_S)
    assert not pub.verify_rs(KAT_H, KAT_R, 0)
    assert not pub.verify_rs(KAT_H, n, KAT_S)
    assert not pub.verify_rs(KAT_H, KAT_R, n)
    assert not pub.verify_rs(KAT_H, KAT_R + n, KAT_S)


def test_range_checks_stop_forgeries_with_chosen_hash():
    """With a hash chosen after the fact, r = 0, s = 0, s = n and s + n would verify."""
    f = C257.field
    n = C257.order
    pub = PublicKey(C257, KAT_PUB)
    top = 1 << (n.bit_length() - 1)

    # r = 0: R = s*G, and h * x(R) truncates to zero.
    s = 5
    h = f.div(top, C257.mul(s, C257.base)[0])
    assert not pub.verify_rs(h, 0, s)

    # s = 0 or s = n: R = r*Q, and h * x(R) equals r.
    r = 777
    h = f.div(r, C257.mul(r, KAT_PUB)[0])
    assert not pub.verify_rs(h, r, 0)
    assert not pub.verify_rs(h, r, n)

    # s + n is the same point as s: only the range check rejects it.
    digest = bytes(range(32))
    key = PrivateKey(C257, KAT_D)
    r, s = decode_signature(key.sign(digest))
    assert pub.verify_rs(digest_to_field(C257, digest), r, s)
    assert not pub.verify_rs(digest_to_field(C257, digest), r, s + n)


def test_verify_rejects_point_at_infinity():
    # Choose s, r so that s*G + r*Q is infinity: with Q = -d*G that needs s = d*r mod n.
    d = 12345
    pub = PrivateKey(C257, d).public_key()
    r = 777
    assert not pub.verify_rs(1, r, d * r % C257.order)


def test_digest_to_field():
    assert digest_to_field(C257, b"\x01\x02") == 0x0201
    assert digest_to_field(C257, b"\x00" * 32) == 1  # ДСТУ 4145-2002: h = 0 is replaced by 1
    assert digest_to_field(C257, b"\xff" * 40) == C257.field.mask


def test_decode_signature_odd_length():
    assert decode_signature(b"\x01\x02\x03") == (0x0201, 0x03)


def test_private_key_validation_and_repr():
    with pytest.raises(ValueError):
        PrivateKey(C257, 0)
    with pytest.raises(ValueError):
        PrivateKey(C257, C257.order)
    assert repr(PrivateKey(C257, KAT_D)) == "PrivateKey(curve=DSTU_PB_257, d=<hidden>)"
    assert repr(PrivateKey(STANDARD_163, 5)) == "PrivateKey(curve=explicit, d=<hidden>)"


def test_public_key_validation():
    with pytest.raises(InvalidPointError):
        PublicKey(C257, (KAT_PUB[0], KAT_PUB[1] ^ 1))
    with pytest.raises(InvalidPointError):
        PublicKey(C257, None)
    pub = PublicKey.from_compressed(C257, PublicKey(C257, KAT_PUB).compressed())
    assert pub.point == KAT_PUB


def test_nonce_that_cannot_sign_raises():
    # nonce = n gives the point at infinity
    with pytest.raises(ValueError):
        PrivateKey(C257, KAT_D).sign_rs(KAT_H, nonce=C257.order)


def test_nonce_giving_r_zero_raises():
    # Pick h so that h * x(eG) has its low L(n)-1 bits clear: r truncates to zero.
    f = C257.field
    x = C257.mul(KAT_E, C257.base)[0]
    h = f.div(1 << (C257.order.bit_length() - 1), x)
    with pytest.raises(ValueError):
        PrivateKey(C257, KAT_D).sign_rs(h, nonce=KAT_E)


def test_nonce_giving_s_zero_raises():
    # Pick d so that s = e + d*r = 0 mod n for the known-answer nonce and hash.
    n = C257.order
    d = (-KAT_E * pow(KAT_R, -1, n)) % n
    with pytest.raises(ValueError):
        PrivateKey(C257, d).sign_rs(KAT_H, nonce=KAT_E)


def test_retry_when_first_nonce_fails(monkeypatch):
    # First draw gives e = n, so e*G is infinity and signing must draw again.
    draws = iter([C257.order - 1, KAT_E - 1])
    monkeypatch.setattr("uakep.dstu4145.secrets.randbelow", lambda _n: next(draws))
    assert PrivateKey(C257, KAT_D).sign_rs(KAT_H) == (KAT_R, KAT_S)


def test_signing_scalar_has_constant_bit_length(monkeypatch):
    """The scalar handed to point multiplication never reveals the nonce length."""
    key = PrivateKey(C257, KAT_D)
    seen = []
    original = Curve.mul

    def recording_mul(self, k, p):
        seen.append(k.bit_length())
        return original(self, k, p)

    monkeypatch.setattr(Curve, "mul", recording_mul)
    for nonce in (1, 2, 1 << 100, C257.order - 1, KAT_E, None):
        seen.clear()
        key.sign(b"\x07" * 32, nonce=nonce)
        assert seen == [C257.order.bit_length() + 1]
    seen.clear()
    key.public_key()
    assert seen == [C257.order.bit_length() + 1]
