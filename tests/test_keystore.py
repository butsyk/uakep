"""Layer 6: IIT Key-6.dat containers and ДСТУ 4145 PKCS#8 keys.

Ground truth: dstu-engine's Key-6.dat (tests/data/dstu-engine), written by IIT software. Beside
each key it stores IIT's key identifier, the ГОСТ 34.311 hash of the public key; the keys uakep
reads must hash to the same values.
"""

import pytest
from asn1crypto import core

from uakep import asn1
from uakep.asn1 import UnsupportedError
from uakep.curve import DSTU_PB_257, DSTU_PB_431
from uakep.dstu4145 import PrivateKey
from uakep.gost28147 import GOST28147
from uakep.gost34311 import gost34311, key6_kdf
from uakep.keystore import (
    KeyFileError,
    WrongPasswordError,
    key_identifier,
    password_candidates,
    private_keys_from_pkcs8,
    read_key6,
)

from .conftest import data_file

KEY6 = data_file("dstu-engine", "Key-6.dat")
# IIT's key identifiers, stored in Key-6.dat as attributes 1.3.6.1.4.1.19398.1.1.2.1 and .2.5
IIT_KEY_ID_1 = "7e9e345dd2cfd91ebadbe23c22eb9fac6bef65552ed42f56f9bac4aac5cb2d06"
IIT_KEY_ID_2 = "7cebcd9412612324209f4cd81cd16a7a9a0ba05a75ad05d38bae9a7483d8f719"


@pytest.fixture(scope="module")
def key6_keys():
    return read_key6(KEY6, "tect4")


@pytest.fixture
def fast_kdf(monkeypatch):
    """Synthetic containers test the container logic; one hash stands in for 10 000."""
    monkeypatch.setattr("uakep.keystore.key6_kdf", gost34311)
    return gost34311


def test_key6_keys_match_iit_key_identifiers(key6_keys):
    first, second = key6_keys
    assert first.curve is DSTU_PB_257
    assert second.curve is DSTU_PB_431
    assert key_identifier(first).hex() == IIT_KEY_ID_1
    assert key_identifier(second).hex() == IIT_KEY_ID_2


def test_key6_identifiers_are_the_ones_stored_in_the_file():
    # The expected values above are read back out of the container itself.
    store = asn1.IitStore.load(KEY6)
    body = store["data"].native + (store["header"]["params"]["pad"].native or b"")
    plain = GOST28147(key6_kdf(b"tect4")).decrypt_ecb(body)
    info = asn1.DstuPrivateKey.load(plain, strict=False)
    stored = {a["type"].dotted: a["values"][0].contents.hex() for a in info["attributes"]}
    assert stored["1.3.6.1.4.1.19398.1.1.2.1"] == IIT_KEY_ID_1
    assert stored["1.3.6.1.4.1.19398.1.1.2.5"] == IIT_KEY_ID_2


def test_key6_password_as_bytes():
    assert len(read_key6(KEY6, bytearray(b"tect4"))) == 2


@pytest.mark.parametrize("password", ["tect5", "тест4"])
def test_key6_wrong_password(password):
    with pytest.raises(WrongPasswordError):
        read_key6(KEY6, password)


def test_password_candidates():
    assert list(password_candidates("abc")) == [b"abc"]
    assert list(password_candidates(b"\xff")) == [b"\xff"]
    assert list(password_candidates("Пароль")) == ["Пароль".encode("cp1251"), "Пароль".encode()]
    assert list(password_candidates("密码")) == ["密码".encode()]  # not in Windows-1251


def _make_key6(plain: bytes, password: bytes, kdf, *, mac: bytes | None = None) -> bytes:
    """A Key-6.dat around ``plain``, built the way IIT's containers are laid out."""
    cipher = GOST28147(kdf(password))
    pad = bytes(-len(plain) % 8)
    encrypted = cipher.encrypt_ecb(plain + pad)
    return asn1.IitStore(
        {
            "header": {
                "type": asn1.IIT_STORE,
                "params": {
                    "mac": cipher.mac(plain) if mac is None else mac,
                    "pad": encrypted[len(plain) :],
                },
            },
            "data": encrypted[: len(plain)],
        }
    ).dump()


def _pkcs8(d: int, curve_spec, attributes=None) -> bytes:
    value = {
        "version": 0,
        "algorithm": {"algorithm": asn1.DSTU4145_LE, "parameters": {"curve": curve_spec}},
        "private_key": d.to_bytes(32, "little"),
    }
    if attributes is not None:
        value["attributes"] = attributes
    return asn1.DstuPrivateKey(value).dump()


NAMED_257 = asn1.CurveSpec(name="named", value="1.2.804.2.1.1.1.1.3.1.1.2.6")


def test_key6_non_ascii_password_in_either_encoding(fast_kdf):
    plain = _pkcs8(12345, NAMED_257)
    for encoding in ("cp1251", "utf-8"):
        container = _make_key6(plain, "Пароль".encode(encoding), fast_kdf)
        (key,) = read_key6(container, "Пароль")
        assert key.d == 12345


@pytest.mark.parametrize(
    "container",
    [
        b"",
        b"\x30\x03\x02\x01\x00",
        asn1.IitStore(
            {"header": {"type": "1.2.3", "params": {"mac": b"1234"}}, "data": b"x" * 8}
        ).dump(),
        asn1.IitStore(
            {"header": {"type": asn1.IIT_STORE, "params": {"mac": b"123"}}, "data": b"x" * 8}
        ).dump(),
        asn1.IitStore(
            {"header": {"type": asn1.IIT_STORE, "params": {"mac": b"1234"}}, "data": b"x" * 7}
        ).dump(),
    ],
    ids=["empty", "not-a-store", "wrong-type", "short-mac", "partial-block"],
)
def test_key6_rejects_damaged_containers(container, fast_kdf):
    with pytest.raises(KeyFileError) as raised:
        read_key6(container, "tect4")
    assert not isinstance(raised.value, WrongPasswordError)  # damage is not a password problem


def test_key6_without_pad_field(fast_kdf):
    plain = _pkcs8(777, NAMED_257)
    plain += bytes(-len(plain) % 8)  # a whole number of blocks, so no pad is needed
    cipher = GOST28147(fast_kdf(b"pw"))
    container = asn1.IitStore(
        {
            "header": {"type": asn1.IIT_STORE, "params": {"mac": cipher.mac(plain)}},
            "data": cipher.encrypt_ecb(plain),
        }
    ).dump()
    assert read_key6(container, "pw")[0].d == 777


def test_key6_plaintext_that_is_not_a_key(fast_kdf):
    with pytest.raises(KeyFileError):
        read_key6(_make_key6(b"\x04\x02ab", b"pw", fast_kdf), "pw")


def test_pkcs8_named_curve_with_dke():
    spec = {"curve": NAMED_257, "dke": bytes(64)}
    der = asn1.DstuPrivateKey(
        {
            "version": 0,
            "algorithm": {"algorithm": asn1.DSTU4145_LE, "parameters": spec},
            "private_key": (5).to_bytes(32, "little"),
        }
    ).dump()
    (key,) = private_keys_from_pkcs8(der)
    assert key.curve is DSTU_PB_257 and key.d == 5


def test_pkcs8_rejects_other_algorithms_and_curves():
    with pytest.raises(UnsupportedError):
        private_keys_from_pkcs8(
            asn1.DstuPrivateKey(
                {
                    "version": 0,
                    "algorithm": {"algorithm": "1.2.840.10045.2.1"},
                    "private_key": b"\x01",
                }
            ).dump()
        )
    with pytest.raises(UnsupportedError, match="not bundled"):
        private_keys_from_pkcs8(
            _pkcs8(5, asn1.CurveSpec(name="named", value="1.2.804.2.1.1.1.1.3.1.1.2.0"))
        )
    with pytest.raises(UnsupportedError, match="unknown curve"):
        private_keys_from_pkcs8(_pkcs8(5, asn1.CurveSpec(name="named", value="1.2.3.4")))
    with pytest.raises(KeyFileError):
        private_keys_from_pkcs8(_pkcs8(0, NAMED_257))  # d out of range
    with pytest.raises(KeyFileError):
        private_keys_from_pkcs8(b"\x30\x00")


def test_pkcs8_attribute_key_needs_both_attributes():
    bits = core.BitString(tuple(0 for _ in range(16)))
    only_bits = [{"type": asn1.IIT_KEY_BITS, "values": [bits]}]
    assert len(private_keys_from_pkcs8(_pkcs8(5, NAMED_257, only_bits))) == 1
    other = [{"type": "1.2.3", "values": [core.OctetString(b"x")]}]
    assert len(private_keys_from_pkcs8(_pkcs8(5, NAMED_257, other))) == 1


def test_explicit_curve_spec_round_trip():
    # DSTU_PB_431 spelled out little-endian, as in certificates and private keys
    c = DSTU_PB_431
    n_bytes = (c.m + 7) // 8
    spec = asn1.CurveSpec(
        name="explicit",
        value={
            "field": {
                "m": c.m,
                "poly": asn1.Polynomial(name="pentanomial", value={"k": 1, "j": 3, "l": 5}),
            },
            "a": c.a,
            "b": c.b.to_bytes(n_bytes, "little"),
            "n": c.order,
            "bp": c.compress(c.base).to_bytes(n_bytes, "little"),
        },
    )
    assert asn1.curve_from_spec(asn1.CurveSpec.load(spec.dump())) is DSTU_PB_431
    # Not a named curve: another base point gives a new Curve with no name.
    other_base = c.compress(c.mul(2, c.base)).to_bytes(n_bytes, "little")
    spec2 = asn1.CurveSpec.load(spec.dump())
    spec2.chosen["bp"] = other_base
    custom = asn1.curve_from_spec(asn1.CurveSpec.load(spec2.dump()))
    assert custom.name is None and custom != DSTU_PB_431


def test_private_key_from_attribute_reads_reversed_bits(key6_keys):
    # The second key's scalar is stored bit-reversed; check one constructed by hand too.
    d = 0b1011 << 400 | 0b1101
    raw = int(format(d, "0432b")[::-1], 2).to_bytes(54, "big")
    bits = core.BitString.load(b"\x03" + bytes([55, 0]) + raw)
    n_bytes = 54
    c = DSTU_PB_431
    spec = asn1.DstuParams(
        {
            "curve": asn1.CurveSpec(
                name="explicit",
                value={
                    "field": {
                        "m": c.m,
                        "poly": asn1.Polynomial(name="pentanomial", value={"k": 1, "j": 3, "l": 5}),
                    },
                    "a": c.a,
                    "b": c.b.to_bytes(n_bytes, "big"),
                    "n": c.order,
                    "bp": c.compress(c.base).to_bytes(n_bytes, "big"),
                },
            )
        }
    )
    attrs = [
        {"type": asn1.IIT_KEY_BITS, "values": [bits]},
        {"type": asn1.IIT_KEY_CURVE, "values": [spec]},
    ]
    keys = private_keys_from_pkcs8(_pkcs8(5, NAMED_257, attrs))
    assert keys[1].curve is DSTU_PB_431 and keys[1].d == d
    assert isinstance(keys[1], PrivateKey)
