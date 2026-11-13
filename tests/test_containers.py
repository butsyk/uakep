"""Layer 10: PKCS#12 (.pfx), Java KeyStore (.jks), PBES2 PKCS#8, and load_key().

Ground truth (dstu-engine's test files):
* Key-6.pfx: each key bag's localKeyId, written by the CA software, is the ГОСТ 34.311 hash of
  the public key of the key inside it;
* key.jks: its chain holds the owner's CA-issued certificate, which must match the second key
  (the one stored bit-reversed in IIT attributes).
Synthetic containers below use one PBKDF2 iteration, so the error paths stay fast.
"""

import hashlib
import struct

import pytest
from asn1crypto import core

from uakep import asn1, cades
from uakep.asn1 import UnsupportedError
from uakep.cades import SigningKey
from uakep.certificate import Certificate
from uakep.curve import DSTU_PB_257, DSTU_PB_431
from uakep.dstu4145 import PrivateKey
from uakep.gost28147 import GOST28147
from uakep.gost34311 import pbkdf2
from uakep.keystore import (
    KeyFileError,
    WrongPasswordError,
    key_identifier,
    load_key,
    read_jks,
    read_key_file,
    read_pfx,
)

from .conftest import certificate_for, data_file

PFX = data_file("dstu-engine", "Key-6.pfx")
JKS = data_file("dstu-engine", "key.jks")
KEY6 = data_file("dstu-engine", "Key-6.dat")


@pytest.fixture(scope="module")
def pfx_contents():
    return read_pfx(PFX, "testplat2021")


@pytest.fixture(scope="module")
def jks_contents():
    return read_jks(JKS, "qwerty")


def _local_key_ids(pfx: bytes) -> list[bytes]:
    outer = asn1.Pfx.load(pfx)
    safes = asn1.AuthenticatedSafe.load(
        outer["auth_safe"]["content"].parse(core.OctetString).native
    )
    bags = asn1.SafeContents.load(safes[0]["content"].parse(core.OctetString).native)
    return [
        next(
            a["values"][0].contents
            for a in bag["bag_attributes"]
            if a["type"].dotted == "1.2.840.113549.1.9.21"
        )
        for bag in bags
    ]


def test_pfx_keys_match_their_local_key_ids(pfx_contents):
    keys, certs = pfx_contents
    assert [k.curve for k in keys] == [DSTU_PB_257, DSTU_PB_431]
    assert certs == []
    assert [key_identifier(k) for k in keys] == _local_key_ids(PFX)


def test_pfx_wrong_password():
    with pytest.raises(WrongPasswordError):
        read_pfx(PFX, "testplat2022")


def test_jks_owner_certificate_matches_the_second_key(jks_contents):
    keys, certs = jks_contents
    assert [k.curve for k in keys] == [DSTU_PB_257, DSTU_PB_431]
    owners = [Certificate(c) for c in certs]
    assert [c.owner_name for c in owners] == [
        "Центральний засвідчувальний орган",
        "КНЕДП - ІДД ДПС",
        "Нестеренко Володимир Борисович (Тест)",
    ]
    owner = owners[2]
    assert owner.key_usage == {"key_agreement"}
    assert owner.public_key == keys[1].public_key()
    assert owner.subject_key_identifier == key_identifier(keys[1])


def test_jks_wrong_password():
    with pytest.raises(WrongPasswordError):
        read_jks(JKS, "123456")  # the store password, not the key's


def test_jks_has_no_signing_certificate():
    with pytest.raises(KeyFileError, match="no signing certificate"):
        load_key(JKS, "qwerty")
    encryption_cert = Certificate(read_jks(JKS, "qwerty")[1][2])
    with pytest.raises(KeyFileError, match="not for signing"):
        load_key(JKS, "qwerty", certificate=encryption_cert)


def test_read_key_file_recognises_formats(jks_contents):
    assert [k.d for k in read_key_file(JKS, "qwerty")[0]] == [k.d for k in jks_contents[0]]
    assert len(read_key_file(KEY6, "tect4")[0]) == 2  # PKCS#12 detection: test_pfx_bag_kinds


# -- load_key ------------------------------------------------------------------------------


def test_load_key_from_key6_with_its_certificate():
    first = read_key_file(KEY6, "tect4")[0][0]
    cert = certificate_for(first)
    key = load_key(KEY6, "tect4", certificate=cert)
    assert isinstance(key, SigningKey)
    assert key.private_key.d == first.d and key.certificate == cert


def test_load_key_accepts_paths_and_bytes(tmp_path):
    cert = certificate_for(KEY)
    (tmp_path / "key.p8").write_bytes(_pkcs8())
    (tmp_path / "signer.cer").write_bytes(cert.der)
    for source in (tmp_path / "key.p8", str(tmp_path / "key.p8"), _pkcs8()):
        for certificate in (cert, cert.der, tmp_path / "signer.cer", str(tmp_path / "signer.cer")):
            key = load_key(source, "unused", certificate=certificate)
            assert key.private_key.d == KEY.d and key.certificate == cert


def test_load_key_certificate_for_another_key():
    stranger = certificate_for(PrivateKey(DSTU_PB_257, 31337))
    with pytest.raises(KeyFileError, match="no key in the key file matches"):
        load_key(KEY6, "tect4", certificate=stranger)


def test_load_key_without_certificate_for_key6():
    with pytest.raises(KeyFileError, match="no signing certificate"):
        load_key(KEY6, "tect4")


# -- synthetic containers --------------------------------------------------------------------

KEY = PrivateKey(DSTU_PB_257, 0x1234567890ABCDEF)
NAMED_257 = asn1.CurveSpec(name="named", value="1.2.804.2.1.1.1.1.3.1.1.2.6")


def _pkcs8(key: PrivateKey = KEY) -> bytes:
    return asn1.DstuPrivateKey(
        {
            "version": 0,
            "algorithm": {"algorithm": asn1.DSTU4145_LE, "parameters": {"curve": NAMED_257}},
            "private_key": key.d.to_bytes(32, "little"),
        }
    ).dump()


def _pbes2(
    password: bytes,
    plain: bytes,
    *,
    prf: str | None = asn1.GOST34311_HMAC,
    cipher: str = asn1.GOST28147_CFB,
    kdf: str = asn1.PBKDF2,
    scheme: str = asn1.PBES2,
):
    salt, iv = b"\x11" * 32, b"\x22" * 8
    encrypted = GOST28147(pbkdf2(password, salt, 1)).encrypt_cfb(iv, plain)
    kdf_params = {"salt": salt, "iteration_count": 1}
    if prf is not None:
        kdf_params["prf"] = {"algorithm": prf, "parameters": core.Null()}
    params = asn1.Pbes2Params(
        {
            "key_derivation_func": {"algorithm": kdf, "parameters": asn1.Pbkdf2Params(kdf_params)},
            "encryption_scheme": {
                "algorithm": cipher,
                "parameters": asn1.Gost28147Params({"iv": iv}),
            },
        }
    )
    algorithm = asn1.AlgorithmIdentifier({"algorithm": scheme, "parameters": params})
    return algorithm, encrypted


def _encrypted_key(password: bytes, **kwargs) -> bytes:
    algorithm, encrypted = _pbes2(password, _pkcs8(), **kwargs)
    return asn1.EncryptedPrivateKeyInfo(
        {"encryption_algorithm": algorithm, "encrypted_data": encrypted}
    ).dump()


def test_pbes2_pkcs8_key_file():
    (key,) = read_key_file(_encrypted_key(b"secret"), "secret")[0]
    assert key.d == KEY.d
    with pytest.raises(WrongPasswordError):
        read_key_file(_encrypted_key(b"secret"), "Secret")


def test_pbes2_non_ascii_passwords_try_utf8_first():
    for encoding in ("utf-8", "cp1251"):
        (key,) = read_key_file(_encrypted_key("Пароль".encode(encoding)), "Пароль")[0]
        assert key.d == KEY.d


@pytest.mark.parametrize(
    "kwargs",
    [
        {"prf": None},  # PBKDF2's default HMAC-SHA1
        {"prf": "1.2.804.2.1.1.1.1.2.2.4"},  # Купина MAC: Kalyna containers
        {"cipher": "1.2.804.2.1.1.1.1.1.3.5.2"},  # Kalyna CBC
        {"kdf": "1.2.840.113549.1.5.3"},
    ],
    ids=["sha1-prf", "kupyna-prf", "kalyna", "other-kdf"],
)
def test_pbes2_unsupported_profiles(kwargs):
    with pytest.raises(UnsupportedError):
        read_key_file(_encrypted_key(b"pw", **kwargs), "pw")


def test_pbes2_other_scheme():
    data = _encrypted_key(b"pw", scheme="1.2.840.113549.1.5.3")
    with pytest.raises(KeyFileError):  # not recognised as PBES2 at all
        read_key_file(data, "pw")
    algorithm, encrypted = _pbes2(b"pw", _pkcs8(), scheme="1.2.840.113549.1.5.3")
    from uakep.keystore import _pbes2_decrypt

    with pytest.raises(UnsupportedError):
        _pbes2_decrypt(algorithm, encrypted, b"pw")


def test_unencrypted_pkcs8_key_file():
    assert read_key_file(_pkcs8(), "ignored")[0][0].d == KEY.d


@pytest.mark.parametrize(
    "data", [b"", b"garbage", b"\x30\x03\x01\x01\xff", b"\x30\x05\x30\x03\x06\x01\x2a"]
)
def test_unknown_key_files(data):
    with pytest.raises(KeyFileError):
        read_key_file(data, "pw")


def _oid(oid: str) -> bytes:
    return core.ObjectIdentifier(oid).dump()


def _bag(bag_id: str, value: bytes) -> bytes:
    """SafeBag: bagId, [0] EXPLICIT bagValue."""
    return cades._seq(_oid(bag_id), cades._der(0xA0, value))


def _content_info(content_type: str, content: bytes) -> bytes:
    return cades._seq(_oid(content_type), cades._der(0xA0, content))


def _data_safe(bags: list[bytes]) -> bytes:
    return _content_info(asn1.ID_DATA, core.OctetString(cades._seq(*bags)).dump())


def _pfx(safes: list[bytes]) -> bytes:
    auth_safe = core.OctetString(cades._seq(*safes)).dump()
    return cades._seq(core.Integer(3).dump(), _content_info(asn1.ID_DATA, auth_safe))


def test_pfx_bag_kinds():
    cert = certificate_for(KEY)
    cert_bag = asn1.CertBag({"cert_id": asn1.X509_CERTIFICATE, "cert_value": cert.der}).dump()
    sdsi_bag = asn1.CertBag({"cert_id": "1.2.840.113549.1.9.22.2", "cert_value": b"sdsi"}).dump()
    nested = cades._seq(_bag(asn1.KEY_BAG, _pkcs8(PrivateKey(DSTU_PB_257, 77))))
    algorithm, encrypted = _pbes2(b"pw", cades._seq(_bag(asn1.CERT_BAG, cert_bag)))
    encrypted_data = cades._seq(
        core.Integer(0).dump(),
        cades._seq(_oid(asn1.ID_DATA), algorithm.dump(), cades._der(0x80, encrypted)),
    )
    pfx = _pfx(
        [
            _data_safe(
                [
                    _bag(asn1.SHROUDED_KEY_BAG, _encrypted_key(b"pw")),
                    _bag(asn1.KEY_BAG, _pkcs8(PrivateKey(DSTU_PB_257, 55))),
                    _bag(asn1.CERT_BAG, sdsi_bag),
                    _bag(asn1.SAFE_CONTENTS_BAG, nested),
                    _bag("1.2.840.113549.1.12.10.1.5", core.OctetString(b"secret").dump()),
                ]
            ),
            _content_info(asn1.ID_ENCRYPTED_DATA, encrypted_data),
            _content_info("1.2.840.113549.1.7.3", core.OctetString(b"x").dump()),  # skipped
        ]
    )
    keys, certs = read_pfx(pfx, "pw")
    assert [k.d for k in keys] == [KEY.d, 55, 77]
    assert certs == [cert.der]
    key = load_key(pfx, "pw")
    assert key.private_key.d == KEY.d and key.certificate == cert
    with pytest.raises(WrongPasswordError):
        read_pfx(_pfx([_content_info(asn1.ID_ENCRYPTED_DATA, encrypted_data)]), "px")


def test_pfx_damaged():
    no_content = cades._seq(core.Integer(3).dump(), cades._seq(_oid(asn1.ID_DATA)))
    with pytest.raises(KeyFileError):
        read_pfx(no_content, "pw")


# -- Java KeyStore -------------------------------------------------------------------------


def _jks(entries: bytes, count: int, *, magic=b"\xfe\xed\xfe\xed", version=2) -> bytes:
    return magic + struct.pack(">II", version, count) + entries + b"\x00" * 20


def _utf(text: str) -> bytes:
    raw = text.encode()
    return struct.pack(">H", len(raw)) + raw


def _protect(plain: bytes, password: str, oid: str = asn1.JKS_KEY_PROTECTOR) -> bytes:
    pw = password.encode("utf-16-be")
    iv = b"\x07" * 20
    stream, block = bytearray(), iv
    while len(stream) < len(plain):
        block = hashlib.sha1(pw + block).digest()
        stream += block
    body = bytes(a ^ b for a, b in zip(plain, stream, strict=False))
    blob = iv + body + hashlib.sha1(pw + plain).digest()
    return asn1.EncryptedPrivateKeyInfo(
        {
            "encryption_algorithm": {"algorithm": oid, "parameters": core.Null()},
            "encrypted_data": blob,
        }
    ).dump()


def _key_entry(protected: bytes, certs: list[bytes], cert_type: str = "X.509") -> bytes:
    chain = b"".join(_utf(cert_type) + struct.pack(">I", len(c)) + c for c in certs)
    return (
        struct.pack(">I", 1) + _utf("alias") + b"\x00" * 8
        + struct.pack(">I", len(protected)) + protected + struct.pack(">I", len(certs)) + chain
    )  # fmt: skip


def test_jks_synthetic_store_and_prefix():
    cert = certificate_for(KEY)
    trusted = (
        struct.pack(">I", 2)
        + _utf("ca")
        + b"\x00" * 8
        + _utf("X.509")
        + struct.pack(">I", len(cert.der))
        + cert.der
    )
    store = _jks(_key_entry(_protect(_pkcs8(), "пароль"), [cert.der]) + trusted, 2)
    keys, certs = read_jks(store, "пароль")
    assert [k.d for k in keys] == [KEY.d] and certs == [cert.der, cert.der]
    assert read_jks(store, "пароль".encode()) == (keys, certs)  # bytes are UTF-8 text
    prefixed = b"Q" + b"\x00" * 5 + store
    assert read_key_file(prefixed, "пароль")[0][0].d == KEY.d


@pytest.mark.parametrize(
    ("store", "error"),
    [
        (_jks(b"", 0, magic=b"\xce\xce\xce\xce"), KeyFileError),
        (_jks(b"", 0, version=1), UnsupportedError),
        (_jks(struct.pack(">I", 9) + _utf("x") + b"\x00" * 8, 1), KeyFileError),
        (
            _jks(struct.pack(">I", 1) + _utf("a") + b"\x00" * 8 + struct.pack(">I", 999), 1),
            KeyFileError,
        ),
        (
            _jks(_key_entry(_protect(_pkcs8(), "pw", oid="1.3.6.1.4.1.42.2.19.1"), []), 1),
            UnsupportedError,
        ),
        (_jks(_key_entry(_protect(_pkcs8(), "pw"), [b"x"], cert_type="PGP"), 1), UnsupportedError),
        (
            _jks(
                _key_entry(
                    asn1.EncryptedPrivateKeyInfo(
                        {
                            "encryption_algorithm": {"algorithm": asn1.JKS_KEY_PROTECTOR},
                            "encrypted_data": b"short",
                        }
                    ).dump(),
                    [],
                ),
                1,
            ),
            KeyFileError,
        ),
        (_jks(_key_entry(b"\x30\x00", []), 1), KeyFileError),
    ],
    ids=[
        "jceks",
        "version-1",
        "unknown-entry",
        "truncated",
        "other-protector",
        "pgp-cert",
        "short-key",
        "bad-der",
    ],
)
def test_jks_errors(store, error):
    with pytest.raises(error):
        read_jks(store, "pw")


def test_load_key_skips_unusable_certificates():
    good = certificate_for(KEY)
    ecdsa = asn1.Certificate.load(good.der)
    ecdsa["tbs_certificate"]["subject_public_key_info"]["algorithm"]["algorithm"] = (
        "1.2.840.10045.2.1"
    )
    fields = ("tbs_certificate", "signature_algorithm", "signature_value")
    ecdsa_der = asn1.Certificate({k: ecdsa[k] for k in fields}).dump()
    assert Certificate(ecdsa_der).can_sign  # a signing certificate, but not for a ДСТУ key
    bags = [
        _bag(
            asn1.CERT_BAG,
            asn1.CertBag({"cert_id": asn1.X509_CERTIFICATE, "cert_value": b"junk"}).dump(),
        ),
        _bag(
            asn1.CERT_BAG,
            asn1.CertBag({"cert_id": asn1.X509_CERTIFICATE, "cert_value": ecdsa_der}).dump(),
        ),
        _bag(
            asn1.CERT_BAG,
            asn1.CertBag({"cert_id": asn1.X509_CERTIFICATE, "cert_value": good.der}).dump(),
        ),
        _bag(asn1.KEY_BAG, _pkcs8()),
    ]
    key = load_key(_pfx([_data_safe(bags)]), "pw")
    assert key.certificate == good


def test_pbes2_uses_the_containers_substitution_table():
    """dstu-engine's .pfx names the default ДКЕ; a container may name another one."""
    from uakep.gost28147 import DEFAULT_SBOX, pack_sbox

    other = DEFAULT_SBOX[::-1]
    salt, iv = b"\x33" * 32, b"\x44" * 8
    encrypted = GOST28147(pbkdf2(b"pw", salt, 1), other).encrypt_cfb(iv, _pkcs8())
    kdf = asn1.Pbkdf2Params(
        {"salt": salt, "iteration_count": 1, "prf": {"algorithm": asn1.GOST34311_HMAC}}
    )
    scheme = asn1.Gost28147Params({"iv": iv, "dke": pack_sbox(other)})
    params = asn1.Pbes2Params(
        {
            "key_derivation_func": {"algorithm": asn1.PBKDF2, "parameters": kdf},
            "encryption_scheme": {"algorithm": asn1.GOST28147_CFB, "parameters": scheme},
        }
    )
    data = asn1.EncryptedPrivateKeyInfo(
        {
            "encryption_algorithm": {"algorithm": asn1.PBES2, "parameters": params},
            "encrypted_data": encrypted,
        }
    ).dump()
    assert read_key_file(data, "pw")[0][0].d == KEY.d
