"""The public API: load a key, sign (with or without a time-stamp), unwrap."""

import asyncio

import pytest

import uakep
from uakep import SignatureError, load_key, sign, sign_async, unwrap
from uakep.curve import DSTU_PB_257
from uakep.dstu4145 import PrivateKey

from .conftest import LocalTsa, certificate_for, data_file


def test_online_document_with_a_signature_timestamp():
    signer = PrivateKey(DSTU_PB_257, 0x5EED)
    key = uakep.SigningKey(signer, certificate_for(signer))
    tsa = LocalTsa(PrivateKey(DSTU_PB_257, 0x75A))
    signed = sign(b"<CHECK/>", key, timestamp=tsa)
    assert unwrap(signed) == b"<CHECK/>"
    assert uakep.verify(signed).timestamp.certificate == tsa.certificate

    async def post(url, request):
        return tsa(url, request)

    signed = asyncio.run(sign_async(b"<ZREP/>", key, timestamp=post))
    assert isinstance(uakep.verify(signed).timestamp, uakep.TimeStamp)
    with pytest.raises(uakep.TimeStampError):
        sign(b"<CHECK/>", key, timestamp=lambda *_: b"")


def test_sign_and_unwrap_with_a_key6_file(tmp_path):
    key6 = data_file("dstu-engine", "Key-6.dat")
    first_key = uakep.keystore.read_key6(key6, "tect4")[0]
    (tmp_path / "Key-6.dat").write_bytes(key6)
    (tmp_path / "signer.cer").write_bytes(certificate_for(first_key).der)

    key = load_key(tmp_path / "Key-6.dat", password="tect4", certificate=tmp_path / "signer.cer")
    receipt = '<?xml version="1.0" encoding="windows-1251"?><CHECK>Кава</CHECK>'.encode("cp1251")
    signed = sign(receipt, key)
    assert unwrap(signed) == receipt
    assert uakep.verify(signed).certificate == key.certificate

    tampered = signed.replace("Кава".encode("cp1251"), "Чай!".encode("cp1251"))
    with pytest.raises(SignatureError):
        unwrap(tampered)


def test_unwrap_the_tax_samples():
    assert unwrap(data_file("tax", "state-request.json.signed")).startswith(b'{"NumFiscal"')
    detached = data_file("czo", "DSTU_CAdES-BES_detached.p7s")
    assert unwrap(detached, detached_content=b"Test\r\n") == b"Test\r\n"


def test_exports():
    for name in uakep.__all__:
        assert hasattr(uakep, name), name
    assert issubclass(uakep.WrongPasswordError, uakep.KeyFileError)
    assert issubclass(uakep.KeyFileError, ValueError)
    assert issubclass(uakep.SignatureError, ValueError)
