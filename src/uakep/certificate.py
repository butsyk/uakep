"""X.509 certificates of Ukrainian qualified trust service providers.

Reads what a signer needs: owner, РНОКПП and ЄДРПОУ, validity, key usage, the ДСТУ 4145 public
key, identifiers for CMS, and the time-stamping URL. Certificates arrive as DER, PEM or bare
base64; all three are accepted.
"""

from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime
from functools import cached_property

from asn1crypto import core, x509

from . import asn1
from .asn1 import UnsupportedError
from .dstu4145 import PublicKey

# subjectDirectoryAttributes: РНОКПП (two OIDs in use) and ЄДРПОУ
_DRFO_OIDS = ("1.2.804.2.1.1.1.11.1.4.1.1", "1.2.804.2.1.1.1.11.1.4.7.1")
_EDRPOU_OID = "1.2.804.2.1.1.1.11.1.4.2.1"
_AD_TIME_STAMPING = "1.3.6.1.5.5.7.48.3"
_AD_OCSP = "1.3.6.1.5.5.7.48.1"
_PEM = re.compile(rb"-----BEGIN [A-Z0-9 ]+-----(.+?)-----END [A-Z0-9 ]+-----", re.S)


class CertificateError(ValueError):
    """Bytes that are not a certificate uakep can read."""


def _to_der(data: bytes) -> bytes:
    data = bytes(data)
    if data[:1] == b"\x30":
        return data
    match = _PEM.search(data)
    text = match.group(1) if match else data
    try:
        return base64.b64decode(b"".join(text.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CertificateError("not a certificate: neither DER, PEM nor base64") from exc


class Certificate:
    """A parsed certificate; ``der`` keeps the exact bytes it was read from."""

    def __init__(self, der: bytes) -> None:
        self.der = bytes(der)
        try:
            self._cert = asn1.Certificate.load(self.der)
            self._tbs = self._cert["tbs_certificate"]
            self._extensions = {e["extn_id"].dotted: e for e in self._tbs["extensions"]}
            self.serial_number: int = self._tbs["serial_number"].native
            self.not_before: datetime = self._tbs["validity"]["not_before"].native
            self.not_after: datetime = self._tbs["validity"]["not_after"].native
            self.subject: dict = dict(self._tbs["subject"].native)
            self.issuer: dict = dict(self._tbs["issuer"].native)
        except (ValueError, TypeError, KeyError) as exc:
            raise CertificateError(f"cannot read the certificate: {exc}") from exc

    @classmethod
    def load(cls, data: bytes) -> Certificate:
        """A certificate from DER, PEM or bare base64 bytes."""
        return cls(_to_der(data))

    def __repr__(self) -> str:
        return f"Certificate(owner={self.owner_name!r}, serial={self.serial_number:x})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Certificate) and self.der == other.der

    def __hash__(self) -> int:
        return hash(self.der)

    # -- who -------------------------------------------------------------------------------

    @property
    def owner_name(self) -> str | None:
        return self.subject.get("common_name")

    @cached_property
    def _directory_attributes(self) -> dict[str, str]:
        ext = self._extensions.get("2.5.29.9")
        if ext is None:
            return {}
        attrs = asn1.DirectoryAttributes.load(ext["extn_value"].contents)
        found = {}
        for attr in attrs:
            if len(attr["values"]):
                found[attr["type"].dotted] = attr["values"][0].contents.decode("ascii", "replace")
        return found

    @property
    def drfo(self) -> str | None:
        """РНОКПП (taxpayer registration number), if the certificate has one."""
        for oid in _DRFO_OIDS:
            if oid in self._directory_attributes:
                return self._directory_attributes[oid]
        serial = self.subject.get("serial_number", "")
        return serial[len("TINUA-") :] if serial.startswith("TINUA-") else None

    @property
    def edrpou(self) -> str | None:
        """ЄДРПОУ (company code), if the certificate names a legal entity."""
        if _EDRPOU_OID in self._directory_attributes:
            return self._directory_attributes[_EDRPOU_OID]
        org_id = self.subject.get("organization_identifier", "")
        return org_id[len("NTRUA-") :] if org_id.startswith("NTRUA-") else None

    # -- what for, and when ----------------------------------------------------------------

    def is_valid_at(self, when: datetime) -> bool:
        return self.not_before <= when <= self.not_after

    @cached_property
    def key_usage(self) -> frozenset[str]:
        ext = self._extensions.get("2.5.29.15")
        if ext is None:
            return frozenset()
        return frozenset(x509.KeyUsage.load(ext["extn_value"].contents).native)

    @property
    def can_sign(self) -> bool:
        return bool(self.key_usage & {"digital_signature", "non_repudiation"})

    @cached_property
    def extended_key_usage(self) -> frozenset[str]:
        ext = self._extensions.get("2.5.29.37")
        if ext is None:
            return frozenset()
        return frozenset(p.dotted for p in x509.ExtKeyUsageSyntax.load(ext["extn_value"].contents))

    # -- identifiers -----------------------------------------------------------------------

    @property
    def issuer_der(self) -> bytes:
        """The issuer Name exactly as encoded, for IssuerAndSerialNumber and IssuerSerial."""
        return self._tbs["issuer"].dump()

    @property
    def subject_key_identifier(self) -> bytes | None:
        ext = self._extensions.get("2.5.29.14")
        return core.OctetString.load(ext["extn_value"].contents).native if ext else None

    @property
    def authority_key_identifier(self) -> bytes | None:
        ext = self._extensions.get("2.5.29.35")
        if ext is None:
            return None
        return x509.AuthorityKeyIdentifier.load(ext["extn_value"].contents)["key_identifier"].native

    def _access_url(self, extension: str, method: str) -> str | None:
        ext = self._extensions.get(extension)
        if ext is None:
            return None
        for desc in asn1.InfoAccess.load(ext["extn_value"].contents):
            location = desc["access_location"]
            is_url = location.name == "uniform_resource_identifier"
            if desc["access_method"].dotted == method and is_url:
                return location.native
        return None

    @property
    def tsp_url(self) -> str | None:
        """The time-stamping service named in subjectInfoAccess."""
        return self._access_url("1.3.6.1.5.5.7.1.11", _AD_TIME_STAMPING)

    @property
    def ocsp_url(self) -> str | None:
        return self._access_url("1.3.6.1.5.5.7.1.1", _AD_OCSP)

    # -- key and signature -----------------------------------------------------------------

    @property
    def public_key_algorithm(self) -> str:
        return self._tbs["subject_public_key_info"]["algorithm"]["algorithm"].dotted

    @cached_property
    def _dstu_params(self) -> asn1.DstuParams:
        if self.public_key_algorithm not in (asn1.DSTU4145_LE, asn1.DSTU4145_KUPYNA):
            raise UnsupportedError(f"not a ДСТУ 4145 public key ({self.public_key_algorithm})")
        params = self._tbs["subject_public_key_info"]["algorithm"]["parameters"]
        return asn1.DstuParams.load(params.dump())

    @cached_property
    def public_key(self) -> PublicKey:
        curve = asn1.curve_from_spec(self._dstu_params["curve"])
        bits = self._tbs["subject_public_key_info"]["public_key"].contents[1:]
        compressed = core.OctetString.load(bits).native
        return PublicKey.from_compressed(curve, int.from_bytes(compressed, "little"))

    @property
    def dke(self) -> bytes | None:
        """The packed ДКЕ substitution table named with the key, if any."""
        return self._dstu_params["dke"].native

    @property
    def signature_algorithm(self) -> str:
        return self._cert["signature_algorithm"]["algorithm"].dotted

    @property
    def tbs_der(self) -> bytes:
        return self._tbs.dump()

    @property
    def signature(self) -> bytes:
        """The issuer's ``r || s``, unwrapped from BIT STRING and OCTET STRING."""
        return core.OctetString.load(self._cert["signature_value"].contents[1:]).native
