"""ДСТУ 4145-2002 digital signature on binary curves.

Encoding conventions are those of the software used by Ukrainian CAs and the tax service:

* the hash value is read as a little-endian integer and truncated to ``m`` bits;
* a signature is ``r || s``, each little-endian, each ``ceil(L(n) / 8)`` bytes long;
* the public key is ``Q = -d*G``.

Signing pads the secret nonce to ``L(n) + 1`` bits before the scalar multiplication
(:meth:`uakep.curve.Curve.pad_scalar`), a countermeasure against timing attacks that read the
nonce length.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .curve import Curve, InvalidPointError, Point


def digest_to_field(curve: Curve, digest: bytes) -> int:
    """Hash value as a field element: little-endian, truncated to m bits; 0 becomes 1."""
    return (int.from_bytes(digest, "little") & curve.field.mask) or 1


def signature_size(curve: Curve) -> int:
    """Length in bytes of ``r || s`` for this curve."""
    return 2 * ((curve.order.bit_length() + 7) // 8)


def encode_signature(curve: Curve, r: int, s: int) -> bytes:
    half = signature_size(curve) // 2
    return r.to_bytes(half, "little") + s.to_bytes(half, "little")


def decode_signature(signature: bytes) -> tuple[int, int]:
    """Split ``r || s``; with an odd length r takes the extra byte."""
    half = (len(signature) + 1) // 2
    return int.from_bytes(signature[:half], "little"), int.from_bytes(signature[half:], "little")


def _truncate_r(curve: Curve, y: int) -> int:
    return y & ((1 << (curve.order.bit_length() - 1)) - 1)


@dataclass(frozen=True)
class PublicKey:
    curve: Curve
    point: Point

    def __post_init__(self) -> None:
        if self.point is None or not self.curve.contains(self.point):
            raise InvalidPointError("public key is not a point on the curve")

    @classmethod
    def from_compressed(cls, curve: Curve, compressed: int) -> PublicKey:
        return cls(curve, curve.decompress(compressed))

    def compressed(self) -> int:
        return self.curve.compress(self.point)

    def verify(self, digest: bytes, signature: bytes) -> bool:
        """Check ``signature`` (``r || s``) over a hash value."""
        r, s = decode_signature(signature)
        return self.verify_rs(digest_to_field(self.curve, digest), r, s)

    def verify_rs(self, h: int, r: int, s: int) -> bool:
        """Verification with the hash already a field element (ДСТУ 4145-2002, section 12)."""
        curve = self.curve
        n = curve.order
        if not (0 < r < n and 0 < s < n):
            return False
        point = curve.add(curve.mul(s, curve.base), curve.mul(r, self.point))
        if point is None:
            return False
        return _truncate_r(curve, curve.field.mul(h, point[0])) == r


@dataclass(frozen=True, repr=False)
class PrivateKey:
    curve: Curve
    d: int

    def __post_init__(self) -> None:
        if not 0 < self.d < self.curve.order:
            raise ValueError("private key is out of range")

    def __repr__(self) -> str:
        return f"PrivateKey(curve={self.curve.name or 'explicit'}, d=<hidden>)"

    @classmethod
    def generate(cls, curve: Curve) -> PrivateKey:
        return cls(curve, secrets.randbelow(curve.order - 1) + 1)

    def public_key(self) -> PublicKey:
        curve = self.curve
        return PublicKey(curve, curve.negate(curve.mul(curve.pad_scalar(self.d), curve.base)))

    def sign(self, digest: bytes, *, nonce: int | None = None) -> bytes:
        """Sign a hash value; returns ``r || s``. ``nonce`` is for known-answer tests only."""
        r, s = self.sign_rs(digest_to_field(self.curve, digest), nonce=nonce)
        return encode_signature(self.curve, r, s)

    def sign_rs(self, h: int, *, nonce: int | None = None) -> tuple[int, int]:
        """Signing with the hash already a field element (ДСТУ 4145-2002, section 11)."""
        curve = self.curve
        n = curve.order
        while True:
            e = secrets.randbelow(n - 1) + 1 if nonce is None else nonce
            point = curve.mul(curve.pad_scalar(e), curve.base)
            if point is not None:
                r = _truncate_r(curve, curve.field.mul(h, point[0]))  # x = 0 gives r = 0
                if r != 0:
                    s = (e + self.d * r) % n
                    if s != 0:
                        return r, s
            if nonce is not None:
                raise ValueError("this nonce does not give a valid signature")
