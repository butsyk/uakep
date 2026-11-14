# Changelog

Notable changes to uakep, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `verify()` no longer hangs on a certificate that spells out a curve over a made-up field. Such a certificate takes no key to make. A curve given by its parameters must now have a field degree from 163 to 509, an irreducible field polynomial, a coefficient `b` inside the field and an order that fits the curve.
- `verify()` and `unwrap()` raise `SignatureError` for signed data they cannot read, however it is damaged. An empty or mistyped attribute value used to escape as `IndexError` or a plain `ValueError`. A damaged time-stamp token is a `TimeStampError` in the same way.

## [0.1.0] - 2026-11-13

The first release.

### Added

- `load_key()` reads the private key from IIT Key-6.dat, PKCS#12 (.pfx), Java KeyStore (.jks) and PKCS#8 files, given the password, and pairs it with its signing certificate.
- `Certificate` reads the owner, РНОКПП, ЄДРПОУ, validity, key usage, the ДСТУ 4145 public key and the time-stamping service's URL.
- `sign()` builds CAdES signed data in the layout of the tax service's signed samples: data attached, the signer's certificate inside, a ГОСТ 34.311 or Купина-256 digest.
- Signature time-stamps (RFC 3161) from the service named in the signer's certificate: `sign(..., timestamp=post)` and `await sign_async(..., timestamp=post)`. uakep makes no network calls; `post` is the caller's.
- `verify()` and `unwrap()` check ДСТУ 4145 signatures, their signed attributes and their signature time-stamps.
- ДСТУ 4145-2002 on binary curves, the ГОСТ 34.311-95 and ДСТУ 7564 «Купина» hashes, and the ГОСТ 28147-89 cipher, in pure Python.

Not yet proven: a test shift accepted by the fiscal server with a real key, the gate of milestone 0.2.

[Unreleased]: https://github.com/butsyk/uakep/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/butsyk/uakep/releases/tag/v0.1.0
