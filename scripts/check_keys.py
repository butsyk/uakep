"""Check that uakep reads your key files, offline. Run it yourself; nothing leaves this machine.

    cd ~/Projects/uakep
    uv run python scripts/check_keys.py path/to/key.jks path/to/Key-6.dat [path/to/signer.cer ...]

Key files ask for their password (no echo). .cer/.crt/.pem files are read as certificates.
Every key is matched with every certificate found, across all the files, and each signing
pair signs a test string that is then verified. The output leaves out names, РНОКПП, serial
numbers and key material, so it is safe to paste back.
"""

import getpass
import sys
from pathlib import Path

import uakep
from uakep import cades
from uakep.certificate import Certificate
from uakep.keystore import read_key_file

CERT_SUFFIXES = {".cer", ".crt", ".pem", ".der"}
KUPYNA = "1.2.804.2.1.1.1.1.3.6.1.1"


def family(cert: Certificate) -> str:
    return "Купина" if KUPYNA in (cert.signature_algorithm, cert.public_key_algorithm) else "ГОСТ"


def describe(cert: Certificate, label: str) -> None:
    usage = "signing" if cert.can_sign else ", ".join(sorted(cert.key_usage)) or "no key usage"
    try:
        curve = f"{cert.public_key.curve.m}-bit curve"
    except ValueError as exc:
        curve = f"public key not readable: {type(exc).__name__}: {exc}"
    print(
        f"  {label}: CA {cert.issuer.get('common_name', '?')!r}; {usage};"
        f" {family(cert)} family; {curve}"
    )
    print(
        f"    valid {cert.not_before:%Y-%m-%d} to {cert.not_after:%Y-%m-%d};"
        f" РНОКПП present: {cert.drfo is not None}; ЄДРПОУ present: {cert.edrpou is not None};"
        f" TSA {cert.tsp_url}"
    )


def main(paths: list[str]) -> int:
    print(f"uakep {uakep.__version__}")
    keys: list[tuple[str, object]] = []  # (label, PrivateKey)
    certs: list[tuple[str, Certificate]] = []
    for path in map(Path, paths):
        print(f"\n{path.name}")
        data = path.read_bytes()
        if path.suffix.lower() in CERT_SUFFIXES:
            try:
                cert = Certificate.load(data)
            except ValueError as exc:
                print(f"  ! not a certificate uakep can read: {type(exc).__name__}: {exc}")
                continue
            certs.append((path.name, cert))
            describe(cert, "certificate")
            continue
        password = getpass.getpass(f"  password for {path.name}: ")
        try:
            found_keys, cert_ders = read_key_file(data, password)
        except ValueError as exc:  # WrongPasswordError, KeyFileError, UnsupportedError
            print(f"  ! {type(exc).__name__}: {exc}")
            continue
        finally:
            del password
        print(f"  read OK: {len(found_keys)} key(s), {len(cert_ders)} certificate(s)")
        for i, key in enumerate(found_keys, 1):
            label = f"{path.name} key {i}"
            keys.append((label, key))
            print(f"  key {i}: {key.curve.m}-bit curve ({key.curve.name or 'explicit parameters'})")
        for i, der in enumerate(cert_ders, 1):
            try:
                cert = Certificate(der)
            except ValueError as exc:
                print(f"  certificate {i}: not readable: {type(exc).__name__}: {exc}")
                continue
            certs.append((f"{path.name} certificate {i}", cert))
            describe(cert, f"certificate {i}")

    print("\nKeys matching a certificate; signing pairs sign and verify a test string offline:")
    pairs = 0
    for cert_label, cert in certs:
        try:
            wanted = cert.public_key
        except ValueError:
            continue
        for key_label, key in keys:
            if key.public_key() != wanted:
                continue
            if not cert.can_sign:
                print(f"  {key_label} + {cert_label}: match, but not a signing certificate")
                continue
            pairs += 1
            try:
                signed = cades.sign(b"uakep key check", cades.SigningKey(key, cert))
                result = cades.verify(signed)
                ok = result.content == b"uakep key check" and result.certificate == cert
                digest = (
                    "Купина-256" if result.digest_algorithm == cades.KUPYNA_256 else "ГОСТ 34.311"
                )
                print(
                    f"  {key_label} + {cert_label}:"
                    f" sign and verify {'OK' if ok else 'MISMATCH'} ({digest})"
                )
            except Exception as exc:  # report, keep going
                print(f"  {key_label} + {cert_label}: FAILED: {type(exc).__name__}: {exc}")
    if not pairs:
        print("  none: no key matches a signing certificate (Key-6.dat needs its .cer passed too)")
    return 0 if pairs else 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1:]))
