# Key containers from dstu-engine

Test key files from the test suite of [dstu-engine](https://github.com/dstucrypt/dstu-engine), an OpenSSL engine and key-reading library in C by Maksym Mamontov.

- **Source:** `tests/` at commit [`c429dbe`](https://github.com/dstucrypt/dstu-engine/tree/c429dbe7416173dd9b4d3d80c2f738e877c39836/tests) (2025-01-15). The files were added in 2020 and 2021 and are unchanged since.
- **License:** Apache License 2.0, copied here as `LICENSE`.
- **Fetched:** 2026-11-13.
- **Checksums:** `SHA256SUMS`; `tests/test_data.py` fails if a file changes.

| File | Contents | Password |
| --- | --- | --- |
| `Key-6.dat` | IIT key container: a key on DSTU_PB_257, a second key on DSTU_PB_431, no certificates | `tect4` |
| `Key-6.pfx` | PKCS#12 container | `testplat2021` |
| `key.jks` | Java KeyStore | key `qwerty`, store `123456` |

These are published test keys with no real owner. The passwords come from dstu-engine's `tests/key6.cpp`, `tests/pkcs12.cpp` and `tests/jks.cpp`.

`Key-6.dat` was written by IIT software: besides the keys it stores IIT's own key identifiers (the ГОСТ 34.311 hash of each public key), which uakep's tests compare with the public keys uakep derives.
