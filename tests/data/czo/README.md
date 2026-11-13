# ЦЗО test signatures

Official test examples of qualified electronic signatures, published by ЦЗО (Центральний засвідчувальний орган, the Central Certification Authority) on [czo.gov.ua/testexamples](https://czo.gov.ua/testexamples) («Тестові приклади кваліфікованого електронного підпису»).

- **Source:** each file from `https://czo.gov.ua/download/test_sign/CAdES/<path>`, the path given below.
- **Version:** the server's Last-Modified date of each file, below. ЦЗО also keeps a change log for the page at [czo.gov.ua/changes/testexamples](https://czo.gov.ua/changes/testexamples).
- **Fetched:** 2026-11-13.
- **Checksums:** `SHA256SUMS`; `tests/test_data.py` fails if a file changes.

`DSTU_*` files are signed with ДСТУ 4145-2002 and the ГОСТ 34.311 hash, `DSTU-7564_*` files with ДСТУ 4145-2002 and the Купина (ДСТУ 7564:2014) hash. Every signature is over `test.txt` (`Test\r\n`), attached except in `DSTU_CAdES-BES_detached.p7s`. The `*_sign.cer` and `*_encryption.cer` files are the certificates the page offers now. For ДСТУ 4145 with ГОСТ 34.311 the signing certificate is the one inside the examples. The ДСТУ 7564 certificates were replaced on 2026-04-24 by a new test owner, «TEST TEST Testov Test», valid until 2027-04-24, so they did not sign the 2024 examples; they are kept as a second, current certificate to parse.

The examples' signer is a test person, «ТЕСТ Тестовий Тест Тестович», with certificates valid from 2024-03-03 22:00 to 2026-03-03 21:59:59 UTC; tests must not assume they are still valid today.

| File | Path under `/download/test_sign/CAdES/` | Last-Modified |
| --- | --- | --- |
| `DSTU-7564_CAdES-BES.p7s` | `DSTU-7564/enveloped/CAdES-BES/test.txt.p7s` | 2024-03-04 |
| `DSTU-7564_CAdES-C.p7s` | `DSTU-7564/enveloped/CAdES-C/test.txt.p7s` | 2024-03-04 |
| `DSTU-7564_CAdES-T.p7s` | `DSTU-7564/enveloped/CAdES-T/test.txt.p7s` | 2024-03-04 |
| `DSTU-7564_CAdES-X_Long-Full.p7s` | `DSTU-7564/enveloped/CAdES-X_Long-Full/test.txt.p7s` | 2024-03-04 |
| `DSTU-7564_CAdES-X_Long.p7s` | `DSTU-7564/enveloped/CAdES-X_Long/test.txt.p7s` | 2024-03-04 |
| `DSTU-7564_encryption.cer` | `DSTU-7564/DSTU_encryption.cer` | 2026-04-24 |
| `DSTU-7564_sign.cer` | `DSTU-7564/DSTU_sign.cer` | 2026-04-24 |
| `DSTU_CAdES-BES.p7s` | `DSTU/enveloped/CAdES-BES/test.txt.p7s` | 2024-03-04 |
| `DSTU_CAdES-BES_detached.p7s` | `DSTU/detached/CAdES-BES/test.txt.p7s` | 2024-03-04 |
| `DSTU_CAdES-C.p7s` | `DSTU/enveloped/CAdES-C/test.txt.p7s` | 2024-03-04 |
| `DSTU_CAdES-T.p7s` | `DSTU/enveloped/CAdES-T/test.txt.p7s` | 2024-03-04 |
| `DSTU_CAdES-X_Long-Full.p7s` | `DSTU/enveloped/CAdES-X_Long-Full/test.txt.p7s` | 2024-03-04 |
| `DSTU_CAdES-X_Long.p7s` | `DSTU/enveloped/CAdES-X_Long/test.txt.p7s` | 2024-03-04 |
| `DSTU_encryption.cer` | `DSTU/DSTU_encryption.cer` | 2024-03-04 |
| `DSTU_sign.cer` | `DSTU/DSTU_sign.cer` | 2024-03-04 |
| `test.txt` | `DSTU/detached/CAdES-BES/test.txt` | 2024-03-04 |
