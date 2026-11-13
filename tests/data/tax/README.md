# Tax service signed samples

The signed examples («Приклади з КЕП») published by the State Tax Service with the fiscal server's API description, [«Опис API фіскального сервера контролюючого органу (ЄВПЕЗ)»](https://tax.gov.ua/baneryi/programni-rro/opis-ari-fiskalnogo-servera/opis-ari--kontrolyuyuchogo-organu/). They show the exact signed format the fiscal server accepts.

- **Source:** copied from [VSydorenko/prro_docs](https://github.com/VSydorenko/prro_docs), a Markdown mirror of the official page (not itself official), folder «Єдине вікно подання електронної звітності/Приклади/Приклади з КЕП», commit [`67b19d3`](https://github.com/VSydorenko/prro_docs/tree/67b19d3b5ad1eba6adc402bbbf5b8ec917f5c8e3).
- **Version:** the mirror added these files on 2021-11-22 (commit `6d6d9c7`, «Актуальні версії прикладів та схем на 22.11.2021», API description of 06.11.2021) and they are byte-for-byte unchanged through the API description of 08.08.2025 (commit `8e3c490`). The mirror converts XML and XSD files to UTF-8 with BOM; these signed files are binary and are not converted.
- **Fetched:** 2026-11-13.
- **Checksums:** `SHA256SUMS`; `tests/test_data.py` fails if a file changes.

| File | Original name | Contents |
| --- | --- | --- |
| `receipt.xml.signed` | `чек.xml.signed` | A receipt (CHECK, Windows-1251 XML), with a signature time-stamp |
| `zreport.xml.signed` | `Z-звіт.xml.signed` | A Z-report (ZREP, Windows-1251 XML), with a signature time-stamp |
| `state-request.json.signed` | `запит_стану_РРО.json.signed` | The TransactionsRegistrarState command (JSON), no time-stamp |

The signer is a test certificate issued by АЦСК ТОВ «Центр сертифікації ключів «Україна»», valid from 2019-12-19 to 2021-12-18; the time-stamps are from 2020-07-21. They were made by IIT software, and the fiscal server's own signatures use the same layout.
