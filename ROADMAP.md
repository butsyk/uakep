# uakep roadmap

Each milestone ends when its gate, in the last column, is met. Where things stand now is in the README's [Status](README.md#status) section.

| Milestone | Brings | Done when |
| --- | --- | --- |
| 0.1 First signature | Key files, ДСТУ 4145, CAdES signed data, certificates | Tax and ЦЗО samples verify in uakep |
| 0.2 Server accepts it | Signature time-stamps; the server's signed answers checked | A test shift is accepted with a real key |
| 0.3 More key files | Keys from more CAs; fuzzed parsers | Keys from several CAs load and sign |
| 1.0 Stable | API frozen; in daily use | Real receipts signed every day |

1.0 waits for real receipts, because tests cannot cover every CA's key files.
