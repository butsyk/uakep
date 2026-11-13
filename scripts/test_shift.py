"""A test shift on the fiscal server with a real key: the gate of milestone 0.2.

Run it yourself, with your own key and a ПРРО registered for it. It sends only test documents
(<TESTING>true</TESTING>), which carry no tax effect:

1. ServerState: is the server reachable?
2. TransactionsRegistrarState: the ПРРО's state, seller details and next local number. The
   script stops here if a shift is open.
3. After you confirm: open a shift, sell one item for 1.00 UAH in cash, send the Z-report and
   close the shift. Each document is signed with a signature time-stamp from the TSA named in
   your certificate, and each ticket the server sends back is checked with uakep. If a step
   fails after the shift is open, the script still sends the Z-report and closes the shift.

Every request and answer is written to --out, by default a new folder in your home directory,
never into the repository. The password is read without echo and never written anywhere. The
output leaves out your name and РНОКПП, except the seller line you confirm before sending.

    uv run python scripts/test_shift.py --key Key-6.dat --certificate signer.cer --prro 4000000001

Without --prro it lists the ПРРО your key may use, and stops.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

import uakep
from uakep import asn1

SERVER = "https://fs.tax.gov.ua:8643/fs"
KYIV = ZoneInfo("Europe/Kyiv")
TIMEOUT = 30
LIMIT = 200 * 1024  # the server refuses larger messages
PRICE = "1.00"


class StepError(Exception):
    """A step the server refused, or an answer the protocol does not allow."""


def post(url: str, body: bytes, content_type: str) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": content_type}
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as answer:
            return answer.status, answer.read()
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", "replace").strip()
        raise StepError(f"{url}: HTTP {exc.code}: {text}") from None
    except urllib.error.URLError as exc:
        raise StepError(f"{url}: {exc.reason}") from None


def tsa_post(url: str, request: bytes) -> bytes:
    """The ``timestamp`` function uakep calls: one RFC 3161 request to the signer's TSA."""
    return post(url, request, "application/timestamp-query")[1]


def _family(digest_algorithm: str) -> str:
    return "Купина" if digest_algorithm.startswith("1.2.804.2.1.1.1.1.2.2") else "ГОСТ 34.311"


class Session:
    def __init__(self, server: str, key: uakep.SigningKey, out: Path) -> None:
        self.server = server.rstrip("/")
        self.key = key
        self.out = out
        self.count = 0
        self.problems: list[str] = []

    def save(self, name: str, data: bytes) -> None:
        self.count += 1
        (self.out / f"{self.count:02d}-{name}").write_bytes(data)

    def open_answer(self, answer: bytes, label: str) -> bytes:
        """The content of the server's signed answer, checked with uakep."""
        try:
            verified = uakep.verify(answer)
        except ValueError as exc:
            self.problems.append(f"{label}: the server's signature did not verify: {exc}")
            print(f"  ! the server's signature did NOT verify: {exc}")
            try:
                signed_data = asn1.ContentInfo.load(answer)["content"]
                return signed_data["encap_content_info"]["content"].native
            except (ValueError, TypeError, KeyError):
                raise StepError(f"{label}: not signed data: {answer[:200]!r}") from None
        cert = verified.certificate
        stamp = verified.timestamp.time.isoformat() if verified.timestamp else "none"
        print(
            f"  server's signature OK: {cert.owner_name}, ЄДРПОУ {cert.edrpou}, "
            f"{_family(verified.digest_algorithm)}, time-stamp {stamp}"
        )
        return verified.content

    def command(self, name: str, fields: dict, *, signed: bool = True) -> dict | None:
        """A JSON command to /cmd; signed commands go without a time-stamp, as in the sample."""
        body = json.dumps({"Command": name, "UID": str(uuid.uuid4()), **fields}).encode()
        self.save(f"{name}.request.json", body)
        if signed:
            body = uakep.sign(body, self.key)
            self.save(f"{name}.request.p7s", body)
        content_type = "application/octet-stream" if signed else "application/json"
        status, answer = post(f"{self.server}/cmd", body, content_type)
        self.save(f"{name}.answer", answer)
        if status == 204:
            return None
        if answer[:1] == b"\x30":
            answer = self.open_answer(answer, name)
        return json.loads(answer)

    def document(self, name: str, xml: str) -> ElementTree.Element:
        """A signed, time-stamped document to /doc; the server's ticket, checked."""
        data = xml.encode("cp1251", "xmlcharrefreplace")
        self.save(f"{name}.xml", data)
        signed = uakep.sign(data, self.key, timestamp=tsa_post)
        self.save(f"{name}.xml.p7s", signed)
        if len(signed) > LIMIT:
            raise StepError(f"{name}: {len(signed)} bytes is over the server's limit")
        mine = uakep.verify(signed)
        stamp = mine.timestamp
        print(
            f"  signed: {len(signed)} bytes, {_family(mine.digest_algorithm)},"
            f" time-stamp {stamp.time.isoformat()} from {stamp.certificate.owner_name}"
        )
        _, answer = post(f"{self.server}/doc", signed, "application/octet-stream")
        self.save(f"{name}.ticket.p7s", answer)
        content = self.open_answer(answer, name)
        self.save(f"{name}.ticket.xml", content)
        ticket = ElementTree.fromstring(content)
        error = ticket.findtext("ERRORCODE")
        if error not in (None, "0"):
            raise StepError(f"{name}: error {error}: {ticket.findtext('ERRORTEXT')}")
        print(f"  accepted: fiscal number {ticket.findtext('ORDERTAXNUM')}")
        return ticket


class Seller:
    """The header fields every document carries, from the ПРРО's tax object."""

    def __init__(self, state: dict, prro: int, cashier: str) -> None:
        obj = state.get("TaxObject")
        if not obj:
            raise StepError("the server sent no TaxObject for this ПРРО")
        registrars = [r for r in obj.get("TransactionsRegistrars") or [] if r["NumFiscal"] == prro]
        if not registrars:
            raise StepError(f"ПРРО {prro} is not listed in its tax object")
        self.tin = obj["Tin"]
        self.ipn = obj.get("Ipn") or None
        self.org = obj["OrgName"]
        self.point = obj["Name"]
        self.address = obj.get("Address") or None
        self.cash_desk = registrars[0]["NumLocal"]
        self.prro = prro
        self.cashier = cashier

    def head(self, number: int, doctype: int | None, subtype: int | None = None) -> str:
        now = datetime.now(KYIV)
        fields = [
            ("DOCTYPE", doctype),
            ("DOCSUBTYPE", subtype),
            ("UID", str(uuid.uuid4()).upper()),
            ("TIN", self.tin),
            ("IPN", self.ipn),
            ("ORGNM", self.org),
            ("POINTNM", self.point),
            ("POINTADDR", self.address),
            ("ORDERDATE", now.strftime("%d%m%Y")),
            ("ORDERTIME", now.strftime("%H%M%S")),
            ("ORDERNUM", number),
            ("CASHDESKNUM", self.cash_desk),
            ("CASHREGISTERNUM", self.prro),
            ("CASHIER", self.cashier),
            ("VER", 1),
            ("TESTING", "true"),
        ]
        return "".join(_element(tag, value) for tag, value in fields if value is not None)


def _element(tag: str, value: object) -> str:
    return f"<{tag}>{escape(str(value))}</{tag}>"


def _xml(root: str, schema: str, body: str) -> str:
    return (
        '<?xml version="1.0" encoding="windows-1251"?>'
        f'<{root} xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        f'xsi:noNamespaceSchemaLocation="{schema}">{body}</{root}>'
    )


def shift_document(seller: Seller, number: int, doctype: int) -> str:
    """Open (100) or close (101) a shift."""
    return _xml("CHECK", "check01.xsd", f"<CHECKHEAD>{seller.head(number, doctype)}</CHECKHEAD>")


def sale(seller: Seller, number: int) -> str:
    """One item for PRICE in cash, without taxes."""
    pay = "".join(
        _element(t, v)
        for t, v in [
            ("PAYFORMCD", 0),
            ("PAYFORMNM", "ГОТІВКА"),
            ("SUM", PRICE),
            ("PROVIDED", PRICE),
        ]
    )
    item = "".join(
        _element(t, v)
        for t, v in [
            ("CODE", 1),
            ("NAME", "Тестовий товар"),
            ("UNITNM", "шт"),
            ("AMOUNT", "1.000"),
            ("PRICE", PRICE),
            ("COST", PRICE),
        ]
    )
    return _xml(
        "CHECK",
        "check01.xsd",
        f"<CHECKHEAD>{seller.head(number, 0, 0)}</CHECKHEAD>"
        f"<CHECKTOTAL>{_element('SUM', PRICE)}</CHECKTOTAL>"
        f'<CHECKPAY><ROW ROWNUM="1">{pay}</ROW></CHECKPAY>'
        f'<CHECKBODY><ROW ROWNUM="1">{item}</ROW></CHECKBODY>',
    )


def z_report(seller: Seller, number: int, sales: int) -> str:
    """The Z-report for ``sales`` accepted sales of PRICE in cash."""
    realiz = ""
    if sales:
        total = f"{sales * float(PRICE):.2f}"
        payforms = "".join(
            _element(t, v) for t, v in [("PAYFORMCD", 0), ("PAYFORMNM", "ГОТІВКА"), ("SUM", total)]
        )
        realiz = (
            f"<ZREPREALIZ>{_element('SUM', total)}{_element('ORDERSCNT', sales)}"
            f'<PAYFORMS><ROW ROWNUM="1">{payforms}</ROW></PAYFORMS></ZREPREALIZ>'
        )
    head = seller.head(number, None)
    return _xml("ZREP", "zrep01.xsd", f"<ZREPHEAD>{head}</ZREPHEAD>{realiz}")


def run_shift(session: Session, seller: Seller, number: int) -> bool:
    """Open, sell, Z-report, close; on failure, still close an opened shift."""
    steps_ok = True
    opened = z_sent = closed = False
    sales = 0
    try:
        print(f"\nOpen shift (local number {number})")
        session.document("open", shift_document(seller, number, 100))
        opened, number = True, number + 1
        print(f"\nSale of {PRICE} UAH in cash (local number {number})")
        session.document("sale", sale(seller, number))
        sales, number = 1, number + 1
        print(f"\nZ-report (local number {number})")
        session.document("zreport", z_report(seller, number, sales))
        z_sent, number = True, number + 1
        print(f"\nClose shift (local number {number})")
        session.document("close", shift_document(seller, number, 101))
        closed = True
    except StepError as exc:
        steps_ok = False
        print(f"  ! {exc}")
    if opened and not closed:
        print("\nThe shift is still open; closing it.")
        try:
            state = session.command("TransactionsRegistrarState", {"NumFiscal": seller.prro})
            number = state["NextLocalNum"]
            if not z_sent:
                print(f"Z-report with {sales} sale(s) (local number {number})")
                session.document("zreport-retry", z_report(seller, number, sales))
                number += 1
            print(f"Close shift (local number {number})")
            session.document("close-retry", shift_document(seller, number, 101))
        except StepError as exc:
            print(f"  ! {exc}")
            print("  ! Close this test shift from your ПРРО software before using the ПРРО.")
    return steps_ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--key", required=True, type=Path, help="Key-6.dat, .pfx or .jks")
    parser.add_argument("--certificate", type=Path, help="signing certificate (for Key-6.dat)")
    parser.add_argument("--prro", type=int, help="the ПРРО's fiscal number (NumFiscal)")
    parser.add_argument("--server", default=SERVER, help=f"default {SERVER}")
    parser.add_argument("--out", type=Path, help="folder for requests and answers")
    args = parser.parse_args(argv)

    out = args.out or Path.home() / datetime.now().strftime("uakep-test-shift-%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=False)
    password = getpass.getpass(f"Password for {args.key.name}: ")
    key = uakep.load_key(args.key, password=password, certificate=args.certificate)
    del password
    cert = key.certificate
    print(f"Signer's certificate from {cert.issuer.get('common_name')!r}")
    print(f"Valid {cert.not_before:%Y-%m-%d} to {cert.not_after:%Y-%m-%d}; TSA {cert.tsp_url}")
    print(f"uakep {uakep.__version__}; requests and answers go to {out}")
    session = Session(args.server, key, out)

    try:
        print("\nServerState")
        print(f"  server time {session.command('ServerState', {}, signed=False)['Timestamp']}")
        if args.prro is None:
            print("\nObjects")
            objects = session.command("Objects", {})
            if objects is None:
                print("  none: the server has no tax object or ПРРО for this key (HTTP 204)")
                return 1
            for obj in objects.get("TaxObjects") or []:
                registrars = obj.get("TransactionsRegistrars") or []
                print(f"  tax object {obj['Name']!r}: {len(registrars)} ПРРО")
                for prro in registrars:
                    print(
                        f"    ПРРО {prro['NumFiscal']} (local {prro['NumLocal']}): {prro['Name']}"
                    )
            return 0
        print("\nTransactionsRegistrarState")
        state = session.command(
            "TransactionsRegistrarState", {"NumFiscal": args.prro, "IncludeTaxObject": True}
        )
        if state is None:
            raise StepError(f"the server knows no ПРРО {args.prro} for this key")
        print(f"  shift state {state['ShiftState']}, next local number {state['NextLocalNum']}")
        if state["ShiftState"] != 0:
            raise StepError(f"a shift is open (testing: {state.get('Testing')}); close it first")
        seller = Seller(state, args.prro, cert.owner_name or "")
    except StepError as exc:
        print(f"  ! {exc}")
        return 1

    print(
        f"\nSeller {seller.org} ({seller.tin}), {seller.point};"
        f" ПРРО {seller.prro}, local {seller.cash_desk}  [private: leave out when sharing]"
    )
    if input(f"Send a TESTING shift to {session.server}? [y/N] ").strip().lower() != "y":
        return 1
    ok = run_shift(session, seller, state["NextLocalNum"])
    print()
    for problem in session.problems:
        print(f"PROBLEM: {problem}")
    passed = ok and not session.problems
    print("PASSED: the test shift was accepted" if passed else "FAILED: see above")
    print(f"Requests and answers: {out}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
