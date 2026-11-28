from __future__ import annotations

import hashlib
import io
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

import pypdf
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject, NumberObject

from .cms import verify_detached
from .rsasig import SignatureError

CONTENTS_BYTES = 8192
RANGE_WIDTH = 44
BOX_W, BOX_H, MARGIN = 236, 54, 36
BYTE_RANGE = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")
HEX_GAP = re.compile(rb"<([0-9A-Fa-f\s]*)>")
SIG_DICT = re.compile(rb"/SubFilter\s*/(?:adbe\.pkcs7|ETSI\.)")
START_XREF = re.compile(rb"startxref\s+(\d+)\s+%%EOF")


class PDFError(ValueError):
    pass


def _pdf_str(s: str) -> bytes:
    safe = s.encode("latin-1", "replace")
    return b"(" + safe.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)") + b")"


def _pdf_date(dt: datetime) -> bytes:
    return dt.astimezone(timezone.utc).strftime("D:%Y%m%d%H%M%S+00'00'").encode()


def _write(obj) -> bytes:
    buf = io.BytesIO()
    obj.write_to_stream(buf)
    return buf.getvalue()


def _appearance(lines: list[str]) -> bytes:
    ops = [b"q 0.93 0.98 0.95 rg 0 0 %d %d re f" % (BOX_W, BOX_H),
           b"0.07 0.53 0.42 RG 1.2 w 0.6 0.6 %.1f %.1f re S" % (BOX_W - 1.2, BOX_H - 1.2),
           b"BT 0.08 0.2 0.18 rg /F1 9 Tf 9 %d Td" % (BOX_H - 15)]
    for i, line in enumerate(lines):
        ops.append((b"0 -12 Td " if i else b"") + _pdf_str(line) + b" Tj")
    ops.append(b"ET Q")
    content = b"\n".join(ops)
    head = (b"<</Type/XObject/Subtype/Form/BBox [0 0 %d %d]/Resources <</Font <</F1 <</Type/Font/Subtype/Type1"
            b"/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>>>>>/Length %d>>" % (BOX_W, BOX_H, len(content)))
    return head + b"stream\n" + content + b"\nendstream"


def _runs(nums: list[int]) -> list[list[int]]:
    runs: list[list[int]] = []
    for n in sorted(nums):
        if runs and runs[-1][-1] + 1 == n:
            runs[-1].append(n)
        else:
            runs.append([n])
    return runs


def _last_startxref(data: bytes) -> int:
    found = list(START_XREF.finditer(data[-4096:]))
    if not found:
        raise PDFError("the file does not end with a valid startxref")
    return int(found[-1].group(1))


def sign_pdf(data: bytes, make_cms: Callable[[bytes], bytes], signer: str, reason: str,
             when: datetime | None = None, location: str = "RekamKu") -> bytes:
    when = (when or datetime.now(timezone.utc)).replace(microsecond=0)
    try:
        reader = pypdf.PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise PDFError("password-protected PDFs cannot be signed")
        page = reader.pages[-1]
        page_ref = page.indirect_reference
        root_ref = reader.trailer.raw_get("/Root")
        root = root_ref.get_object()
        size = int(reader.trailer["/Size"])
        box = page.cropbox
    except PDFError:
        raise
    except Exception as e:
        raise PDFError(f"the PDF could not be read: {e}") from None
    if page_ref is None or not isinstance(root_ref, IndirectObject):
        raise PDFError("the PDF structure is not supported")
    prev = _last_startxref(data)
    xref_stream = not data[prev:prev + 4] == b"xref"

    sig_n, widget_n, ap_n, xref_n = size, size + 1, size + 2, size + 3
    raw_annots = dict.get(page, "/Annots")
    annots = list(raw_annots.get_object()) if raw_annots is not None else []
    existing = 0
    for a in annots:
        try:
            if a.get_object().get("/FT") == "/Sig":
                existing += 1
        except Exception:
            continue
    new_page = DictionaryObject({k: v for k, v in dict.items(page)})
    new_page[NameObject("/Annots")] = ArrayObject(annots + [IndirectObject(widget_n, 0, reader)])

    raw_form = dict.get(root, "/AcroForm")
    form = raw_form.get_object() if raw_form is not None else DictionaryObject()
    new_form = DictionaryObject({k: v for k, v in dict.items(form)})
    raw_fields = dict.get(form, "/Fields")
    fields = list(raw_fields.get_object()) if raw_fields is not None else []
    new_form[NameObject("/Fields")] = ArrayObject(fields + [IndirectObject(widget_n, 0, reader)])
    new_form[NameObject("/SigFlags")] = NumberObject(3)
    new_root = DictionaryObject({k: v for k, v in dict.items(root)})
    new_root[NameObject("/AcroForm")] = new_form

    x0, y0 = float(box.left) + MARGIN, float(box.bottom) + MARGIN + existing * (BOX_H + 8)
    rect = b"[%.2f %.2f %.2f %.2f]" % (x0, y0, x0 + BOX_W, y0 + BOX_H)
    stamp = when.strftime("%d %b %Y %H:%M UTC")
    lines = [f"Digitally signed by {signer}", f"{location}, {stamp}", "RSA-3072, SHA-256 (CMS detached)"]

    placeholder_range = b"/ByteRange [" + b" " * RANGE_WIDTH + b"]"
    sig_body = (b"<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/adbe.pkcs7.detached" + placeholder_range +
                b"/Contents <" + b"0" * (2 * CONTENTS_BYTES) + b">/M " + _pdf_str(_pdf_date(when).decode()) + b"/Name " + _pdf_str(signer) +
                b"/Reason " + _pdf_str(reason) + b"/Location " + _pdf_str(location) +
                b"/Prop_Build <</App <</Name /RekamKu>>>>>>")
    widget = (b"<</Type/Annot/Subtype/Widget/FT/Sig/T " + _pdf_str(f"RekamKu-{uuid.uuid4().hex[:8]}") +
              b"/V %d 0 R/F 132/P %d %d R/Rect " % (sig_n, page_ref.idnum, page_ref.generation) + rect +
              b"/AP <</N %d 0 R>>>>" % ap_n)

    out = bytearray(data)
    if not out.endswith(b"\n"):
        out += b"\n"
    offsets: dict[int, tuple[int, int]] = {}

    def put(num: int, gen: int, body: bytes):
        offsets[num] = (len(out), gen)
        out.extend(b"%d %d obj\n" % (num, gen) + body + b"\nendobj\n")

    put(sig_n, 0, sig_body)
    sig_start = offsets[sig_n][0]
    put(widget_n, 0, widget)
    put(ap_n, 0, _appearance(lines))
    put(page_ref.idnum, page_ref.generation, _write(new_page))
    if root_ref.idnum != page_ref.idnum:
        put(root_ref.idnum, root_ref.generation, _write(new_root))

    trailer_bits = b"/Root " + _write(root_ref)
    for key in ("/Info", "/ID"):
        val = reader.trailer.raw_get(key) if key in reader.trailer else None
        if val is not None:
            trailer_bits += key.encode() + b" " + _write(val)
    trailer_bits += b"/Prev %d" % prev

    if xref_stream:
        xref_at = len(out)
        offsets[xref_n] = (xref_at, 0)
        rows, index = bytearray(), []
        for run in _runs(list(offsets)):
            index += [run[0], len(run)]
            for n in run:
                off, gen = offsets[n]
                rows += b"\x01" + off.to_bytes(4, "big") + gen.to_bytes(2, "big")
        head = (b"<</Type/XRef/Size %d/W [1 4 2]/Index [%s]" % (max(size, xref_n + 1),
                                                               b" ".join(b"%d" % i for i in index)) +
                trailer_bits + b"/Length %d>>" % len(rows))
        out.extend(b"%d 0 obj\n" % xref_n + head + b"stream\n" + bytes(rows) + b"\nendstream\nendobj\n")
    else:
        xref_at = len(out)
        out.extend(b"xref\n")
        for run in _runs(list(offsets)):
            out.extend(b"%d %d\n" % (run[0], len(run)))
            for n in run:
                off, gen = offsets[n]
                out.extend(b"%010d %05d n\r\n" % (off, gen))
        out.extend(b"trailer\n<</Size %d" % max(size, ap_n + 1) + trailer_bits + b">>\n")
    out.extend(b"startxref\n%d\n%%%%EOF\n" % xref_at)

    contents_at = out.index(b"/Contents <", sig_start) + len(b"/Contents ")
    gap_end = contents_at + 2 + 2 * CONTENTS_BYTES
    byte_range = b"0 %d %d %d" % (contents_at, gap_end, len(out) - gap_end)
    range_at = out.index(placeholder_range, sig_start) + len(b"/ByteRange [")
    out[range_at:range_at + RANGE_WIDTH] = byte_range.ljust(RANGE_WIDTH)

    digest = hashlib.sha256(bytes(out[:contents_at]) + bytes(out[gap_end:])).digest()
    cms = make_cms(digest)
    hexed = cms.hex().upper().encode()
    if len(hexed) > 2 * CONTENTS_BYTES:
        raise PDFError("the signature does not fit in the space reserved for it")
    out[contents_at + 1:contents_at + 1 + len(hexed)] = hexed
    return bytes(out)


@dataclass
class PdfSignature:
    index: int
    byte_range: tuple[int, int, int, int]
    covers_whole_file: bool = False
    digest_ok: bool = False
    signature_ok: bool = False
    signer: str = ""
    fingerprint: str = ""
    signing_time: datetime | None = None
    hash_name: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.digest_ok and self.signature_ok and not self.errors


def verify_pdf(data: bytes) -> list[PdfSignature]:
    results = []
    for i, m in enumerate(BYTE_RANGE.finditer(data), 1):
        a, b, c, d = (int(x) for x in m.groups())
        sig = PdfSignature(index=i, byte_range=(a, b, c, d))
        results.append(sig)
        if a != 0 or not 0 < b < c or c + d > len(data):
            sig.errors.append("the byte range does not describe this file")
            continue
        gap = HEX_GAP.fullmatch(data[b:c])
        if gap is None:
            sig.errors.append("the unsigned gap is not exactly the signature value")
            continue
        sig.covers_whole_file = c + d == len(data)
        try:
            cms_der = bytes.fromhex(re.sub(rb"\s", b"", gap.group(1)).decode())
            res = verify_detached(cms_der, [data[a:a + b], data[c:c + d]])
        except (ValueError, SignatureError) as e:
            sig.errors.append(str(e))
            continue
        sig.digest_ok, sig.signature_ok, sig.hash_name = res.digest_ok, res.signature_ok, res.hash_name
        sig.errors += res.errors
        if res.certificate is not None:
            sig.signer = res.certificate.common_name
            sig.fingerprint = res.certificate.fingerprint
        sig.signing_time = res.signing_time
    markers = len(SIG_DICT.findall(data))
    for n in range(len(results), markers):
        results.append(PdfSignature(index=n + 1, byte_range=(0, 0, 0, 0),
                                    errors=["a signature dictionary was found but its byte range is missing or damaged"]))
    return results

