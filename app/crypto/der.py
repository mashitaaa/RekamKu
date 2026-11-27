from __future__ import annotations

from datetime import datetime, timezone

SEQUENCE, SET, INTEGER, OID, NULL, OCTET_STRING, BIT_STRING = 0x30, 0x31, 0x02, 0x06, 0x05, 0x04, 0x03
BOOLEAN, UTF8_STRING, PRINTABLE_STRING, UTC_TIME, GENERALIZED_TIME = 0x01, 0x0C, 0x13, 0x17, 0x18


class DERError(ValueError):
    pass


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _length(len(content)) + content


def seq(*items: bytes) -> bytes:
    return tlv(SEQUENCE, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(SET, b"".join(sorted(items)))


def integer(v: int) -> bytes:
    if v < 0:
        raise DERError("negative integers are not used")
    return tlv(INTEGER, v.to_bytes(v.bit_length() // 8 + 1, "big"))


def oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return tlv(OID, bytes(out))


def null() -> bytes:
    return b"\x05\x00"


def boolean(v: bool) -> bytes:
    return tlv(BOOLEAN, b"\xff" if v else b"\x00")


def octet_string(b: bytes) -> bytes:
    return tlv(OCTET_STRING, b)


def bit_string(b: bytes, unused: int = 0) -> bytes:
    return tlv(BIT_STRING, bytes([unused]) + b)


def utf8(s: str) -> bytes:
    return tlv(UTF8_STRING, s.encode("utf-8"))


def printable(s: str) -> bytes:
    return tlv(PRINTABLE_STRING, s.encode("ascii"))


def time_value(dt: datetime) -> bytes:
    dt = dt.astimezone(timezone.utc)
    if 1950 <= dt.year < 2050:
        return tlv(UTC_TIME, dt.strftime("%y%m%d%H%M%SZ").encode())
    return tlv(GENERALIZED_TIME, dt.strftime("%Y%m%d%H%M%SZ").encode())


def explicit(n: int, content: bytes) -> bytes:
    return tlv(0xA0 | n, content)


def implicit(n: int, encoded: bytes, constructed: bool = True) -> bytes:
    return bytes([(0xA0 if constructed else 0x80) | n]) + encoded[1:]


def algorithm(dotted: str, params: bytes | None = None) -> bytes:
    return seq(oid(dotted), params if params is not None else b"")


class Node:
    __slots__ = ("tag", "raw", "content", "_children")

    def __init__(self, tag: int, raw: bytes, content: bytes):
        self.tag, self.raw, self.content = tag, raw, content
        self._children = None

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    @property
    def children(self) -> list[Node]:
        if self._children is None:
            if not self.constructed:
                raise DERError("primitive value has no children")
            self._children = parse_all(self.content)
        return self._children

    def __getitem__(self, i: int) -> Node:
        try:
            return self.children[i]
        except IndexError:
            raise DERError("missing element") from None

    def __len__(self) -> int:
        return len(self.children)

    def expect(self, tag: int) -> Node:
        if self.tag != tag:
            raise DERError(f"expected tag {tag:#x}, found {self.tag:#x}")
        return self

    def int(self) -> int:
        self.expect(INTEGER)
        if not self.content:
            raise DERError("empty integer")
        return int.from_bytes(self.content, "big", signed=True)

    def oid(self) -> str:
        self.expect(OID)
        b = self.content
        if not b:
            raise DERError("empty OID")
        parts = [min(b[0] // 40, 2), b[0] - 40 * min(b[0] // 40, 2)]
        v = 0
        for x in b[1:]:
            v = (v << 7) | (x & 0x7F)
            if not x & 0x80:
                parts.append(v)
                v = 0
        if b[-1] & 0x80:
            raise DERError("truncated OID")
        return ".".join(map(str, parts))

    def bits(self) -> bytes:
        self.expect(BIT_STRING)
        if not self.content or self.content[0] != 0:
            raise DERError("unsupported bit string")
        return self.content[1:]

    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def time(self) -> datetime:
        s = self.content.decode("ascii")
        if self.tag == UTC_TIME:
            dt = datetime.strptime(s, "%y%m%d%H%M%SZ")
        elif self.tag == GENERALIZED_TIME:
            dt = datetime.strptime(s, "%Y%m%d%H%M%SZ")
        else:
            raise DERError("not a time value")
        return dt.replace(tzinfo=timezone.utc)


def parse_one(data: bytes, pos: int = 0) -> tuple[Node, int]:
    if pos + 2 > len(data):
        raise DERError("truncated value")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise DERError("multi-byte tags are not supported")
    first = data[pos + 1]
    hdr = 2
    if first < 0x80:
        n = first
    else:
        k = first & 0x7F
        if k == 0 or k > 4 or pos + 2 + k > len(data):
            raise DERError("bad length")
        n = int.from_bytes(data[pos + 2:pos + 2 + k], "big")
        if n < 0x80 or data[pos + 2] == 0:
            raise DERError("non-minimal length")
        hdr += k
    end = pos + hdr + n
    if end > len(data):
        raise DERError("value runs past the end")
    return Node(tag, bytes(data[pos:end]), bytes(data[pos + hdr:end])), end


def parse(data: bytes) -> Node:
    node, end = parse_one(data)
    return node


def parse_exact(data: bytes) -> Node:
    node, end = parse_one(data)
    if end != len(data):
        raise DERError("trailing data")
    return node


def parse_all(data: bytes) -> list[Node]:
    out, pos = [], 0
    while pos < len(data):
        node, pos = parse_one(data, pos)
        out.append(node)
    return out
