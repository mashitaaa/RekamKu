from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from . import der
from .rsasig import SHA256_WITH_RSA, RSA_WITH, PrivateKey, PublicKey, SignatureError, hash_bytes, public_from_spki, \
    sign_digest, verify_digest

CN, O, OU = "2.5.4.3", "2.5.4.10", "2.5.4.11"
NAMES = {CN: "CN", O: "O", OU: "OU", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "1.2.840.113549.1.9.1": "E"}
KEY_USAGE, BASIC_CONSTRAINTS, SUBJECT_KEY_ID = "2.5.29.15", "2.5.29.19", "2.5.29.14"


def name(cn: str, org: str = "RekamKu", unit: str = "Patient signing key") -> bytes:
    def rdn(o, v):
        return der.set_of(der.seq(der.oid(o), der.utf8(v)))
    return der.seq(rdn(O, org), rdn(OU, unit), rdn(CN, cn))


def _extension(o: str, critical: bool, value: bytes) -> bytes:
    return der.seq(der.oid(o), der.boolean(True) if critical else b"", der.octet_string(value))


def build_self_signed(key: PrivateKey, cn: str, days: int = 5 * 365, now: datetime | None = None) -> bytes:
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    subject = name(cn)
    pub = key.public
    extensions = der.explicit(3, der.seq(
        _extension(BASIC_CONSTRAINTS, True, der.seq()),
        _extension(KEY_USAGE, True, der.bit_string(b"\xc0", unused=6)),
        _extension(SUBJECT_KEY_ID, False, der.octet_string(pub.key_id())),
    ))
    tbs = der.seq(
        der.explicit(0, der.integer(2)),
        der.integer(secrets.randbits(127) | (1 << 126)),
        der.algorithm(SHA256_WITH_RSA, der.null()),
        subject,
        der.seq(der.time_value(now - timedelta(minutes=5)), der.time_value(now + timedelta(days=days))),
        subject,
        pub.spki(),
        extensions,
    )
    sig = sign_digest(key, hashlib.sha256(tbs).digest())
    return der.seq(tbs, der.algorithm(SHA256_WITH_RSA, der.null()), der.bit_string(sig))


def name_dict(node: der.Node) -> dict[str, str]:
    out = {}
    for rdn in node.expect(der.SEQUENCE).children:
        for atv in rdn.children:
            out[NAMES.get(atv[0].oid(), atv[0].oid())] = atv[1].text()
    return out


@dataclass
class Certificate:
    raw: bytes
    tbs: bytes
    serial: int
    issuer_raw: bytes
    subject_raw: bytes
    subject: dict
    issuer: dict
    not_before: datetime
    not_after: datetime
    key: PublicKey
    sig_alg: str
    signature: bytes

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.raw).hexdigest().upper()

    @property
    def common_name(self) -> str:
        return self.subject.get("CN", "")

    def self_signed_ok(self) -> bool:
        h = RSA_WITH.get(self.sig_alg)
        if h is None or self.issuer_raw != self.subject_raw:
            return False
        return verify_digest(self.key, hash_bytes(h, self.tbs), self.signature, h)


def parse_certificate(data: bytes | der.Node) -> Certificate:
    node = data if isinstance(data, der.Node) else der.parse_exact(data)
    try:
        tbs, alg, sig = node.expect(der.SEQUENCE).children
        fields = tbs.expect(der.SEQUENCE).children
        i = 1 if fields[0].tag == 0xA0 else 0
        serial = fields[i].int()
        issuer, validity, subject, spki = fields[i + 2], fields[i + 3], fields[i + 4], fields[i + 5]
        cert = Certificate(raw=node.raw, tbs=tbs.raw, serial=serial, issuer_raw=issuer.raw,
                           subject_raw=subject.raw, subject=name_dict(subject), issuer=name_dict(issuer),
                           not_before=validity[0].time(), not_after=validity[1].time(),
                           key=public_from_spki(spki), sig_alg=alg[0].oid(), signature=sig.bits())
        return cert
    except (der.DERError, ValueError) as e:
        raise SignatureError(f"unreadable certificate: {e}") from None


def fingerprint_groups(hex_fpr: str, groups: int = 8) -> str:
    return " ".join(hex_fpr[i:i + 4] for i in range(0, groups * 4, 4))
