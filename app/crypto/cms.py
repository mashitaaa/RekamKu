from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import der
from .rsasig import DIGESTS, RSA_ENCRYPTION, RSA_WITH, PrivateKey, SignatureError, hash_bytes, sign_digest, \
    verify_digest
from .x509 import Certificate, parse_certificate

SIGNED_DATA, DATA = "1.2.840.113549.1.7.2", "1.2.840.113549.1.7.1"
CONTENT_TYPE, MESSAGE_DIGEST, SIGNING_TIME = "1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4", "1.2.840.113549.1.9.5"
SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
SHA256 = "2.16.840.1.101.3.4.2.1"


def _attribute(o: str, value: bytes) -> bytes:
    return der.seq(der.oid(o), der.set_of(value))


def sign_detached(digest: bytes, cert_der: bytes, key: PrivateKey, when: datetime | None = None) -> bytes:
    cert = parse_certificate(cert_der)
    if cert.key.n != key.n:
        raise SignatureError("certificate does not belong to this key")
    when = (when or datetime.now(timezone.utc)).replace(microsecond=0)
    attrs = [
        _attribute(CONTENT_TYPE, der.oid(DATA)),
        _attribute(SIGNING_TIME, der.time_value(when)),
        _attribute(MESSAGE_DIGEST, der.octet_string(digest)),
        _attribute(SIGNING_CERT_V2, der.seq(der.seq(der.seq(der.octet_string(hashlib.sha256(cert_der).digest()))))),
    ]
    signed_attrs = der.set_of(*attrs)
    signature = sign_digest(key, hashlib.sha256(signed_attrs).digest())
    signer_info = der.seq(
        der.integer(1),
        der.seq(cert.issuer_raw, der.integer(cert.serial)),
        der.algorithm(SHA256, der.null()),
        der.implicit(0, signed_attrs),
        der.algorithm(RSA_ENCRYPTION, der.null()),
        der.octet_string(signature),
    )
    signed_data = der.seq(
        der.integer(1),
        der.set_of(der.algorithm(SHA256, der.null())),
        der.seq(der.oid(DATA)),
        der.implicit(0, der.set_of(cert_der)),
        der.set_of(signer_info),
    )
    return der.seq(der.oid(SIGNED_DATA), der.explicit(0, signed_data))


@dataclass
class SignerResult:
    digest_ok: bool = False
    signature_ok: bool = False
    hash_name: str = ""
    certificate: Certificate | None = None
    signing_time: datetime | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.digest_ok and self.signature_ok and not self.errors


def verify_detached(cms_der: bytes, content_parts: list[bytes]) -> SignerResult:
    res = SignerResult()
    try:
        root = der.parse(cms_der).expect(der.SEQUENCE)
        if root[0].oid() != SIGNED_DATA:
            raise SignatureError("not a CMS SignedData structure")
        sd = root[1].expect(0xA0)[0].expect(der.SEQUENCE)
        items = sd.children
        certs = [parse_certificate(c) for n in items if n.tag == 0xA0 for c in n.children]
        infos = items[-1].expect(der.SET).children
        if len(infos) != 1:
            raise SignatureError("expected exactly one signer")
        si = infos[0].children
        sid = si[1]
        if sid.tag != der.SEQUENCE:
            raise SignatureError("signer identified by key ID is not supported")
        serial = sid[1].int()
        cert = next((c for c in certs if c.serial == serial and c.issuer_raw == sid[0].raw), None)
        if cert is None:
            raise SignatureError("the signer's certificate is not embedded")
        res.certificate = cert
        digest_oid = si[2][0].oid()
        if digest_oid not in DIGESTS:
            raise SignatureError(f"unsupported digest algorithm {digest_oid}")
        h = DIGESTS[digest_oid][0]
        res.hash_name = h
        pos = 3
        signed_attrs = None
        if si[pos].tag == 0xA0:
            signed_attrs = si[pos]
            pos += 1
        sig_alg = si[pos][0].oid()
        if sig_alg != RSA_ENCRYPTION and RSA_WITH.get(sig_alg) != h:
            raise SignatureError(f"unsupported signature algorithm {sig_alg}")
        signature = si[pos + 1].expect(der.OCTET_STRING).content
        content_digest = hash_bytes(h, *content_parts)
        if signed_attrs is None:
            res.digest_ok = True
            res.signature_ok = verify_digest(cert.key, content_digest, signature, h)
            return res
        attrs = {}
        for a in signed_attrs.children:
            o = a[0].oid()
            if o in attrs:
                raise SignatureError("duplicate signed attribute")
            attrs[o] = a[1].children
        if attrs.get(CONTENT_TYPE, [None])[0] is None or attrs[CONTENT_TYPE][0].oid() != DATA:
            raise SignatureError("content type attribute missing or wrong")
        md = attrs.get(MESSAGE_DIGEST)
        if not md:
            raise SignatureError("message digest attribute missing")
        res.digest_ok = md[0].expect(der.OCTET_STRING).content == content_digest
        if SIGNING_CERT_V2 in attrs:
            ess = attrs[SIGNING_CERT_V2][0][0][0]
            if ess[0].tag == der.OCTET_STRING and ess[0].content != hashlib.sha256(cert.raw).digest():
                raise SignatureError("signing-certificate attribute does not match the embedded certificate")
        if SIGNING_TIME in attrs:
            res.signing_time = attrs[SIGNING_TIME][0].time()
        to_sign = bytes([der.SET]) + signed_attrs.raw[1:]
        res.signature_ok = verify_digest(cert.key, hash_bytes(h, to_sign), signature, h)
    except (der.DERError, SignatureError, ValueError) as e:
        res.errors.append(str(e))
    return res
