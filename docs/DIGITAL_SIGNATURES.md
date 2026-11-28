# Assignment 3: Digital Signatures on PDF Documents

RekamKu from Assignments 1 and 2 stores every file encrypted with a per-file key (FEK) wrapped by the user's account
key (UMK), and lets a patient share chosen files with a doctor or relative through a share key. Assignment 3 lets the
patient sign their PDF documents, so that whoever receives one, inside or outside RekamKu, can check that it was
signed with the patient's key and has not changed since.

Scenario: `siti` keeps a referral letter, a consent form and a lab result in RekamKu. Before she shares the lab result
with `dr_budi` or sends the PDF to her insurer, she signs it. `dr_budi` verifies it inside RekamKu; the insurer
verifies it in a PDF reader such as Adobe Acrobat after trusting Siti's certificate.

| Requirement | How RekamKu does it |
|---|---|
| A PDF can be signed with its owner's private key | **Sign with my private key** on every PDF in the vault. Only the owner reaches this route; others get 404. |
| The application verifies the signature | **Verify signature** on the owner's page and on a shared file. It checks every signature in the file, says whether it was made with the owner's registered key, and whether anything was added after the last signature. |
| The signature is embedded in the PDF | A standard PDF signature (`/Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached`) appended as an incremental update, with a visible signature box on the last page. The original bytes are left untouched. |
| Generate a key pair if the user has none | The first signature generates an RSA-3072 key pair and a self-signed X.509 certificate (CN = username). It can also be created on **My keys**. |
| Bonus: third-party readers | poppler `pdfsig`: "Signature is Valid", "Total document signed". `openssl cms -verify` accepts the CMS. `qpdf --check` finds no errors. Readers such as Adobe Acrobat use the same `adbe.pkcs7.detached` format; with a self-signed certificate they show the signer as unknown until the certificate (download on **My keys**) is trusted. We tested poppler, OpenSSL, qpdf and Adobe Acrobat Reader: Acrobat first reports the signer as unknown (document unmodified), and after the certificate is trusted it shows "Signed and all signatures are valid" (screenshots in `docs/screenshots/acrobat-before-trust.png` and `acrobat-after-trust.png`). |
| Libraries only for keys, hashes, encryption; signing logic our own | `cryptography` only generates the RSA key pair (and stores it as PKCS#8). `hashlib` hashes. `pypdf` reads the PDF structure and serialises the two existing objects we update. Everything else is ours: DER (`der.py`), RSA PKCS#1 v1.5 signing and verification (`rsasig.py`), the certificate (`x509.py`), CMS SignedData (`cms.py`) and the incremental update, byte range and verification (`pdfsign.py`). |

## Signing (`app/crypto/pdfsign.py: sign_pdf`)

1. Refuse password-protected PDFs. Find the last page, the catalog and the last cross-reference section.
2. Append an incremental update: a signature dictionary with a fixed-width `/ByteRange` placeholder and an 8 KiB
   `/Contents` placeholder, a signature widget with a visible appearance on the last page, the page with the widget
   added to `/Annots`, the catalog with `/AcroForm` (`/Fields` + `/SigFlags 3`), and a new cross-reference section
   (a classic table, or an xref stream if the file used one) with `/Prev` pointing to the old one.
3. Fill in `/ByteRange` = everything except the `/Contents` value, and hash those bytes with SHA-256.
4. Build the signed attributes (content type, signing time, message digest, signing-certificate-v2), hash them and
   sign the hash with our own RSA PKCS#1 v1.5 code: EMSA-PKCS1-v1_5 encoding, then `m^d mod n` with the Chinese
   remainder theorem, random blinding against timing attacks, and a check that `s^e mod n == m` before the
   signature is released.
5. Wrap the signature and the certificate in CMS SignedData and write it, hex encoded, into `/Contents`.

In the app the signed PDF is then encrypted again with the same file key (a new random salt gives new cascade
subkeys), the old ciphertext is deleted, the stored SHA-256 is updated, and so is the metadata copy of every share
that includes the file, so a doctor keeps access to the signed version.

## Verification (`verify_pdf`)

For every `/ByteRange` in the file: the range must start at 0 and the excluded gap must be exactly one hex string
(so nothing can hide in the unsigned part); the CMS is parsed; the hash of the two signed ranges must equal the
`messageDigest` attribute; the RSA signature over the signed attributes must verify with the key in the embedded
certificate; and the signing-certificate attribute must match that certificate. The app then compares the
certificate fingerprint with the one registered for the owner (`users.sig_fpr`), and reports whether the last
signature covers the whole file. A signature dictionary whose byte range is damaged is reported as invalid, not
ignored.

## Keys and what is stored

| Column | Content | Protection |
|---|---|---|
| `users.sig_priv` | RSA-3072 signing key (PKCS#8) | encrypted with the user's UMK |
| `users.sig_cert` | self-signed certificate (contains the username) | encrypted with the user's UMK |
| `users.sig_fpr` | SHA-256 of the certificate | readable: lets a share recipient check that a PDF was signed with the owner's key |

The signing key is separate from the RSA encryption key of Assignment 2, so a key used to decrypt share keys is
never used to sign, and the two can be replaced independently.

## Design decisions

* **RSA-3072, PKCS#1 v1.5, SHA-256.** Every PDF reader supports it, and `adbe.pkcs7.detached` with RSA PKCS#1 v1.5
  is what poppler, Acrobat and OpenSSL all verify. RSA-3072 gives about 128-bit security. PSS would be stronger in
  theory but is less widely accepted in PDF readers, and the bonus asks for third-party verification.
* **Our own RSA arithmetic.** The assignment wants the signing logic to be ours. Python's `pow` is about 29 ms per
  signature instead of 2 ms for OpenSSL, which is invisible next to decrypting and re-encrypting the file. Blinding
  hides the private exponent from timing measurements; the fault check prevents a faulty CRT result from leaking
  a prime.
* **Incremental update instead of rewriting the PDF.** The original bytes stay exactly as uploaded, the result is
  a normal PDF revision that readers understand, and a later signature does not invalidate an earlier one.
* **Self-signed certificate.** There is no certificate authority for patients. A self-signed certificate still lets
  any reader verify the signature; the identity is established by trusting the certificate once, or by comparing its
  fingerprint. Inside RekamKu the fingerprint is compared automatically.
* **Key generated on demand.** Users who never sign do not get a signing key. The first signature creates it, as the
  assignment requires.
* **Sign on the server.** The private key is stored encrypted with the UMK and only decrypted in memory while the
  patient is signed in, the same trust model as Assignment 1.

## Limitations

* Self-signed: outside RekamKu, the signer's identity is only as good as the reader's decision to trust the
  certificate. Someone can create their own certificate with CN = siti; RekamKu flags it as "not the owner's key",
  but a reader that has not pinned Siti's certificate shows the same name.
* No trusted timestamp: the signing time comes from the server clock.
* No key revocation or renewal yet; the certificate is valid for five years.
* A signature proves that the patient vouched for the document, not that the lab result inside is medically correct.

## Tests and analysis

`tests/test_signatures.py` (23 tests): DER encoding, our RSA signature is byte-identical to the library's and
verified by it, the certificate is accepted by the library, CMS accepted by `openssl cms`, valid/tampered/appended/
edited-range/hidden-gap-bytes/second signature, xref-stream PDFs, encrypted PDFs refused, `pdfsig` and `qpdf` acceptance, and the
app flow (key generated on first signature, file still intact and downloadable, foreign signatures flagged, other
users refused, a shared doctor verifies the signed PDF, nothing readable in the database).

`python bench/sign_bench.py` measures signing and verification and runs 12 attack scenarios; results are in
`bench/results/e10_sign_cost.csv` and `bench/results/e11_sign_attacks.csv`.
