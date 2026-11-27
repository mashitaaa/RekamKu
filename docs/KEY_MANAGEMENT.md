# Assignment 2: Key Management

RekamKu from Assignment 1 already gives every user an account key (UMK) that only their password or recovery
code can unlock, gives every file its own file key (FEK) wrapped by the UMK, and stores each file encrypted with
the DES-CBC → RC4 → AES-256-GCM cascade. Assignment 2 adds a way to share records with another user.

Scenario: a neurologist (`dr_budi`) needs the seizure video and the latest lab result of a patient (`siti_demo`).

| Requirement | How RekamKu does it |
|---|---|
| A user can request to see the private data of other users (including the images and documents) | **Shared with me → Request access**: the requester enters the patient's username, a reason and what they need (health profile, identity scans, documents, videos). The patient sees it under **Requests to me**. |
| The requested user generates a symmetric key to share the data | **Review and decide**: the patient picks the exact files (and optionally the health profile) and how long access lasts. On approval RekamKu generates a fresh random 256-bit **share key** for this request. Each chosen file key is wrapped with the share key, so files are not re-encrypted or copied. |
| The key is distributed by other means, encrypted with asymmetric encryption | The share key is encrypted with the requester's **RSA-3072 public key (RSA-OAEP, SHA-256)** and shown as a text token (`RKS1.<share id>.<ciphertext>`). The patient sends it by WhatsApp or e-mail; the buttons only open the patient's own app and RekamKu never sends the key. The requester pastes it into **Add a share key**, and their private key decrypts it. |
| The symmetric keys must be stored securely | The share key is never stored in the clear. It is stored wrapped with the patient's UMK (so they can show it again or revoke) and, after the requester adds the token, wrapped with the requester's UMK. A UMK only exists in server memory during a session. The RSA private key is stored encrypted with the UMK. |

## Key hierarchy

```
password ─scrypt+pepper→ KEK ─unwraps→ UMK(patient) ─wraps→ FEK(file) ─encrypts→ file (cascade)
                                             └─wraps→ share key ─wraps→ FEK(file)      (shared_files.fek)
share key ─RSA-OAEP with requester's public key→ token ── WhatsApp / e-mail ──→ requester
requester's RSA private key (encrypted with UMK(requester)) ─decrypts→ share key ─wrapped by→ UMK(requester)
```

## What is stored

| Table.column | Content | Protection |
|---|---|---|
| `users.enc_pub` | RSA-3072 public key | readable (public by definition) |
| `users.enc_priv` | RSA private key | encrypted with the user's UMK |
| `shares.request` | who asked, reason, what, when | sealed to the patient's X25519 key (the same mechanism as the activity log), so the requester's name is never stored in the clear |
| `shares.outbox` | the requester's own copy of the request | encrypted with the requester's UMK |
| `shares.grant_info` | owner name, profile copy, expiry | encrypted with the share key |
| `shares.key_owner`, `shares.key_requester` | the share key | wrapped with the patient's / requester's UMK |
| `shared_files.fek`, `shared_files.meta` | file key and file metadata | wrapped / encrypted with the share key |
| `shares.id`, `owner_id`, `requester_id`, `status` | bookkeeping | readable: needed to route requests and block revoked shares |

## Design decisions

* **Wrap the file key, do not re-encrypt the file.** A 90 MB video is shared in milliseconds and stays a single
  encrypted copy; revoking only has to delete the wrapped keys.
* **One share key per approved request.** Each request gets its own key, so revoking one doctor's access does not
  affect anyone else, and a leaked token reveals nothing about other shares.
* **RSA-OAEP for the token.** The share key is 32 bytes, well within the OAEP limit of a 3072-bit key, so no
  hybrid scheme is needed. OAEP is randomised (the same key gives a different token every time) and uses a label,
  so tokens cannot be confused with other ciphertexts. The share ID is inside the ciphertext as well, so a token for
  one request cannot be redeemed for another, and only the requester's private key can open it.
* **Key pairs for every user.** The RSA key pair is generated at registration; accounts created before Assignment 2
  get one automatically at their next sign-in.
* **Fingerprint check.** The review page shows the SHA-256 fingerprint of the requester's public key as stored in
  the database. The requester's own pages compute their fingerprint from their private key, which only their
  password can unlock, and warn them if the stored public key does not match it. If someone swaps the public key in
  the database, the two fingerprints differ, so comparing them by phone exposes the swap.
* **Revocation and expiry.** Revoking, expiry or the requester withdrawing deletes both copies of the share key and
  every file key wrapped with it. Every file opened or downloaded through a share is written to the patient's
  activity log (UU PDP Art. 16(2)(h)).

## Limitations

* Public keys come from the server; without the fingerprint check, someone who can write to the database could swap
  them (`bench/share_bench.py` shows the attack works). A compromised running server could also lie on every page.
* The request form says when a username does not exist, so usernames can be guessed.
* Revoking stops access through RekamKu but cannot take back a file the requester already downloaded.
* The shared health profile is a copy taken at approval time.

## Tests

`python -m unittest` runs 74 tests: 49 from Assignment 1 and 25 in `tests/test_sharing.py` (token round-trip,
wrong private key, token bound to its share, tampered token, chat-app line breaks, only the owner can approve,
files of other users cannot be shared, unshared files unreachable, revocation deletes keys, expiry, withdrawal,
deleting a file removes it from shares, activity log, no plaintext in the new tables, existing accounts get keys,
a swapped public key is detected).

`python bench/share_bench.py` measures the cost of sharing and runs 15 attack scenarios; results are in
`bench/results/e8_share_cost.csv` and `bench/results/e9_share_attacks.csv`.
