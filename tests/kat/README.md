# Known-answer tests

Holocron seals data for storage, so a message sealed by one release must still
open in every later release that reads the same format version. Round-trip tests
cannot check this: a change applied to both `seal` and `unseal` (flipping every
seed bit, dropping the header from the AEAD associated data, swapping the KDF)
still round-trips, but it can no longer open messages already in storage.

[`vectors.json`](vectors.json) holds messages sealed under fixed keys with fixed
encapsulation randomness. [`../kat.rs`](../kat.rs) checks that the current code
still opens them and that every vector can be rebuilt from its inputs.

## Vector format

A JSON array of objects. Every field except `name` is lowercase hex.

| Field        | Contents |
|--------------|----------|
| `name`       | The edge case the vector covers (see [Coverage](#coverage)). |
| `seed`       | 32-byte X-Wing secret key seed, as passed to `SecretKey::from_seed`. |
| `eseed`      | 64-byte X-Wing encapsulation randomness: the ML-KEM-768 message (bytes 0..32) followed by the X25519 ephemeral secret (bytes 32..64). |
| `info`       | HPKE `info`. Empty means no `info` (`None`). |
| `plaintext`  | The sealed plaintext. |
| `public_key` | 1216-byte X-Wing public key derived from `seed`, as returned by `PublicKey::to_bytes`. |
| `sealed`     | The message in wire format version `0x02`. |

## Generation

For each vector, `sealed` is `HEADER || enc || ct`, where:

- `HEADER` is `02 647a 0001 0003`: format version `0x02`, then the KEM (X-Wing),
  KDF (HKDF-SHA256) and AEAD (ChaCha20-Poly1305) IDs, big-endian.
- `(enc, ct)` is HPKE base-mode `SealBase(pkR = public_key, info, aad = HEADER,
  pt = plaintext)` ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)), with
  X-Wing encapsulation run as `EncapsulateDerand(public_key, eseed)`.

`generate` in [`../kat.rs`](../kat.rs) builds this directly on the `hpke` crate,
using a hand-written header and an RNG that returns exactly the 64 `eseed` bytes.
It does not call Holocron's `seal` or header code, so a bug there cannot leak
into the vectors.

The process is deterministic. `known_answers_are_reproducible` regenerates every
vector from its inputs and requires byte-for-byte equality, so CI confirms the
file is exactly what this process produces.

## What the tests check

`unseal_known_answers` uses only the public API. For each vector:

1. `SecretKey::from_seed(seed).public_key().to_bytes()` equals `public_key`.
2. `PublicKey::from_bytes(public_key)` parses to that same key.
3. `SecretKey::unseal(sk, sealed, Some(info))` returns `plaintext`. When `info`
   is empty, `None` must work as well.

## Coverage

| # | `name` | `seed` | `eseed` | Covers |
|---|--------|--------|---------|--------|
| 1 | `empty-plaintext` | draft vector 1 | draft vector 1 | Shortest valid message: header, encapsulated key and tag only (1143 bytes). |
| 2 | `single-zero-byte-plaintext` | draft vector 2 | draft vector 2 | One-byte plaintext, a NUL byte. |
| 3 | `text-plaintext-with-info` | draft vector 3 | draft vector 3 | Non-empty `info`. |
| 4 | `all-byte-values-plaintext` | draft vector 1 | `04` × 64 | Every byte value `00`–`ff`. At 256 bytes it spans four ChaCha20 blocks. A second message to the key from vector 1. |
| 5 | `info-longer-than-255-bytes` | draft vector 2 | `05` × 64 | 300-byte `info`, whose length does not fit in one byte. |
| 6 | `all-zero-seed-and-eseed` | `00` × 32 | `00` × 64 | All-zero key seed and encapsulation randomness. |
| 7 | `all-ones-seed-and-eseed` | `ff` × 32 | `ff` × 64 | Bitwise complement of vector 6. A bug that flips every seed bit turns one of these keys into the other. |

Vectors 1–3 reuse the `seed` and `eseed` of test vectors 1–3 from
[draft-connolly-cfrg-xwing-kem-06](https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem/blob/main/spec/test-vectors.json).
Their `public_key` and encapsulated key (bytes `7..1127` of `sealed`) equal the
draft's `pk` and `ct`, so the key material can be checked against the published
draft without trusting this repository's code.

The draft seeds in vectors 1–5 are asymmetric, so they also catch bugs that
reorder seed bytes. Vectors 6 and 7 are unchanged by reordering and only catch
bit-level corruption.

### Covered elsewhere

- **Rejection paths** (empty, short or truncated input, unsupported version or
  suite, tampering, wrong recipient, wrong `info`, unauthenticated header): unit
  tests in `src/lib.rs` and the `unseal` fuzz target. These checks don't need
  fixed bytes because they only assert that the input is rejected.
- **`info` at the maximum length** (65 530 bytes):
  `seal_and_unseal_accept_info_at_max_len`. It is not a vector because it would
  add 131 KB of hex to the file.

## Adding vectors

1. Append an entry with the inputs filled in and `"public_key": ""`, `"sealed": ""`.
2. Run `cargo test --test kat -- --ignored fill_new_vectors`. It fills in only
   the entries whose outputs are both empty, and never rewrites existing outputs.
3. Run `cargo test --test kat` and check that the diff only adds the new entry.

## When a vector fails

A failing vector means the change can no longer open messages that are already
in storage. Fix the change; do not regenerate or edit the vector. Dependency
upgrades (`hpke`, `x-wing`, `chacha20poly1305`) count too: these vectors are how
an upgrade that changes the format gets caught.

Dropping support for a format is a deliberate breaking change: bump `VERSION` in
`src/lib.rs` in a PR of its own. `generate` and `HEADER` describe format `0x02`
only, so vectors for a new format need a generator for that format.
