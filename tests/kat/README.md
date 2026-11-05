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
| 5 | `info-longer-than-255-bytes` | draft vector 2 | `05` × 64 | 300-byte `info`. Catches `info` being cut to 255 bytes or fewer anywhere on the way to the key schedule. |
| 6 | `all-zero-seed-and-eseed` | `00` × 32 | `00` × 64 | All-zero key seed and encapsulation randomness. |
| 7 | `all-ones-seed-and-eseed` | `ff` × 32 | `ff` × 64 | All-ones key seed and encapsulation randomness, the bitwise complement of vector 6. |
| 8 | `plaintext-with-partial-final-block` | draft vector 3 | `08` × 64 | 1000-byte plaintext (byte `i` is `i mod 251`): 15 full ChaCha20 blocks and a 40-byte tail, so it covers the leftover handling after the 4-block (x86_64 SSE2/AVX2) and 8-block (aarch64 NEON) parallel paths. CI runs these tests on x86_64 only. |

Vectors 1–3 reuse the `seed` and `eseed` of the test vectors in
[draft-connolly-cfrg-xwing-kem-06, Appendix C](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-06#appendix-C).
Their `public_key` and encapsulated key (bytes `7..1127` of `sealed`) equal the
draft's `pk` and `ct`. The draft also lists the shared secret `ss`, so these
three messages can be opened end to end with any RFC 9180 key schedule and
ChaCha20-Poly1305, without trusting this repository's code.

The draft seeds in vectors 1–5 and 8 are asymmetric, so they also catch bugs
that reorder seed bytes. Vectors 6 and 7 are unchanged by reordering and only
catch bit-level corruption.

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
   the entries whose outputs are both empty, and refuses to write anything if an
   existing vector no longer reproduces.
3. Run `cargo test --test kat` and check that the diff only adds the new entry.

## When a test fails

Never edit or regenerate the stored outputs of an existing vector.

- **`unseal_known_answers` fails:** the change can no longer open messages that
  are already in storage, or no longer accepts public keys that are already
  published. Fix the change. This includes dependency upgrades
  (`hpke`, `x-wing`, `chacha20poly1305`) that land in `Cargo.lock`.
- **Only `known_answers_are_reproducible` fails:** stored messages still open,
  but `generate` no longer produces them from their inputs. For example, an
  upgrade may consume `eseed` differently. Update `generate` and the
  [Generation](#generation) section until the stored outputs reproduce again.

Dropping support for a format is a deliberate breaking change: bump `VERSION` in
`src/lib.rs` in a PR of its own. That makes every `0x02` vector fail with
`UnsupportedVersion(2)`, so that PR has to change what this test expects of
them. `generate` and `HEADER` describe format `0x02` only, so vectors for a new
format need a generator for that format.
