#![no_main]
//! Fuzz public-key parsing and serialization.
//!
//! Two invariants:
//! 1. `PublicKey::from_bytes` never panics on arbitrary bytes. Malformed keys
//!    (wrong length, invalid ML-KEM / X25519 encoding) must return an error.
//! 2. Any key the library itself produces round-trips through `to_bytes` /
//!    `from_bytes` and compares equal.

use arbitrary::Arbitrary;
use holocron::{PublicKey, SecretKey};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Input {
    /// Seed for a well-formed key that must round-trip.
    seed: [u8; 32],
    /// Untrusted bytes handed straight to the parser.
    raw: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // 1. Arbitrary bytes must never panic the parser.
    let _ = PublicKey::from_bytes(&input.raw);

    // 2. A serialized key must parse back to an equal key.
    let pk = SecretKey::from_seed(&input.seed).public_key();
    let bytes = pk.to_bytes();
    let Ok(parsed) = PublicKey::from_bytes(&bytes) else {
        panic!("a key produced by to_bytes must parse back");
    };
    assert_eq!(parsed, pk, "public key must round-trip through bytes");
});
