#![no_main]
//! Feed arbitrary, attacker-controlled bytes to `SecretKey::unseal`.
//!
//! `unseal` parses fully untrusted input (the wire header, the encapsulated
//! key, and the AEAD ciphertext). The invariant under test is simple: it must
//! never panic, never over-read, and only ever return a `Result`. Every path
//! that rejects malformed input must do so gracefully.

use holocron::SecretKey;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

/// A fixed recipient. Key material is not the fuzzed surface here — the
/// ciphertext bytes are — so we build the keypair once to keep throughput high.
static RECIPIENT: LazyLock<SecretKey> = LazyLock::new(|| SecretKey::from_seed(&[0x42; 32]));

fuzz_target!(|data: &[u8]| {
    let recipient: &SecretKey = &RECIPIENT;

    // Both the empty-info and non-empty-info paths through the length check and
    // AEAD open must survive arbitrary ciphertext.
    let _ = SecretKey::unseal(recipient, data, None);
    let _ = SecretKey::unseal(recipient, data, Some(b"holocron-fuzz"));
});
