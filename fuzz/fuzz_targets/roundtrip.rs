#![no_main]
//! Seal then unseal must return the original plaintext, for arbitrary
//! plaintext, `info`, and key material.
//!
//! The encapsulation randomness is drawn from a `ChaCha20Rng` seeded from the
//! fuzz input, so every discovered failure reproduces deterministically.

use arbitrary::Arbitrary;
use holocron::{Error, PublicKey, SecretKey};
use libfuzzer_sys::fuzz_target;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

#[derive(Debug, Arbitrary)]
struct Input {
    /// Seed for the recipient keypair.
    key_seed: [u8; 32],
    /// Seed for the ephemeral encapsulation RNG.
    rng_seed: [u8; 32],
    /// Optional application context, sealed and unsealed identically.
    info: Option<Vec<u8>>,
    /// The message to seal.
    plaintext: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let sk = SecretKey::from_seed(&input.key_seed);
    let pk = sk.public_key();
    let mut rng = ChaCha20Rng::from_seed(input.rng_seed);
    let info = input.info.as_deref();

    let sealed = match PublicKey::seal(&pk, &input.plaintext, info, &mut rng) {
        Ok(sealed) => sealed,
        // Oversized `info` is a defined rejection, not a failure.
        Err(Error::InfoExceedsSize) => return,
        Err(e) => panic!("seal failed on valid inputs: {e:?}"),
    };

    match SecretKey::unseal(&sk, &sealed, info) {
        Ok(opened) => assert_eq!(opened, input.plaintext, "roundtrip must preserve plaintext"),
        Err(e) => panic!("freshly sealed message failed to unseal: {e:?}"),
    }
});
