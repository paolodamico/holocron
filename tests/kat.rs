//! Known-answer tests (KATs) for the sealed-box wire format.
//!
//! `kat/vectors.json` holds messages sealed under fixed keys with fixed
//! encapsulation randomness. Every release must keep opening them. See
//! `kat/README.md` for how they are generated and what each one covers.
#![expect(clippy::unwrap_used, reason = "clearer in tests")]

use std::convert::Infallible;

use holocron::{PublicKey, SecretKey};
use hpke::{
    Deserializable, Kem, OpModeS, Serializable,
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::XWing,
    rand_core::{TryCryptoRng, TryRng, utils},
    single_shot_seal_with_rng,
};
use serde::{Deserialize, Serialize};

const VECTORS: &str = include_str!("kat/vectors.json");

/// Format version `0x02` header, written out by hand so the generator does not
/// share the library's encoder.
const HEADER: [u8; 7] = [0x02, 0x64, 0x7A, 0x00, 0x01, 0x00, 0x03];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    name: String,
    #[serde(with = "hex::serde")]
    seed: [u8; 32],
    #[serde(with = "hex::serde")]
    eseed: [u8; 64],
    #[serde(with = "hex::serde")]
    info: Vec<u8>,
    #[serde(with = "hex::serde")]
    plaintext: Vec<u8>,
    #[serde(with = "hex::serde")]
    public_key: Vec<u8>,
    #[serde(with = "hex::serde")]
    sealed: Vec<u8>,
}

fn vectors() -> Vec<Vector> {
    let vectors: Vec<Vector> = serde_json::from_str(VECTORS).unwrap();
    assert!(!vectors.is_empty(), "kat/vectors.json has no vectors");
    vectors
}

/// Hands out the vector's `eseed` as the encapsulation randomness.
struct FixedRng<'a>(&'a [u8]);

impl TryRng for FixedRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let (head, rest) = self.0.split_at(dst.len());
        dst.copy_from_slice(head);
        self.0 = rest;
        Ok(())
    }
}

impl TryCryptoRng for FixedRng<'_> {}

/// Computes `(public_key, sealed)` from a vector's inputs, following the
/// documented format directly on top of hpke rather than through `holocron`.
fn generate(vector: &Vector) -> (Vec<u8>, Vec<u8>) {
    let sk = <XWing as Kem>::PrivateKey::from_bytes(&vector.seed).unwrap();
    let pk = XWing::sk_to_pk(&sk);
    let mut rng = FixedRng(&vector.eseed);
    let (enc, ciphertext) = single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &pk,
        &vector.info,
        &vector.plaintext,
        &HEADER,
        &mut rng,
    )
    .unwrap();
    assert!(
        rng.0.is_empty(),
        "{}: encapsulation did not consume the whole eseed",
        vector.name
    );

    let sealed = [&HEADER[..], &enc.to_bytes()[..], &ciphertext[..]].concat();
    (pk.to_bytes().to_vec(), sealed)
}

/// Describes how `unseal` with `info` disagrees with the stored plaintext, if it does.
fn unseal_mismatch(sk: &SecretKey, vector: &Vector, info: Option<&[u8]>) -> Option<String> {
    let name = &vector.name;
    let call = if info.is_some() { "Some(info)" } else { "None" };
    match SecretKey::unseal(sk, &vector.sealed, info) {
        Ok(plaintext) if plaintext == vector.plaintext => None,
        Ok(_) => Some(format!(
            "{name}: unseal with {call} returned a different plaintext"
        )),
        Err(err) => Some(format!("{name}: unseal with {call} failed: {err}")),
    }
}

/// Checks every vector and reports all failures at once, so a change that breaks
/// only some of them (say, those with `info`) shows the pattern.
#[test]
fn unseal_known_answers() {
    let mut failures = Vec::new();
    for vector in vectors() {
        let name = &vector.name;
        let sk = SecretKey::from_seed(&vector.seed);
        let pk = sk.public_key();

        if pk.to_bytes() != vector.public_key {
            failures.push(format!(
                "{name}: seed no longer derives the stored public key"
            ));
        }
        if PublicKey::from_bytes(&vector.public_key) != Ok(pk) {
            failures.push(format!(
                "{name}: stored public key no longer parses to the derived key"
            ));
        }
        failures.extend(unseal_mismatch(&sk, &vector, Some(&vector.info)));
        if vector.info.is_empty() {
            failures.extend(unseal_mismatch(&sk, &vector, None));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The stored outputs are exactly what `generate` computes from the stored
/// inputs, so anyone can rebuild and audit the file from its inputs alone.
#[test]
fn known_answers_are_reproducible() {
    let mut failures = Vec::new();
    for vector in vectors() {
        let (public_key, sealed) = generate(&vector);
        if public_key != vector.public_key || sealed != vector.sealed {
            failures.push(vector.name);
        }
    }
    assert!(
        failures.is_empty(),
        "stored outputs no longer reproduce from their inputs: {}",
        failures.join(", ")
    );
}

/// Fills `public_key` and `sealed` for vectors that have neither, then rewrites
/// `kat/vectors.json`. Refuses to write if any existing vector no longer
/// reproduces, and never touches outputs already in the file.
#[test]
#[ignore = "rewrites tests/kat/vectors.json; run only when adding vectors"]
fn fill_new_vectors() {
    let mut vectors = vectors();
    for vector in &mut vectors {
        let (public_key, sealed) = generate(vector);
        if vector.public_key.is_empty() && vector.sealed.is_empty() {
            (vector.public_key, vector.sealed) = (public_key, sealed);
        } else {
            assert!(
                public_key == vector.public_key && sealed == vector.sealed,
                "{}: existing vector no longer reproduces; fix `generate` first",
                vector.name
            );
        }
    }

    let json = serde_json::to_string_pretty(&vectors).unwrap() + "\n";
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/kat/vectors.json");
    std::fs::write(path, json).unwrap();
}
