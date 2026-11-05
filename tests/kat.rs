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

#[test]
fn unseal_known_answers() {
    for vector in vectors() {
        let name = &vector.name;
        let sk = SecretKey::from_seed(&vector.seed);
        let pk = sk.public_key();

        assert!(
            pk.to_bytes() == vector.public_key,
            "{name}: seed no longer derives the stored public key"
        );
        assert!(
            PublicKey::from_bytes(&vector.public_key) == Ok(pk),
            "{name}: stored public key no longer parses to the derived key"
        );
        assert_eq!(
            SecretKey::unseal(&sk, &vector.sealed, Some(&vector.info)),
            Ok(vector.plaintext.clone()),
            "{name}: stored message no longer unseals"
        );
        if vector.info.is_empty() {
            assert_eq!(
                SecretKey::unseal(&sk, &vector.sealed, None),
                Ok(vector.plaintext.clone()),
                "{name}: absent info must equal empty info"
            );
        }
    }
}

/// The stored outputs are exactly what `generate` computes from the stored
/// inputs, so anyone can rebuild and audit the file from its inputs alone.
#[test]
fn known_answers_are_reproducible() {
    for vector in vectors() {
        let (public_key, sealed) = generate(&vector);

        assert!(
            public_key == vector.public_key,
            "{}: generated public key differs from the stored one",
            vector.name
        );
        assert!(
            sealed == vector.sealed,
            "{}: generated sealed message differs from the stored one",
            vector.name
        );
    }
}

/// Fills `public_key` and `sealed` for vectors that have neither, then rewrites
/// `kat/vectors.json`. Outputs already in the file are never touched.
#[test]
#[ignore = "rewrites tests/kat/vectors.json; run only when adding vectors"]
fn fill_new_vectors() {
    let mut vectors = vectors();
    for vector in &mut vectors {
        if vector.public_key.is_empty() && vector.sealed.is_empty() {
            (vector.public_key, vector.sealed) = generate(vector);
        }
    }

    let json = serde_json::to_string_pretty(&vectors).unwrap() + "\n";
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/kat/vectors.json");
    std::fs::write(path, json).unwrap();
}
