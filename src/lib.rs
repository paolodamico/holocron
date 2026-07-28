#![doc = include_str!("../README.md")]

use hpke::kem::XWing;

mod keys;
pub use keys::{PublicKey, SecretKey};

/// The KEM (Key Encapsulation Mechanism) used: X-Wing is chosen
/// for its IND-CCA security. Reference: <https://eprint.iacr.org/2024/039.pdf>
pub(crate) type XKem = XWing;

/// Failure modes with encryption or keys
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A key string is malformed: bad encoding, checksum, HRP, or length.
    KeyFormat,
}
