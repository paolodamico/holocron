use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use hpke::{Deserializable, Kem as KemTrait, Serializable};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::{Error, XKem};

/// The private key used for key encapsulation and encryption.
///
/// The X-Wing KEM is used which uses ML-KEM-768 (Kyber) and X25519 under
/// the hood.
// TODO: Implement zeroize
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(<XKem as KemTrait>::PrivateKey);

/// The public component of the encapsulation key. This is usually the key
/// of the recipient.
///
/// For X-Wing, the key is 1216 bytes (1184 bytes for ML-KEM-768 and 32 bytes for X25519).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(<XKem as KemTrait>::PublicKey);

impl SecretKey {
    /// Construct a secret key from a raw 32-byte X-Wing seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let Ok(sk) = <XKem as KemTrait>::PrivateKey::from_bytes(seed) else {
            unreachable!("a 32-byte array is always a valid X-Wing seed")
        };
        Self(sk)
    }

    /// Initializes a new secret key using the provided CSPRNG.
    pub fn rand<R: CryptoRng>(rng: &mut R) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut seed[..]);
        Self::from_seed(&seed)
    }

    pub(crate) fn as_hpke(&self) -> &<XKem as KemTrait>::PrivateKey {
        &self.0
    }

    /// Derive the corresponding [`PublicKey`].
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(<XKem as KemTrait>::sk_to_pk(&self.0))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(REDACTED)")
    }
}

impl PublicKey {
    pub(crate) fn new(pk: <XKem as KemTrait>::PublicKey) -> Self {
        Self(pk)
    }

    pub(crate) fn as_hpke(&self) -> &<XKem as KemTrait>::PublicKey {
        &self.0
    }

    /// The raw 1216-byte encapsulation key.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().as_slice().to_vec()
    }

    /// Parse a raw 1216-byte encapsulation key.
    ///
    /// # Errors
    /// Returns [`Error::KeyFormat`] if the length is wrong or the key is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        <XKem as KemTrait>::PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::KeyFormat)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&STANDARD_NO_PAD.encode(self.to_bytes()))
    }
}
