#![doc = include_str!("../README.md")]

use hpke::{
    HpkeError, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::XWing,
    single_shot_seal_with_rng,
};

mod keys;
pub use keys::{PublicKey, SecretKey};
use x_wing::CryptoRng;

/// The KEM (Key Encapsulation Mechanism) used: X-Wing is chosen
/// for its IND-CCA security. Reference: <https://eprint.iacr.org/2024/039.pdf>
pub(crate) type XKem = XWing;

pub(crate) type Aead = ChaCha20Poly1305;
pub(crate) type Kdf = HkdfSha256;

/// Internal wire format version. Applicable only to this implementation.
///
/// Bumped only on a breaking encoding change.
const VERSION: u8 = 0x01;
/// The HPKE algorithm ID: X-Wing (ML-KEM-768 and X25519)
///
/// The explicit ID (`0x647A`) is assigned in the [IANA HPKE KEM Identifiers Registry](https://www.iana.org/assignments/hpke/hpke.xhtml).
const KEM_ID: u16 = 0x647A;
/// The explicit Key Derivation Function: HKDF-SHA256 (RFC 5869)
///
/// The explicit ID (`0x0001`) is defined in [RFC 9180](https://www.rfc-editor.org/info/rfc9180/#section-7.2) and IANA registry.
const KDF_ID: u16 = 0x0001;
/// The AEAD Cipher: ChaCha20-Poly1305
///
/// The explicit ID (`0x0003`) is defined in [RFC 9180](https://www.rfc-editor.org/info/rfc9180/#section-7.3) and IANA registry.
const AEAD_ID: u16 = 0x0003;

/// The header is attached as a prefix to all sealed ciphertext.
///
/// [RFC-9180](https://datatracker.ietf.org/doc/rfc9180/) does not specify a
/// wire format, so this implementation incorporates it to define encoding. The
/// header format is inspired by the OHTTP RFC ([RFC 9458](https://www.ietf.org/rfc/rfc9458.html#section-4.3)).
///
/// All values are encoded big-endian.
///
/// # Security
/// The header is neither encrypted nor authenticated, it is added only
/// to future proof for different cryptographic primitives or encoding format.
const HEADER: [u8; 7] = {
    let kem = KEM_ID.to_be_bytes();
    let kdf = KDF_ID.to_be_bytes();
    let aead = AEAD_ID.to_be_bytes();
    [VERSION, kem[0], kem[1], kdf[0], kdf[1], aead[0], aead[1]]
};
const HEADER_LEN: usize = HEADER.len();

impl PublicKey {
    /// Seal `plaintext` to the `recipient`'s public key. This is analogous to
    /// libsodium's [Sealed Box](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes) where
    /// a message is sent anonymously to a recipient's public key. The important difference is that a hybrid KEM
    /// is used.
    ///
    /// With the choice of X-Wing, the ciphertext remains IND-CCA secure as long as either the security
    /// properties of `X25519` or `ML-KEM-768` (Kyber768) holds.
    ///
    /// # Arguments
    /// - `recipient`: The public key of the recipient.
    /// - `plaintext`: The plaintext message to be encrypted.
    /// - `info`: Optional application-supplied information. This is usually global
    ///   context (e.g. "a backup of X app"). The exact same `info` must be provided for sealing and unsealing,
    ///   otherwise unsealing will fail.
    /// - `rng`: The CSPRNG provider.
    ///
    /// # Errors
    /// Returns [`Error::Seal`] if HPKE encapsulation or AEAD sealing unexpectedly fails.
    ///
    /// # Wire Format
    /// ```plaintext
    /// HEADER || ENCAPSULATED_KEY || CIPHERTEXT
    /// ```
    pub fn seal<R: CryptoRng>(
        recipient: &PublicKey,
        plaintext: &[u8],
        info: Option<&[u8]>,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let (enc, ciphertext) = single_shot_seal_with_rng::<Aead, Kdf, XKem>(
            &OpModeS::Base,
            recipient.as_hpke(),
            info.unwrap_or_default(),
            plaintext,
            // Making the explicit opinionated decision of not exposing associated data (AAD)
            // (RFC 5116 authenticated buit not encrypted data) in this reference implementation because
            // the use cases it intends to cover warrant a global context (i.e. `info`).
            &[],
            rng,
        )?;
        let enc = enc.to_bytes();
        let mut out = Vec::with_capacity(HEADER_LEN + enc.len() + ciphertext.len());
        out.extend_from_slice(&HEADER);
        out.extend_from_slice(enc.as_slice());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
}

/// Failure modes with encryption or keys
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Provided key is malformed: bad encoding, checksum, HRP, or length.
    #[error("provided key is malformed")]
    KeyFormat,
    /// The sealed message is too short or malformed.
    #[error("sealed message is malformed")]
    Decode,
    /// KEM decapsulation failed.
    #[error("decapsulation failed")]
    Decap,
    /// AEAD authentication failed: tampered ciphertext or wrong recipient.
    #[error("AEAD authentication failed")]
    Open,
    /// Sealing the message failed.
    #[error("seal unexpectedly failed")]
    Seal,
    /// An HPKE state that this construction never produces. Critical library bug.
    #[error("internal critical bug")]
    Internal,
}

impl From<HpkeError> for Error {
    fn from(e: HpkeError) -> Self {
        match e {
            HpkeError::OpenError => Error::Open,
            HpkeError::DecapError => Error::Decap,
            HpkeError::EncapError | HpkeError::SealError => Error::Seal,
            HpkeError::ValidationError | HpkeError::IncorrectInputLength(_, _) => Error::Decode,
            HpkeError::MessageLimitReached
            | HpkeError::KdfOutputTooLong
            | HpkeError::InvalidPskBundle => Error::Internal,
        }
    }
}
