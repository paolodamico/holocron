//! The library's single, trusted source of cryptographic randomness.
//!
//! When sealing, `ChaCha20-Poly1305` requires a true cryptograhically secure
//! random source or its catastrophic. Re-using the nonce exposes the key
//! outright. As such, the library makes the opinionated decision of drawing from
//! the OS randomness source directly, to avoid implementation mistakes.
use getrandom::SysRng;
use rand_core::UnwrapErr;

use crate::Error;

/// Fill `dst` with cryptographically secure random bytes from the OS CSPRNG.
///
/// # Errors
/// [`Error::Rng`] if the operating system CSPRNG is unavailable.
pub(crate) fn fill(dst: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(dst).map_err(|_| Error::Rng)
}

/// A ready-to-use OS CSPRNG handle for dependencies that drive the RNG through
/// an infallible [`rand_core::CryptoRng`] (namely hpke encapsulation).
///
/// The OS CSPRNG is checked for availability up front so that an unavailable
/// source is reported as [`Error::Rng`] rather than a panic.
///
/// # Errors
/// [`Error::Rng`] if the operating system CSPRNG is unavailable.
pub(crate) fn os_csprng() -> Result<UnwrapErr<SysRng>, Error> {
    let mut readiness_check = [0u8; 1];
    fill(&mut readiness_check)?;
    Ok(UnwrapErr(SysRng))
}
