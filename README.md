# Holocron

<img src="header-image.jpg" alt ="" width="250px" />

> [!WARNING]  
> This code is currently **UNAUDITED**. Please be careful with any use. Furthermore, the underlying `hpke` library has only undergone an informal review in version 0.8 and the `x-wing` library has also not been independently audited.

This is a reference implementation of a sealed box with hybrid key derivation (post-quantum and classic elliptic curve). This is inspired by libsodium's [Sealed Boxes](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes) where a message can be anonymously sent to a recipient given their public key.

The motivation for this implementation is to follow libsodium's design but implementing a key encapsulation mechanism that already incorporates a quantum-resistant algorithm. The (few) design choices made here follow the principle that the ciphertext will remain secure as long as the security of either the classical **OR** post-quantum algorithms holds.

This implementation does not roll its own cryptography, there are no cryptographic algorithms or ciphers being implemented here, this is rather a reference implementation of a specific standardized ciphersuite choice and the wiring/encoding format.

## Design Choices

1. The primary scheme is **Hybrid Public Key Encryption (HPKE)** from [RFC 9180](https://www.rfc-editor.org/info/rfc9180) which defines the glue for a hybrid KEM, a KDF and authenticated encryption (AEAD). This is implemented through the [hpke](https://github.com/rozbb/rust-hpke) crate. HPKE is already used in some TLS schemes, MLS and OHTTP.
2. The Key Encapsulation Mechanism (KEM) choice is `X-Wing` [draft-connolly-cfrg-xwing-kem-10](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) and [paper](https://eprint.iacr.org/2024/039) which is IND-CCA secure (internally it uses `ML-KEM-768` prev. `Kyber-768` and `X25519` curve). The X-Wing implementation comes from RustCrypto's [crate](https://github.com/RustCrypto/KEMs/tree/master/x-wing).
3. The KDF is `HKDF-SHA-256` matching the 128-bit security of `ML-KEM-768`.
4. The AEAD is `ChaCha20-Poly1305` which is constant time on any hardware. The decision is to maximize portability.


## Example

```rust
use holocron::{SecretKey, PublicKey};
use getrandom::SysRng;
use rand_core::UnwrapErr;

let sk = SecretKey::rand(&mut UnwrapErr(SysRng));
let pk = sk.public_key();

let msg: &[u8] = b"execute order 66";

let sealed = PublicKey::seal(&pk, msg, None, &mut UnwrapErr(SysRng)).unwrap();

let unsealed = SecretKey::unseal(&sk, &sealed, None).unwrap();

assert_eq!(unsealed, msg);
```
