//! Secret-file loading and request authentication.
//!
//! # What changed and why
//!
//! **HKDF-SHA256 and AES-256-GCM are gone from this module.** They were correct
//! implementations of the wrong primitives for this position in the protocol. The
//! erasure proof has to demonstrate, in zero knowledge, that the wiped key is the
//! one that decrypts from the time-locked ciphertext under a key derived from the
//! VDF output. Neither HKDF-SHA256 nor AES-GCM is provable in R1CS at a sane
//! constraint count, which is why the previous revision shipped a 60,000-constraint
//! gadget that computed nothing. Both are replaced by
//! [`chronos_snark::aead::ChronosAead`], built on the Poseidon permutation the
//! circuit already pays for. AES-256-GCM remains the right choice anywhere CHRONOS
//! talks to something else; it is simply the wrong choice here.
//!
//! **The raw-key fallback is gone.** The previous protocol loop did this:
//!
//! ```ignore
//! Err(e) => {
//!     warn!("AES-GCM decrypt failed — using ct_sk as raw key (prototype mode)");
//!     ct_sk.clone()
//! }
//! ```
//!
//! Supplying a `ct_sk.bin` that was not a valid ciphertext therefore caused the
//! agent to adopt the file's contents *as the key*. The VDF output was never
//! consulted, so the entire time-lock — the property CHRONOS exists to provide —
//! was bypassed by a malformed input file. Decryption failure is now fatal.
//!
//! # Request authentication
//!
//! The previous middleware required an `X-Chronos-Nonce` header containing 24 hex
//! characters. Any 24 hex characters. It was a replay window, not a credential:
//! every endpoint, including `/mission/init`, was reachable by anyone who could
//! open a TCP connection. Since `/mission/init` starts the mission and `/verify`
//! consumes the rate-limit budget, that is a denial-of-service and a mission-abort
//! primitive at minimum.
//!
//! Authentication is now an HMAC-SHA256 over the request's method, path, nonce and
//! body digest, under a pre-shared operator key. Binding all four matters:
//!
//! | Bound | Prevents |
//! |---|---|
//! | method | replaying a `GET` MAC on a `POST` |
//! | path | replaying a `/status` MAC against `/mission/init` |
//! | nonce | replaying the same request twice (with [`NonceCache`]) |
//! | body digest | swapping the payload under a captured MAC |
//!
//! [`NonceCache`]: crate::tls::NonceCache
//!
//! This is symmetric and pre-shared, so it authenticates *the operator*, not a
//! specific individual, and it is not a substitute for mTLS — an eavesdropper still
//! sees plaintext requests over HTTP. It closes the "no credential at all" hole;
//! transport confidentiality remains open and is tracked in the README.

use chronos_core::{ChronosError, ChronosResult};
use chronos_snark::aead::Ciphertext;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs;

type HmacSha256 = Hmac<Sha256>;

/// Required length of the operator authentication key.
pub const AUTH_KEY_BYTES: usize = 32;

/// Read a secret file, refusing over-permissive modes on Unix.
///
/// # Errors
/// Returns [`ChronosError::Io`] on read failure, or
/// [`ChronosError::ExclusivityAssumption`] if the mode is not exactly `0600`.
pub async fn read_secret_file<P: AsRef<Path>>(path: P) -> ChronosResult<Vec<u8>> {
    let path_ref = path.as_ref();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path_ref).await.map_err(ChronosError::Io)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(ChronosError::ExclusivityAssumption(format!(
                "secret file '{}' has mode {mode:o} — must be 0600. Run: chmod 600 {}",
                path_ref.display(),
                path_ref.display()
            )));
        }
    }

    #[cfg(not(unix))]
    {
        // Windows ACLs are not expressible through `std::fs::Permissions`, so the
        // mode check cannot be performed. Stated rather than silently skipped.
        tracing::warn!(
            target: "chronos",
            path = %path_ref.display(),
            "file permission check unavailable on this platform — protect the file with ACLs"
        );
    }

    fs::read(path_ref).await.map_err(ChronosError::Io)
}

/// Load a Chronos-AEAD ciphertext from disk.
///
/// # Errors
/// Returns [`ChronosError::Io`] if unreadable, [`ChronosError::ExclusivityAssumption`]
/// on a bad file mode, or [`ChronosError::Erasure`] if the bytes are not a
/// well-formed ciphertext.
pub async fn load_ct_sk<P: AsRef<Path>>(path: P) -> ChronosResult<Ciphertext> {
    let bytes = read_secret_file(path).await?;
    Ciphertext::from_bytes(&bytes)
}

/// Load the operator authentication key.
///
/// # Errors
/// Returns an error if the file is unreadable, has a bad mode, or is not exactly
/// [`AUTH_KEY_BYTES`] long. A short key is rejected rather than padded, because
/// padding would silently weaken authentication.
pub async fn load_auth_key<P: AsRef<Path>>(path: P) -> ChronosResult<[u8; AUTH_KEY_BYTES]> {
    let bytes = read_secret_file(path).await?;
    if bytes.len() != AUTH_KEY_BYTES {
        return Err(ChronosError::Config(format!(
            "operator auth key must be exactly {AUTH_KEY_BYTES} bytes, got {}. \
             Generate one with: head -c {AUTH_KEY_BYTES} /dev/urandom > operator.key",
            bytes.len()
        )));
    }
    let mut key = [0u8; AUTH_KEY_BYTES];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Build the canonical string that the request MAC covers.
///
/// Fields are length-prefixed rather than delimiter-joined. With a plain `\n`
/// delimiter, a path containing a newline could shift bytes between fields and
/// produce the same canonical string from two different requests — a classic
/// canonicalisation ambiguity. Length prefixes make the encoding injective.
fn canonical_request(method: &str, path: &str, nonce_hex: &str, body: &[u8]) -> Vec<u8> {
    let body_digest = Sha256::digest(body);
    let mut out = Vec::with_capacity(method.len() + path.len() + nonce_hex.len() + 64);
    for field in [method.as_bytes(), path.as_bytes(), nonce_hex.as_bytes()] {
        out.extend_from_slice(&(field.len() as u64).to_be_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&(body_digest.len() as u64).to_be_bytes());
    out.extend_from_slice(&body_digest);
    out
}

/// Compute the expected request MAC.
///
/// Exposed so client tooling can produce the `X-Chronos-Auth` header with exactly
/// the same construction the agent verifies. A separate client-side
/// reimplementation is how signing schemes drift out of sync.
#[must_use]
pub fn request_mac(
    key: &[u8; AUTH_KEY_BYTES],
    method: &str,
    path: &str,
    nonce_hex: &str,
    body: &[u8],
) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts keys of any length; 32 bytes is always valid");
    mac.update(&canonical_request(method, path, nonce_hex, body));
    let out = mac.finalize().into_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

/// Verify a request MAC in constant time.
///
/// Uses `Hmac::verify_slice`, which compares via `subtle`'s constant-time
/// equality. A byte-wise `==` would leak the position of the first differing byte
/// through timing, letting an attacker recover a valid MAC one byte at a time.
///
/// # Errors
/// Returns [`ChronosError::ExclusivityAssumption`] if the MAC is absent,
/// malformed, or wrong. The error deliberately does not distinguish those cases.
pub fn verify_request_mac(
    key: &[u8; AUTH_KEY_BYTES],
    method: &str,
    path: &str,
    nonce_hex: &str,
    body: &[u8],
    presented_hex: &str,
) -> ChronosResult<()> {
    let presented = hex::decode(presented_hex)
        .map_err(|_| ChronosError::ExclusivityAssumption("request authentication failed".into()))?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|_| ChronosError::ExclusivityAssumption("request authentication failed".into()))?;
    mac.update(&canonical_request(method, path, nonce_hex, body));
    mac.verify_slice(&presented)
        .map_err(|_| ChronosError::ExclusivityAssumption("request authentication failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; AUTH_KEY_BYTES] = [0x5Au8; AUTH_KEY_BYTES];
    const NONCE: &str = "0123456789abcdef01234567";

    fn mac_hex(method: &str, path: &str, nonce: &str, body: &[u8]) -> String {
        hex::encode(request_mac(&KEY, method, path, nonce, body))
    }

    #[test]
    fn test_valid_mac_accepted() {
        let m = mac_hex("POST", "/mission/init", NONCE, b"");
        verify_request_mac(&KEY, "POST", "/mission/init", NONCE, b"", &m)
            .expect("a correctly computed MAC must verify");
    }

    /// The hole this closes: without the key, no request is accepted.
    #[test]
    fn test_request_without_key_cannot_be_forged() {
        let wrong_key = [0xA5u8; AUTH_KEY_BYTES];
        let forged = hex::encode(request_mac(&wrong_key, "POST", "/mission/init", NONCE, b""));
        assert!(
            verify_request_mac(&KEY, "POST", "/mission/init", NONCE, b"", &forged).is_err(),
            "a MAC computed under a different key must be rejected"
        );
    }

    /// Each of the four bound fields must be load-bearing.
    #[test]
    fn test_every_field_is_bound() {
        let base = mac_hex("POST", "/mission/init", NONCE, b"payload");

        // Method substitution.
        assert!(
            verify_request_mac(&KEY, "GET", "/mission/init", NONCE, b"payload", &base).is_err(),
            "method must be bound"
        );
        // Path substitution — replaying a /status MAC against /mission/init.
        assert!(
            verify_request_mac(&KEY, "POST", "/status", NONCE, b"payload", &base).is_err(),
            "path must be bound"
        );
        // Nonce substitution.
        assert!(
            verify_request_mac(&KEY, "POST", "/mission/init", "ffffffffffffffffffffffff", b"payload", &base)
                .is_err(),
            "nonce must be bound"
        );
        // Body substitution under a captured MAC.
        assert!(
            verify_request_mac(&KEY, "POST", "/mission/init", NONCE, b"tampered", &base).is_err(),
            "body must be bound"
        );
    }

    #[test]
    fn test_malformed_mac_rejected() {
        assert!(verify_request_mac(&KEY, "GET", "/status", NONCE, b"", "not-hex").is_err());
        assert!(verify_request_mac(&KEY, "GET", "/status", NONCE, b"", "").is_err());
        // Right hex, wrong length.
        assert!(verify_request_mac(&KEY, "GET", "/status", NONCE, b"", "abcd").is_err());
    }

    /// Length-prefixing must make the canonical encoding injective. With a `\n`
    /// delimiter these two requests would produce the same canonical string.
    #[test]
    fn test_canonicalisation_is_unambiguous() {
        let a = canonical_request("GET", "/a\n/b", NONCE, b"");
        let b = canonical_request("GET", "/a", &format!("/b\n{NONCE}"), b"");
        assert_ne!(
            a, b,
            "field boundaries must not be forgeable by embedding delimiters"
        );
    }

    #[test]
    fn test_mac_is_deterministic() {
        let a = mac_hex("POST", "/infer", NONCE, b"ct");
        let b = mac_hex("POST", "/infer", NONCE, b"ct");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "HMAC-SHA256 is 32 bytes, 64 hex chars");
    }

    #[test]
    fn test_empty_and_large_bodies_both_work() {
        let empty = mac_hex("POST", "/infer", NONCE, b"");
        verify_request_mac(&KEY, "POST", "/infer", NONCE, b"", &empty).expect("empty body");

        let large = vec![0xABu8; 1 << 16];
        let m = mac_hex("POST", "/infer", NONCE, &large);
        verify_request_mac(&KEY, "POST", "/infer", NONCE, &large, &m).expect("large body");
    }

    #[tokio::test]
    async fn test_auth_key_wrong_length_rejected() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("chronos-authkey-short-{}.key", std::process::id()));
        tokio::fs::write(&path, b"tooshort").await.expect("write");

        // On Unix the mode check fires first; on Windows the length check does.
        // Either way it must not succeed.
        assert!(
            load_auth_key(&path).await.is_err(),
            "a key of the wrong length must be rejected, never padded"
        );
        tokio::fs::remove_file(&path).await.ok();
    }

    #[tokio::test]
    async fn test_load_ct_sk_rejects_malformed() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("chronos-ctsk-bad-{}.bin", std::process::id()));
        // 31 bytes: not a whole number of 32-byte field words.
        tokio::fs::write(&path, vec![0u8; 31]).await.expect("write");
        assert!(load_ct_sk(&path).await.is_err());
        tokio::fs::remove_file(&path).await.ok();
    }

    #[tokio::test]
    async fn test_missing_file_is_an_error_not_a_fallback() {
        assert!(
            load_ct_sk("/definitely/not/a/real/path/ct_sk.bin").await.is_err(),
            "a missing ciphertext must fail, never fall back to using raw bytes as the key"
        );
    }
}
