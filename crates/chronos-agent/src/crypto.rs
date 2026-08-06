use chronos_core::{ChronosError, ChronosResult};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::Sha256;
use std::path::Path;
use tokio::fs;

// ─── STEP 15: Secure file loading ────────────────────────────────────────────

/// Read a secret file and return its bytes.
///
/// On Unix, this function verifies that the file's Unix permissions are exactly
/// `0o600` (owner-read/write only). If the permissions are too permissive the
/// agent refuses to read the file, preventing accidental secret exposure.
///
/// # Errors
/// Returns [`ChronosError::Io`] on read failure, or
/// [`ChronosError::ExclusivityAssumption`] on permission violations.
pub async fn read_secret_file<P: AsRef<Path>>(path: P) -> ChronosResult<Vec<u8>> {
    let path_ref = path.as_ref();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path_ref).await.map_err(|e| {
            ChronosError::Io(e)
        })?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(ChronosError::ExclusivityAssumption(format!(
                "Secret file '{}' has mode {mode:o} — must be 0600. \
                 Run: chmod 600 {path}",
                path_ref.display(),
                path = path_ref.display()
            )));
        }
    }

    fs::read(path_ref).await.map_err(|e| ChronosError::Io(e))
}

// ─── STEP 18: RFC 5869 HKDF Derivation ───────────────────────────────────────

/// Derive the FHE encryption key `K_enc` from the VDF output `y` and a random
/// `salt` via HKDF-SHA256, per §4.3 of the CHRONOS v2 paper.
///
/// ```text
/// K_enc = HKDF-SHA256(IKM = y || salt, info = b"chronos-kenc-v1")
/// ```
///
/// This strictly follows RFC 5869 §2.
///
/// # Arguments
/// * `y`    – VDF output `y = g^(2^T) mod N` as a big-endian byte slice.
/// * `salt` – 32-byte random salt from the drand beacon.
///
/// # Errors
/// Returns [`ChronosError::Fhe`] if HKDF output expansion fails (only if
/// `output_len > 255 * hash_len`, which cannot happen for 32-byte output).
pub fn derive_k_enc(y: &BigUint, salt: &[u8]) -> ChronosResult<[u8; 32]> {
    let y_bytes = y.to_bytes_be();

    // IKM = y || salt
    let mut ikm = Vec::with_capacity(y_bytes.len() + salt.len());
    ikm.extend_from_slice(&y_bytes);
    ikm.extend_from_slice(salt);

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"chronos-kenc-v1", &mut okm).map_err(|e| {
        ChronosError::Fhe(format!("HKDF expand failed: {e}"))
    })?;

    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    /// Test-only salt value — not a production secret.
    const TEST_SALT_A: [u8; 32] = [0xAB; 32];
    /// Second test-only salt, distinct from TEST_SALT_A to verify salt sensitivity.
    const TEST_SALT_B: [u8; 32] = [0xCD; 32];
    /// Arbitrary test input — chosen to be non-trivial but not a real VDF output.
    const TEST_Y_VALUE: u32 = 12345;

    #[test]
    fn test_hkdf_deterministic() -> ChronosResult<()> {
        let y = BigUint::from(TEST_Y_VALUE);
        let k1 = derive_k_enc(&y, &TEST_SALT_A)?;
        let k2 = derive_k_enc(&y, &TEST_SALT_A)?;
        assert_eq!(k1, k2, "HKDF must be deterministic");
        assert_ne!(k1, [0u8; 32], "HKDF output must not be all-zero");
        Ok(())
    }

    #[test]
    fn test_hkdf_different_salt_changes_output() -> ChronosResult<()> {
        let y = BigUint::from(TEST_Y_VALUE);
        let k1 = derive_k_enc(&y, &TEST_SALT_A)?;
        let k2 = derive_k_enc(&y, &TEST_SALT_B)?;
        assert_ne!(k1, k2);
        Ok(())
    }
}
