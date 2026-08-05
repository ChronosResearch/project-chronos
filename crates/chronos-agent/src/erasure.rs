use chronos_core::{ChronosError, ChronosResult};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::os::raw::c_void;
use tracing::info;

/// Compute the SHA-256 Merkle root of a memory region and verify that the
/// region has been correctly triple-pass wiped (ends in `0xFF` pattern).
///
/// This implements the erasure attestation check from §5.1 of the CHRONOS v2
/// paper.  The proof is the SHA-256 digest of the pre-wipe snapshot (`M_pre`).
///
/// # STEP 11 – Secret Redaction
/// The `sk` argument is the wiped buffer (expected to be all-`0xFF`).  We do
/// **not** log its contents; the caller wraps it in a `Redacted<&[u8]>` before
/// passing to any log statement.
///
/// # Safety (inner unsafe block)
/// `libc::memcmp` is used for the byte-level comparison to avoid potential
/// compiler optimisation of a plain loop.
///
/// # Errors
/// Returns [`ChronosError::Erasure`] if the wipe pattern is incorrect.
pub fn prove_erasure(
    sk_wiped: &[u8],
    m_pre: &[u8],
    _y: &BigUint,
) -> ChronosResult<Vec<u8>> {
    // 1. Compute Merkle root of the pre-wipe snapshot.
    let mut hasher = Sha256::new();
    hasher.update(m_pre);
    let root = hasher.finalize();

    info!(target: "chronos", "Erasure proof: computing wipe pattern check (sk=[REDACTED])");

    // 2. Verify the wiped buffer is all-0xFF using libc::memcmp.
    let expected = vec![0xFFu8; sk_wiped.len()];

    // SAFETY: Both `sk_wiped` and `expected` are valid, non-overlapping Rust
    // slices of the same length.  memcmp reads exactly `sk_wiped.len()` bytes
    // from each pointer.  This avoids a bare Rust loop which the compiler could
    // theoretically optimise away.
    let cmp = unsafe {
        libc::memcmp(
            sk_wiped.as_ptr() as *const c_void,
            expected.as_ptr() as *const c_void,
            sk_wiped.len(),
        )
    };

    if cmp != 0 {
        return Err(ChronosError::Erasure(
            "Wipe pattern mismatch: sk buffer is not all-0xFF — secure_wipe may have been \
             optimised away or was not called"
                .into(),
        ));
    }

    Ok(root.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chronos_core::wipe::secure_wipe;

    #[test]
    fn test_erasure_succeeds_after_wipe() -> ChronosResult<()> {
        let mut sk = vec![0xAAu8; 64];
        let m_pre = sk.clone();
        // STEP 9: Wipe then verify via prove_erasure.
        // SAFETY: sk is alive, ptr valid, single-threaded test.
        unsafe { secure_wipe(sk.as_mut_ptr(), sk.len()); }
        let proof = prove_erasure(&sk, &m_pre, &BigUint::from(1u32))?;
        assert_eq!(proof.len(), 32);
        Ok(())
    }

    #[test]
    fn test_erasure_fails_if_not_wiped() {
        let sk = vec![0xAAu8; 64]; // Not wiped.
        let m_pre = sk.clone();
        let result = prove_erasure(&sk, &m_pre, &BigUint::from(1u32));
        assert!(matches!(result, Err(ChronosError::Erasure(_))));
    }
}
