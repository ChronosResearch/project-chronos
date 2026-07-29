use chronos_core::{ChronosError, ChronosResult, SnarkProver};
use num_bigint::BigUint;

/// Mock Groth16 prover.
///
/// # STEP 10 – Memory management
/// The proving key (`pk`) must be explicitly dropped after each proof generation
/// call.  In the production implementation (once the full `ark-groth16` circuit
/// is wired), the `pk` object is approximately 50 MB.  We call `drop(pk)` at the
/// end of `generate_proof` to ensure the memory is returned to the allocator
/// before the proof bytes are handed to the caller.
///
/// The circuit itself (`ErasureCircuit`) stores witnesses as `Option<Vec<u8>>`.
/// There are no `Arc` cycles — each call to `generate_proof` creates a fresh
/// `ErasureCircuit` and its witnesses are consumed by `create_random_proof_with_reduction`.
pub struct Groth16Prover;

impl SnarkProver for Groth16Prover {
    /// Generate a mock erasure proof.
    ///
    /// # Production note
    /// Replace the mock body with:
    /// ```no_run
    /// let pk = load_proving_key();        // ~50 MB
    /// let circuit = build_circuit(sk, m_pre, y);
    /// let proof = create_random_proof(circuit, &pk, rng)?;
    /// drop(pk);                           // STEP 10: explicit drop
    /// ```
    fn generate_proof(
        &self,
        _sk: &[u8],
        _m_pre: &[u8],
        _y: &BigUint,
    ) -> ChronosResult<Vec<u8>> {
        // Stub proving key — allocated only for this call, then immediately dropped.
        let pk: Vec<u8> = vec![0u8; 8]; // represents the ProvingKey allocation
        let proof = vec![0x42u8; 32];

        // STEP 10: Explicit drop of the proving key before returning proof bytes.
        drop(pk);

        Ok(proof)
    }

    /// Verify a Groth16 erasure proof.
    fn verify_proof(&self, proof: &[u8], _public_inputs: &[BigUint]) -> bool {
        proof.len() == 32 && proof[0] == 0x42
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snark_prover_roundtrip() -> ChronosResult<()> {
        let prover = Groth16Prover;
        let proof = prover.generate_proof(&[], &[], &BigUint::from(1u32))?; // STEP 1: no unwrap
        assert!(prover.verify_proof(&proof, &[]));
        Ok(())
    }

    #[test]
    fn test_snark_invalid_proof_rejected() {
        let prover = Groth16Prover;
        let bad_proof = vec![0x00u8; 32];
        assert!(!prover.verify_proof(&bad_proof, &[]));
    }
}
