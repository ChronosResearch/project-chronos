/// Axiomatic Containment Monitor: containment expressed as order-theoretic
/// invariants over a lattice-valued state, verified exhaustively at startup.
pub mod containment;
pub mod error;
pub mod fhe;
pub mod memory;
pub mod mlp;
pub mod mpc;
pub mod redacted;
pub mod wipe;

pub use containment::{
    AxiomReport, Capabilities, ContainmentLedger, ContainmentState, Decision, DenyReason, Event,
    Phase,
};
pub use error::{ChronosError, ChronosResult};

use num_bigint::BigUint;

/// Output of a VDF evaluation — the proof `π` in Wesolowski's scheme.
#[derive(Clone, Debug)]
pub struct VdfProof {
    /// The Wesolowski proof element `π` (a BigUint in the RSA group).
    pub proof: BigUint,
}

/// Trait implemented by both the PoSW hash-chain and the Wesolowski VDF.
pub trait VdfEngine: Send + Sync {
    /// Evaluate the VDF: compute `y = g^(2^T) mod N` and produce a proof `π`.
    ///
    /// # Errors
    /// Returns [`ChronosError::Vdf`] on computation or FFI failure.
    fn evaluate(
        &self,
        g: &BigUint,
        t: u64,
        n: &BigUint,
    ) -> ChronosResult<(BigUint, VdfProof)>;

    /// Verify the VDF output `y` against the claimed proof `π`.
    fn verify(&self, g: &BigUint, y: &BigUint, proof: &VdfProof, t: u64, n: &BigUint) -> bool;
}

/// Trait implemented by the Groth16 SNARK prover for erasure attestation.
pub trait SnarkProver: Send + Sync {
    /// Generate an erasure proof given the pre-wipe memory root, VDF output `y`,
    /// and the (already wiped) secret key buffer.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] on circuit synthesis or prover failure.
    fn generate_proof(
        &self,
        sk: &[u8],
        m_pre: &[u8],
        y: &BigUint,
    ) -> ChronosResult<Vec<u8>>;

    /// Verify a SNARK proof against the given public inputs.
    fn verify_proof(&self, proof: &[u8], public_inputs: &[BigUint]) -> bool;
}

#[cfg(test)]
mod tests {
    use crate::wipe::secure_wipe;

    /// Ensures the wipe function leaves 0xFF in every byte (final pass).
    #[test]
    fn test_secure_wipe_final_pattern() {
        let mut data = vec![0x42u8; 64];
        let ptr = data.as_mut_ptr();
        // SAFETY: ptr valid, data alive, single-threaded test.
        unsafe { secure_wipe(ptr, data.len()); }
        for byte in &data {
            assert_eq!(*byte, 0xFF);
        }
    }
}
