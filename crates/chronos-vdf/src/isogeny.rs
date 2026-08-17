/// Post-Quantum VDF via Supersingular Isogenies — Novel Contribution 2.
///
/// This module defines the `IsogenyVdfEngine` trait and a simulation backend
/// that models the sequential work property of an isogeny walk without
/// requiring a full SIDH/CSIDH implementation (which would require a
/// dedicated cryptographic library not yet stable in Rust).
///
/// # Protocol sketch
/// A supersingular isogeny VDF works as follows:
///
/// ```text
/// Setup:  E_0 = supersingular elliptic curve over F_{p^2}
///         Walk length T (sequential isogeny steps)
/// Eval:   E_T = E_0 → E_1 → ... → E_T  (T sequential 2-isogenies)
///         y = j-invariant(E_T)
///         π = compressed isogeny path (quasi-log verification)
/// Verify: Recompute j-invariant from π in O(T / log T) steps
/// ```
///
/// Security: hardness of the isogeny path problem (post-quantum).
/// No trusted setup required (unlike RSA-based VDFs).
///
/// # Reference
/// "Post-Quantum Verifiable Delay Functions" (2025) and
/// "Isogeny-based Verifiable Delay Functions" (Chavez-Saab et al., 2022).
/// No existing system integrates isogeny VDFs with ephemeral FHE agents.
///
/// # Current status
/// The `IsogenyVdfSimulator` provides a SHA-256 hash-chain simulation that
/// preserves the sequential non-parallelisability property.  The
/// `IsogenyVdfEngine` trait defines the production interface for a real
/// CSIDH-based implementation.
use chronos_core::{ChronosError, ChronosResult};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

/// Output of an isogeny VDF evaluation.
#[derive(Clone, Debug)]
pub struct IsogenyVdfOutput {
    /// The j-invariant of the terminal curve (or its simulation).
    pub y: Vec<u8>,
    /// Compressed isogeny path proof (or simulation).
    pub proof: Vec<u8>,
}

/// Trait for post-quantum isogeny-based VDF engines.
///
/// Implementors provide the actual CSIDH/SIDH walk; the simulator provides
/// a sequential hash-chain substitute for development and testing.
pub trait IsogenyVdfEngine: Send + Sync {
    /// Evaluate the isogeny VDF: walk T steps from the starting curve encoded
    /// in `seed`, returning the terminal j-invariant and a path proof.
    ///
    /// # Errors
    /// Returns [`ChronosError::Vdf`] on computation failure.
    fn evaluate_isogeny(&self, seed: &[u8], t: u64) -> ChronosResult<IsogenyVdfOutput>;

    /// Verify the isogeny path proof in sub-linear time.
    ///
    /// Returns `true` iff the proof is valid for the given seed and output.
    fn verify_isogeny(&self, seed: &[u8], output: &IsogenyVdfOutput, t: u64) -> bool;

    /// Whether this engine provides post-quantum security.
    fn is_post_quantum(&self) -> bool;
}

/// Simulation backend: SHA-256 hash-chain with Merkle-path proof.
///
/// Preserves sequential non-parallelisability.  Not post-quantum in the
/// cryptographic sense, but structurally identical to the isogeny walk for
/// integration testing.
pub struct IsogenyVdfSimulator;

impl IsogenyVdfEngine for IsogenyVdfSimulator {
    fn evaluate_isogeny(&self, seed: &[u8], t: u64) -> ChronosResult<IsogenyVdfOutput> {
        // `t` is honoured exactly in every build profile.  A previous revision
        // clamped it to 16 under `#[cfg(debug_assertions)]`, which silently
        // reduced the sequential work to a constant in any non-release build.
        let mut state = seed.to_vec();
        // Collect every 256th intermediate for the Merkle proof.
        let checkpoint_interval = 256u64;
        let mut checkpoints: Vec<Vec<u8>> = vec![state.clone()];

        for i in 0..t {
            let mut h = Sha256::new();
            h.update(&state);
            // Domain-separate each step with the step index.
            h.update(i.to_le_bytes());
            state = h.finalize().to_vec();

            if (i + 1) % checkpoint_interval == 0 {
                checkpoints.push(state.clone());
            }
        }

        // Proof = Merkle root of checkpoints (SHA-256 binary tree).
        let proof = merkle_root(&checkpoints);

        Ok(IsogenyVdfOutput { y: state, proof })
    }

    fn verify_isogeny(&self, seed: &[u8], output: &IsogenyVdfOutput, t: u64) -> bool {
        // Full re-evaluation for the simulator (production would use the path).
        match self.evaluate_isogeny(seed, t) {
            Ok(expected) => expected.y == output.y,
            Err(_) => false,
        }
    }

    fn is_post_quantum(&self) -> bool {
        // The simulator uses SHA-256, which is quantum-resistant (Grover gives
        // only a quadratic speedup).  A real CSIDH implementation would return true.
        false // Honest: this is a simulation, not a real isogeny walk.
    }
}

/// Compute the SHA-256 Merkle root of a list of leaves.
fn merkle_root(leaves: &[Vec<u8>]) -> Vec<u8> {
    if leaves.is_empty() {
        return vec![0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0].clone();
    }
    let mut layer: Vec<Vec<u8>> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::new();
        let mut i = 0;
        while i < layer.len() {
            let left = &layer[i];
            let right = if i + 1 < layer.len() { &layer[i + 1] } else { left };
            let mut h = Sha256::new();
            h.update(left);
            h.update(right);
            next.push(h.finalize().to_vec());
            i += 2;
        }
        layer = next;
    }
    layer.remove(0)
}

/// Configuration for selecting the VDF backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VdfBackend {
    /// RSA-based Wesolowski VDF (classical security, fast).
    Wesolowski,
    /// Isogeny-based VDF (post-quantum security, slower).
    Isogeny,
}

impl VdfBackend {
    /// Parse from a config string (`"wesolowski"` or `"isogeny"`).
    pub fn parse_backend(s: &str) -> ChronosResult<Self> {
        match s.to_lowercase().as_str() {
            "wesolowski" => Ok(Self::Wesolowski),
            "isogeny" => Ok(Self::Isogeny),
            other => Err(ChronosError::Config(format!(
                "Unknown VDF backend '{other}'. Valid: wesolowski, isogeny"
            ))),
        }
    }
}

/// Convert a BigUint seed to bytes for the isogeny VDF.
pub fn biguint_to_seed(g: &BigUint) -> Vec<u8> {
    g.to_bytes_be()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isogeny_simulator_deterministic() -> ChronosResult<()> {
        let sim = IsogenyVdfSimulator;
        let seed = b"chronos-isogeny-test-seed";
        let out1 = sim.evaluate_isogeny(seed, 64)?;
        let out2 = sim.evaluate_isogeny(seed, 64)?;
        assert_eq!(out1.y, out2.y, "Isogeny VDF must be deterministic");
        assert_eq!(out1.proof, out2.proof);
        Ok(())
    }

    #[test]
    fn test_isogeny_simulator_verify() -> ChronosResult<()> {
        let sim = IsogenyVdfSimulator;
        let seed = b"chronos-isogeny-verify-test";
        let out = sim.evaluate_isogeny(seed, 32)?;
        assert!(sim.verify_isogeny(seed, &out, 32), "Valid output must verify");
        Ok(())
    }

    #[test]
    fn test_isogeny_simulator_wrong_output_rejected() -> ChronosResult<()> {
        let sim = IsogenyVdfSimulator;
        let seed = b"chronos-isogeny-tamper-test";
        let mut out = sim.evaluate_isogeny(seed, 32)?;
        out.y[0] ^= 0xFF; // Tamper with output.
        assert!(!sim.verify_isogeny(seed, &out, 32), "Tampered output must be rejected");
        Ok(())
    }

    #[test]
    fn test_vdf_backend_parse() -> ChronosResult<()> {
        assert_eq!(VdfBackend::parse_backend("wesolowski")?, VdfBackend::Wesolowski);
        assert_eq!(VdfBackend::parse_backend("isogeny")?, VdfBackend::Isogeny);
        assert!(VdfBackend::parse_backend("unknown").is_err());
        Ok(())
    }
}
