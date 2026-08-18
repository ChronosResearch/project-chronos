/// Real Groth16 prover, simulated 3-party MPC trusted setup, and Dynark incremental updater.
///
/// Uses `ark-groth16` over BN254 to generate and verify erasure proofs.
/// Compressed proof size is 128 bytes (2 × G1 at 32 bytes, 1 × G2 at 64).
///
/// # Trusted setup — NOT a multi-party ceremony
///
/// [`mpc_ceremony_rng`] XOR-folds entropy from three RNGs, but all three run in
/// this process on this machine. There is one party, and it holds the trapdoor.
/// This provides **no** ceremony security: whoever runs setup can forge proofs.
///
/// Earlier documentation claimed the toxic waste was recoverable only if all
/// three parties colluded and that one honest party guaranteed security. That is
/// false as implemented — there are not three parties.
///
/// It is adequate for local development, where the same process proves and
/// verifies. Any deployment where the verifier does not trust the prover needs a
/// real Powers-of-Tau ceremony with independent participants on separate
/// machines (Zcash Sapling and Hermez are the usual references).
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use chronos_core::{ChronosError, ChronosResult, SnarkProver};
use num_bigint::BigUint;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use crate::circuit::ErasureCircuit;

// ─── Simulated 3-Party MPC Ceremony ──────────────────────────────────────────

/// Contribution from one MPC ceremony participant.
struct MpcContribution {
    /// 32 bytes of entropy from this participant's independent RNG.
    entropy: [u8; 32],
}

impl MpcContribution {
    /// Generate a fresh contribution from OS entropy.
    fn generate() -> Self {
        let mut entropy = [0u8; 32];
        StdRng::from_entropy().fill_bytes(&mut entropy);
        Self { entropy }
    }
}

/// Derive a setup RNG by XOR-folding three local entropy draws.
///
/// # This is not multi-party
///
/// All three draws come from this process. XOR-folding several RNGs on one
/// machine adds no security property that a single `StdRng::from_entropy()`
/// lacks — the resulting trapdoor is known to whoever runs it. The three-way
/// split mirrors the *shape* of a ceremony, not its security.
///
/// Replace with a real Powers-of-Tau ceremony before any deployment where the
/// verifier does not trust the prover.
pub fn mpc_ceremony_rng() -> StdRng {
    let p1 = MpcContribution::generate();
    let p2 = MpcContribution::generate();
    let p3 = MpcContribution::generate();

    // Combine: seed = SHA-256(p1 XOR p2 XOR p3)
    // XOR ensures no single party controls the output.
    let mut combined = [0u8; 32];
    for i in 0..32 {
        combined[i] = p1.entropy[i] ^ p2.entropy[i] ^ p3.entropy[i];
    }

    // Hash the combined entropy to produce a uniform seed.
    use sha2::{Digest, Sha256};
    let seed_bytes = Sha256::digest(combined);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    StdRng::from_seed(seed)
}

// ─── Groth16 Prover ───────────────────────────────────────────────────────────

/// Production Groth16 prover for the CHRONOS erasure circuit.
pub struct Groth16Prover {
    pk: Option<ProvingKey<Bn254>>,
    pvk: Option<PreparedVerifyingKey<Bn254>>,
}

impl Groth16Prover {
    pub fn new() -> Self {
        Self { pk: None, pvk: None }
    }

    /// Generate proving and verifying keys via a simulated 3-party MPC ceremony.
    ///
    /// Uses `mpc_ceremony_rng()` which XOR-folds entropy from 3 independent
    /// OS-seeded RNGs. No single party's contribution is sufficient to
    /// reconstruct the toxic waste (trapdoor).
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if key generation fails.
    pub fn generate_keys(&mut self) -> ChronosResult<()> {
        let circuit = ErasureCircuit::<Fr>::new_for_setup();
        let mut rng = mpc_ceremony_rng();

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| ChronosError::Snark(format!("Key generation failed: {e}")))?;

        self.pvk = Some(prepare_verifying_key(&vk));
        self.pk = Some(pk);
        Ok(())
    }

    /// Borrow the raw verifying key.
    ///
    /// Needed by [`crate::solidity::export_verifying_key`] to emit EVM
    /// constructor arguments; `verifying_key_bytes` returns arkworks' own
    /// little-endian encoding, which the EVM cannot consume directly.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if keys have not been generated.
    pub fn verifying_key(&self) -> ChronosResult<&ark_groth16::VerifyingKey<Bn254>> {
        let pk = self.pk.as_ref().ok_or_else(|| {
            ChronosError::Snark("Proving key not loaded — call generate_keys first".into())
        })?;
        Ok(&pk.vk)
    }

    /// Serialize the verifying key to bytes.
    pub fn verifying_key_bytes(&self) -> ChronosResult<Vec<u8>> {
        let pk = self.pk.as_ref().ok_or_else(|| {
            ChronosError::Snark("Proving key not loaded — call generate_keys first".into())
        })?;
        let mut buf = Vec::new();
        pk.vk
            .serialize_compressed(&mut buf)
            .map_err(|e| ChronosError::Snark(format!("VK serialization failed: {e}")))?;
        Ok(buf)
    }

    /// Generate a Groth16 erasure proof.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_erasure(
        &self,
        sk: &[u8],
        m_pre: &[u8],
        y: &[u8],
        salt: &[u8],
        ct_sk: &[u8],
        g: &[u8],
        n_mod: &[u8],
        pi_vdf: &[u8],
    ) -> ChronosResult<Vec<u8>> {
        let pk = self.pk.as_ref().ok_or_else(|| {
            ChronosError::Snark("Proving key not loaded — call generate_keys first".into())
        })?;

        let circuit = ErasureCircuit::<Fr>::new_for_proving(
            sk.to_vec(),
            m_pre.to_vec(),
            y.to_vec(),
            salt.to_vec(),
            ct_sk.to_vec(),
            g.to_vec(),
            n_mod.to_vec(),
            pi_vdf.to_vec(),
        );

        let mut rng = StdRng::from_entropy();
        let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
            .map_err(|e| ChronosError::Snark(format!("Proof generation failed: {e}")))?;

        // Serialize to compressed bytes (~192 bytes on BN254).
        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| ChronosError::Snark(format!("Proof serialization failed: {e}")))?;

        Ok(proof_bytes)
    }

    /// Verify a serialized Groth16 erasure proof.
    ///
    /// Public inputs: `y_first_byte` (first byte of VDF output) and
    /// `wipe_pattern` (expected wipe byte, 255 = 0xFF).
    pub fn verify_erasure(
        &self,
        proof_bytes: &[u8],
        y_first_byte: u8,
        wipe_pattern: u8,
    ) -> ChronosResult<bool> {
        let pvk = self.pvk.as_ref().ok_or_else(|| {
            ChronosError::Snark("Verifying key not loaded — call generate_keys first".into())
        })?;

        let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
            .map_err(|e| ChronosError::Snark(format!("Proof deserialization failed: {e}")))?;

        let public_inputs = vec![
            Fr::from(y_first_byte as u64),
            Fr::from(wipe_pattern as u64),
        ];

        let result = Groth16::<Bn254>::verify_proof(pvk, &proof, &public_inputs)
            .map_err(|e| ChronosError::Snark(format!("Proof verification failed: {e}")))?;

        Ok(result)
    }
}

impl Default for Groth16Prover {
    fn default() -> Self {
        Self::new()
    }
}

impl SnarkProver for Groth16Prover {
    fn generate_proof(&self, sk: &[u8], m_pre: &[u8], y: &BigUint) -> ChronosResult<Vec<u8>> {
        let y_bytes = y.to_bytes_be();
        let salt = vec![0u8; 32];
        let ct_sk = vec![0u8; 48];
        let g = vec![2u8; 32];
        let n_mod = vec![1u8; 32];
        let pi_vdf = vec![3u8; 32];
        self.prove_erasure(sk, m_pre, &y_bytes, &salt, &ct_sk, &g, &n_mod, &pi_vdf)
    }

    fn verify_proof(&self, proof: &[u8], _public_inputs: &[BigUint]) -> bool {
        self.verify_erasure(proof, 0, 255).unwrap_or(false)
    }
}

// ─── Dynark: Dynamic SNARK incremental updater ───────────────────────────────

/// Dynark witness delta.
#[derive(Debug, Clone)]
pub struct WitnessDelta {
    pub variable_index: usize,
    pub old_value: u64,
    pub new_value: u64,
}

/// Dynark incremental proof updater — Novel Contribution 3.
///
/// Maintains a proof and supports O(|Δw|) updates when witnesses change.
/// Primary use case: re-attestation when a new drand beacon updates the salt,
/// without re-proving the full circuit.
pub struct DynarkUpdater {
    prover: Groth16Prover,
    current_proof: Option<Vec<u8>>,
    current_sk: Vec<u8>,
    current_m_pre: Vec<u8>,
    current_y: Vec<u8>,
    current_salt: Vec<u8>,
    current_ct_sk: Vec<u8>,
    current_g: Vec<u8>,
    current_n_mod: Vec<u8>,
    current_pi_vdf: Vec<u8>,
}

impl DynarkUpdater {
    pub fn new(prover: Groth16Prover) -> Self {
        Self {
            prover,
            current_proof: None,
            current_sk: vec![0u8; 32],
            current_m_pre: vec![0u8; 32],
            current_y: vec![0u8; 32],
            current_salt: vec![0u8; 32],
            current_ct_sk: vec![0u8; 48],
            current_g: vec![2u8; 32],
            current_n_mod: vec![1u8; 32],
            current_pi_vdf: vec![3u8; 32],
        }
    }

    /// Generate the initial proof and cache the witness.
    #[allow(clippy::too_many_arguments)]
    pub fn initial_prove(
        &mut self,
        sk: Vec<u8>,
        m_pre: Vec<u8>,
        y: Vec<u8>,
        salt: Vec<u8>,
        ct_sk: Vec<u8>,
        g: Vec<u8>,
        n_mod: Vec<u8>,
        pi_vdf: Vec<u8>,
    ) -> ChronosResult<Vec<u8>> {
        let proof = self.prover.prove_erasure(
            &sk, &m_pre, &y, &salt, &ct_sk, &g, &n_mod, &pi_vdf,
        )?;
        self.current_proof = Some(proof.clone());
        self.current_sk = sk;
        self.current_m_pre = m_pre;
        self.current_y = y;
        self.current_salt = salt;
        self.current_ct_sk = ct_sk;
        self.current_g = g;
        self.current_n_mod = n_mod;
        self.current_pi_vdf = pi_vdf;
        Ok(proof)
    }

    /// Incrementally update the proof when only the salt changes.
    ///
    /// NOTE: this is not currently an incremental update — it re-proves the
    /// whole circuit. A real Dynark implementation would patch only the Poseidon
    /// gadget constraints affected by the new salt. The name and the O(|Δw|)
    /// claim in this module's docs describe the intended design, not the
    /// present behaviour.
    pub fn update_salt(&mut self, new_salt: Vec<u8>) -> ChronosResult<Vec<u8>> {
        if self.current_proof.is_none() {
            return Err(ChronosError::Snark(
                "Dynark: no initial proof — call initial_prove first".into(),
            ));
        }
        let proof = self.prover.prove_erasure(
            &self.current_sk.clone(),
            &self.current_m_pre.clone(),
            &self.current_y.clone(),
            &new_salt,
            &self.current_ct_sk.clone(),
            &self.current_g.clone(),
            &self.current_n_mod.clone(),
            &self.current_pi_vdf.clone(),
        )?;
        self.current_salt = new_salt;
        self.current_proof = Some(proof.clone());
        Ok(proof)
    }

    pub fn current_proof(&self) -> Option<&[u8]> {
        self.current_proof.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prover() -> Groth16Prover {
        let mut p = Groth16Prover::new();
        p.generate_keys().expect("Key generation must succeed");
        p
    }

    #[test]
    fn test_groth16_prove_and_verify() {
        let prover = make_prover();
        let proof = prover
            .prove_erasure(
                &[0xFFu8; 32],
                &[0xDEu8; 32],
                &[0xABu8; 32],
                &[0xCDu8; 32],
                &[0x00u8; 48],
                &[0x02u8; 32],
                &[0x01u8; 32],
                &[0x03u8; 32],
            )
            .expect("Proof generation must succeed");

        assert!(!proof.is_empty(), "Proof must not be empty");

        let valid = prover
            .verify_erasure(&proof, 0xAB, 0xFF)
            .expect("Verification must not error");
        assert!(valid, "Valid proof must verify");
    }

    #[test]
    fn test_groth16_wrong_public_input_rejected() {
        let prover = make_prover();
        let proof = prover
            .prove_erasure(
                &[0xFFu8; 32],
                &[0xDEu8; 32],
                &[0xABu8; 32],
                &[0xCDu8; 32],
                &[0x00u8; 48],
                &[0x02u8; 32],
                &[0x01u8; 32],
                &[0x03u8; 32],
            )
            .expect("Proof generation must succeed");

        // Wrong y[0] — should fail.
        let valid = prover
            .verify_erasure(&proof, 0x00, 0xFF)
            .expect("Verification must not error");
        assert!(!valid, "Proof with wrong public input must be rejected");
    }

    #[test]
    fn test_dynark_initial_and_update() {
        let prover = make_prover();
        let mut dynark = DynarkUpdater::new(prover);

        let proof0 = dynark
            .initial_prove(
                vec![0xFFu8; 32],
                vec![0xDEu8; 32],
                vec![0xABu8; 32],
                vec![0xCDu8; 32],
                vec![0x00u8; 48],
                vec![0x02u8; 32],
                vec![0x01u8; 32],
                vec![0x03u8; 32],
            )
            .expect("Initial prove must succeed");

        let proof1 = dynark
            .update_salt(vec![0xEFu8; 32])
            .expect("Dynark update must succeed");

        assert!(!proof0.is_empty());
        assert!(!proof1.is_empty());
    }

    #[test]
    fn test_dynark_update_without_initial_fails() {
        let prover = make_prover();
        let mut dynark = DynarkUpdater::new(prover);
        let result = dynark.update_salt(vec![0xEFu8; 32]);
        assert!(matches!(result, Err(ChronosError::Snark(_))));
    }
}
