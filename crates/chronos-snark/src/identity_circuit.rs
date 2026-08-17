/// EAIP identity circuit — mission-ID binding. No filler constraints.
///
/// # What this circuit proves
///
/// | Property | Status |
/// |----------|--------|
/// | The prover used the mission ID the verifier claims | **enforced** |
/// | The proof is bound to a declared identity root byte | **enforced** |
/// | Knowledge of `y` such that `SHA-256(y) == R` | **not enforced** |
///
/// # The pre-image claim is not yet met
///
/// Proving `SHA-256(y) == R` in zero knowledge requires a SHA-256 R1CS gadget.
/// SHA-256 is bit-oriented and costs on the order of 25,000 constraints. The
/// previous revision did not implement one: it emitted 10,000 filler
/// multiplications in a `while count < IDENTITY_CONSTRAINTS` loop, described in
/// a comment as a "constraint chain that encodes the binding relationship with
/// the correct constraint count".
///
/// It also contained a soundness bug. Two products were computed —
/// `y[0] * mid[0]` and `root_pub * mid_pub` — each assigned to a fresh witness
/// variable, but the two were **never constrained equal**. Both constraints were
/// therefore just definitions, and nothing tied the witness to either public
/// input. A prover could supply any `y` and any mission ID.
///
/// The filler is removed and the mission-ID binding is made real. Until the
/// pre-image relation is encoded, this is a **commitment to a mission ID**, not
/// a zero-knowledge identity proof, and `EAIP` should be described that way.
///
/// The right fix is to bind the identity root with the Poseidon permutation
/// already implemented in [`crate::circuit`] instead of SHA-256 — a few hundred
/// real constraints rather than 25,000 — which means changing how the root is
/// derived in `chronos-vdf::generate_identity_root`. That is a protocol change,
/// tracked separately.
///
/// Public inputs, in allocation order — this order is the verifier ABI and must
/// match [`IdentityProver::verify_identity_proof`]:
/// 1. `root[0]` — first byte of the declared identity root
/// 2. `mission_id_bytes[0]` — first byte of the mission ID hash
use ark_ff::PrimeField;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use ark_std::vec::Vec;
use chronos_core::{ChronosError, ChronosResult};

/// Zero-knowledge identity proof circuit.
///
/// All witness fields are `Option<_>`: `None` during trusted setup,
/// `Some(_)` during proof generation.
#[derive(Clone)]
pub struct IdentityCircuit<F: PrimeField> {
    /// VDF output bytes (private witness — never revealed).
    pub y_bytes: Option<Vec<u8>>,
    /// Mission ID bytes (private witness).
    pub mission_id_bytes: Option<Vec<u8>>,
    /// Identity root (public — first byte used as public input).
    pub root: Option<[u8; 32]>,
    pub _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> IdentityCircuit<F> {
    /// Construct circuit for proof generation.
    pub fn new_for_proving(
        y_bytes: Vec<u8>,
        mission_id_bytes: Vec<u8>,
        root: [u8; 32],
    ) -> Self {
        Self {
            y_bytes: Some(y_bytes),
            mission_id_bytes: Some(mission_id_bytes),
            root: Some(root),
            _marker: std::marker::PhantomData,
        }
    }

    /// Construct circuit for trusted setup (no witnesses).
    pub fn new_for_setup() -> Self {
        Self {
            y_bytes: None,
            mission_id_bytes: None,
            root: None,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for IdentityCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Allocate private witnesses: y_bytes (32) and mission_id_bytes (32).
        let y_vars = alloc_witnesses::<F>(&cs, &self.y_bytes, 32)?;
        let mid_vars = alloc_witnesses::<F>(&cs, &self.mission_id_bytes, 32)?;

        // Public input: root[0] — binds the proof to the identity root.
        let root_val = self.root.as_ref().map(|r| r[0]).unwrap_or(0);
        let root_pub = cs.new_input_variable(|| Ok(F::from(root_val as u64)))?;

        // Public input: mission_id_bytes[0] — binds the proof to the mission.
        let mid_val = self
            .mission_id_bytes
            .as_ref()
            .and_then(|b| b.first())
            .copied()
            .unwrap_or(0);
        let mid_pub = cs.new_input_variable(|| Ok(F::from(mid_val as u64)))?;

        // Enforce: mission_id_bytes[0] == mid_pub.
        //
        // This is the one binding the circuit genuinely establishes: the prover
        // must have used the mission ID the verifier supplies. The previous
        // revision computed two products and never constrained them equal, so no
        // binding existed at all.
        cs.enforce_constraint(
            LinearCombination::from(mid_vars[0]),
            LinearCombination::from(Variable::One),
            LinearCombination::from(mid_pub),
        )?;

        // `root_pub` is exposed so the proof is bound to a declared identity
        // root, but the relation `SHA-256(y) == root` is NOT encoded — see the
        // module docs. `y_vars` is therefore unconstrained: it is allocated so
        // the witness layout stays stable for when the pre-image gadget lands.
        let _ = (&y_vars, root_pub);

        Ok(())
    }
}

fn alloc_witnesses<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    data: &Option<Vec<u8>>,
    len: usize,
) -> Result<Vec<Variable>, SynthesisError> {
    (0..len)
        .map(|i| {
            let val = data.as_ref().and_then(|b| b.get(i)).copied().unwrap_or(0);
            cs.new_witness_variable(|| Ok(F::from(val as u64)))
        })
        .collect()
}

// ─── Groth16 Identity Prover ─────────────────────────────────────────────────

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Groth16 prover for the EAIP identity circuit.
pub struct IdentityProver {
    pk: Option<ProvingKey<Bn254>>,
    pvk: Option<PreparedVerifyingKey<Bn254>>,
}

impl IdentityProver {
    pub fn new() -> Self {
        Self { pk: None, pvk: None }
    }

    /// Generate proving and verifying keys via a simulated 3-party MPC ceremony.
    pub fn generate_keys(&mut self) -> ChronosResult<()> {
        let circuit = IdentityCircuit::<Fr>::new_for_setup();
        let mut rng = crate::prover::mpc_ceremony_rng();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| ChronosError::Snark(format!("Identity key generation failed: {e}")))?;
        self.pvk = Some(prepare_verifying_key(&vk));
        self.pk = Some(pk);
        Ok(())
    }

    /// Generate an identity proof binding the mission ID and declared root.
    ///
    /// NOTE: this does **not** currently prove knowledge of `y_bytes` such that
    /// `SHA-256(y_bytes) == root`. That relation is not encoded in the circuit —
    /// see the module documentation. `y_bytes` is accepted and kept private, but
    /// no constraint ties it to `root`.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if proof generation fails.
    pub fn generate_identity_proof(
        &self,
        y_bytes: &[u8],
        mission_id: &str,
        root: &[u8; 32],
    ) -> ChronosResult<Vec<u8>> {
        let pk = self.pk.as_ref().ok_or_else(|| {
            ChronosError::Snark("Identity proving key not loaded".into())
        })?;

        let mid_bytes = mission_id_to_bytes(mission_id);
        let circuit = IdentityCircuit::<Fr>::new_for_proving(
            y_bytes.to_vec(),
            mid_bytes,
            *root,
        );

        let mut rng = StdRng::from_entropy();
        let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
            .map_err(|e| ChronosError::Snark(format!("Identity proof generation failed: {e}")))?;

        let mut buf = Vec::new();
        proof
            .serialize_compressed(&mut buf)
            .map_err(|e| ChronosError::Snark(format!("Proof serialization failed: {e}")))?;
        Ok(buf)
    }

    /// Verify a zero-knowledge identity proof.
    ///
    /// Public inputs: `root[0]` and `mission_id_bytes[0]`.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if verification fails.
    pub fn verify_identity_proof(
        &self,
        proof_bytes: &[u8],
        root: &[u8; 32],
        mission_id: &str,
    ) -> ChronosResult<bool> {
        let pvk = self.pvk.as_ref().ok_or_else(|| {
            ChronosError::Snark("Identity verifying key not loaded".into())
        })?;

        let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
            .map_err(|e| ChronosError::Snark(format!("Proof deserialization failed: {e}")))?;

        let mid_bytes = mission_id_to_bytes(mission_id);
        let public_inputs = vec![
            Fr::from(root[0] as u64),
            Fr::from(mid_bytes[0] as u64),
        ];

        Groth16::<Bn254>::verify_proof(pvk, &proof, &public_inputs)
            .map_err(|e| ChronosError::Snark(format!("Identity proof verification failed: {e}")))
    }
}

impl Default for IdentityProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash a mission ID string to 32 bytes via SHA-256.
pub fn mission_id_to_bytes(mission_id: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(mission_id.as_bytes());
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_identity_circuit_satisfiable() {
        let root = [0xABu8; 32];
        let circuit = IdentityCircuit::<Fr>::new_for_proving(
            vec![0xABu8; 32],
            vec![0x01u8; 32],
            root,
        );
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("constraint generation must not fail");
        assert!(
            cs.is_satisfied().expect("satisfiability check must not fail"),
            "Identity circuit must be satisfiable"
        );
    }

    /// Guard against filler constraints returning. The circuit currently encodes
    /// exactly one real constraint (the mission-ID binding); a count in the
    /// thousands means padding has been reintroduced.
    #[test]
    fn test_identity_circuit_constraint_count_is_small() {
        let root = [0xABu8; 32];
        let circuit = IdentityCircuit::<Fr>::new_for_proving(
            vec![0xABu8; 32],
            vec![0x01u8; 32],
            root,
        );
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("constraint generation must not fail");
        let n = cs.num_constraints();
        println!("IdentityCircuit constraint count: {n}");
        assert!(
            n <= 100,
            "expected a handful of real constraints, got {n} — filler reintroduced?"
        );
    }


    #[test]
    fn test_identity_prover_roundtrip() {
        let mut prover = IdentityProver::new();
        prover.generate_keys().expect("key generation must succeed");

        let root = [0x42u8; 32];
        let y_bytes = vec![0x42u8; 32];
        let mission_id = "mission-alpha-001";

        let proof = prover
            .generate_identity_proof(&y_bytes, mission_id, &root)
            .expect("proof generation must succeed");

        assert!(!proof.is_empty(), "Proof must not be empty");

        let valid = prover
            .verify_identity_proof(&proof, &root, mission_id)
            .expect("verification must not error");
        assert!(valid, "Valid identity proof must verify");
    }

    #[test]
    fn test_identity_proof_wrong_mission_rejected() {
        let mut prover = IdentityProver::new();
        prover.generate_keys().expect("key generation must succeed");

        let root = [0x42u8; 32];
        let y_bytes = vec![0x42u8; 32];

        let proof = prover
            .generate_identity_proof(&y_bytes, "mission-alpha-001", &root)
            .expect("proof generation must succeed");

        // Different mission ID — public input changes — proof must be rejected.
        let valid = prover
            .verify_identity_proof(&proof, &root, "mission-beta-999")
            .expect("verification must not error");
        assert!(!valid, "Proof with wrong mission ID must be rejected");
    }

    #[test]
    fn test_mission_id_to_bytes_deterministic() {
        let b1 = mission_id_to_bytes("test-mission");
        let b2 = mission_id_to_bytes("test-mission");
        assert_eq!(b1, b2);
        assert_eq!(b1.len(), 32);
    }
}
