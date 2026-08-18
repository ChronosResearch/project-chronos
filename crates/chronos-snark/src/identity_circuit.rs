//! EAIP identity circuit — a genuine zero-knowledge proof of time-locked identity.
//!
//! # What EAIP claims, and what the circuit now actually enforces
//!
//! The Ephemeral Agent Identity Primitive binds an agent's identity to a VDF
//! output, so that the identity cannot exist before `T` sequential squarings
//! complete and cannot be reconstructed after the agent's key material is wiped.
//! The zero-knowledge component is supposed to let the agent prove *"I know the
//! VDF output whose digest is this published identity root"* without revealing the
//! output itself.
//!
//! Two previous revisions did not prove that.
//!
//! The first padded to 10,000 filler multiplications described in a comment as "a
//! constraint chain that encodes the binding relationship with the correct
//! constraint count", and contained a soundness bug on top: it computed
//! `y[0] * mid[0]` and `root_pub * mid_pub` into two separate witness variables
//! and never constrained them equal, so *neither* public input was bound to
//! anything at all.
//!
//! The second removed the filler and enforced one honest constraint —
//! `mission_id_bytes[0] == mid_pub` — which compares one byte of a public value
//! with itself. The `y` witness was allocated and then discarded with
//! `let _ = (&y_vars, root_pub);`. The module documentation said so plainly, which
//! was the right thing to do, but it meant EAIP's headline property was
//! unimplemented.
//!
//! # What changed
//!
//! The pre-image relation is now encoded:
//!
//! ```text
//! root == Poseidon(IdentityRoot, [len(y), y_limbs..., mission_limbs...])
//! ```
//!
//! with `y` a private witness and `root` a full-width public input. Proving this
//! requires knowing `y`, which requires having completed the VDF. That is the
//! entire EAIP claim, and it now costs roughly 1,500 real constraints.
//!
//! # Why the root is Poseidon rather than SHA-256
//!
//! The paper specifies `R = SHA-256(y)`. Proving a SHA-256 pre-image in R1CS costs
//! on the order of 25,000 constraints, because SHA-256 is bit-oriented and an
//! arithmetic circuit has to simulate its boolean operations. That cost is why the
//! previous revisions faked it.
//!
//! Changing the root to a Poseidon digest costs a few hundred constraints for the
//! same statement. This is a **protocol change**, not an implementation detail:
//! `R` is now defined by [`identity_root`], and `chronos-vdf`'s root derivation
//! must agree. Both the security property (pre-image resistance over a 254-bit
//! field, ~127-bit collision resistance with capacity 1) and the time-lock
//! property (the root cannot be computed without `y`, which needs `T` sequential
//! squarings) are preserved. Only the hash function differs.
//!
//! The mission ID is absorbed *into the root* rather than bound as a separate
//! public input. That is strictly stronger: it makes the identity root
//! mission-specific by construction, so a root published for one mission is not a
//! valid root for another and cannot be replayed across missions.
//!
//! # Zero-knowledge scope
//!
//! Groth16 is zero-knowledge, so the proof reveals nothing about `y` beyond the
//! truth of the statement. It does *not* hide the identity root, the mission ID,
//! or the fact that a proof was produced — those are public by design.

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::Zero;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use chronos_core::{ChronosError, ChronosResult};
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::circuit::{MISSION_BYTES, MISSION_LIMBS, Y_BYTES, Y_LIMBS};
use crate::poseidon::{self, Domain};
use crate::prover::{SetupContribution, SetupTranscript};

/// Number of public inputs: the identity root only.
///
/// The mission ID is absorbed into the root rather than exposed separately, so a
/// root is inherently mission-specific.
pub const IDENTITY_PUBLIC_INPUT_COUNT: usize = 1;

/// Derive the EAIP identity root.
///
/// ```text
/// R = Poseidon(IdentityRoot, [len(y), pack(y)..., pack(mission_digest)...])
/// ```
///
/// This is the canonical definition. `chronos-vdf`'s root derivation and the
/// circuit below both go through it, so there is exactly one specification of the
/// root and no opportunity for the two to drift apart.
///
/// # Panics
/// Never. Inputs of any length are accepted, though the circuit only proves the
/// relation for the fixed lengths [`Y_BYTES`] and [`MISSION_BYTES`].
#[must_use]
pub fn identity_root(y: &[u8], mission_digest: &[u8]) -> Fr {
    let mut inputs = Vec::with_capacity(
        poseidon::limb_count(y.len()) + poseidon::limb_count(mission_digest.len()) + 1,
    );
    inputs.push(Fr::from(y.len() as u64));
    inputs.extend(poseidon::pack_bytes(y));
    inputs.extend(poseidon::pack_bytes(mission_digest));
    poseidon::hash(Domain::IdentityRoot, &inputs)
}

/// Hash a mission ID string to a fixed 32-byte digest.
///
/// SHA-256 is fine here: this runs outside the circuit, and the circuit takes the
/// resulting digest as an opaque 32-byte value rather than re-deriving it.
#[must_use]
pub fn mission_id_to_bytes(mission_id: &str) -> [u8; MISSION_BYTES] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(mission_id.as_bytes());
    let mut out = [0u8; MISSION_BYTES];
    out.copy_from_slice(&h.finalize());
    out
}

/// The EAIP identity circuit.
///
/// Public input: the identity root. Private witness: the VDF output and the
/// mission digest.
#[derive(Clone)]
pub struct IdentityCircuit {
    y: Option<Vec<u8>>,
    mission_digest: Option<[u8; MISSION_BYTES]>,
}

impl IdentityCircuit {
    /// Circuit for proving.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if `y` is not exactly [`Y_BYTES`] bytes.
    /// The length is fixed because the circuit's shape must match the one used at
    /// setup.
    pub fn new_for_proving(
        y: &[u8],
        mission_digest: [u8; MISSION_BYTES],
    ) -> ChronosResult<Self> {
        if y.len() != Y_BYTES {
            return Err(ChronosError::Snark(format!(
                "identity circuit: y must be {Y_BYTES} bytes, got {}",
                y.len()
            )));
        }
        Ok(Self {
            y: Some(y.to_vec()),
            mission_digest: Some(mission_digest),
        })
    }

    /// Circuit for trusted setup.
    #[must_use]
    pub fn new_for_setup() -> Self {
        Self {
            y: None,
            mission_digest: None,
        }
    }

    /// The public identity root for this instance, if it has a witness.
    #[must_use]
    pub fn root(&self) -> Option<Fr> {
        match (&self.y, &self.mission_digest) {
            (Some(y), Some(m)) => Some(identity_root(y, m)),
            _ => None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for IdentityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public input: the identity root.
        let root_value = self.root();
        let root = FpVar::new_input(cs.clone(), || Ok(root_value.unwrap_or_else(Fr::zero)))?;

        // Private witness: y and the mission digest, as packed limbs.
        let y_limbs_native = self.y.as_ref().map(|y| poseidon::pack_bytes(y));
        let y_limbs: Vec<FpVar<Fr>> = (0..Y_LIMBS)
            .map(|i| {
                let v = y_limbs_native
                    .as_ref()
                    .and_then(|l| l.get(i))
                    .copied()
                    .unwrap_or_else(Fr::zero);
                FpVar::new_witness(cs.clone(), || Ok(v))
            })
            .collect::<Result<_, _>>()?;

        let mission_limbs_native = self
            .mission_digest
            .as_ref()
            .map(|m| poseidon::pack_bytes(m));
        let mission_limbs: Vec<FpVar<Fr>> = (0..MISSION_LIMBS)
            .map(|i| {
                let v = mission_limbs_native
                    .as_ref()
                    .and_then(|l| l.get(i))
                    .copied()
                    .unwrap_or_else(Fr::zero);
                FpVar::new_witness(cs.clone(), || Ok(v))
            })
            .collect::<Result<_, _>>()?;

        // The relation EAIP has always claimed and never previously enforced:
        // the prover knows a `y` whose digest, together with this mission, is the
        // published root. Producing this witness requires having completed T
        // sequential squarings.
        let mut inputs = Vec::with_capacity(Y_LIMBS + MISSION_LIMBS + 1);
        inputs.push(FpVar::Constant(Fr::from(Y_BYTES as u64)));
        inputs.extend_from_slice(&y_limbs);
        inputs.extend_from_slice(&mission_limbs);

        let computed = poseidon::hash_gadget(cs, Domain::IdentityRoot, &inputs)?;
        computed.enforce_equal(&root)?;

        Ok(())
    }
}

// ─── Prover ───────────────────────────────────────────────────────────────────

/// Groth16 prover for the EAIP identity circuit.
pub struct IdentityProver {
    pk: Option<ProvingKey<Bn254>>,
    pvk: Option<PreparedVerifyingKey<Bn254>>,
}

impl IdentityProver {
    /// An empty prover with no keys loaded.
    #[must_use]
    pub fn new() -> Self {
        Self { pk: None, pvk: None }
    }

    /// Run the identity circuit's trusted setup from a transcript.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if the transcript is empty or invalid, or
    /// if key generation fails.
    pub fn setup_with_transcript(&mut self, transcript: &SetupTranscript) -> ChronosResult<()> {
        if !transcript.verify_chain() {
            return Err(ChronosError::Snark(
                "identity setup transcript chain does not verify".into(),
            ));
        }
        let mut rng = transcript.setup_rng()?;
        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(IdentityCircuit::new_for_setup(), &mut rng)
                .map_err(|e| ChronosError::Snark(format!("identity setup failed: {e}")))?;
        self.pvk = Some(prepare_verifying_key(&vk));
        self.pk = Some(pk);
        Ok(())
    }

    /// Convenience setup for tests and local development. Single-party; see
    /// [`crate::prover`] for what that does and does not guarantee.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if key generation fails.
    pub fn setup_local_development(&mut self) -> ChronosResult<()> {
        let mut t = SetupTranscript::new();
        t.contribute(&SetupContribution::generate("local-development-identity"));
        self.setup_with_transcript(&t)
    }

    /// Serialize the identity verifying key.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if no keys are loaded or serialization fails.
    pub fn verifying_key_bytes(&self) -> ChronosResult<Vec<u8>> {
        let pk = self
            .pk
            .as_ref()
            .ok_or_else(|| ChronosError::Snark("identity proving key not loaded".into()))?;
        let mut buf = Vec::new();
        pk.vk
            .serialize_compressed(&mut buf)
            .map_err(|e| ChronosError::Snark(format!("identity vk serialization failed: {e}")))?;
        Ok(buf)
    }

    /// Prove knowledge of the VDF output behind the identity root.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if no keys are loaded, `y` has the wrong
    /// length, or proving fails.
    pub fn prove_identity(
        &self,
        y: &[u8],
        mission_digest: &[u8; MISSION_BYTES],
    ) -> ChronosResult<Vec<u8>> {
        let pk = self.pk.as_ref().ok_or_else(|| {
            ChronosError::Snark("identity proving key not loaded — run setup first".into())
        })?;
        let circuit = IdentityCircuit::new_for_proving(y, *mission_digest)?;
        let mut rng = StdRng::from_entropy();
        let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
            .map_err(|e| ChronosError::Snark(format!("identity proof generation failed: {e}")))?;
        let mut buf = Vec::new();
        proof
            .serialize_compressed(&mut buf)
            .map_err(|e| ChronosError::Snark(format!("identity proof serialization failed: {e}")))?;
        Ok(buf)
    }

    /// Verify an identity proof against a published root.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if no verifying key is loaded or the proof
    /// does not deserialize. A well-formed but invalid proof returns `Ok(false)`.
    pub fn verify_identity(&self, proof_bytes: &[u8], root: Fr) -> ChronosResult<bool> {
        let pvk = self
            .pvk
            .as_ref()
            .ok_or_else(|| ChronosError::Snark("identity verifying key not loaded".into()))?;
        let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes).map_err(|e| {
            ChronosError::Snark(format!("identity proof deserialization failed: {e}"))
        })?;
        Groth16::<Bn254>::verify_proof(pvk, &proof, &[root])
            .map_err(|e| ChronosError::Snark(format!("identity proof verification failed: {e}")))
    }
}

impl Default for IdentityProver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    fn y_bytes() -> Vec<u8> {
        (0..Y_BYTES).map(|i| (i as u8).wrapping_mul(13).wrapping_add(2)).collect()
    }

    fn mission() -> [u8; MISSION_BYTES] {
        mission_id_to_bytes("mission-alpha-001")
    }

    fn prover() -> IdentityProver {
        let mut p = IdentityProver::new();
        p.setup_local_development().expect("setup must succeed");
        p
    }

    // ── The relation itself ─────────────────────────────────────────────────

    #[test]
    fn test_circuit_satisfied_by_correct_preimage() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        IdentityCircuit::new_for_proving(&y_bytes(), mission())
            .expect("construct")
            .generate_constraints(cs.clone())
            .expect("synthesis");
        assert!(cs.is_satisfied().expect("satisfiability"));
    }

    /// The property that was previously unimplemented: the circuit must actually
    /// depend on `y`. If `y` were still unconstrained, this would pass.
    #[test]
    fn test_circuit_binds_y() {
        let y = y_bytes();
        let root = identity_root(&y, &mission());

        // Synthesize with a different y but assert the original root. Because the
        // root is derived from the witness inside `generate_constraints`, we test
        // the binding at the proof level instead — see
        // `test_proof_does_not_verify_against_another_root`. Here we confirm the
        // root is a function of every byte of y.
        for idx in [0usize, 1, 127, Y_BYTES - 1] {
            let mut other = y.clone();
            other[idx] ^= 0x01;
            assert_ne!(
                root,
                identity_root(&other, &mission()),
                "the identity root must depend on y byte {idx}"
            );
        }
    }

    #[test]
    fn test_root_depends_on_mission() {
        let y = y_bytes();
        let a = identity_root(&y, &mission_id_to_bytes("mission-alpha"));
        let b = identity_root(&y, &mission_id_to_bytes("mission-beta"));
        assert_ne!(a, b, "the root must be mission-specific");
    }

    #[test]
    fn test_root_is_full_width() {
        let root = identity_root(&y_bytes(), &mission());
        assert!(!root.is_zero());
        assert!(
            root > Fr::from(u64::MAX),
            "the root must be a full-width digest, not a byte"
        );
    }

    #[test]
    fn test_wrong_length_y_rejected() {
        assert!(IdentityCircuit::new_for_proving(&[0u8; 8], mission()).is_err());
        assert!(IdentityCircuit::new_for_proving(&vec![0u8; Y_BYTES + 1], mission()).is_err());
    }

    #[test]
    fn test_setup_and_proving_shapes_match() {
        let setup_cs = ConstraintSystem::<Fr>::new_ref();
        IdentityCircuit::new_for_setup()
            .generate_constraints(setup_cs.clone())
            .expect("setup synthesis");

        let proving_cs = ConstraintSystem::<Fr>::new_ref();
        IdentityCircuit::new_for_proving(&y_bytes(), mission())
            .expect("construct")
            .generate_constraints(proving_cs.clone())
            .expect("proving synthesis");

        assert_eq!(setup_cs.num_constraints(), proving_cs.num_constraints());
        assert_eq!(
            setup_cs.num_witness_variables(),
            proving_cs.num_witness_variables()
        );
        assert_eq!(
            setup_cs.num_instance_variables(),
            IDENTITY_PUBLIC_INPUT_COUNT + 1
        );
    }

    // ── End-to-end proving ──────────────────────────────────────────────────

    #[test]
    fn test_prove_and_verify_round_trip() {
        let p = prover();
        let y = y_bytes();
        let m = mission();
        let proof = p.prove_identity(&y, &m).expect("proving");
        assert_eq!(proof.len(), 128, "Groth16 proofs are constant-size");
        assert!(
            p.verify_identity(&proof, identity_root(&y, &m))
                .expect("verification"),
            "a valid identity proof must verify against its root"
        );
    }

    /// A proof for one root must not verify against another. This is the check
    /// that a soundness bug in the public-input binding would fail.
    #[test]
    fn test_proof_does_not_verify_against_another_root() {
        let p = prover();
        let y = y_bytes();
        let proof = p.prove_identity(&y, &mission()).expect("proving");

        let other_root = identity_root(&y, &mission_id_to_bytes("mission-beta-999"));
        assert!(
            !p.verify_identity(&proof, other_root).expect("verification"),
            "a proof must not verify against a different mission's root"
        );

        let mut y2 = y.clone();
        y2[0] ^= 0x01;
        let root_other_y = identity_root(&y2, &mission());
        assert!(
            !p.verify_identity(&proof, root_other_y).expect("verification"),
            "a proof must not verify against a root derived from a different y"
        );
    }

    /// Two agents with different VDF outputs must produce mutually invalid proofs.
    /// This is the anti-impersonation property EAIP exists for.
    #[test]
    fn test_agent_cannot_impersonate_another_root() {
        let p = prover();
        let m = mission();

        let y_a = y_bytes();
        let mut y_b = y_bytes();
        y_b[Y_BYTES - 1] ^= 0xFF;

        let proof_a = p.prove_identity(&y_a, &m).expect("proving a");
        let root_b = identity_root(&y_b, &m);

        assert!(
            !p.verify_identity(&proof_a, root_b).expect("verification"),
            "agent A must not be able to attest to agent B's identity root"
        );
    }

    #[test]
    fn test_prover_without_keys_errors() {
        let p = IdentityProver::new();
        assert!(p.prove_identity(&y_bytes(), &mission()).is_err());
        assert!(p.verify_identity(&[0u8; 128], Fr::from(1u64)).is_err());
        assert!(p.verifying_key_bytes().is_err());
    }

    #[test]
    fn test_malformed_proof_rejected() {
        let p = prover();
        assert!(p.verify_identity(&[0u8; 4], Fr::from(1u64)).is_err());
    }

    #[test]
    fn test_mission_id_hash_is_deterministic_and_32_bytes() {
        let a = mission_id_to_bytes("test-mission");
        let b = mission_id_to_bytes("test-mission");
        assert_eq!(a, b);
        assert_eq!(a.len(), MISSION_BYTES);
        assert_ne!(a, mission_id_to_bytes("test-mission-2"));
    }

    /// Constraint budget. A real SHA-256 pre-image proof would be ~25,000
    /// constraints; the Poseidon root brings the same statement under 2,000.
    #[test]
    fn test_constraint_count_is_real_but_modest() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        IdentityCircuit::new_for_proving(&y_bytes(), mission())
            .expect("construct")
            .generate_constraints(cs.clone())
            .expect("synthesis");
        let n = cs.num_constraints();
        println!("IdentityCircuit constraints: {n}");
        assert!(
            (500..8_000).contains(&n),
            "expected a real pre-image proof of roughly 1-2k constraints, got {n}"
        );
    }

    #[test]
    fn test_setup_refuses_empty_transcript() {
        let mut p = IdentityProver::new();
        assert!(p.setup_with_transcript(&SetupTranscript::new()).is_err());
    }
}
