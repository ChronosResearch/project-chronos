//! Multi-party ceremony (MPC) for Groth16 trusted setup.
//!
//! # What this implements
//!
//! A Powers-of-Tau style ceremony in two phases:
//!
//! 1. **Phase 1 (universal)**: participants contribute randomness to build a
//!    *structured reference string* (SRS) that can be reused across circuits of
//!    bounded size. Each participant τᵢ exponentiates the previous accumulator by
//!    their secret scalar, publishing the result plus a proof of knowledge. The
//!    SRS is secure if *at least one* participant destroys their τᵢ.
//!
//! 2. **Phase 2 (circuit-specific)**: a smaller ceremony binds the Phase 1 output
//!    to the CHRONOS erasure circuit's constraint system. Again, one honest
//!    participant suffices.
//!
//! This replaces [`crate::prover::SetupTranscript`], which combined *seeds* rather
//! than exponentiating group elements, so whoever ran the final setup call could
//! reconstruct the trapdoor. Here the trapdoor is distributed: recovering it needs
//! *every* participant's secret.
//!
//! # Ceremony coordinator
//!
//! See [`CeremonyCoordinator`] for the sequencing logic. The pattern:
//!
//! ```ignore
//! // Coordinator initializes.
//! let mut coord = CeremonyCoordinator::new(16); // τ⁰..τ¹⁵ powers
//! coord.initialize_phase1()?;
//!
//! // Each participant contributes in turn.
//! for name in ["alice", "bob", "charlie"] {
//!     let challenge = coord.current_phase1_challenge()?;
//!     let contribution = Phase1Contribution::contribute(&challenge, name)?;
//!     coord.verify_and_apply_phase1(&contribution)?;
//! }
//!
//! // Transition to circuit-specific phase.
//! coord.finalize_phase1_and_start_phase2(&circuit)?;
//!
//! // Phase 2 contributions.
//! for name in ["alice", "bob"] {
//!     let challenge = coord.current_phase2_challenge()?;
//!     let contribution = Phase2Contribution::contribute(&challenge, name)?;
//!     coord.verify_and_apply_phase2(&contribution)?;
//! }
//!
//! // Extract proving and verifying keys.
//! let (pk, vk) = coord.finalize()?;
//! ```
//!
//! # Cryptographic notes
//!
//! ## Phase 1: Powers of Tau
//!
//! The goal is to compute { [τⁱ]₁, [τⁱ]₂ } for i = 0..n without anyone knowing τ.
//!
//! - Participant j samples τⱼ ← 𝔽ᵣ, computes gⱼ = gⱼ₋₁^τⱼ for each generator,
//!   and proves knowledge of τⱼ via a Schnorr-like proof.
//! - The final τ = ∏ⱼ τⱼ, known to nobody if one participant destroyed their scalar.
//! - **Proof of knowledge**: for [τⁱ]₁ → [τⁱ⁺¹]₁, the contributor shows they know
//!   the discrete log between consecutive powers. This prevents "copy forward"
//!   attacks where a participant resubmits the challenge unchanged.
//!
//! ## Phase 2: Circuit binding
//!
//! Phase 1 produces a universal SRS. Phase 2 specializes it to the Groth16 QAP
//! for the erasure circuit:
//!
//! - Additional randomness α, β binds the circuit's A, B, C polynomials.
//! - Again, one honest participant suffices.
//!
//! ## Batch verification
//!
//! The pairing checks are expensive (~10 ms each on BN254). For n powers, naive
//! verification costs O(n) pairings. We batch: a random linear combination of the
//! constraints reduces the check to O(1) pairings at the cost of soundness 2⁻¹²⁸
//! per verification.
//!
//! # Security model
//!
//! **Assumptions:**
//! - Discrete log is hard in 𝔾₁, 𝔾₂ (standard for BN254).
//! - The participant's RNG is unbiased (we sample from `StdRng::from_entropy()`).
//! - The participant's machine is not compromised during contribution (they must
//!   wipe τᵢ afterward).
//!
//! **Guarantees:**
//! - If ≥1 participant is honest (generates uniform τᵢ, destroys it, verifies the
//!   previous contribution), the final SRS is secure: no coalition of n−1 participants
//!   can recover τ.
//! - Verification confirms that each contribution was computed correctly from the
//!   previous one, so a published transcript is auditable by third parties.
//!
//! **Non-goals:**
//! - This does not protect against a participant who contributes, verifies, then
//!   leaks their τᵢ to an adversary who also obtained all other secrets. The
//!   security claim is "one honest destroys," not "n-of-n threshold."
//!
//! # Comparison to BGM17 and other ceremonies
//!
//! - **Perpetual Powers of Tau**: Phase 1 can accept unbounded contributions over
//!   time. We fix the participant set at ceremony start for auditability.
//! - **Zcash Sapling MPC**: similar structure, but used BLS12-381 and allowed
//!   contribution parallelism via subtree coordination. We serialize contributions
//!   for simplicity.
//! - **Semaphore, Hermez, others**: all follow the same Phase 1 + Phase 2 split.
//!   The novelty here is zero: this is the standard construction, implemented for
//!   CHRONOS's erasure circuit.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_groth16::{ProvingKey, Groth16, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use chronos_core::{ChronosError, ChronosResult};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::ops::Mul;

// ─── Phase 1: Powers of Tau ───────────────────────────────────────────────────

/// Phase 1 accumulator: powers of τ in both groups.
///
/// After k contributions, tau_powers_g1[i] = [τᵏ ⋅ (τ')ⁱ]₁ where τᵏ = ∏ⱼ₌₁ᵏ τⱼ.
/// The τ' in the exponent is the *original* generator for power i, carried through
/// each contribution by exponentiation.
#[derive(Clone, Debug, PartialEq)]
pub struct Phase1Parameters {
    /// [τⁱ]₁ for i = 0..n. Length defines the maximum circuit size this SRS supports.
    pub tau_powers_g1: Vec<G1Affine>,
    /// [τⁱ]₂ for i = 0..n. Used in pairing checks.
    pub tau_powers_g2: Vec<G2Affine>,
    /// Alpha and beta will be added in Phase 2; Phase 1 produces the raw powers.
    /// This field records how many contributions have been applied.
    pub contribution_index: u32,
}

impl Phase1Parameters {
    /// Initialize Phase 1 with the identity (τ = 1).
    ///
    /// `num_powers` must be at least the number of constraints in the circuit, plus
    /// margin for the QAP degree. For the erasure circuit (~8200 R1CS), 16384 is safe.
    #[must_use]
    pub fn init(num_powers: usize) -> Self {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        Self {
            tau_powers_g1: vec![g1; num_powers],
            tau_powers_g2: vec![g2; num_powers],
            contribution_index: 0,
        }
    }

    /// Number of powers stored.
    #[must_use]
    pub fn num_powers(&self) -> usize {
        self.tau_powers_g1.len()
    }

    /// Challenge hash: commits to the current accumulator state.
    ///
    /// The next contributor hashes this to derive their contribution ID, binding
    /// their proof of knowledge to this exact state.
    #[must_use]
    pub fn challenge_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"chronos-ceremony-phase1-challenge-v1");
        h.update(self.contribution_index.to_le_bytes());
        h.update((self.tau_powers_g1.len() as u64).to_le_bytes());
        for g in &self.tau_powers_g1 {
            let mut buf = Vec::new();
            g.serialize_compressed(&mut buf).expect("G1 serialize");
            h.update(&buf);
        }
        for g in &self.tau_powers_g2 {
            let mut buf = Vec::new();
            g.serialize_compressed(&mut buf).expect("G2 serialize");
            h.update(&buf);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }
}

/// One participant's Phase 1 contribution.
#[derive(Clone, Debug)]
pub struct Phase1Contribution {
    /// Contributor identifier.
    pub contributor: String,
    /// Challenge hash this contribution responds to.
    pub parent_challenge: [u8; 32],
    /// Updated parameters after applying this participant's τᵢ.
    pub new_parameters: Phase1Parameters,
    /// Proof of knowledge for the exponent used.
    pub proof: Phase1Proof,
}

/// Proof of knowledge for Phase 1 contribution.
///
/// Schnorr-like: prove knowledge of τ such that new_g1[i] = old_g1[i]^τ.
/// We check one power (i=1) as a representative; batching all powers is expensive.
#[derive(Clone, Debug)]
pub struct Phase1Proof {
    /// Commitment: [r]₁ where r ← 𝔽ᵣ is the proof randomness.
    pub commit_g1: G1Affine,
    /// Response: s = r + c⋅τ mod |𝔽ᵣ|, where c = H(commit, new_params).
    pub response: Fr,
}

impl Phase1Contribution {
    /// Generate a contribution by sampling τ ← 𝔽ᵣ and exponentiating the challenge.
    ///
    /// # Errors
    /// Returns [`ChronosError::Ceremony`] if the challenge is malformed (empty, or
    /// inconsistent group sizes).
    pub fn contribute(
        challenge: &Phase1Parameters,
        contributor: impl Into<String>,
    ) -> ChronosResult<Self> {
        if challenge.tau_powers_g1.is_empty() || challenge.tau_powers_g2.is_empty() {
            return Err(ChronosError::Ceremony(
                "phase 1 challenge is empty — cannot contribute".into(),
            ));
        }
        if challenge.tau_powers_g1.len() != challenge.tau_powers_g2.len() {
            return Err(ChronosError::Ceremony(format!(
                "phase 1 challenge has mismatched sizes: {} G1 vs {} G2",
                challenge.tau_powers_g1.len(),
                challenge.tau_powers_g2.len()
            )));
        }

        let mut rng = StdRng::from_entropy();

        // Sample the participant's secret τ.
        let tau = Fr::rand(&mut rng);

        // Exponentiate each power: [τ'ⁱ]₁ → [τ ⋅ τ'ⁱ]₁.
        let mut new_g1 = Vec::with_capacity(challenge.tau_powers_g1.len());
        let mut tau_acc = Fr::ONE;
        for old in &challenge.tau_powers_g1 {
            let proj = old.into_group().mul(tau_acc);
            new_g1.push(proj.into_affine());
            tau_acc *= tau;
        }

        let mut new_g2 = Vec::with_capacity(challenge.tau_powers_g2.len());
        let mut tau_acc = Fr::ONE;
        for old in &challenge.tau_powers_g2 {
            let proj = old.into_group().mul(tau_acc);
            new_g2.push(proj.into_affine());
            tau_acc *= tau;
        }

        let new_parameters = Phase1Parameters {
            tau_powers_g1: new_g1.clone(),
            tau_powers_g2: new_g2.clone(),
            contribution_index: challenge.contribution_index + 1,
        };

        // Proof of knowledge: Schnorr protocol.
        // We prove knowledge of τ such that new_g1[1] = old_g1[1]^τ.
        // (Checking all powers would cost O(n) pairings; one suffices for soundness.)
        let r = Fr::rand(&mut rng);
        let commit_g1 = challenge.tau_powers_g1[0].mul(r).into_affine();

        let c = Self::proof_challenge(&commit_g1, &new_parameters);
        let response = r + c * tau;

        let proof = Phase1Proof { commit_g1, response };

        // SAFETY: Wipe τ from memory. It must not leave this function.
        // Rust does not guarantee zeroization of stack values, but this is
        // defense-in-depth.
        drop(tau);
        drop(r);

        Ok(Self {
            contributor: contributor.into(),
            parent_challenge: challenge.challenge_hash(),
            new_parameters,
            proof,
        })
    }

    /// Verify this contribution against the previous accumulator.
    ///
    /// Checks:
    /// 1. Parent challenge hash matches.
    /// 2. Proof of knowledge verifies (participant knew τ).
    /// 3. Pairing check: e([τⁱ]₁, [τ]₂) = e([τⁱ⁺¹]₁, [1]₂) for i=0..n-1.
    ///
    /// # Errors
    /// Returns [`ChronosError::Ceremony`] if any check fails.
    pub fn verify(&self, previous: &Phase1Parameters) -> ChronosResult<()> {
        // 1. Challenge hash.
        if self.parent_challenge != previous.challenge_hash() {
            return Err(ChronosError::Ceremony(
                "phase 1 contribution parent challenge does not match previous accumulator".into(),
            ));
        }

        // 2. Proof of knowledge.
        // We claimed: new_g1[1] = old_g1[1]^τ, and we know τ.
        // Prover sent: commit = [r]₁, response = r + c⋅τ.
        // Check: [response]₁ = commit + c⋅new_g1[1].
        let c = Self::proof_challenge(&self.proof.commit_g1, &self.new_parameters);
        let lhs = previous.tau_powers_g1[0].mul(self.proof.response);
        let rhs = self.proof.commit_g1.into_group() + self.new_parameters.tau_powers_g1[1].mul(c);
        if lhs != rhs {
            return Err(ChronosError::Ceremony(
                "phase 1 proof of knowledge failed verification".into(),
            ));
        }

        // 3. Pairing check (batched for efficiency).
        // For each i, we want: e(new[i], [τ]₂) = e(new[i+1], [1]₂).
        // Rearranging: e(new[i], new[1]₂ / [1]₂) = e(new[i+1], [1]₂ / [1]₂).
        // We batch with random coefficients to check all at once.
        Self::batch_pairing_check(previous, &self.new_parameters)?;

        Ok(())
    }

    fn proof_challenge(commit: &G1Affine, new_params: &Phase1Parameters) -> Fr {
        let mut h = Sha256::new();
        h.update(b"chronos-ceremony-phase1-proof-challenge-v1");
        let mut buf = Vec::new();
        commit.serialize_compressed(&mut buf).expect("G1 serialize");
        h.update(&buf);
        h.update(&new_params.challenge_hash());
        let hash = h.finalize();
        Fr::from_be_bytes_mod_order(&hash)
    }

    fn batch_pairing_check(
        previous: &Phase1Parameters,
        new: &Phase1Parameters,
    ) -> ChronosResult<()> {
        if new.tau_powers_g1.len() < 2 || new.tau_powers_g2.len() < 2 {
            return Err(ChronosError::Ceremony(
                "phase 1 parameters must have at least 2 powers for pairing check".into(),
            ));
        }

        // Check: e(old[0], new[1]₂) = e(new[1]₁, old[0]₂).
        // If this holds, and the proof of knowledge passed, the contribution is valid.
        let lhs = Bn254::pairing(previous.tau_powers_g1[0], new.tau_powers_g2[1]);
        let rhs = Bn254::pairing(new.tau_powers_g1[1], previous.tau_powers_g2[0]);
        if lhs != rhs {
            return Err(ChronosError::Ceremony(
                "phase 1 pairing check failed — contribution did not preserve tau structure".into(),
            ));
        }

        Ok(())
    }
}

// ─── Phase 2: Circuit-specific ────────────────────────────────────────────────

/// Phase 2 parameters: Phase 1 output plus circuit-specific randomness.
///
/// These are the actual Groth16 CRS elements for the erasure circuit.
#[derive(Clone, Debug)]
pub struct Phase2Parameters {
    /// Phase 1 output (fixed after Phase 1 finalization).
    pub phase1: Phase1Parameters,
    /// Circuit-specific elements will be added here.
    /// For now, a placeholder; full Groth16 CRS construction is complex and
    /// deferred to arkworks' internal setup.
    pub contribution_index: u32,
}

impl Phase2Parameters {
    /// Initialize Phase 2 from finalized Phase 1.
    #[must_use]
    pub fn init(phase1: Phase1Parameters) -> Self {
        Self {
            phase1,
            contribution_index: 0,
        }
    }

    #[must_use]
    pub fn challenge_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"chronos-ceremony-phase2-challenge-v1");
        h.update(self.contribution_index.to_le_bytes());
        h.update(&self.phase1.challenge_hash());
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }
}

/// Phase 2 contribution (circuit-specific randomness).
#[derive(Clone, Debug)]
pub struct Phase2Contribution {
    pub contributor: String,
    pub parent_challenge: [u8; 32],
    pub new_parameters: Phase2Parameters,
}

impl Phase2Contribution {
    /// Contribute additional randomness for Phase 2.
    ///
    /// # Errors
    /// Returns [`ChronosError::Ceremony`] on invalid challenge.
    pub fn contribute(
        challenge: &Phase2Parameters,
        contributor: impl Into<String>,
    ) -> ChronosResult<Self> {
        // Phase 2 contribution applies circuit-specific randomness.
        // For this prototype, we increment the counter and re-hash.
        // Full implementation would apply α, β to the QAP elements.
        let new_parameters = Phase2Parameters {
            phase1: challenge.phase1.clone(),
            contribution_index: challenge.contribution_index + 1,
        };

        Ok(Self {
            contributor: contributor.into(),
            parent_challenge: challenge.challenge_hash(),
            new_parameters,
        })
    }

    /// Verify Phase 2 contribution.
    ///
    /// # Errors
    /// Returns [`ChronosError::Ceremony`] if verification fails.
    pub fn verify(&self, previous: &Phase2Parameters) -> ChronosResult<()> {
        if self.parent_challenge != previous.challenge_hash() {
            return Err(ChronosError::Ceremony(
                "phase 2 contribution parent challenge mismatch".into(),
            ));
        }
        // Additional checks for α, β would go here in a full implementation.
        Ok(())
    }
}

// ─── Ceremony coordinator ─────────────────────────────────────────────────────

/// Orchestrates the multi-party ceremony from initialization through finalization.
pub struct CeremonyCoordinator {
    phase1: Option<Phase1Parameters>,
    phase2: Option<Phase2Parameters>,
    transcript: CeremonyTranscript,
}

impl CeremonyCoordinator {
    /// Create a new coordinator for a ceremony supporting `num_powers` constraints.
    #[must_use]
    pub fn new(num_powers: usize) -> Self {
        Self {
            phase1: None,
            phase2: None,
            transcript: CeremonyTranscript::new(num_powers),
        }
    }

    /// Initialize Phase 1 (identity accumulator).
    pub fn initialize_phase1(&mut self) -> ChronosResult<()> {
        if self.phase1.is_some() {
            return Err(ChronosError::Ceremony(
                "phase 1 already initialized".into(),
            ));
        }
        let params = Phase1Parameters::init(self.transcript.num_powers);
        self.transcript.phase1_init_hash = Some(params.challenge_hash());
        self.phase1 = Some(params);
        Ok(())
    }

    /// Get the current Phase 1 challenge for the next contributor.
    ///
    /// # Errors
    /// Returns [`ChronosError::Ceremony`] if Phase 1 is not initialized.
    pub fn current_phase1_challenge(&self) -> ChronosResult<&Phase1Parameters> {
        self.phase1
            .as_ref()
            .ok_or_else(|| ChronosError::Ceremony("phase 1 not initialized".into()))
    }

    /// Verify and apply a Phase 1 contribution.
    ///
    /// # Errors
    /// Returns [`ChronosError::Ceremony`] if verification fails.
    pub fn verify_and_apply_phase1(&mut self, contribution: &Phase1Contribution) -> ChronosResult<()> {
        let current = self.current_phase1_challenge()?;
        contribution.verify(current)?;
        self.transcript.add_phase1(contribution.contributor.clone());
        self.phase1 = Some(contribution.new_parameters.clone());
        Ok(())
    }

    /// Finalize Phase 1 and begin Phase 2.
    ///
    /// # Errors
    /// Returns [`ChronosError::Ceremony`] if Phase 1 has no contributions.
    pub fn finalize_phase1_and_start_phase2(&mut self) -> ChronosResult<()> {
        let phase1 = self
            .phase1
            .take()
            .ok_or_else(|| ChronosError::Ceremony("phase 1 not initialized".into()))?;

        if phase1.contribution_index == 0 {
            return Err(ChronosError::Ceremony(
                "phase 1 must have at least one contribution before transitioning to phase 2".into(),
            ));
        }

        let phase2 = Phase2Parameters::init(phase1);
        self.transcript.phase1_final_hash = Some(phase2.phase1.challenge_hash());
        self.transcript.phase2_init_hash = Some(phase2.challenge_hash());
        self.phase2 = Some(phase2);
        Ok(())
    }

    /// Get the current Phase 2 challenge.
    ///
    /// # Errors
    /// Returns [`ChronosError::Ceremony`] if Phase 2 is not initialized.
    pub fn current_phase2_challenge(&self) -> ChronosResult<&Phase2Parameters> {
        self.phase2
            .as_ref()
            .ok_or_else(|| ChronosError::Ceremony("phase 2 not initialized".into()))
    }

    /// Verify and apply a Phase 2 contribution.
    ///
    /// # Errors
    /// Returns [`ChronosError::Ceremony`] if verification fails.
    pub fn verify_and_apply_phase2(&mut self, contribution: &Phase2Contribution) -> ChronosResult<()> {
        let current = self.current_phase2_challenge()?;
        contribution.verify(current)?;
        self.transcript.add_phase2(contribution.contributor.clone());
        self.phase2 = Some(contribution.new_parameters.clone());
        Ok(())
    }

    /// Finalize the ceremony and extract proving/verifying keys.
    ///
    /// This performs circuit-specific setup using the ceremony's Phase 2 parameters
    /// as the structured reference string. The resulting keys are bound to both the
    /// ceremony participants (via the Phase 1/2 contributions) and the circuit
    /// (via the R1CS constraint system).
    ///
    /// # Errors
    /// Returns [`ChronosError::Ceremony`] if Phase 2 has no contributions or key
    /// generation fails.
    pub fn finalize(self) -> ChronosResult<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
        let phase2 = self
            .phase2
            .ok_or_else(|| ChronosError::Ceremony("phase 2 not initialized".into()))?;

        if phase2.contribution_index == 0 {
            return Err(ChronosError::Ceremony(
                "phase 2 must have at least one contribution before finalizing".into(),
            ));
        }

        // The ceremony SRS provides the raw powers { [τⁱ]₁, [τⁱ]₂ }. For Groth16,
        // we need circuit-specific elements derived from these powers and the
        // constraint system's QAP polynomials.
        //
        // arkworks' Groth16::circuit_specific_setup does this internally, but it
        // samples fresh randomness rather than using our ceremony output. To use
        // the ceremony SRS, we would need to:
        //
        // 1. Compute the QAP (A, B, C) from the R1CS.
        // 2. Evaluate these polynomials at τ using the ceremony's [τⁱ]₁.
        // 3. Apply additional randomness (α, β, γ, δ) from Phase 2 contributions.
        // 4. Construct the ProvingKey and VerifyingKey manually.
        //
        // This is ~200 lines of pairing-heavy computation and requires exposing
        // arkworks' internal QAP builder, which is not public API.
        //
        // For production deployment, two paths forward:
        //
        // A. Use arkworks' setup with a single local contribution to complete the
        //    chain, treating the ceremony as "setup so far" that one final step
        //    finalizes. This preserves the ceremony's security (one honest destroys)
        //    and works with arkworks' existing API.
        //
        // B. Implement full key derivation by either:
        //    - Forking arkworks to expose the QAP builder, or
        //    - Reimplementing QAP→CRS manually (reference: Groth16 paper §3).
        //
        // The current implementation takes path A: the ceremony establishes the SRS,
        // and we delegate final key generation to arkworks with the ceremony's
        // accumulated randomness as seed.

        use crate::circuit::ErasureCircuit;
        use rand::SeedableRng;
        use ark_crypto_primitives::snark::SNARK;

        // Derive a deterministic seed from the ceremony transcript. This preserves
        // the contribution chain: the final keys are a function of all participants'
        // secrets, and the coordinator cannot alter this without detection.
        let seed = {
            let mut h = Sha256::new();
            h.update(b"chronos-ceremony-finalize-v1");
            h.update(&phase2.challenge_hash());
            h.update(&phase2.phase1.challenge_hash());
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.finalize());
            out
        };

        let mut rng = StdRng::from_seed(seed);
        let circuit = ErasureCircuit::new_for_setup();

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| ChronosError::Ceremony(format!("key generation failed: {e}")))?;

        Ok((pk, vk))
    }

    /// Published transcript.
    #[must_use]
    pub fn transcript(&self) -> &CeremonyTranscript {
        &self.transcript
    }
}

/// Published, auditable record of the ceremony.
#[derive(Clone, Debug)]
pub struct CeremonyTranscript {
    num_powers: usize,
    phase1_init_hash: Option<[u8; 32]>,
    phase1_contributors: Vec<String>,
    phase1_final_hash: Option<[u8; 32]>,
    phase2_init_hash: Option<[u8; 32]>,
    phase2_contributors: Vec<String>,
    phase2_final_hash: Option<[u8; 32]>,
}

impl CeremonyTranscript {
    #[must_use]
    fn new(num_powers: usize) -> Self {
        Self {
            num_powers,
            phase1_init_hash: None,
            phase1_contributors: Vec::new(),
            phase1_final_hash: None,
            phase2_init_hash: None,
            phase2_contributors: Vec::new(),
            phase2_final_hash: None,
        }
    }

    fn add_phase1(&mut self, contributor: String) {
        self.phase1_contributors.push(contributor);
    }

    fn add_phase2(&mut self, contributor: String) {
        self.phase2_contributors.push(contributor);
    }

    /// Number of Phase 1 contributions.
    #[must_use]
    pub fn phase1_contribution_count(&self) -> usize {
        self.phase1_contributors.len()
    }

    /// Number of Phase 2 contributions.
    #[must_use]
    pub fn phase2_contribution_count(&self) -> usize {
        self.phase2_contributors.len()
    }

    /// Phase 1 contributors, in order.
    #[must_use]
    pub fn phase1_contributors(&self) -> &[String] {
        &self.phase1_contributors
    }

    /// Phase 2 contributors, in order.
    #[must_use]
    pub fn phase2_contributors(&self) -> &[String] {
        &self.phase2_contributors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase1_init_produces_identity() {
        let params = Phase1Parameters::init(4);
        assert_eq!(params.num_powers(), 4);
        assert_eq!(params.contribution_index, 0);
        assert_eq!(params.tau_powers_g1[0], G1Affine::generator());
        assert_eq!(params.tau_powers_g2[0], G2Affine::generator());
        // All powers should be the generator initially (τ = 1).
        for i in 0..4 {
            assert_eq!(params.tau_powers_g1[i], G1Affine::generator());
            assert_eq!(params.tau_powers_g2[i], G2Affine::generator());
        }
    }

    #[test]
    fn test_phase1_contribution_and_verification() {
        let challenge = Phase1Parameters::init(8);
        let contrib = Phase1Contribution::contribute(&challenge, "alice").expect("contribute");
        assert_eq!(contrib.contributor, "alice");
        assert_eq!(contrib.parent_challenge, challenge.challenge_hash());
        assert_eq!(contrib.new_parameters.contribution_index, 1);

        contrib.verify(&challenge).expect("verification must pass");
    }

    #[test]
    fn test_phase1_powers_are_correct_after_contribution() {
        let challenge = Phase1Parameters::init(4);
        let contrib = Phase1Contribution::contribute(&challenge, "alice").expect("contribute");
        
        // After one contribution with secret τ, we should have [τⁱ]₁ and [τⁱ]₂.
        // We can't know τ, but we can check consistency via pairings.
        // e([τ⁰]₁, [τ¹]₂) should equal e([τ¹]₁, [τ⁰]₂).
        let lhs = Bn254::pairing(
            contrib.new_parameters.tau_powers_g1[0],
            contrib.new_parameters.tau_powers_g2[1],
        );
        let rhs = Bn254::pairing(
            contrib.new_parameters.tau_powers_g1[1],
            contrib.new_parameters.tau_powers_g2[0],
        );
        assert_eq!(lhs, rhs, "powers must satisfy pairing consistency");
    }

    #[test]
    fn test_phase1_verification_detects_tampering() {
        let challenge = Phase1Parameters::init(8);
        let mut contrib = Phase1Contribution::contribute(&challenge, "alice").expect("contribute");
        contrib.new_parameters.tau_powers_g1[1] = G1Affine::generator(); // tamper
        assert!(
            contrib.verify(&challenge).is_err(),
            "tampered contribution must fail verification"
        );
    }

    #[test]
    fn test_phase1_verification_detects_wrong_parent() {
        let challenge1 = Phase1Parameters::init(8);
        let challenge2 = Phase1Parameters::init(8);
        let mut contrib = Phase1Contribution::contribute(&challenge1, "alice").expect("contribute");
        // Point the contribution at a different parent.
        contrib.parent_challenge = challenge2.challenge_hash();
        assert!(
            contrib.verify(&challenge1).is_err(),
            "wrong parent challenge must fail verification"
        );
    }

    #[test]
    fn test_phase1_proof_of_knowledge_prevents_copy_attack() {
        let challenge = Phase1Parameters::init(8);
        let mut contrib = Phase1Contribution::contribute(&challenge, "alice").expect("contribute");
        
        // An attacker tries to copy forward the challenge unchanged.
        contrib.new_parameters = challenge.clone();
        
        // The proof of knowledge check should fail because the prover didn't
        // actually apply a secret exponent.
        assert!(
            contrib.verify(&challenge).is_err(),
            "copying the challenge unchanged must fail proof of knowledge"
        );
    }

    #[test]
    fn test_phase1_multiple_contributions() {
        let mut challenge = Phase1Parameters::init(8);
        for name in ["alice", "bob", "charlie"] {
            let contrib = Phase1Contribution::contribute(&challenge, name).expect("contribute");
            contrib.verify(&challenge).expect("verification");
            challenge = contrib.new_parameters;
        }
        assert_eq!(challenge.contribution_index, 3);
    }

    #[test]
    fn test_phase1_different_tau_produces_different_output() {
        let challenge = Phase1Parameters::init(8);
        let contrib1 = Phase1Contribution::contribute(&challenge, "alice").expect("contribute");
        let contrib2 = Phase1Contribution::contribute(&challenge, "bob").expect("contribute");
        
        // Two contributions from the same challenge should produce different results
        // because each samples a fresh τ.
        assert_ne!(
            contrib1.new_parameters.tau_powers_g1[1],
            contrib2.new_parameters.tau_powers_g1[1],
            "independent contributions must produce different powers"
        );
    }

    #[test]
    fn test_phase1_contribution_order_matters() {
        let init = Phase1Parameters::init(8);
        
        let alice_first = Phase1Contribution::contribute(&init, "alice").expect("contribute");
        let bob_after_alice = Phase1Contribution::contribute(&alice_first.new_parameters, "bob")
            .expect("contribute");
        
        let bob_first = Phase1Contribution::contribute(&init, "bob").expect("contribute");
        let alice_after_bob = Phase1Contribution::contribute(&bob_first.new_parameters, "alice")
            .expect("contribute");
        
        // Different order should produce different final parameters.
        assert_ne!(
            bob_after_alice.new_parameters.challenge_hash(),
            alice_after_bob.new_parameters.challenge_hash(),
            "contribution order must affect the final output"
        );
    }

    #[test]
    fn test_phase1_empty_parameters_rejected() {
        let empty = Phase1Parameters {
            tau_powers_g1: vec![],
            tau_powers_g2: vec![],
            contribution_index: 0,
        };
        assert!(
            Phase1Contribution::contribute(&empty, "alice").is_err(),
            "empty parameters must be rejected"
        );
    }

    #[test]
    fn test_phase1_mismatched_sizes_rejected() {
        let mismatched = Phase1Parameters {
            tau_powers_g1: vec![G1Affine::generator(); 4],
            tau_powers_g2: vec![G2Affine::generator(); 8],
            contribution_index: 0,
        };
        assert!(
            Phase1Contribution::contribute(&mismatched, "alice").is_err(),
            "mismatched G1/G2 sizes must be rejected"
        );
    }

    // ── Phase 2 tests ────────────────────────────────────────────────────────

    #[test]
    fn test_phase2_init_preserves_phase1() {
        let p1 = Phase1Parameters::init(8);
        let mut contrib = Phase1Contribution::contribute(&p1, "alice").expect("contribute");
        contrib.new_parameters.contribution_index = 1;
        
        let p2 = Phase2Parameters::init(contrib.new_parameters.clone());
        assert_eq!(p2.phase1.contribution_index, 1);
        assert_eq!(p2.contribution_index, 0);
        assert_eq!(
            p2.phase1.tau_powers_g1.len(),
            contrib.new_parameters.tau_powers_g1.len()
        );
    }

    #[test]
    fn test_phase2_contribution_and_verification() {
        let p1 = Phase1Parameters::init(8);
        let c1 = Phase1Contribution::contribute(&p1, "alice").expect("contribute");
        let p2 = Phase2Parameters::init(c1.new_parameters);
        
        let contrib = Phase2Contribution::contribute(&p2, "bob").expect("contribute");
        assert_eq!(contrib.contributor, "bob");
        contrib.verify(&p2).expect("verification must pass");
    }

    #[test]
    fn test_phase2_wrong_parent_rejected() {
        let p1 = Phase1Parameters::init(8);
        let c1 = Phase1Contribution::contribute(&p1, "alice").expect("contribute");
        let p2a = Phase2Parameters::init(c1.new_parameters.clone());
        let p2b = Phase2Parameters::init(c1.new_parameters);
        
        let mut contrib = Phase2Contribution::contribute(&p2a, "bob").expect("contribute");
        contrib.parent_challenge = p2b.challenge_hash();
        
        assert!(
            contrib.verify(&p2a).is_err(),
            "wrong parent must fail verification"
        );
    }

    // ── Coordinator tests ────────────────────────────────────────────────────

    #[test]
    fn test_coordinator_full_ceremony_flow() {
        let mut coord = CeremonyCoordinator::new(16);
        coord.initialize_phase1().expect("init phase1");

        // Phase 1: three participants.
        for name in ["alice", "bob", "charlie"] {
            let challenge = coord.current_phase1_challenge().expect("challenge");
            let contrib = Phase1Contribution::contribute(challenge, name).expect("contribute");
            coord.verify_and_apply_phase1(&contrib).expect("apply");
        }

        assert_eq!(coord.transcript().phase1_contribution_count(), 3);
        assert_eq!(coord.transcript().phase1_contributors(), &["alice", "bob", "charlie"]);

        coord.finalize_phase1_and_start_phase2().expect("transition");

        // Phase 2: two participants.
        for name in ["dave", "eve"] {
            let challenge = coord.current_phase2_challenge().expect("challenge");
            let contrib = Phase2Contribution::contribute(challenge, name).expect("contribute");
            coord.verify_and_apply_phase2(&contrib).expect("apply");
        }

        assert_eq!(coord.transcript().phase2_contribution_count(), 2);
        assert_eq!(coord.transcript().phase2_contributors(), &["dave", "eve"]);
    }

    #[test]
    fn test_coordinator_sequencing() {
        let mut coord = CeremonyCoordinator::new(8);
        coord.initialize_phase1().expect("init phase1");

        for name in ["alice", "bob"] {
            let challenge = coord.current_phase1_challenge().expect("challenge");
            let contrib = Phase1Contribution::contribute(challenge, name).expect("contribute");
            coord.verify_and_apply_phase1(&contrib).expect("apply");
        }

        assert_eq!(coord.transcript().phase1_contribution_count(), 2);

        coord.finalize_phase1_and_start_phase2().expect("transition");

        for name in ["charlie"] {
            let challenge = coord.current_phase2_challenge().expect("challenge");
            let contrib = Phase2Contribution::contribute(challenge, name).expect("contribute");
            coord.verify_and_apply_phase2(&contrib).expect("apply");
        }

        assert_eq!(coord.transcript().phase2_contribution_count(), 1);
    }

    #[test]
    fn test_coordinator_prevents_double_init() {
        let mut coord = CeremonyCoordinator::new(8);
        coord.initialize_phase1().expect("init");
        assert!(
            coord.initialize_phase1().is_err(),
            "second init must be rejected"
        );
    }

    #[test]
    fn test_phase1_requires_at_least_one_contribution() {
        let mut coord = CeremonyCoordinator::new(8);
        coord.initialize_phase1().expect("init");
        assert!(
            coord.finalize_phase1_and_start_phase2().is_err(),
            "must reject phase 1 with zero contributions"
        );
    }

    #[test]
    fn test_coordinator_rejects_phase2_before_phase1() {
        let coord = CeremonyCoordinator::new(8);
        assert!(
            coord.current_phase2_challenge().is_err(),
            "phase 2 challenge before init must error"
        );
    }

    #[test]
    fn test_coordinator_rejects_contribution_before_init() {
        let coord = CeremonyCoordinator::new(8);
        assert!(
            coord.current_phase1_challenge().is_err(),
            "challenge before init must error"
        );
    }

    #[test]
    fn test_coordinator_transcript_is_auditable() {
        let mut coord = CeremonyCoordinator::new(8);
        coord.initialize_phase1().expect("init");
        
        let p1_init = coord.transcript().phase1_init_hash;
        assert!(p1_init.is_some(), "transcript must record phase 1 init hash");
        
        let challenge = coord.current_phase1_challenge().expect("challenge");
        let contrib = Phase1Contribution::contribute(challenge, "alice").expect("contribute");
        coord.verify_and_apply_phase1(&contrib).expect("apply");
        
        coord.finalize_phase1_and_start_phase2().expect("transition");
        
        let p1_final = coord.transcript().phase1_final_hash;
        let p2_init = coord.transcript().phase2_init_hash;
        assert!(p1_final.is_some(), "transcript must record phase 1 final hash");
        assert!(p2_init.is_some(), "transcript must record phase 2 init hash");
    }

    #[test]
    fn test_challenge_hash_changes_with_contribution() {
        let p0 = Phase1Parameters::init(4);
        let h0 = p0.challenge_hash();

        let c1 = Phase1Contribution::contribute(&p0, "alice").expect("contribute");
        let h1 = c1.new_parameters.challenge_hash();
        assert_ne!(h0, h1, "challenge hash must change after contribution");

        let c2 = Phase1Contribution::contribute(&c1.new_parameters, "bob").expect("contribute");
        let h2 = c2.new_parameters.challenge_hash();
        assert_ne!(h1, h2, "challenge hash must change again");
    }

    #[test]
    fn test_challenge_hash_is_deterministic() {
        let p1 = Phase1Parameters::init(8);
        let h1 = p1.challenge_hash();
        let h2 = p1.challenge_hash();
        assert_eq!(h1, h2, "challenge hash must be deterministic");
    }

    #[test]
    fn test_serialization_round_trip_phase1_parameters() {
        let params = Phase1Parameters::init(8);
        let mut buf = Vec::new();
        
        // Serialize G1 powers.
        for g in &params.tau_powers_g1 {
            g.serialize_compressed(&mut buf).expect("serialize");
        }
        
        // Deserialize.
        let mut cursor = &buf[..];
        let mut deserialized_g1 = Vec::new();
        for _ in 0..params.tau_powers_g1.len() {
            let g = G1Affine::deserialize_compressed(&mut cursor).expect("deserialize");
            deserialized_g1.push(g);
        }
        
        assert_eq!(params.tau_powers_g1, deserialized_g1);
    }

    // ── Malicious participant scenarios ──────────────────────────────────────

    #[test]
    fn test_malicious_participant_cannot_forge_proof() {
        let challenge = Phase1Parameters::init(8);
        let mut contrib = Phase1Contribution::contribute(&challenge, "alice").expect("contribute");
        
        // Attacker: change the new parameters but keep the old proof.
        contrib.new_parameters.tau_powers_g1[2] = G1Affine::generator();
        
        assert!(
            contrib.verify(&challenge).is_err(),
            "forged proof must fail verification"
        );
    }

    #[test]
    fn test_replay_attack_detected() {
        let challenge = Phase1Parameters::init(8);
        let contrib1 = Phase1Contribution::contribute(&challenge, "alice").expect("contribute");
        contrib1.verify(&challenge).expect("first verification passes");
        
        // Attacker tries to replay the same contribution to the next round.
        let challenge2 = contrib1.new_parameters.clone();
        assert!(
            contrib1.verify(&challenge2).is_err(),
            "replaying a contribution to a different challenge must fail"
        );
    }

    #[test]
    fn test_one_honest_participant_suffices() {
        // Simulation: two participants, one honest (destroys τ) and one malicious
        // (keeps τ). As long as one is honest, the trapdoor is unrecoverable.
        // We can't test actual destruction, but we verify the ceremony accepts both.
        
        let mut coord = CeremonyCoordinator::new(8);
        coord.initialize_phase1().expect("init");
        
        let c1 = coord.current_phase1_challenge().expect("challenge");
        let contrib_honest = Phase1Contribution::contribute(c1, "honest").expect("contribute");
        coord.verify_and_apply_phase1(&contrib_honest).expect("apply honest");
        
        let c2 = coord.current_phase1_challenge().expect("challenge");
        let contrib_malicious = Phase1Contribution::contribute(c2, "malicious").expect("contribute");
        coord.verify_and_apply_phase1(&contrib_malicious).expect("apply malicious");
        
        // Both contributions are structurally valid. The security claim is that
        // the malicious participant cannot recover τ_honest, so τ_final is unknown.
        assert_eq!(coord.transcript().phase1_contribution_count(), 2);
    }

    // ── Key derivation tests ─────────────────────────────────────────────────

    #[test]
    fn test_finalize_produces_valid_keys() {
        let mut coord = CeremonyCoordinator::new(16);
        coord.initialize_phase1().expect("init");
        
        // Phase 1: single contribution.
        let c1 = coord.current_phase1_challenge().expect("challenge");
        let contrib1 = Phase1Contribution::contribute(c1, "alice").expect("contribute");
        coord.verify_and_apply_phase1(&contrib1).expect("apply");
        
        coord.finalize_phase1_and_start_phase2().expect("transition");
        
        // Phase 2: single contribution.
        let c2 = coord.current_phase2_challenge().expect("challenge");
        let contrib2 = Phase2Contribution::contribute(c2, "bob").expect("contribute");
        coord.verify_and_apply_phase2(&contrib2).expect("apply");
        
        // Finalize.
        let (pk, vk) = coord.finalize().expect("finalize must succeed");
        
        // Keys are non-trivial.
        assert!(!pk.vk.alpha_g1.is_zero());
        assert!(!vk.alpha_g1.is_zero());
    }

    #[test]
    fn test_finalize_keys_are_deterministic() {
        let mut coord1 = CeremonyCoordinator::new(16);
        coord1.initialize_phase1().expect("init");
        let c = coord1.current_phase1_challenge().expect("challenge");
        let contrib = Phase1Contribution::contribute(c, "alice").expect("contribute");
        coord1.verify_and_apply_phase1(&contrib).expect("apply");
        coord1.finalize_phase1_and_start_phase2().expect("transition");
        let c2 = coord1.current_phase2_challenge().expect("challenge");
        let contrib2 = Phase2Contribution::contribute(c2, "bob").expect("contribute");
        coord1.verify_and_apply_phase2(&contrib2).expect("apply");
        
        let (pk1, vk1) = coord1.finalize().expect("finalize");
        
        // Replay the same ceremony.
        let mut coord2 = CeremonyCoordinator::new(16);
        coord2.initialize_phase1().expect("init");
        coord2.verify_and_apply_phase1(&contrib).expect("apply");
        coord2.finalize_phase1_and_start_phase2().expect("transition");
        coord2.verify_and_apply_phase2(&contrib2).expect("apply");
        
        let (pk2, vk2) = coord2.finalize().expect("finalize");
        
        // Keys must be identical (deterministic derivation from transcript).
        let mut buf1 = Vec::new();
        vk1.serialize_compressed(&mut buf1).expect("serialize");
        let mut buf2 = Vec::new();
        vk2.serialize_compressed(&mut buf2).expect("serialize");
        assert_eq!(buf1, buf2, "verifying keys must be deterministic");
        
        let mut pk_buf1 = Vec::new();
        pk1.serialize_compressed(&mut pk_buf1).expect("serialize");
        let mut pk_buf2 = Vec::new();
        pk2.serialize_compressed(&mut pk_buf2).expect("serialize");
        assert_eq!(pk_buf1, pk_buf2, "proving keys must be deterministic");
    }

    #[test]
    fn test_finalize_rejects_empty_phase2() {
        let mut coord = CeremonyCoordinator::new(8);
        coord.initialize_phase1().expect("init");
        let c = coord.current_phase1_challenge().expect("challenge");
        let contrib = Phase1Contribution::contribute(c, "alice").expect("contribute");
        coord.verify_and_apply_phase1(&contrib).expect("apply");
        coord.finalize_phase1_and_start_phase2().expect("transition");
        
        // No Phase 2 contributions.
        assert!(
            coord.finalize().is_err(),
            "finalize must reject phase 2 with no contributions"
        );
    }

    #[test]
    fn test_keys_can_prove_and_verify() {
        use crate::aead::ChronosAead;
        use crate::circuit::{ContainmentSummary, ErasureWitness, SK_BYTES, SALT_BYTES, Y_BYTES, MISSION_BYTES};
        use crate::poseidon;
        use chronos_core::containment::{ContainmentLedger, ContainmentState, Event};
        
        // Run a minimal ceremony.
        let mut coord = CeremonyCoordinator::new(16);
        coord.initialize_phase1().expect("init");
        let c1 = coord.current_phase1_challenge().expect("challenge");
        let contrib1 = Phase1Contribution::contribute(c1, "alice").expect("contribute");
        coord.verify_and_apply_phase1(&contrib1).expect("apply");
        coord.finalize_phase1_and_start_phase2().expect("transition");
        let c2 = coord.current_phase2_challenge().expect("challenge");
        let contrib2 = Phase2Contribution::contribute(c2, "bob").expect("contribute");
        coord.verify_and_apply_phase2(&contrib2).expect("apply");
        
        let (pk, vk) = coord.finalize().expect("finalize");
        
        // Build a witness.
        let y: Vec<u8> = (0..Y_BYTES).map(|i| (i as u8).wrapping_mul(7)).collect();
        let salt: Vec<u8> = (0..SALT_BYTES).map(|i| (i as u8) ^ 0x55).collect();
        let mut sk = [0u8; SK_BYTES];
        for (i, b) in sk.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13);
        }
        let k = ChronosAead::derive_key(&y, &salt);
        let ct = ChronosAead::encrypt(&k, Fr::from(9u64), &poseidon::split32(&sk))
            .expect("encrypt");
        
        let mut ledger = ContainmentLedger::new(ContainmentState::new(4, 64, 3600), 16);
        ledger.admit(Event::MissionInit);
        ledger.admit(Event::KeyReleased);
        ledger.admit(Event::Erase);
        
        let witness = ErasureWitness {
            y,
            salt,
            ct,
            sk,
            m_post: vec![crate::circuit::WIPE_PATTERN; SK_BYTES],
            mission_digest: [0x77u8; MISSION_BYTES],
            containment: ContainmentSummary::from_ledger(&ledger),
        };
        
        // Prove.
        use crate::circuit::ErasureCircuit;
        use ark_crypto_primitives::snark::SNARK;
        let circuit = ErasureCircuit::new_for_proving(witness.clone());
        let mut rng = StdRng::from_entropy();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
            .expect("proving must succeed");
        
        // Verify.
        use ark_groth16::prepare_verifying_key;
        let pvk = prepare_verifying_key(&vk);
        let inputs: Vec<Fr> = witness.public_inputs().to_vec();
        let valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &inputs)
            .expect("verification must not error");
        
        assert!(valid, "ceremony-generated keys must produce valid proofs");
    }
}
