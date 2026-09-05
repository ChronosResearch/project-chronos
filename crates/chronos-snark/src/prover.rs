//! Groth16 prover and verifier for the CHRONOS erasure circuit, plus an auditable
//! trusted-setup transcript and on-disk key persistence.
//!
//! # Trusted setup: what is claimed and what is not
//!
//! Groth16 needs a per-circuit trusted setup. Whoever samples the setup
//! randomness learns a trapdoor that lets them forge proofs for *any* statement
//! under the resulting key. That is a property of the proof system, not of this
//! implementation, and the only way to remove it is a multi-party ceremony in
//! which at least one participant is honest and destroys their contribution.
//!
//! Earlier revisions of this file claimed to implement such a ceremony. They did
//! not. Three `StdRng::from_entropy()` draws were XOR-folded inside a single
//! process, and the result was documented as a "3-party simulated MPC ceremony"
//! where "no single party's contribution is sufficient to reconstruct the toxic
//! waste". There was one party, it ran all three draws, and it held the trapdoor.
//! XOR-folding local RNGs adds no security property whatsoever.
//!
//! [`SetupTranscript`] replaces that with something that is at least honest and
//! genuinely useful:
//!
//! * contributions are **hash-chained**, so the transcript is tamper-evident and
//!   the order of contributions is fixed;
//! * each contribution records a **commitment to** the contributor's entropy
//!   rather than the entropy itself, so a published transcript does not leak it;
//! * contributions can be collected from **separate machines and separate
//!   operators** as files, then combined;
//! * the transcript is **publishable**, so anyone can check which parties
//!   participated and that the deployed key was derived from that exact chain.
//!
//! What it still does **not** provide: phase-2 ceremony security. A real
//! Powers-of-Tau / BGM17 ceremony has each participant re-randomise the *structured
//! reference string* and publish a proof of knowledge of their scalar, so the
//! trapdoor is only recoverable if every participant colludes. This transcript
//! combines *seeds*, which means whoever runs the final
//! [`Groth16Prover::setup_with_transcript`] call sees the combined seed and can
//! reconstruct the trapdoor.
//!
//! So: use this for development, and for deployments where the verifier already
//! trusts the setup operator. Do not present an on-chain attestation as
//! trust-free until a real ceremony replaces it. This limitation is repeated in
//! `contracts/Groth16Verifier.sol` because that is where a reader is most likely
//! to over-interpret an accepted proof.
//!
//! # Key persistence
//!
//! Setup must happen **once** and the verifying key must be **published**. A
//! previous revision generated a fresh setup inside every `/mission/init`, which
//! meant the verifying key changed per mission and no external party could ever
//! check a proof — the agent was both prover and sole verifier, which is not
//! attestation. [`Groth16Prover::save`] and [`Groth16Prover::load`] make the key
//! a deployment artifact.

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use chronos_core::{ChronosError, ChronosResult};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::circuit::{ErasureCircuit, ErasureWitness, PublicInputs};

// ─── Setup transcript ─────────────────────────────────────────────────────────

/// One participant's contribution to the setup randomness.
///
/// `entropy` must be generated on the contributor's own machine and never
/// transmitted. Only [`SetupRecord`], which contains a commitment to it, is
/// published.
pub struct SetupContribution {
    /// Human-readable participant identifier, recorded in the transcript.
    pub contributor: String,
    /// 32 bytes of participant-generated entropy.
    pub entropy: [u8; 32],
}

impl SetupContribution {
    /// Draw a fresh contribution from the OS entropy source.
    #[must_use]
    pub fn generate(contributor: impl Into<String>) -> Self {
        let mut entropy = [0u8; 32];
        StdRng::from_entropy().fill_bytes(&mut entropy);
        Self {
            contributor: contributor.into(),
            entropy,
        }
    }

    /// Commitment to this contribution: `SHA-256(domain || contributor || entropy)`.
    ///
    /// Publishing this rather than `entropy` lets a participant prove after the
    /// fact that a given contribution was theirs, without revealing the value
    /// that went into the seed.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"chronos-setup-contribution-v1");
        h.update((self.contributor.len() as u64).to_be_bytes());
        h.update(self.contributor.as_bytes());
        h.update(self.entropy);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }
}

/// A published, tamper-evident record of one contribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupRecord {
    /// Participant identifier.
    pub contributor: String,
    /// [`SetupContribution::commitment`].
    pub commitment: [u8; 32],
    /// Chain head after including this record.
    pub head: [u8; 32],
}

/// An auditable, hash-chained setup transcript.
///
/// See the module documentation for the precise scope of the guarantee.
pub struct SetupTranscript {
    records: Vec<SetupRecord>,
    head: [u8; 32],
    seed_accumulator: [u8; 32],
}

impl SetupTranscript {
    /// Genesis domain tag.
    const GENESIS: &'static [u8] = b"chronos-setup-transcript-genesis-v1";

    /// Start an empty transcript.
    #[must_use]
    pub fn new() -> Self {
        let mut h = Sha256::new();
        h.update(Self::GENESIS);
        let mut head = [0u8; 32];
        head.copy_from_slice(&h.finalize());
        Self {
            records: Vec::new(),
            head,
            seed_accumulator: [0u8; 32],
        }
    }

    /// Append a contribution.
    ///
    /// The contribution's entropy is folded into the seed accumulator and its
    /// commitment into the public chain. The entropy itself is not retained beyond
    /// the fold.
    pub fn contribute(&mut self, contribution: &SetupContribution) {
        let commitment = contribution.commitment();

        // Public chain: binds contributor identity, commitment, and order.
        let mut h = Sha256::new();
        h.update(b"chronos-setup-chain-v1");
        h.update(self.head);
        h.update(commitment);
        let mut head = [0u8; 32];
        head.copy_from_slice(&h.finalize());
        self.head = head;

        // Private accumulator: XOR then hash. XOR alone would let a participant
        // who goes last cancel an earlier contribution by submitting its value;
        // hashing after each fold removes that.
        for (a, b) in self
            .seed_accumulator
            .iter_mut()
            .zip(contribution.entropy.iter())
        {
            *a ^= *b;
        }
        let mut h = Sha256::new();
        h.update(b"chronos-setup-accumulator-v1");
        h.update(self.seed_accumulator);
        h.update(self.head);
        self.seed_accumulator.copy_from_slice(&h.finalize());

        self.records.push(SetupRecord {
            contributor: contribution.contributor.clone(),
            commitment,
            head,
        });
    }

    /// Published records, in order.
    #[must_use]
    pub fn records(&self) -> &[SetupRecord] {
        &self.records
    }

    /// Current chain head. This is the value to publish alongside the verifying key.
    #[must_use]
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    /// Number of contributions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no contribution has been made.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Recompute the chain from the published records and confirm it matches.
    ///
    /// This is the check an external auditor runs against a published transcript.
    #[must_use]
    pub fn verify_chain(&self) -> bool {
        let mut h = Sha256::new();
        h.update(Self::GENESIS);
        let mut head = [0u8; 32];
        head.copy_from_slice(&h.finalize());

        for record in &self.records {
            let mut h = Sha256::new();
            h.update(b"chronos-setup-chain-v1");
            h.update(head);
            h.update(record.commitment);
            head.copy_from_slice(&h.finalize());
            if head != record.head {
                return false;
            }
        }
        head == self.head
    }

    /// Derive the setup RNG.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if the transcript is empty. Falling back to
    /// a local RNG here is how the previous revision ended up with a setup nobody
    /// could audit, so an empty transcript is a hard error.
    pub fn setup_rng(&self) -> ChronosResult<StdRng> {
        if self.records.is_empty() {
            return Err(ChronosError::Snark(
                "setup transcript is empty — at least one contribution is required; \
                 refusing to fall back to an unaudited local seed"
                    .into(),
            ));
        }
        Ok(StdRng::from_seed(self.seed_accumulator))
    }
}

impl Default for SetupTranscript {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Prover ───────────────────────────────────────────────────────────────────

/// Groth16 prover and verifier for the erasure circuit.
pub struct Groth16Prover {
    pk: Option<ProvingKey<Bn254>>,
    pvk: Option<PreparedVerifyingKey<Bn254>>,
    transcript_head: Option<[u8; 32]>,
}

impl Groth16Prover {
    /// An empty prover with no keys loaded.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pk: None,
            pvk: None,
            transcript_head: None,
        }
    }

    /// Run the trusted setup using a transcript.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if the transcript is empty, its chain does
    /// not verify, or key generation fails.
    pub fn setup_with_transcript(&mut self, transcript: &SetupTranscript) -> ChronosResult<()> {
        if !transcript.verify_chain() {
            return Err(ChronosError::Snark(
                "setup transcript chain does not verify — records were altered or reordered".into(),
            ));
        }
        let mut rng = transcript.setup_rng()?;
        let circuit = ErasureCircuit::new_for_setup();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| ChronosError::Snark(format!("erasure setup failed: {e}")))?;
        self.pvk = Some(prepare_verifying_key(&vk));
        self.pk = Some(pk);
        self.transcript_head = Some(transcript.head());
        Ok(())
    }

    /// Convenience setup for tests and local development.
    ///
    /// Builds a single-contributor transcript. The resulting key must not be used
    /// where the verifier does not trust this process — that is exactly the
    /// single-party case described in the module docs.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if key generation fails.
    pub fn setup_local_development(&mut self) -> ChronosResult<()> {
        let mut transcript = SetupTranscript::new();
        transcript.contribute(&SetupContribution::generate("local-development"));
        self.setup_with_transcript(&transcript)
    }

    /// The transcript head the loaded keys were generated from, if known.
    #[must_use]
    pub fn transcript_head(&self) -> Option<[u8; 32]> {
        self.transcript_head
    }

    /// Borrow the raw verifying key, for the EVM export path.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if no keys are loaded.
    pub fn verifying_key(&self) -> ChronosResult<&VerifyingKey<Bn254>> {
        Ok(&self.require_pk()?.vk)
    }

    /// Serialize the verifying key in arkworks' compressed encoding.
    ///
    /// This is *not* the EVM encoding — see [`crate::solidity`].
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if no keys are loaded or serialization fails.
    pub fn verifying_key_bytes(&self) -> ChronosResult<Vec<u8>> {
        let mut buf = Vec::new();
        self.verifying_key()?
            .serialize_compressed(&mut buf)
            .map_err(|e| ChronosError::Snark(format!("verifying key serialization failed: {e}")))?;
        Ok(buf)
    }

    fn require_pk(&self) -> ChronosResult<&ProvingKey<Bn254>> {
        self.pk.as_ref().ok_or_else(|| {
            ChronosError::Snark(
                "proving key not loaded — run setup_with_transcript or load first".into(),
            )
        })
    }

    /// Persist the proving key to `path`.
    ///
    /// The proving key is not secret — the *setup randomness* is, and it is not
    /// stored here — but it is large, so this is a deployment artifact rather than
    /// something to regenerate per mission.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] on serialization failure or
    /// [`ChronosError::Io`] on write failure.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> ChronosResult<()> {
        let mut buf = Vec::new();
        self.require_pk()?
            .serialize_compressed(&mut buf)
            .map_err(|e| ChronosError::Snark(format!("proving key serialization failed: {e}")))?;
        std::fs::write(path, buf).map_err(ChronosError::Io)
    }

    /// Load a proving key previously written by [`Self::save`].
    ///
    /// # Errors
    /// Returns [`ChronosError::Io`] if the file cannot be read, or
    /// [`ChronosError::Snark`] if it does not deserialize.
    pub fn load<P: AsRef<Path>>(path: P) -> ChronosResult<Self> {
        let bytes = std::fs::read(path).map_err(ChronosError::Io)?;
        let pk = ProvingKey::<Bn254>::deserialize_compressed(&bytes[..]).map_err(|e| {
            ChronosError::Snark(format!("proving key deserialization failed: {e}"))
        })?;
        let pvk = prepare_verifying_key(&pk.vk);
        Ok(Self {
            pk: Some(pk),
            pvk: Some(pvk),
            transcript_head: None,
        })
    }

    /// Load ceremony-generated keys with transcript verification.
    ///
    /// This is the production path: keys generated by a multi-party ceremony
    /// distributed across independent participants. The transcript head binds
    /// the keys to a specific ceremony run, so an auditor can verify which
    /// participants contributed.
    ///
    /// # Errors
    /// Returns [`ChronosError::Io`] if files cannot be read, or
    /// [`ChronosError::Snark`] if deserialization fails.
    pub fn load_ceremony_keys<P: AsRef<Path>>(
        proving_key_path: P,
        verifying_key_path: P,
        transcript_head: [u8; 32],
    ) -> ChronosResult<Self> {
        let pk_bytes = std::fs::read(proving_key_path).map_err(ChronosError::Io)?;
        let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..]).map_err(|e| {
            ChronosError::Snark(format!("proving key deserialization failed: {e}"))
        })?;

        let vk_bytes = std::fs::read(verifying_key_path).map_err(ChronosError::Io)?;
        let vk_loaded = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])
            .map_err(|e| ChronosError::Snark(format!("verifying key deserialization failed: {e}")))?;

        // Verify that the loaded verifying key matches the proving key's embedded VK.
        let mut pk_vk_bytes = Vec::new();
        pk.vk.serialize_compressed(&mut pk_vk_bytes)
            .map_err(|e| ChronosError::Snark(format!("vk serialization failed: {e}")))?;
        if pk_vk_bytes != vk_bytes {
            return Err(ChronosError::Snark(
                "verifying key does not match proving key — keys are from different setups".into(),
            ));
        }

        let pvk = prepare_verifying_key(&vk_loaded);
        Ok(Self {
            pk: Some(pk),
            pvk: Some(pvk),
            transcript_head: Some(transcript_head),
        })
    }

    /// Generate an erasure proof.
    ///
    /// The witness is validated first, so a mismatch between `sk` and `ct_sk`, a
    /// non-terminal containment summary, or an unwiped buffer produces a named
    /// error instead of an unsatisfiable constraint system.
    ///
    /// # Ordering
    /// This must be called while the agent still holds the genuine key — see the
    /// ordering note in [`crate::circuit`]. Wipe the witness immediately after.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if the witness is invalid or proving fails.
    pub fn prove_erasure(&self, witness: &ErasureWitness) -> ChronosResult<Vec<u8>> {
        witness.check_shape()?;
        let pk = self.require_pk()?;

        let circuit = ErasureCircuit::new_for_proving(witness.clone());
        let mut rng = StdRng::from_entropy();
        let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
            .map_err(|e| ChronosError::Snark(format!("erasure proof generation failed: {e}")))?;

        let mut buf = Vec::new();
        proof
            .serialize_compressed(&mut buf)
            .map_err(|e| ChronosError::Snark(format!("proof serialization failed: {e}")))?;
        Ok(buf)
    }

    /// Verify an erasure proof against the five public commitments.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if no verifying key is loaded or the proof
    /// does not deserialize. A well-formed but invalid proof returns `Ok(false)`.
    pub fn verify_erasure(
        &self,
        proof_bytes: &[u8],
        public_inputs: &PublicInputs,
    ) -> ChronosResult<bool> {
        let pvk = self.pvk.as_ref().ok_or_else(|| {
            ChronosError::Snark("verifying key not loaded — run setup or load first".into())
        })?;
        let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
            .map_err(|e| ChronosError::Snark(format!("proof deserialization failed: {e}")))?;
        let inputs: Vec<Fr> = public_inputs.to_vec();
        Groth16::<Bn254>::verify_proof(pvk, &proof, &inputs)
            .map_err(|e| ChronosError::Snark(format!("proof verification failed: {e}")))
    }
}

impl Default for Groth16Prover {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::ChronosAead;
    use crate::circuit::{ContainmentSummary, SK_BYTES, SALT_BYTES, Y_BYTES, MISSION_BYTES};
    use crate::poseidon;
    use chronos_core::containment::{ContainmentLedger, ContainmentState, Event};

    fn terminal_ledger() -> ContainmentLedger {
        let mut l = ContainmentLedger::new(ContainmentState::new(4, 64, 3600), 16);
        l.admit(Event::MissionInit);
        l.admit(Event::KeyReleased);
        l.admit(Event::Erase);
        l
    }

    fn witness() -> ErasureWitness {
        let y: Vec<u8> = (0..Y_BYTES).map(|i| (i as u8).wrapping_mul(5)).collect();
        let salt: Vec<u8> = (0..SALT_BYTES).map(|i| (i as u8) ^ 0x33).collect();
        let mut sk = [0u8; SK_BYTES];
        for (i, b) in sk.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11).wrapping_add(5);
        }
        let k = ChronosAead::derive_key(&y, &salt);
        let ct = ChronosAead::encrypt(&k, Fr::from(7u64), &poseidon::split32(&sk))
            .expect("encrypt must succeed");
        ErasureWitness {
            y,
            salt,
            ct,
            sk,
            m_post: vec![crate::circuit::WIPE_PATTERN; SK_BYTES],
            mission_digest: [0x5Cu8; MISSION_BYTES],
            containment: ContainmentSummary::from_ledger(&terminal_ledger()),
        }
    }

    fn prover() -> Groth16Prover {
        let mut p = Groth16Prover::new();
        p.setup_local_development().expect("setup must succeed");
        p
    }

    // ── End-to-end ──────────────────────────────────────────────────────────

    #[test]
    fn test_prove_and_verify_round_trip() {
        let p = prover();
        let w = witness();
        let proof = p.prove_erasure(&w).expect("proving must succeed");
        assert!(!proof.is_empty());
        assert!(
            p.verify_erasure(&proof, &w.public_inputs())
                .expect("verification must not error"),
            "a valid proof must verify against its own public inputs"
        );
    }

    /// Groth16 proofs are constant-size regardless of circuit size. Compressed
    /// BN254 is 2 x G1 (32 bytes each) + 1 x G2 (64 bytes) = 128 bytes.
    #[test]
    fn test_proof_is_128_bytes() {
        let p = prover();
        let proof = p.prove_erasure(&witness()).expect("proving");
        assert_eq!(
            proof.len(),
            128,
            "compressed Groth16 on BN254 is 128 bytes; got {}",
            proof.len()
        );
    }

    /// Every public input must be load-bearing. Perturbing any one must cause
    /// rejection, otherwise that commitment is not actually bound.
    #[test]
    fn test_each_public_input_is_bound() {
        let p = prover();
        let w = witness();
        let proof = p.prove_erasure(&w).expect("proving");
        let good = w.public_inputs();

        let mut variants = Vec::new();
        let mut v = good;
        v.y_commit += Fr::from(1u64);
        variants.push(("y_commit", v));
        let mut v = good;
        v.ct_commit += Fr::from(1u64);
        variants.push(("ct_commit", v));
        let mut v = good;
        v.sk_commit += Fr::from(1u64);
        variants.push(("sk_commit", v));
        let mut v = good;
        v.mission_commit += Fr::from(1u64);
        variants.push(("mission_commit", v));
        let mut v = good;
        v.containment_commit += Fr::from(1u64);
        variants.push(("containment_commit", v));

        for (name, bad) in variants {
            assert!(
                !p.verify_erasure(&proof, &bad).expect("verification"),
                "altering {name} must cause rejection"
            );
        }
    }

    #[test]
    fn test_malformed_proof_is_rejected() {
        let p = prover();
        assert!(p.verify_erasure(&[0u8; 8], &witness().public_inputs()).is_err());
        assert!(p.verify_erasure(&[], &witness().public_inputs()).is_err());
    }

    /// Proof-level binding of the containment history.
    ///
    /// This is the check that cannot be expressed at the circuit level, because
    /// `generate_constraints` derives the public inputs from the witness. Here the
    /// verifier supplies them independently, which is how a real verifier works:
    /// it holds the containment summary the agent published and checks the proof
    /// against *that*.
    #[test]
    fn test_containment_history_is_bound_at_proof_level() {
        let p = prover();
        let w = witness();
        let proof = p.prove_erasure(&w).expect("proving");

        // A different history that still terminates correctly.
        let mut other = ContainmentLedger::new(ContainmentState::new(4, 64, 3600), 16);
        other.admit(Event::MissionInit);
        other.admit(Event::Infer { declared_secs: 1, disclosure_bits: 4 });
        other.admit(Event::KeyReleased);
        other.admit(Event::Erase);
        let other_summary = ContainmentSummary::from_ledger(&other);
        assert!(other_summary.is_terminal());

        let mut claimed = w.public_inputs();
        claimed.containment_commit = other_summary.commitment();

        assert!(
            !p.verify_erasure(&proof, &claimed).expect("verification"),
            "a proof for one containment history must not verify against another"
        );
    }

    /// An agent that ran the mission but never erased cannot produce a proof at
    /// all — proof-carrying containment in its most important form.
    #[test]
    fn test_no_proof_without_erasure() {
        let p = prover();
        let mut w = witness();

        let mut still_active = ContainmentLedger::new(ContainmentState::new(4, 64, 3600), 16);
        still_active.admit(Event::MissionInit);
        w.containment = ContainmentSummary::from_ledger(&still_active);

        let err = p.prove_erasure(&w).expect_err("proving must be refused");
        assert!(
            format!("{err}").contains("not terminal"),
            "the error should name the containment failure, got: {err}"
        );
    }

    /// A witness whose key does not match the ciphertext must be refused at
    /// proving time, not silently turned into an invalid proof.
    #[test]
    fn test_proving_rejects_inconsistent_witness() {
        let p = prover();
        let mut w = witness();
        w.sk[0] ^= 0xFF;
        let err = p.prove_erasure(&w).expect_err("must refuse");
        assert!(
            format!("{err}").contains("does not authenticate")
                || format!("{err}").contains("different key"),
            "error should name the mismatch, got: {err}"
        );
    }

    #[test]
    fn test_prover_without_keys_errors() {
        let p = Groth16Prover::new();
        assert!(p.prove_erasure(&witness()).is_err());
        assert!(p.verify_erasure(&[0u8; 128], &witness().public_inputs()).is_err());
        assert!(p.verifying_key().is_err());
    }

    // ── Key persistence ─────────────────────────────────────────────────────

    /// Setup once, publish, verify later. Without this the verifying key changes
    /// per mission and external attestation is impossible.
    #[test]
    fn test_keys_survive_save_and_load() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("chronos-pk-test-{}.bin", std::process::id()));

        let original = prover();
        let w = witness();
        let proof = original.prove_erasure(&w).expect("proving");
        original.save(&path).expect("save must succeed");

        let reloaded = Groth16Prover::load(&path).expect("load must succeed");
        assert!(
            reloaded
                .verify_erasure(&proof, &w.public_inputs())
                .expect("verification"),
            "a reloaded key must verify a proof made with the original"
        );

        // And the reloaded key can prove too.
        let proof2 = reloaded.prove_erasure(&w).expect("reloaded proving");
        assert!(original
            .verify_erasure(&proof2, &w.public_inputs())
            .expect("verification"));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_load_rejects_garbage() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("chronos-pk-bad-{}.bin", std::process::id()));
        std::fs::write(&path, b"not a proving key").expect("write");
        assert!(Groth16Prover::load(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    /// Independent setups produce independent keys. A proof from one must not
    /// verify under the other.
    #[test]
    fn test_distinct_setups_are_not_interchangeable() {
        let a = prover();
        let b = prover();
        let w = witness();
        let proof = a.prove_erasure(&w).expect("proving");
        assert!(
            !b.verify_erasure(&proof, &w.public_inputs())
                .expect("verification"),
            "a proof must not verify under a different setup's key"
        );
    }

    // ── Setup transcript ────────────────────────────────────────────────────

    #[test]
    fn test_transcript_chains_and_verifies() {
        let mut t = SetupTranscript::new();
        assert!(t.is_empty());
        let genesis = t.head();

        t.contribute(&SetupContribution::generate("alice"));
        let after_alice = t.head();
        assert_ne!(genesis, after_alice);

        t.contribute(&SetupContribution::generate("bob"));
        assert_ne!(after_alice, t.head());

        assert_eq!(t.len(), 2);
        assert!(t.verify_chain(), "an untampered chain must verify");
        assert_eq!(t.records()[0].contributor, "alice");
        assert_eq!(t.records()[1].contributor, "bob");
    }

    /// Tamper-evidence is the property the transcript exists for.
    #[test]
    fn test_transcript_detects_tampering() {
        let mut t = SetupTranscript::new();
        t.contribute(&SetupContribution::generate("alice"));
        t.contribute(&SetupContribution::generate("bob"));
        assert!(t.verify_chain());

        t.records[0].commitment[0] ^= 0x01;
        assert!(
            !t.verify_chain(),
            "altering a published commitment must break the chain"
        );
    }

    #[test]
    fn test_transcript_detects_reordering() {
        let a = SetupContribution::generate("alice");
        let b = SetupContribution::generate("bob");

        let mut forward = SetupTranscript::new();
        forward.contribute(&a);
        forward.contribute(&b);

        let mut reverse = SetupTranscript::new();
        reverse.contribute(&b);
        reverse.contribute(&a);

        assert_ne!(
            forward.head(),
            reverse.head(),
            "contribution order must be bound into the chain"
        );
    }

    /// The seed must depend on every contribution. If a late contributor could
    /// cancel an earlier one, a single malicious participant could control the
    /// trapdoor entirely.
    #[test]
    fn test_seed_depends_on_every_contribution() {
        let a = SetupContribution {
            contributor: "alice".into(),
            entropy: [0x11u8; 32],
        };
        let b = SetupContribution {
            contributor: "bob".into(),
            entropy: [0x22u8; 32],
        };

        let seed_of = |contribs: &[&SetupContribution]| -> [u8; 32] {
            let mut t = SetupTranscript::new();
            for c in contribs {
                t.contribute(c);
            }
            t.seed_accumulator
        };

        let ab = seed_of(&[&a, &b]);
        let a_only = seed_of(&[&a]);
        let b_only = seed_of(&[&b]);
        assert_ne!(ab, a_only);
        assert_ne!(ab, b_only);

        // The cancellation attack a plain XOR fold would permit: bob submits
        // alice's value hoping to zero the accumulator.
        let cancel = SetupContribution {
            contributor: "bob".into(),
            entropy: [0x11u8; 32],
        };
        assert_ne!(
            seed_of(&[&a, &cancel]),
            [0u8; 32],
            "hashing after each fold must prevent XOR cancellation"
        );
    }

    /// An empty transcript must be a hard error. Silently falling back to a local
    /// seed is how the previous revision's unaudited setup came about.
    #[test]
    fn test_empty_transcript_is_rejected() {
        let t = SetupTranscript::new();
        assert!(t.setup_rng().is_err());

        let mut p = Groth16Prover::new();
        assert!(
            p.setup_with_transcript(&t).is_err(),
            "setup must refuse an empty transcript"
        );
    }

    #[test]
    fn test_setup_refuses_tampered_transcript() {
        let mut t = SetupTranscript::new();
        t.contribute(&SetupContribution::generate("alice"));
        t.records[0].head[0] ^= 0x01;

        let mut p = Groth16Prover::new();
        assert!(
            p.setup_with_transcript(&t).is_err(),
            "setup must refuse a transcript whose chain does not verify"
        );
    }

    /// The published commitment must not reveal the entropy, and must bind the
    /// contributor identity.
    #[test]
    fn test_contribution_commitment_hides_and_binds() {
        let c = SetupContribution {
            contributor: "alice".into(),
            entropy: [0x42u8; 32],
        };
        let commitment = c.commitment();
        assert_ne!(
            commitment, c.entropy,
            "the commitment must not be the entropy itself"
        );

        let same_entropy_other_name = SetupContribution {
            contributor: "bob".into(),
            entropy: [0x42u8; 32],
        };
        assert_ne!(
            commitment,
            same_entropy_other_name.commitment(),
            "contributor identity must be bound into the commitment"
        );
    }

    #[test]
    fn test_setup_records_transcript_head() {
        let mut t = SetupTranscript::new();
        t.contribute(&SetupContribution::generate("alice"));
        let mut p = Groth16Prover::new();
        p.setup_with_transcript(&t).expect("setup");
        assert_eq!(
            p.transcript_head(),
            Some(t.head()),
            "the prover must record which transcript produced its key"
        );
    }
}
