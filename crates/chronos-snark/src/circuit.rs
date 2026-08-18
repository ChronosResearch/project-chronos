//! CHRONOS erasure circuit — the full key-release chain, encoded.
//!
//! # What this circuit proves
//!
//! Given five public commitments that the verifier holds independently, the proof
//! establishes that the prover knew a witness for all of the following
//! simultaneously:
//!
//! | # | Property | Cost |
//! |---|---|---|
//! | 1 | The prover knows the VDF output `y` committed to by `y_commit` | ~1 permutation |
//! | 2 | `K_enc` is the Poseidon KDF of that exact `y` and the beacon salt | ~1 permutation |
//! | 3 | The prover knows the ciphertext committed to by `ct_commit` | ~1 permutation |
//! | 4 | That ciphertext **authenticates and decrypts under `K_enc`** | ~2 permutations |
//! | 5 | The decrypted plaintext equals the key committed to by `sk_commit` | 2 constraints |
//! | 6 | The prover knows the mission ID committed to by `mission_commit` | ~1 permutation |
//! | 7 | The containment monitor terminated **erased, fully revoked, budgets zero** | ~1 permutation + 4 |
//! | 8 | The observed post-wipe buffer reads the declared wipe pattern | 32 constraints |
//!
//! Chained together, 1–5 say: *the agent genuinely held the key that the
//! provisioner time-locked, and it obtained it the only way the protocol
//! permits — by completing the VDF.* An agent that never ran the VDF cannot
//! produce this witness, and neither can one that fabricated a key, because
//! `sk_commit` is fixed by the provisioner before the mission starts.
//!
//! # What it does not prove, stated precisely
//!
//! **No circuit can prove that memory was freed.** A SNARK constrains a witness,
//! and a witness is a value, not a location. The prover supplies `m_post`, so it
//! can present an all-`0xFF` buffer while retaining a copy of the key elsewhere in
//! its address space. Property 8 therefore carries no soundness weight on its own;
//! it is retained because it forces the prover to have *observed* the post-wipe
//! state, and because it is the exact hook where a hardware-attested pre-wipe
//! commitment would attach.
//!
//! What changed relative to earlier revisions is the size of that residual gap.
//! Before, the gap was everything: the circuit checked `[0xFF; 32] == 0xFF` and
//! nothing else, so a prover that had never seen the key, the ciphertext, or the
//! VDF could produce a passing proof. Now the prover must exhibit the genuine key
//! and demonstrate the whole derivation path. The remaining assumption is exactly
//! `F_OS` — that `mlock`, the volatile triple-pass wipe, disabled core dumps and
//! disabled swap leave no recoverable copy — and nothing more.
//!
//! That distinction is the difference between an unproven claim and a claim
//! reduced to a stated, auditable assumption.
//!
//! # Proof-carrying containment
//!
//! Property 7 is not part of the classical erasure statement and, as far as the
//! author is aware, has no precedent in the ephemeral-agent literature. The same
//! proof that attests key destruction also attests that the agent's capability
//! monitor ended in a terminal, fully-revoked state with both budgets exhausted.
//! One on-chain record therefore covers *destruction* and *discipline*. See
//! [`ContainmentSummary`] and `chronos_core::containment`.
//!
//! # Ordering requirement
//!
//! Property 5 requires the genuine key as a witness, so the proof must be
//! generated **while the agent still holds it**, and the witness copy wiped
//! immediately afterwards. The correct sequence is decrypt, run the mission,
//! prove, then wipe both the key and the proving witness. Proving *after* the wipe
//! — which is what earlier revisions did — is what made the old circuit vacuous:
//! it was handed the erased buffer and dutifully attested that erased bytes are
//! erased.
//!
//! # Why Poseidon everywhere
//!
//! Properties 2 and 4 are the ones a previous revision faked with 60,000 filler
//! multiplications labelled "AES-GCM key schedule and decryption". They are
//! encoded here for roughly 2,000 real constraints because the KDF and cipher are
//! built on the Poseidon permutation rather than SHA-256 and AES. See
//! [`crate::aead`] for why that substitution is safe and where AES is still used.

use ark_bn254::Fr;
use ark_ff::Zero;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use chronos_core::containment::{Capabilities, ContainmentLedger, Phase};
use chronos_core::{ChronosError, ChronosResult};

use crate::aead::{self, Ciphertext};
use crate::poseidon::{self, Domain};

// ─── Fixed shape ──────────────────────────────────────────────────────────────
//
// Groth16 requires the constraint system to be identical at setup and at proving
// time, so every length here is a compile-time constant. A witness that does not
// match is rejected by `check_shape` with a specific error rather than producing a
// proof that mysteriously fails to verify.

/// Byte length of the VDF output. RSA-2048 means a 256-byte group element.
pub const Y_BYTES: usize = 256;
/// Limbs needed for [`Y_BYTES`].
pub const Y_LIMBS: usize = Y_BYTES / poseidon::BYTES_PER_LIMB;

/// Byte length of the drand beacon salt.
pub const SALT_BYTES: usize = 32;
/// Limbs needed for [`SALT_BYTES`].
pub const SALT_LIMBS: usize = SALT_BYTES / poseidon::BYTES_PER_LIMB;

/// Byte length of the secret key under attestation.
pub const SK_BYTES: usize = 32;
/// Field elements representing the secret key.
pub const SK_ELEMS: usize = SK_BYTES / poseidon::BYTES_PER_LIMB;

/// Ciphertext body length, in field elements. Matches [`SK_ELEMS`].
pub const CT_BODY_ELEMS: usize = SK_ELEMS;

/// Byte length of the mission identifier digest.
pub const MISSION_BYTES: usize = 32;
/// Limbs needed for [`MISSION_BYTES`].
pub const MISSION_LIMBS: usize = MISSION_BYTES / poseidon::BYTES_PER_LIMB;

/// Final resting byte value of the triple-pass wipe (`0xFF -> 0x00 -> 0xFF`).
pub const WIPE_PATTERN: u8 = 0xFF;

/// Public input count. Part of the verifier ABI; must match
/// `contracts/Groth16Verifier.sol`'s `PUBLIC_INPUT_COUNT`.
pub const PUBLIC_INPUT_COUNT: usize = 5;

// ─── Containment summary ──────────────────────────────────────────────────────

/// Fixed-size digest of a containment run, committed to by the erasure proof.
///
/// # Why a summary rather than the whole ledger
///
/// A mission arbitrates an unbounded number of events, and a Groth16 circuit has
/// a fixed shape, so the full ledger cannot be a witness. Hashing a
/// variable-length ledger in-circuit is possible but would make proving cost grow
/// with mission length.
///
/// Instead the circuit binds this fixed-size summary, whose `chain_head` field is
/// the SHA-256 head of the complete append-only ledger. The proof therefore
/// commits to the entire event history transitively, while the four terminal-state
/// fields are checked *directly in-circuit* against the values a properly erased
/// agent must have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContainmentSummary {
    /// Terminal phase discriminant. Must be [`Phase::Erased`].
    pub final_phase: u64,
    /// Capability bits remaining. Must be exactly `ERASURE_ATTEST`.
    pub final_granted: u64,
    /// Operation budget left. Must be zero.
    pub op_budget_remaining: u64,
    /// Disclosure budget left. Must be zero.
    pub disclosure_remaining: u64,
    /// Events admitted.
    pub admitted: u64,
    /// Events refused.
    pub denied: u64,
    /// Total ledger length.
    pub ledger_len: u64,
    /// Low 16 bytes of the ledger's SHA-256 chain head.
    pub chain_head_lo: Fr,
    /// High 16 bytes of the ledger's SHA-256 chain head.
    pub chain_head_hi: Fr,
}

impl ContainmentSummary {
    /// Field elements in the canonical encoding.
    pub const ELEMS: usize = 9;

    /// The capability bits a correctly erased agent must retain: erasure
    /// attestation only. Every other capability must have been revoked.
    #[must_use]
    pub fn expected_final_granted() -> u64 {
        u64::from(Capabilities::ERASURE_ATTEST.bits())
    }

    /// Summarise a ledger that has reached its terminal state.
    #[must_use]
    pub fn from_ledger(ledger: &ContainmentLedger) -> Self {
        let state = ledger.state();
        let (admitted, denied) = ledger.counters();
        let head = ledger.chain_digest();
        let [lo, hi] = poseidon::split32(&head);
        Self {
            final_phase: state.phase as u64,
            final_granted: u64::from(state.granted.bits()),
            op_budget_remaining: state.op_budget,
            disclosure_remaining: state.disclosure_budget_bits,
            admitted,
            denied,
            ledger_len: ledger.len(),
            chain_head_lo: lo,
            chain_head_hi: hi,
        }
    }

    /// Canonical field encoding, in declaration order.
    ///
    /// This ordering is part of the verifier ABI: it determines
    /// `containment_commit`, so changing it invalidates published attestations.
    #[must_use]
    pub fn to_elements(&self) -> [Fr; Self::ELEMS] {
        [
            Fr::from(self.final_phase),
            Fr::from(self.final_granted),
            Fr::from(self.op_budget_remaining),
            Fr::from(self.disclosure_remaining),
            Fr::from(self.admitted),
            Fr::from(self.denied),
            Fr::from(self.ledger_len),
            self.chain_head_lo,
            self.chain_head_hi,
        ]
    }

    /// The public commitment.
    #[must_use]
    pub fn commitment(&self) -> Fr {
        poseidon::hash(Domain::ContainmentLedger, &self.to_elements())
    }

    /// Whether this summary describes a properly terminated containment run.
    ///
    /// Checked natively so provisioning and tooling can reject a bad summary
    /// early; the same four predicates are enforced in-circuit, which is what
    /// makes them load-bearing.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.final_phase == Phase::Erased as u64
            && self.final_granted == Self::expected_final_granted()
            && self.op_budget_remaining == 0
            && self.disclosure_remaining == 0
    }
}

// ─── Public inputs ────────────────────────────────────────────────────────────

/// The five public commitments, in verifier-ABI order.
///
/// `y_commit` is computed by the verifier from the `y` it validated natively with
/// [`chronos_core::VdfEngine::verify`]. `ct_commit` and `sk_commit` come from the
/// provisioner that produced `ct_sk.bin` — that is what makes them binding rather
/// than self-asserted. `mission_commit` is public mission metadata, and
/// `containment_commit` is produced by the agent but constrained in-circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    /// Poseidon commitment to the VDF output.
    pub y_commit: Fr,
    /// Poseidon commitment to the time-locked ciphertext.
    pub ct_commit: Fr,
    /// Poseidon commitment to the plaintext secret key.
    pub sk_commit: Fr,
    /// Poseidon commitment to the mission identifier.
    pub mission_commit: Fr,
    /// Poseidon commitment to the containment summary.
    pub containment_commit: Fr,
}

impl PublicInputs {
    /// Derive every commitment from the underlying values.
    ///
    /// Both prover and verifier call this, so there is exactly one definition of
    /// each commitment and no opportunity for the two sides to disagree.
    #[must_use]
    pub fn derive(
        y: &[u8],
        ct: &Ciphertext,
        sk: &[u8; SK_BYTES],
        mission_digest: &[u8; MISSION_BYTES],
        containment: &ContainmentSummary,
    ) -> Self {
        Self {
            y_commit: poseidon::hash_bytes(Domain::VdfOutput, y),
            ct_commit: poseidon::hash(Domain::Ciphertext, &ct.to_elements()),
            sk_commit: poseidon::hash(Domain::SecretKey, &poseidon::split32(sk)),
            mission_commit: poseidon::hash_bytes(Domain::MissionId, mission_digest),
            containment_commit: containment.commitment(),
        }
    }

    /// Flatten in ABI order, for `Groth16::verify_proof` and the EVM verifier.
    #[must_use]
    pub fn to_vec(&self) -> Vec<Fr> {
        vec![
            self.y_commit,
            self.ct_commit,
            self.sk_commit,
            self.mission_commit,
            self.containment_commit,
        ]
    }
}

// ─── Witness ──────────────────────────────────────────────────────────────────

/// The private witness.
///
/// Held separately from the circuit so the caller can wipe it explicitly after
/// proving; it contains the plaintext secret key.
#[derive(Clone)]
pub struct ErasureWitness {
    /// VDF output, big-endian, exactly [`Y_BYTES`] bytes.
    pub y: Vec<u8>,
    /// Beacon salt, exactly [`SALT_BYTES`] bytes.
    pub salt: Vec<u8>,
    /// Time-locked ciphertext with a [`CT_BODY_ELEMS`]-element body.
    pub ct: Ciphertext,
    /// The genuine plaintext secret key.
    pub sk: [u8; SK_BYTES],
    /// The observed post-wipe buffer.
    pub m_post: Vec<u8>,
    /// Mission identifier digest.
    pub mission_digest: [u8; MISSION_BYTES],
    /// Terminal containment summary.
    pub containment: ContainmentSummary,
}

impl ErasureWitness {
    /// Validate the witness against the circuit's fixed shape and semantics.
    ///
    /// Called before proving so a malformed witness produces a named error rather
    /// than an unsatisfiable constraint system, whose only symptom would be
    /// "proof generation failed".
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] naming the first problem found.
    pub fn check_shape(&self) -> ChronosResult<()> {
        if self.y.len() != Y_BYTES {
            return Err(ChronosError::Snark(format!(
                "erasure witness: y must be {Y_BYTES} bytes, got {}",
                self.y.len()
            )));
        }
        if self.salt.len() != SALT_BYTES {
            return Err(ChronosError::Snark(format!(
                "erasure witness: salt must be {SALT_BYTES} bytes, got {}",
                self.salt.len()
            )));
        }
        if self.ct.body.len() != CT_BODY_ELEMS {
            return Err(ChronosError::Snark(format!(
                "erasure witness: ciphertext body must be {CT_BODY_ELEMS} elements, got {}",
                self.ct.body.len()
            )));
        }
        if self.m_post.len() != SK_BYTES {
            return Err(ChronosError::Snark(format!(
                "erasure witness: m_post must be {SK_BYTES} bytes, got {}",
                self.m_post.len()
            )));
        }
        if let Some(bad) = self.m_post.iter().position(|b| *b != WIPE_PATTERN) {
            return Err(ChronosError::Snark(format!(
                "erasure witness: m_post byte {bad} is {:#04x}, expected {WIPE_PATTERN:#04x} — \
                 secure_wipe did not run, or ran on a different buffer",
                self.m_post[bad]
            )));
        }
        if !self.containment.is_terminal() {
            return Err(ChronosError::Snark(format!(
                "erasure witness: containment summary is not terminal \
                 (phase={}, granted={}, op_budget={}, disclosure={}) — \
                 the monitor must reach Erased with all capabilities but \
                 ERASURE_ATTEST revoked and both budgets at zero",
                self.containment.final_phase,
                self.containment.final_granted,
                self.containment.op_budget_remaining,
                self.containment.disclosure_remaining
            )));
        }
        // The relation the circuit will enforce. Checking it here converts a
        // silent proving failure into an actionable message.
        let k_enc = aead::ChronosAead::derive_key(&self.y, &self.salt);
        let recovered = aead::ChronosAead::decrypt(&k_enc, &self.ct).map_err(|e| {
            ChronosError::Snark(format!(
                "erasure witness: ciphertext does not authenticate under the key derived \
                 from this (y, salt): {e}"
            ))
        })?;
        if recovered != poseidon::split32(&self.sk).to_vec() {
            return Err(ChronosError::Snark(
                "erasure witness: ciphertext decrypts to a different key than the one supplied — \
                 sk does not match ct_sk"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Derive the matching public inputs.
    #[must_use]
    pub fn public_inputs(&self) -> PublicInputs {
        PublicInputs::derive(
            &self.y,
            &self.ct,
            &self.sk,
            &self.mission_digest,
            &self.containment,
        )
    }
}

// ─── Circuit ──────────────────────────────────────────────────────────────────

/// The erasure circuit. `None` witness means "setup only".
#[derive(Clone)]
pub struct ErasureCircuit {
    witness: Option<ErasureWitness>,
}

impl ErasureCircuit {
    /// Circuit for proving.
    #[must_use]
    pub fn new_for_proving(witness: ErasureWitness) -> Self {
        Self {
            witness: Some(witness),
        }
    }

    /// Circuit for trusted setup. Carries no witness, only the shape.
    #[must_use]
    pub fn new_for_setup() -> Self {
        Self { witness: None }
    }

    /// Public input values for this circuit instance, if it has a witness.
    #[must_use]
    pub fn public_inputs(&self) -> Option<PublicInputs> {
        self.witness.as_ref().map(ErasureWitness::public_inputs)
    }
}

/// Allocate `n` witness field elements, defaulting to zero during setup.
fn alloc_witness_elems(
    cs: &ConstraintSystemRef<Fr>,
    values: Option<&[Fr]>,
    n: usize,
) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    (0..n)
        .map(|i| {
            let v = values.and_then(|s| s.get(i)).copied().unwrap_or_else(Fr::zero);
            FpVar::new_witness(cs.clone(), || Ok(v))
        })
        .collect()
}

impl ConstraintSynthesizer<Fr> for ErasureCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let w = self.witness;

        // ── Public inputs, allocated in ABI order ────────────────────────────
        let pi = w.as_ref().map(ErasureWitness::public_inputs);
        let alloc_input = |value: Option<Fr>| -> Result<FpVar<Fr>, SynthesisError> {
            FpVar::new_input(cs.clone(), || Ok(value.unwrap_or_else(Fr::zero)))
        };
        let y_commit = alloc_input(pi.map(|p| p.y_commit))?;
        let ct_commit = alloc_input(pi.map(|p| p.ct_commit))?;
        let sk_commit = alloc_input(pi.map(|p| p.sk_commit))?;
        let mission_commit = alloc_input(pi.map(|p| p.mission_commit))?;
        let containment_commit = alloc_input(pi.map(|p| p.containment_commit))?;

        // ── Private witness ─────────────────────────────────────────────────
        let y_limbs_native = w.as_ref().map(|w| poseidon::pack_bytes(&w.y));
        let y_limbs = alloc_witness_elems(&cs, y_limbs_native.as_deref(), Y_LIMBS)?;

        let salt_limbs_native = w.as_ref().map(|w| poseidon::pack_bytes(&w.salt));
        let salt_limbs = alloc_witness_elems(&cs, salt_limbs_native.as_deref(), SALT_LIMBS)?;

        let nonce = FpVar::new_witness(cs.clone(), || {
            Ok(w.as_ref().map_or_else(Fr::zero, |w| w.ct.nonce))
        })?;
        let ct_body_native = w.as_ref().map(|w| w.ct.body.clone());
        let ct_body = alloc_witness_elems(&cs, ct_body_native.as_deref(), CT_BODY_ELEMS)?;
        let tag = FpVar::new_witness(cs.clone(), || {
            Ok(w.as_ref().map_or_else(Fr::zero, |w| w.ct.tag))
        })?;

        let sk_native = w.as_ref().map(|w| poseidon::split32(&w.sk).to_vec());
        let sk_elems = alloc_witness_elems(&cs, sk_native.as_deref(), SK_ELEMS)?;

        let mission_limbs_native = w.as_ref().map(|w| poseidon::pack_bytes(&w.mission_digest));
        let mission_limbs =
            alloc_witness_elems(&cs, mission_limbs_native.as_deref(), MISSION_LIMBS)?;

        let summary_native = w.as_ref().map(|w| w.containment.to_elements().to_vec());
        let summary =
            alloc_witness_elems(&cs, summary_native.as_deref(), ContainmentSummary::ELEMS)?;

        let m_post_native = w.as_ref().map(|w| w.m_post.clone());
        let m_post: Vec<FpVar<Fr>> = (0..SK_BYTES)
            .map(|i| {
                let byte = m_post_native
                    .as_ref()
                    .and_then(|b| b.get(i))
                    .copied()
                    .unwrap_or(WIPE_PATTERN);
                FpVar::new_witness(cs.clone(), || Ok(Fr::from(u64::from(byte))))
            })
            .collect::<Result<_, _>>()?;

        // ── 1. The prover knows the committed VDF output ─────────────────────
        let y_digest =
            poseidon::hash_bytes_gadget(cs.clone(), Domain::VdfOutput, Y_BYTES, &y_limbs)?;
        y_digest.enforce_equal(&y_commit)?;

        // ── 2. K_enc is the KDF of that y and this salt ──────────────────────
        //
        // Because `y_limbs` is the same variable vector bound in step 1, the key
        // is derived from the *verifier-validated* VDF output, not from an
        // arbitrary value the prover chose.
        let k_enc = aead::derive_key_gadget(
            cs.clone(),
            Y_BYTES,
            &y_limbs,
            SALT_BYTES,
            &salt_limbs,
        )?;

        // ── 3. The prover knows the committed ciphertext ─────────────────────
        let mut ct_elems = Vec::with_capacity(CT_BODY_ELEMS + 2);
        ct_elems.push(nonce.clone());
        ct_elems.extend_from_slice(&ct_body);
        ct_elems.push(tag.clone());
        let ct_digest = poseidon::hash_gadget(cs.clone(), Domain::Ciphertext, &ct_elems)?;
        ct_digest.enforce_equal(&ct_commit)?;

        // ── 4. That ciphertext authenticates and decrypts under K_enc ────────
        //
        // `decrypt_gadget` enforces the tag relation internally, so a ciphertext
        // that does not authenticate makes the system unsatisfiable.
        let recovered = aead::decrypt_gadget(cs.clone(), &k_enc, &nonce, &ct_body, &tag)?;

        // ── 5. The plaintext is the committed secret key ─────────────────────
        //
        // This is the constraint that closes the "any buffer" hole: `sk_commit`
        // is fixed by the provisioner before the mission, so the prover cannot
        // choose a key to suit a fabricated ciphertext.
        for (r, s) in recovered.iter().zip(sk_elems.iter()) {
            r.enforce_equal(s)?;
        }
        let sk_digest = poseidon::hash_gadget(cs.clone(), Domain::SecretKey, &sk_elems)?;
        sk_digest.enforce_equal(&sk_commit)?;

        // ── 6. The prover knows the committed mission ID ─────────────────────
        let mission_digest = poseidon::hash_bytes_gadget(
            cs.clone(),
            Domain::MissionId,
            MISSION_BYTES,
            &mission_limbs,
        )?;
        mission_digest.enforce_equal(&mission_commit)?;

        // ── 7. Containment terminated erased and fully revoked ───────────────
        //
        // The four terminal predicates are enforced against compile-time
        // constants, so a proof cannot be produced for a run that ended with
        // inference still permitted or budget still available.
        let summary_digest =
            poseidon::hash_gadget(cs.clone(), Domain::ContainmentLedger, &summary)?;
        summary_digest.enforce_equal(&containment_commit)?;

        summary[0].enforce_equal(&FpVar::Constant(Fr::from(Phase::Erased as u64)))?;
        summary[1].enforce_equal(&FpVar::Constant(Fr::from(
            ContainmentSummary::expected_final_granted(),
        )))?;
        summary[2].enforce_equal(&FpVar::Constant(Fr::zero()))?;
        summary[3].enforce_equal(&FpVar::Constant(Fr::zero()))?;

        // ── 8. The observed buffer reads the wipe pattern ────────────────────
        //
        // Carries no soundness weight — see the module docs — but forces the
        // prover to present the post-wipe state and marks where a hardware-
        // attested pre-wipe commitment would attach.
        let pattern = FpVar::Constant(Fr::from(u64::from(WIPE_PATTERN)));
        for byte in &m_post {
            byte.enforce_equal(&pattern)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use chronos_core::containment::{ContainmentState, Event};

    /// Build a terminal ledger the way a real mission would: init, one inference,
    /// key release, erase.
    fn terminal_ledger() -> ContainmentLedger {
        let mut l = ContainmentLedger::new(ContainmentState::new(4, 64, 3600), 16);
        l.admit(Event::MissionInit);
        l.admit(Event::Infer {
            declared_secs: 1,
            disclosure_bits: 8,
        });
        l.admit(Event::KeyReleased);
        l.admit(Event::Erase);
        l
    }

    /// A fully consistent witness, built the way the agent builds one.
    fn good_witness() -> ErasureWitness {
        let y: Vec<u8> = (0..Y_BYTES).map(|i| (i as u8).wrapping_mul(3)).collect();
        let salt: Vec<u8> = (0..SALT_BYTES).map(|i| (i as u8) ^ 0x5A).collect();
        let mut sk = [0u8; SK_BYTES];
        for (i, b) in sk.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }

        let k_enc = aead::ChronosAead::derive_key(&y, &salt);
        let ct = aead::ChronosAead::encrypt(&k_enc, Fr::from(99u64), &poseidon::split32(&sk))
            .expect("encrypt must succeed");

        let ledger = terminal_ledger();

        ErasureWitness {
            y,
            salt,
            ct,
            sk,
            m_post: vec![WIPE_PATTERN; SK_BYTES],
            mission_digest: [0x2Au8; MISSION_BYTES],
            containment: ContainmentSummary::from_ledger(&ledger),
        }
    }

    fn synthesize(w: ErasureWitness) -> ConstraintSystemRef<Fr> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        ErasureCircuit::new_for_proving(w)
            .generate_constraints(cs.clone())
            .expect("synthesis must not fail");
        cs
    }

    #[test]
    fn test_good_witness_is_satisfiable() {
        let w = good_witness();
        w.check_shape().expect("witness must be well formed");
        let cs = synthesize(w);
        assert!(
            cs.is_satisfied().expect("satisfiability"),
            "a consistent witness must satisfy the circuit"
        );
    }

    #[test]
    fn test_setup_circuit_synthesizes() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        ErasureCircuit::new_for_setup()
            .generate_constraints(cs.clone())
            .expect("setup synthesis must not fail");
        assert_eq!(
            cs.num_instance_variables(),
            PUBLIC_INPUT_COUNT + 1,
            "instance variables are the implicit One plus the public inputs"
        );
    }

    /// The setup and proving circuits must have identical shape, or Groth16
    /// produces a key that cannot verify the proofs it was made for.
    #[test]
    fn test_setup_and_proving_shapes_match() {
        let setup_cs = ConstraintSystem::<Fr>::new_ref();
        ErasureCircuit::new_for_setup()
            .generate_constraints(setup_cs.clone())
            .expect("setup");

        let proving_cs = synthesize(good_witness());

        assert_eq!(
            setup_cs.num_constraints(),
            proving_cs.num_constraints(),
            "constraint count must not depend on the witness"
        );
        assert_eq!(
            setup_cs.num_witness_variables(),
            proving_cs.num_witness_variables(),
            "witness variable count must not depend on the witness"
        );
        assert_eq!(
            setup_cs.num_instance_variables(),
            proving_cs.num_instance_variables()
        );
    }

    // ── The soundness properties the old circuit lacked ─────────────────────

    /// The attack that defeated every previous revision: present an all-`0xFF`
    /// buffer as the key and keep the real one. It must now fail, because the
    /// buffer has to decrypt from the committed ciphertext.
    #[test]
    fn test_rejects_fabricated_key() {
        let mut w = good_witness();
        w.sk = [WIPE_PATTERN; SK_BYTES];
        assert!(
            w.check_shape().is_err(),
            "a key that does not match ct_sk must be rejected before proving"
        );
        let cs = synthesize(w);
        assert!(
            !cs.is_satisfied().expect("satisfiability"),
            "a fabricated key must make the circuit unsatisfiable"
        );
    }

    /// An agent that never completed the VDF cannot derive `K_enc`, so the
    /// ciphertext will not authenticate.
    #[test]
    fn test_rejects_wrong_vdf_output() {
        let mut w = good_witness();
        w.y[Y_BYTES - 1] ^= 0x01;
        assert!(w.check_shape().is_err(), "a wrong y must be caught early");
        let cs = synthesize(w);
        assert!(
            !cs.is_satisfied().expect("satisfiability"),
            "a y that does not derive the right key must be unsatisfiable"
        );
    }

    #[test]
    fn test_rejects_wrong_salt() {
        let mut w = good_witness();
        w.salt[0] ^= 0xFF;
        let cs = synthesize(w);
        assert!(!cs.is_satisfied().expect("satisfiability"));
    }

    #[test]
    fn test_rejects_tampered_ciphertext() {
        for i in 0..CT_BODY_ELEMS {
            let mut w = good_witness();
            w.ct.body[i] += Fr::from(1u64);
            let cs = synthesize(w);
            assert!(
                !cs.is_satisfied().expect("satisfiability"),
                "tampering with ciphertext element {i} must be detected"
            );
        }

        let mut w = good_witness();
        w.ct.tag += Fr::from(1u64);
        let cs = synthesize(w);
        assert!(!cs.is_satisfied().expect("satisfiability"), "tag forgery must fail");
    }

    /// Every byte of the wipe pattern is checked, not just the first — the
    /// single-byte binding was one of the original defects.
    #[test]
    fn test_rejects_partial_wipe_at_any_byte() {
        for idx in [0usize, 1, 7, 16, 31] {
            let mut w = good_witness();
            w.m_post[idx] = 0x00;
            assert!(
                w.check_shape().is_err(),
                "an unwiped byte at {idx} must be caught early"
            );
            let cs = synthesize(w);
            assert!(
                !cs.is_satisfied().expect("satisfiability"),
                "an unwiped byte at {idx} must be unsatisfiable"
            );
        }
    }

    // ── Proof-carrying containment ──────────────────────────────────────────

    /// A mission that never erased must not be able to produce an erasure proof.
    #[test]
    fn test_rejects_non_terminal_containment() {
        let mut l = ContainmentLedger::new(ContainmentState::new(4, 64, 3600), 16);
        l.admit(Event::MissionInit); // Active, not Erased
        let mut w = good_witness();
        w.containment = ContainmentSummary::from_ledger(&l);

        assert!(
            w.check_shape().is_err(),
            "a non-terminal containment summary must be rejected early"
        );
        let cs = synthesize(w);
        assert!(
            !cs.is_satisfied().expect("satisfiability"),
            "the circuit must refuse a run that did not reach Erased"
        );
    }

    /// Each terminal predicate must be individually load-bearing. Perturbing any
    /// one of the four must break the proof.
    #[test]
    fn test_each_terminal_predicate_is_enforced() {
        let base = good_witness();

        let mut phase_bad = base.clone();
        phase_bad.containment.final_phase = Phase::Locked as u64;

        let mut granted_bad = base.clone();
        granted_bad.containment.final_granted =
            u64::from(Capabilities::all().bits());

        let mut op_bad = base.clone();
        op_bad.containment.op_budget_remaining = 1;

        let mut disc_bad = base.clone();
        disc_bad.containment.disclosure_remaining = 1;

        for (name, w) in [
            ("final_phase", phase_bad),
            ("final_granted", granted_bad),
            ("op_budget_remaining", op_bad),
            ("disclosure_remaining", disc_bad),
        ] {
            assert!(
                !w.containment.is_terminal(),
                "{name} perturbation must fail the native terminal check"
            );
            let cs = synthesize(w);
            assert!(
                !cs.is_satisfied().expect("satisfiability"),
                "{name} perturbation must make the circuit unsatisfiable"
            );
        }
    }

    /// The ledger chain head is folded into `containment_commit`, so two runs that
    /// reach the same terminal state via different event histories are
    /// distinguishable.
    ///
    /// # Why this is a commitment-level test
    ///
    /// `generate_constraints` derives the public inputs from the witness, so
    /// within a single synthesis any witness change is self-consistent and
    /// `is_satisfied` cannot detect a witness/public-input mismatch. Binding is
    /// only observable at the *proof* level, where the verifier supplies the
    /// public inputs independently — see
    /// `prover::tests::test_containment_history_is_bound_at_proof_level`.
    ///
    /// What is testable here is that the commitment is injective over the
    /// history, which is the property that makes the proof-level check work.
    #[test]
    fn test_containment_commitment_distinguishes_histories() {
        let base = ContainmentSummary::from_ledger(&terminal_ledger());

        // Same terminal state, shorter history.
        let mut other = ContainmentLedger::new(ContainmentState::new(4, 64, 3600), 16);
        other.admit(Event::MissionInit);
        other.admit(Event::Erase);
        let other_summary = ContainmentSummary::from_ledger(&other);

        assert!(
            base.is_terminal() && other_summary.is_terminal(),
            "both runs must be terminal, so only the history differs"
        );
        assert_ne!(
            base.commitment(),
            other_summary.commitment(),
            "different histories must produce different containment commitments"
        );

        // And the chain head is the field carrying that difference: substituting
        // it alone must change the commitment.
        let mut swapped = base;
        swapped.chain_head_lo = other_summary.chain_head_lo;
        assert_ne!(
            base.commitment(),
            swapped.commitment(),
            "the chain head must be bound into the commitment"
        );

        let mut swapped_hi = base;
        swapped_hi.chain_head_hi = other_summary.chain_head_hi;
        assert_ne!(base.commitment(), swapped_hi.commitment());
    }

    /// Every summary field must affect the commitment, otherwise an agent could
    /// misreport the unbound one.
    #[test]
    fn test_every_summary_field_affects_the_commitment() {
        let base = ContainmentSummary::from_ledger(&terminal_ledger());
        let d = base.commitment();

        let mut v = base;
        v.admitted += 1;
        assert_ne!(d, v.commitment(), "admitted count must be bound");

        let mut v = base;
        v.denied += 1;
        assert_ne!(d, v.commitment(), "denied count must be bound");

        let mut v = base;
        v.ledger_len += 1;
        assert_ne!(d, v.commitment(), "ledger length must be bound");

        let mut v = base;
        v.final_phase = Phase::Locked as u64;
        assert_ne!(d, v.commitment(), "final phase must be bound");

        let mut v = base;
        v.op_budget_remaining += 1;
        assert_ne!(d, v.commitment(), "op budget must be bound");
    }

    // ── Public input hygiene ────────────────────────────────────────────────

    /// Every public input must be full-width. Earlier revisions exposed a single
    /// byte of `y`, giving 8 bits of binding.
    #[test]
    fn test_public_inputs_are_full_width_field_elements() {
        let pi = good_witness().public_inputs();
        let vals = pi.to_vec();
        assert_eq!(vals.len(), PUBLIC_INPUT_COUNT);
        for (i, v) in vals.iter().enumerate() {
            assert!(!v.is_zero(), "public input {i} must not be trivially zero");
            // A byte-width value would be < 256. A Poseidon digest is ~254 bits.
            assert!(
                *v > Fr::from(u64::MAX),
                "public input {i} must be a full-width digest, not a small integer"
            );
        }
    }

    /// Distinct commitments must not collide with each other — that is what
    /// domain separation buys.
    #[test]
    fn test_public_inputs_are_pairwise_distinct() {
        let vals = good_witness().public_inputs().to_vec();
        for i in 0..vals.len() {
            for j in (i + 1)..vals.len() {
                assert_ne!(vals[i], vals[j], "public inputs {i} and {j} must differ");
            }
        }
    }

    #[test]
    fn test_public_inputs_change_with_every_component() {
        let base = good_witness();
        let base_pi = base.public_inputs();

        let mut y_changed = base.clone();
        y_changed.y[0] ^= 0x01;
        assert_ne!(y_changed.public_inputs().y_commit, base_pi.y_commit);

        let mut sk_changed = base.clone();
        sk_changed.sk[0] ^= 0x01;
        assert_ne!(sk_changed.public_inputs().sk_commit, base_pi.sk_commit);

        let mut mission_changed = base.clone();
        mission_changed.mission_digest[0] ^= 0x01;
        assert_ne!(
            mission_changed.public_inputs().mission_commit,
            base_pi.mission_commit
        );

        let mut ct_changed = base.clone();
        ct_changed.ct.nonce += Fr::from(1u64);
        assert_ne!(ct_changed.public_inputs().ct_commit, base_pi.ct_commit);
    }

    // ── Shape validation ────────────────────────────────────────────────────

    #[test]
    fn test_check_shape_rejects_wrong_lengths() {
        let mut w = good_witness();
        w.y.truncate(Y_BYTES - 1);
        assert!(w.check_shape().is_err());

        let mut w = good_witness();
        w.salt.push(0);
        assert!(w.check_shape().is_err());

        let mut w = good_witness();
        w.m_post.pop();
        assert!(w.check_shape().is_err());
    }

    /// Constraint budget. The whole chain is now genuinely encoded and should
    /// still cost only a few thousand constraints. A jump into the tens of
    /// thousands means a bit-oriented gadget crept back in; a collapse to the
    /// low hundreds means constraints were removed.
    #[test]
    fn test_constraint_count_is_in_expected_band() {
        let cs = synthesize(good_witness());
        let n = cs.num_constraints();
        println!("ErasureCircuit constraints: {n}");
        assert!(
            (2_000..20_000).contains(&n),
            "expected a few thousand constraints for the full chain, got {n}"
        );
    }

    #[test]
    fn test_summary_element_count_matches_constant() {
        let s = ContainmentSummary::from_ledger(&terminal_ledger());
        assert_eq!(s.to_elements().len(), ContainmentSummary::ELEMS);
    }

    #[test]
    fn test_expected_final_granted_is_erasure_attest_only() {
        assert_eq!(
            ContainmentSummary::expected_final_granted(),
            u64::from(Capabilities::ERASURE_ATTEST.bits())
        );
        // Sanity: it must not accidentally include inference.
        assert_ne!(
            ContainmentSummary::expected_final_granted(),
            u64::from(Capabilities::all().bits())
        );
    }
}
