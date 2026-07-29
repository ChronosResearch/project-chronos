use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// R1CS circuit for the CHRONOS erasure proof.
///
/// When fully implemented (see §5.2 of the CHRONOS v2 paper), this circuit
/// encodes three sub-gadgets in approximately 150 000 constraints:
///
/// | Gadget                        | Constraints |
/// |-------------------------------|-------------|
/// | Wesolowski VDF verification   | ~70 000     |
/// | HKDF-SHA256 (Poseidon sponge) | ~20 000     |
/// | AES-GCM decryption            | ~60 000     |
///
/// The current implementation is a **stub** skeleton that satisfies the
/// `ConstraintSynthesizer` interface with a single trivial constraint.  The
/// witness fields (`sk`, `m_pre`, `y`) are present so the API is spec-compliant.
///
/// # Production note
/// Replace the stub body with real gadgets from `ark-crypto-primitives` before
/// deploying.  The proving key will be approximately 50 MB — see
/// [`super::prover::Groth16Prover::generate_proof`] for drop discipline.
#[derive(Clone)]
pub struct ErasureCircuit<F: PrimeField> {
    /// Secret key witness (None for the verifier).
    pub sk: Option<Vec<u8>>,
    /// Pre-wipe memory snapshot witness.
    pub m_pre: Option<Vec<u8>>,
    /// VDF output witness `y = g^(2^T) mod N`.
    pub y: Option<Vec<u8>>,
    /// Phantom marker for the field type `F`.
    pub _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ErasureCircuit<F> {
    /// Synthesise the R1CS constraints for this circuit.
    ///
    /// # Errors
    /// Propagates [`SynthesisError`] from the constraint system.
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Stub: one trivial constraint linking a private witness to a public input.
        // TODO(production): replace with VDF + HKDF + AES-GCM gadgets.
        let one = F::from(1u32);
        let var = cs.new_witness_variable(|| Ok(one))?;
        let pub_var = cs.new_input_variable(|| Ok(one))?;

        cs.enforce_constraint(
            ark_relations::r1cs::lc!() + var,
            ark_relations::r1cs::lc!() + (one, ark_relations::r1cs::Variable::One),
            ark_relations::r1cs::lc!() + pub_var,
        )?;

        Ok(())
    }
}
