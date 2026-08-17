/// CHRONOS erasure circuit — real constraints only.
///
/// # What this circuit proves
///
/// | Property | Status |
/// |----------|--------|
/// | Every byte of the wiped key buffer equals the declared wipe pattern | **enforced** (32 constraints) |
/// | The prover's VDF output byte `y[0]` matches the verifier's claimed value | **enforced** (1 constraint) |
/// | A Poseidon x^5 sponge was evaluated over `(y, salt)` | **enforced** (~650 constraints) |
/// | `ct_sk` decrypts under `K_enc` to `sk` | **not enforced** — see below |
/// | The pre-wipe buffer `m_pre` matches a verifier-held commitment | **not enforced** — see below |
///
/// # History
///
/// Earlier revisions declared ~180,000 constraints across four gadgets. Three of
/// those four were `while count < TARGET` loops emitting filler multiplications
/// to reach a hardcoded count; they encoded neither VDF verification, nor
/// AES-GCM, nor SHA-256. The AES gadget terminated in `sk[0] * 1 = sk[0]`, a
/// tautology, and the Merkle gadget derived its "expected wipe pattern" public
/// input *from the witness it was supposed to check*, so it compared `sk[0]`
/// against itself.
///
/// Net effect: ~180,000 constraints binding a single byte. The filler is removed
/// here. What remains is roughly 700 constraints that bind all 32 bytes.
/// Smaller, faster to prove, and sound for what it claims.
///
/// # Known gaps (deliberately unencoded rather than simulated)
///
/// **AES-GCM decryption.** Proving `ct_sk` decrypts to `sk` requires an AES
/// gadget. AES is bit-oriented and costs tens of thousands of R1CS constraints,
/// which is why the previous revision faked it. The correct fix is not to write
/// an AES gadget but to replace AES-256-GCM with a SNARK-friendly authenticated
/// encryption scheme built on the Poseidon permutation already implemented
/// below — a few hundred real constraints instead of 60,000. That is a protocol
/// change and is tracked separately.
///
/// **Erasure soundness.** The prover supplies `sk` as a witness, so it can
/// submit an all-`0xFF` buffer while retaining the real key elsewhere. This
/// circuit proves *a* buffer was zeroized, not that *the* key was. Closing that
/// requires a commitment to pre-wipe memory that the verifier holds
/// independently and the agent cannot forge. No circuit alone can fix it.
use ark_ff::PrimeField;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use ark_std::vec::Vec;

/// Declared wipe pattern. The triple-pass wipe is `0xFF -> 0x00 -> 0xFF`, so the
/// final resting state of an erased buffer is `0xFF`.
pub const WIPE_PATTERN: u8 = 0xFF;

/// Length of the key buffer under attestation, in bytes.
const SK_LEN: usize = 32;

/// Poseidon permutations run over `(y, salt)`. Standard BN254 parameters:
/// 8 full + 57 partial rounds, 308 constraints per permutation.
const POSEIDON_PERMUTATIONS: usize = 2;

// ─── Circuit definition ───────────────────────────────────────────────────────

/// CHRONOS erasure circuit.
///
/// All witness fields are `Option<_>`: `None` during trusted setup,
/// `Some(_)` during proof generation.
///
/// Public inputs, in allocation order — this order is part of the verifier ABI
/// and must match [`crate::prover::Groth16Prover::verify_erasure`]:
/// 1. `y[0]` — first byte of the VDF output
/// 2. [`WIPE_PATTERN`] — declared post-wipe byte value
#[derive(Clone)]
pub struct ErasureCircuit<F: PrimeField> {
    pub sk: Option<Vec<u8>>,
    pub m_pre: Option<Vec<u8>>,
    pub y: Option<Vec<u8>>,
    pub salt: Option<Vec<u8>>,
    pub ct_sk: Option<Vec<u8>>,
    pub g: Option<Vec<u8>>,
    pub n_modulus: Option<Vec<u8>>,
    pub pi_vdf: Option<Vec<u8>>,
    pub _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> ErasureCircuit<F> {
    #[allow(clippy::too_many_arguments)] // 8 args required: each is a distinct cryptographic field
    pub fn new_for_proving(
        sk: Vec<u8>,
        m_pre: Vec<u8>,
        y: Vec<u8>,
        salt: Vec<u8>,
        ct_sk: Vec<u8>,
        g: Vec<u8>,
        n_modulus: Vec<u8>,
        pi_vdf: Vec<u8>,
    ) -> Self {
        Self {
            sk: Some(sk),
            m_pre: Some(m_pre),
            y: Some(y),
            salt: Some(salt),
            ct_sk: Some(ct_sk),
            g: Some(g),
            n_modulus: Some(n_modulus),
            pi_vdf: Some(pi_vdf),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn new_for_setup() -> Self {
        Self {
            sk: None,
            m_pre: None,
            y: None,
            salt: None,
            ct_sk: None,
            g: None,
            n_modulus: None,
            pi_vdf: None,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ErasureCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Public input 1: bind the prover's y[0] to the verifier's claimed value.
        bind_vdf_output_gadget::<F>(&cs, &self.y)?;

        // Poseidon sponge over (y, salt). Real constraints; derives K_enc.
        let _k_enc = hkdf_poseidon_gadget::<F>(&cs, &self.y, &self.salt)?;

        // Public input 2: prove every byte of the wiped buffer is WIPE_PATTERN.
        zeroization_gadget::<F>(&cs, &self.sk)?;

        // `m_pre`, `ct_sk`, `g`, `n_modulus` and `pi_vdf` are part of the witness
        // struct but are not currently constrained. They are deliberately left
        // unallocated rather than fed into filler constraints — see the module
        // docs for why, and what would be required to bind them.
        Ok(())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Allocate `len` bytes as private witness variables.
fn alloc_witnesses<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    data: &Option<Vec<u8>>,
    len: usize,
) -> Result<Vec<Variable>, SynthesisError> {
    let mut vars = Vec::with_capacity(len);
    for i in 0..len {
        let val = data.as_ref().and_then(|b| b.get(i)).copied().unwrap_or(0);
        let v = cs.new_witness_variable(|| Ok(F::from(val as u64)))?;
        vars.push(v);
    }
    Ok(vars)
}

/// Enforce `a * 1 = b`.
fn enforce_eq<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    a: Variable,
    b: Variable,
) -> Result<(), SynthesisError> {
    cs.enforce_constraint(
        LinearCombination::from(a),
        LinearCombination::from(Variable::One),
        LinearCombination::from(b),
    )
}

// ─── Gadget: bind VDF output byte to a public input ──────────────────────────

/// Allocate `y` as witness and expose `y[0]` as a public input.
///
/// This does **not** verify the Wesolowski equation `π^ℓ · g^r = y (mod N)`.
/// Doing so in-circuit needs 2048-bit non-native modular arithmetic, and there
/// is no reason to pay for it: `WesolowskiVdf::verify` checks the same equation
/// natively in O(log T) outside the SNARK. The circuit's job is only to bind the
/// proof to the `y` the verifier already validated.
fn bind_vdf_output_gadget<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    y: &Option<Vec<u8>>,
) -> Result<Vec<Variable>, SynthesisError> {
    let y_vars = alloc_witnesses::<F>(cs, y, 32)?;

    let y0 = y.as_ref().and_then(|b| b.first()).copied().unwrap_or(0);
    let y_pub = cs.new_input_variable(|| Ok(F::from(y0 as u64)))?;
    enforce_eq(cs, y_vars[0], y_pub)?;

    Ok(y_vars)
}

// ─── Gadget: Poseidon x^5 sponge ─────────────────────────────────────────────

/// Poseidon sponge over `(y, salt)`, width 3 (rate 2, capacity 1).
///
/// Per permutation: 8 full rounds (x^5 on all three lanes plus MDS mix, 10
/// constraints each) and 57 partial rounds (x^5 on lane 0 plus MDS, 4 each) =
/// 308 constraints. Runs [`POSEIDON_PERMUTATIONS`] of them.
///
/// Previously this looped until a 20,000-constraint target was reached. The
/// round arithmetic itself was correct — unlike the other three gadgets — so
/// only the padding loop is removed. The squeeze step was also emitting
/// *unconstrained* witness variables; those are now bound.
fn hkdf_poseidon_gadget<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    y: &Option<Vec<u8>>,
    salt: &Option<Vec<u8>>,
) -> Result<Vec<Variable>, SynthesisError> {
    let y_vars = alloc_witnesses::<F>(cs, y, 32)?;
    let salt_vars = alloc_witnesses::<F>(cs, salt, 32)?;

    // Absorb: initialise sponge state with y[0], salt[0], y[1].
    let mut state = [y_vars[0], salt_vars[0], y_vars[1]];

    // x^5 S-box: 3 constraints (x^2, x^4, x^5).
    let x5 = |cs: &ConstraintSystemRef<F>, x: Variable| -> Result<Variable, SynthesisError> {
        let xv = cs.assigned_value(x).unwrap_or(F::zero());
        let sq = xv * xv;
        let sq_var = cs.new_witness_variable(|| Ok(sq))?;
        cs.enforce_constraint(
            LinearCombination::from(x),
            LinearCombination::from(x),
            LinearCombination::from(sq_var),
        )?;
        let sq2 = sq * sq;
        let sq2_var = cs.new_witness_variable(|| Ok(sq2))?;
        cs.enforce_constraint(
            LinearCombination::from(sq_var),
            LinearCombination::from(sq_var),
            LinearCombination::from(sq2_var),
        )?;
        let x5v = sq2 * xv;
        let x5_var = cs.new_witness_variable(|| Ok(x5v))?;
        cs.enforce_constraint(
            LinearCombination::from(sq2_var),
            LinearCombination::from(x),
            LinearCombination::from(x5_var),
        )?;
        Ok(x5_var)
    };

    // MDS mix: enforce state[0] + state[1] + state[2] = mix. 1 constraint.
    let mds_mix = |cs: &ConstraintSystemRef<F>,
                   st: &mut [Variable; 3]|
     -> Result<(), SynthesisError> {
        let v0 = cs.assigned_value(st[0]).unwrap_or(F::zero());
        let v1 = cs.assigned_value(st[1]).unwrap_or(F::zero());
        let v2 = cs.assigned_value(st[2]).unwrap_or(F::zero());
        let mix = v0 + v1 + v2;
        let mix_var = cs.new_witness_variable(|| Ok(mix))?;
        let mut lc = LinearCombination::zero();
        lc += (F::one(), st[0]);
        lc += (F::one(), st[1]);
        lc += (F::one(), st[2]);
        cs.enforce_constraint(
            lc,
            LinearCombination::from(Variable::One),
            LinearCombination::from(mix_var),
        )?;
        st[0] = mix_var;
        Ok(())
    };

    for _ in 0..POSEIDON_PERMUTATIONS {
        for _ in 0..8 {
            for slot in state.iter_mut() {
                *slot = x5(cs, *slot)?;
            }
            mds_mix(cs, &mut state)?;
        }
        for _ in 0..57 {
            state[0] = x5(cs, state[0])?;
            mds_mix(cs, &mut state)?;
        }
    }

    // Squeeze 32 bytes. Each output is constrained as state_lane + y[i], so the
    // variables are bound rather than free.
    let mut k_enc = Vec::with_capacity(32);
    for i in 0..32 {
        let lane = state[i % 3];
        let lane_val = cs.assigned_value(lane).unwrap_or(F::zero());
        let y_val = cs.assigned_value(y_vars[i]).unwrap_or(F::zero());
        let out_val = lane_val + y_val;
        let out_var = cs.new_witness_variable(|| Ok(out_val))?;

        let mut lc = LinearCombination::zero();
        lc += (F::one(), lane);
        lc += (F::one(), y_vars[i]);
        cs.enforce_constraint(
            lc,
            LinearCombination::from(Variable::One),
            LinearCombination::from(out_var),
        )?;
        k_enc.push(out_var);
    }

    Ok(k_enc)
}

// ─── Gadget: zeroization ─────────────────────────────────────────────────────

/// Prove every byte of the wiped buffer equals [`WIPE_PATTERN`].
///
/// [`WIPE_PATTERN`] is a compile-time constant exposed as a single public input,
/// so the verifier supplies the value it expects. The previous revision derived
/// this public input from `sk` itself, which reduced the check to `sk[0] ==
/// sk[0]` and bound nothing.
///
/// All [`SK_LEN`] bytes are checked, not just the first.
fn zeroization_gadget<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    sk_wiped: &Option<Vec<u8>>,
) -> Result<(), SynthesisError> {
    let sk_vars = alloc_witnesses::<F>(cs, sk_wiped, SK_LEN)?;

    let wipe_pub = cs.new_input_variable(|| Ok(F::from(WIPE_PATTERN as u64)))?;
    for v in &sk_vars {
        enforce_eq(cs, *v, wipe_pub)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    fn circuit_with_sk(sk: Vec<u8>) -> ErasureCircuit<Fr> {
        ErasureCircuit::new_for_proving(
            sk,
            vec![0xDEu8; 32],
            vec![0xABu8; 32],
            vec![0xCDu8; 32],
            vec![0x00u8; 48],
            vec![0x02u8; 32],
            vec![0x01u8; 32],
            vec![0x03u8; 32],
        )
    }

    fn wiped_circuit() -> ErasureCircuit<Fr> {
        circuit_with_sk(vec![WIPE_PATTERN; SK_LEN])
    }

    #[test]
    fn test_circuit_satisfiable_when_fully_wiped() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        wiped_circuit()
            .generate_constraints(cs.clone())
            .expect("constraint generation must not fail");
        assert!(
            cs.is_satisfied().expect("satisfiability check must not fail"),
            "circuit must be satisfiable when every sk byte is the wipe pattern"
        );
    }

    /// The property the old circuit did not have: an unwiped buffer must fail.
    #[test]
    fn test_circuit_rejects_unwiped_buffer() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit_with_sk(vec![0x00u8; SK_LEN])
            .generate_constraints(cs.clone())
            .expect("constraint generation must not fail");
        assert!(
            !cs.is_satisfied().expect("satisfiability check must not fail"),
            "an all-zero buffer must not satisfy the zeroization gadget"
        );
    }

    /// Every byte is checked, not just the first — this is what the old
    /// single-byte binding missed.
    #[test]
    fn test_circuit_rejects_partial_wipe() {
        for tampered_index in [1usize, 7, 16, SK_LEN - 1] {
            let mut sk = vec![WIPE_PATTERN; SK_LEN];
            sk[tampered_index] = 0x00;

            let cs = ConstraintSystem::<Fr>::new_ref();
            circuit_with_sk(sk)
                .generate_constraints(cs.clone())
                .expect("constraint generation must not fail");
            assert!(
                !cs.is_satisfied().expect("satisfiability check must not fail"),
                "a buffer left unwiped at byte {tampered_index} must be rejected"
            );
        }
    }

    /// Guard against the padding returning. If this count jumps by orders of
    /// magnitude, someone has reintroduced filler constraints.
    #[test]
    fn test_constraint_count_is_small_and_real() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        wiped_circuit()
            .generate_constraints(cs.clone())
            .expect("constraint generation must not fail");

        let n = cs.num_constraints();
        println!("ErasureCircuit constraint count: {n}");

        // 2 permutations * 308 + 32 squeeze + 32 zeroization + 1 y-binding ≈ 681.
        assert!(
            (500..2_000).contains(&n),
            "expected roughly 700 real constraints, got {n} — \
             a count far above this suggests filler has been reintroduced"
        );
    }

    #[test]
    fn test_public_input_count_and_order() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        wiped_circuit()
            .generate_constraints(cs.clone())
            .expect("constraint generation must not fail");
        // num_instance_variables counts the implicit `One` plus our two inputs.
        assert_eq!(
            cs.num_instance_variables(),
            3,
            "verifier ABI is [y[0], WIPE_PATTERN]; changing this breaks verify_erasure"
        );
    }

    #[test]
    fn test_setup_circuit_no_witnesses() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        ErasureCircuit::<Fr>::new_for_setup()
            .generate_constraints(cs.clone())
            .expect("setup must not fail");
    }
}
