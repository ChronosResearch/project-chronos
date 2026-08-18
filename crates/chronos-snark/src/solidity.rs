/// Export Groth16 verifying keys and proofs in the encoding the EVM expects.
///
/// BN254 is the same curve the EVM calls `alt_bn128`, so a proof produced here
/// is checkable by the `ecAdd` / `ecMul` / `ecPairing` precompiles at addresses
/// 0x06 / 0x07 / 0x08. That is the whole reason the erasure circuit targets
/// BN254: erasure attestations can be verified by any Ethereum node instead of
/// by a server the verifier has to trust.
///
/// # Two encoding hazards this module exists to handle
///
/// **Endianness.** arkworks serializes field elements little-endian. The EVM
/// reads 32-byte words big-endian. Passing arkworks' native bytes to Solidity
/// yields a verifier that rejects every valid proof.
///
/// **Fp2 coordinate order.** An Fp2 element is `c0 + c1·u`. The `ecPairing`
/// precompile expects the pair encoded as `[c1, c0]` — imaginary part first,
/// the reverse of arkworks' `(c0, c1)`. Every G2 point exported here is swapped
/// accordingly. This is the single most common cause of a Groth16 Solidity
/// verifier that compiles, deploys, and then rejects everything.
///
/// # Scope
///
/// This module changes *where* a proof can be checked, not *what* it proves. The
/// limits documented in `contracts/Groth16Verifier.sol` still apply — in
/// particular, CHRONOS's trusted setup is currently single-party, so on-chain
/// acceptance is conditional on trusting the setup operator.
use ark_bn254::{Bn254, Fq, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use chronos_core::{ChronosError, ChronosResult};

/// A field element as a `0x`-prefixed, 32-byte, big-endian hex string.
pub type Word = String;

/// Number of public inputs the erasure circuit exposes.
///
/// Re-exported from [`crate::circuit`] so the EVM side and the circuit cannot
/// drift apart. Must equal `PUBLIC_INPUT_COUNT` in
/// `contracts/Groth16Verifier.sol`.
pub const ERASURE_PUBLIC_INPUT_COUNT: usize = crate::circuit::PUBLIC_INPUT_COUNT;

/// Encode a base-field element as a 32-byte big-endian hex word.
fn fq_to_word(f: &Fq) -> Word {
    let be = f.into_bigint().to_bytes_be();
    // BN254's base field is 254 bits, so `be` is at most 32 bytes. Left-pad so
    // every word is exactly 32 bytes, which is what the EVM expects.
    let mut padded = [0u8; 32];
    let start = 32usize.saturating_sub(be.len());
    padded[start..].copy_from_slice(&be[be.len().saturating_sub(32)..]);
    format!("0x{}", hex_encode(&padded))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Encode a G1 point as `[x, y]`.
///
/// # Errors
/// Returns [`ChronosError::Snark`] if the point is the identity, which a valid
/// Groth16 verifying key or proof element never is. Silently encoding it as
/// `(0, 0)` would produce a verifier that fails in a way that is very hard to
/// debug.
fn g1_to_words(p: &G1Affine) -> ChronosResult<[Word; 2]> {
    if p.infinity {
        return Err(ChronosError::Snark(
            "G1 point at infinity cannot be encoded for the EVM".into(),
        ));
    }
    Ok([fq_to_word(&p.x), fq_to_word(&p.y)])
}

/// Encode a G2 point as `[[x.c1, x.c0], [y.c1, y.c0]]`.
///
/// Note the deliberate `c1` before `c0` — see the module documentation.
fn g2_to_words(p: &G2Affine) -> ChronosResult<[[Word; 2]; 2]> {
    if p.infinity {
        return Err(ChronosError::Snark(
            "G2 point at infinity cannot be encoded for the EVM".into(),
        ));
    }
    Ok([
        [fq_to_word(&p.x.c1), fq_to_word(&p.x.c0)],
        [fq_to_word(&p.y.c1), fq_to_word(&p.y.c0)],
    ])
}

/// A verifying key in EVM encoding, ready to pass to the
/// `Groth16Verifier` constructor.
#[derive(Debug, Clone)]
pub struct SolidityVerifyingKey {
    pub alpha: [Word; 2],
    pub beta: [[Word; 2]; 2],
    pub gamma: [[Word; 2]; 2],
    pub delta: [[Word; 2]; 2],
    /// `gamma_abc_g1`. Length is always public inputs + 1.
    pub ic: Vec<[Word; 2]>,
}

impl SolidityVerifyingKey {
    /// Render the constructor arguments as Solidity literals.
    ///
    /// Paste into a deploy script, or feed to `forge create --constructor-args`.
    #[must_use]
    pub fn to_constructor_args(&self) -> String {
        let mut out = String::new();
        out.push_str("// Groth16Verifier constructor arguments\n");
        out.push_str(&format!(
            "// IC length {} implies {} public inputs\n",
            self.ic.len(),
            self.ic.len().saturating_sub(1)
        ));
        out.push_str(&format!("uint256[2] alpha = [\n    {},\n    {}\n];\n", self.alpha[0], self.alpha[1]));
        out.push_str(&render_g2("beta", &self.beta));
        out.push_str(&render_g2("gamma", &self.gamma));
        out.push_str(&render_g2("delta", &self.delta));

        out.push_str(&format!("uint256[2][{}] ic = [\n", self.ic.len()));
        for (i, p) in self.ic.iter().enumerate() {
            let comma = if i + 1 == self.ic.len() { "" } else { "," };
            out.push_str(&format!("    [{}, {}]{comma}\n", p[0], p[1]));
        }
        out.push_str("];\n");
        out
    }

    /// Number of public inputs this key was generated for.
    #[must_use]
    pub fn public_input_count(&self) -> usize {
        self.ic.len().saturating_sub(1)
    }
}

fn render_g2(name: &str, g2: &[[Word; 2]; 2]) -> String {
    format!(
        "uint256[2][2] {name} = [\n    [{}, {}],\n    [{}, {}]\n];\n",
        g2[0][0], g2[0][1], g2[1][0], g2[1][1]
    )
}

/// A proof in EVM encoding, ready for `verifyProof` or `attestErasure`.
#[derive(Debug, Clone)]
pub struct SolidityProof {
    pub a: [Word; 2],
    pub b: [[Word; 2]; 2],
    pub c: [Word; 2],
}

impl SolidityProof {
    /// Render as a `cast send` / `forge script` argument triple.
    #[must_use]
    pub fn to_calldata_args(&self) -> String {
        format!(
            "[{},{}] [[{},{}],[{},{}]] [{},{}]",
            self.a[0], self.a[1],
            self.b[0][0], self.b[0][1],
            self.b[1][0], self.b[1][1],
            self.c[0], self.c[1]
        )
    }
}

/// Convert an arkworks verifying key into EVM encoding.
///
/// # Errors
/// Returns [`ChronosError::Snark`] if any group element is the identity, or if
/// `gamma_abc_g1` is empty.
pub fn export_verifying_key(vk: &VerifyingKey<Bn254>) -> ChronosResult<SolidityVerifyingKey> {
    if vk.gamma_abc_g1.is_empty() {
        return Err(ChronosError::Snark(
            "verifying key has empty gamma_abc_g1".into(),
        ));
    }

    let mut ic = Vec::with_capacity(vk.gamma_abc_g1.len());
    for p in &vk.gamma_abc_g1 {
        ic.push(g1_to_words(p)?);
    }

    Ok(SolidityVerifyingKey {
        alpha: g1_to_words(&vk.alpha_g1)?,
        beta: g2_to_words(&vk.beta_g2)?,
        gamma: g2_to_words(&vk.gamma_g2)?,
        delta: g2_to_words(&vk.delta_g2)?,
        ic,
    })
}

/// Convert an arkworks proof into EVM encoding.
///
/// # Errors
/// Returns [`ChronosError::Snark`] if any proof element is the identity.
pub fn export_proof(proof: &Proof<Bn254>) -> ChronosResult<SolidityProof> {
    Ok(SolidityProof {
        a: g1_to_words(&proof.a)?,
        b: g2_to_words(&proof.b)?,
        c: g1_to_words(&proof.c)?,
    })
}

/// Convert a serialized proof into EVM encoding.
///
/// Exists so callers that only ever hold proof *bytes* — the agent's HTTP layer,
/// for instance — do not need to depend on `ark-groth16` and `ark-serialize` just
/// to deserialize and re-encode. Keeping arkworks types inside this crate is what
/// stops the proof-system choice leaking into the agent.
///
/// # Errors
/// Returns [`ChronosError::Snark`] if the bytes do not deserialize as a
/// compressed BN254 Groth16 proof, or if any element is the identity.
pub fn export_proof_bytes(proof_bytes: &[u8]) -> ChronosResult<SolidityProof> {
    use ark_serialize::CanonicalDeserialize;
    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| ChronosError::Snark(format!("proof deserialization failed: {e}")))?;
    export_proof(&proof)
}

/// Encode the erasure circuit's public inputs as EVM words, in ABI order.
///
/// The order is part of the verifier ABI and must match
/// [`crate::circuit::PublicInputs::to_vec`],
/// `ErasureCircuit::generate_constraints`, and `Groth16Verifier.verifyProof`.
///
/// Each input is a full-width Poseidon digest. Earlier revisions exposed two
/// single-byte values here, which meant the on-chain verifier's entire binding to
/// the VDF was eight bits wide.
#[must_use]
pub fn erasure_public_inputs(
    inputs: &crate::circuit::PublicInputs,
) -> [Word; ERASURE_PUBLIC_INPUT_COUNT] {
    let v = inputs.to_vec();
    // `to_vec` returns exactly PUBLIC_INPUT_COUNT elements; index directly so a
    // future change to the ABI fails to compile rather than silently truncating.
    [
        fq_scalar_to_word(v[0]),
        fq_scalar_to_word(v[1]),
        fq_scalar_to_word(v[2]),
        fq_scalar_to_word(v[3]),
        fq_scalar_to_word(v[4]),
    ]
}

/// Encode a scalar-field element as a 32-byte big-endian hex word.
///
/// Separate from [`fq_to_word`] because public inputs live in the *scalar* field
/// `Fr`, while curve coordinates live in the *base* field `Fq`. They have
/// different moduli, and conflating them produces words the pairing precompile
/// silently misinterprets.
fn fq_scalar_to_word(f: ark_bn254::Fr) -> Word {
    let be = f.into_bigint().to_bytes_be();
    let mut padded = [0u8; 32];
    let start = 32usize.saturating_sub(be.len());
    padded[start..].copy_from_slice(&be[be.len().saturating_sub(32)..]);
    format!("0x{}", hex_encode(&padded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq2, G1Projective, G2Projective};
    use ark_ec::CurveGroup;
    use ark_ff::{One, Zero};
    use ark_std::UniformRand;

    fn rng() -> ark_std::rand::rngs::StdRng {
        use ark_std::rand::SeedableRng;
        ark_std::rand::rngs::StdRng::seed_from_u64(42)
    }

    #[test]
    fn test_word_is_32_bytes_hex() {
        let w = fq_to_word(&Fq::one());
        assert!(w.starts_with("0x"), "word must be 0x-prefixed");
        assert_eq!(w.len(), 66, "0x + 64 hex chars = 32 bytes");
        assert!(
            w.ends_with('1'),
            "Fq::one() must encode big-endian, ending in 1, got {w}"
        );
    }

    #[test]
    fn test_zero_encodes_to_all_zero_word() {
        let w = fq_to_word(&Fq::zero());
        assert_eq!(w, format!("0x{}", "0".repeat(64)));
    }

    /// The G2 swap is the whole point of this module — pin it with a test so a
    /// future refactor cannot quietly restore arkworks' native ordering.
    #[test]
    fn test_g2_export_swaps_c0_and_c1() {
        let mut r = rng();
        let g2 = G2Projective::rand(&mut r).into_affine();
        let words = g2_to_words(&g2).expect("random point is not infinity");

        // Exported X must be [c1, c0], i.e. the reverse of native order.
        assert_eq!(words[0][0], fq_to_word(&g2.x.c1), "X[0] must be x.c1");
        assert_eq!(words[0][1], fq_to_word(&g2.x.c0), "X[1] must be x.c0");
        assert_eq!(words[1][0], fq_to_word(&g2.y.c1), "Y[0] must be y.c1");
        assert_eq!(words[1][1], fq_to_word(&g2.y.c0), "Y[1] must be y.c0");
    }

    #[test]
    fn test_g2_swap_is_observable() {
        // Construct a point whose c0 and c1 differ, so a missing swap would
        // change the output rather than coincidentally matching.
        let mut r = rng();
        let g2 = G2Projective::rand(&mut r).into_affine();
        assert_ne!(
            g2.x.c0, g2.x.c1,
            "test vector must have distinct Fp2 components to be meaningful"
        );
        let words = g2_to_words(&g2).unwrap();
        assert_ne!(
            words[0][0], words[0][1],
            "swapped words must differ for this vector"
        );
    }

    #[test]
    fn test_g1_infinity_is_rejected() {
        let inf = G1Affine::identity();
        assert!(
            g1_to_words(&inf).is_err(),
            "identity must be rejected rather than encoded as (0,0)"
        );
    }

    #[test]
    fn test_g2_infinity_is_rejected() {
        let inf = G2Affine::identity();
        assert!(g2_to_words(&inf).is_err());
    }

    /// Public inputs must encode as full-width 32-byte words in ABI order.
    #[test]
    fn test_public_inputs_are_padded_words_in_abi_order() {
        use crate::circuit::PublicInputs;
        use ark_bn254::Fr;

        let pi = PublicInputs {
            y_commit: Fr::from(0xAAu64),
            ct_commit: Fr::from(0xBBu64),
            sk_commit: Fr::from(0xCCu64),
            mission_commit: Fr::from(0xDDu64),
            containment_commit: Fr::from(0xEEu64),
        };
        let words = erasure_public_inputs(&pi);
        assert_eq!(words.len(), ERASURE_PUBLIC_INPUT_COUNT);
        for w in &words {
            assert_eq!(w.len(), 66, "each input must be one 32-byte word");
            assert!(w.starts_with("0x"));
        }
        // Order must match `PublicInputs::to_vec`.
        assert!(words[0].ends_with("aa"), "slot 0 is y_commit, got {}", words[0]);
        assert!(words[1].ends_with("bb"), "slot 1 is ct_commit");
        assert!(words[2].ends_with("cc"), "slot 2 is sk_commit");
        assert!(words[3].ends_with("dd"), "slot 3 is mission_commit");
        assert!(words[4].ends_with("ee"), "slot 4 is containment_commit");
    }

    /// The exported public input count must track the circuit, so the Solidity
    /// verifier's `PUBLIC_INPUT_COUNT` cannot silently fall out of step.
    #[test]
    fn test_public_input_count_tracks_the_circuit() {
        assert_eq!(
            ERASURE_PUBLIC_INPUT_COUNT,
            crate::circuit::PUBLIC_INPUT_COUNT
        );
        assert_eq!(ERASURE_PUBLIC_INPUT_COUNT, 5);
    }

    #[test]
    fn test_export_rejects_empty_ic() {
        let mut r = rng();
        let vk = VerifyingKey::<Bn254> {
            alpha_g1: G1Projective::rand(&mut r).into_affine(),
            beta_g2: G2Projective::rand(&mut r).into_affine(),
            gamma_g2: G2Projective::rand(&mut r).into_affine(),
            delta_g2: G2Projective::rand(&mut r).into_affine(),
            gamma_abc_g1: vec![],
        };
        assert!(export_verifying_key(&vk).is_err());
    }

    #[test]
    fn test_constructor_args_render_expected_shape() {
        let mut r = rng();
        let vk = VerifyingKey::<Bn254> {
            alpha_g1: G1Projective::rand(&mut r).into_affine(),
            beta_g2: G2Projective::rand(&mut r).into_affine(),
            gamma_g2: G2Projective::rand(&mut r).into_affine(),
            delta_g2: G2Projective::rand(&mut r).into_affine(),
            gamma_abc_g1: vec![
                G1Projective::rand(&mut r).into_affine(),
                G1Projective::rand(&mut r).into_affine(),
                G1Projective::rand(&mut r).into_affine(),
            ],
        };
        let exported = export_verifying_key(&vk).expect("export must succeed");
        assert_eq!(
            exported.public_input_count(),
            2,
            "3 IC points implies 2 public inputs"
        );

        let args = exported.to_constructor_args();
        assert!(args.contains("uint256[2] alpha"));
        assert!(args.contains("uint256[2][2] beta"));
        assert!(args.contains("uint256[2][2] gamma"));
        assert!(args.contains("uint256[2][2] delta"));
        assert!(args.contains("uint256[2][3] ic"));
    }

    /// Fp2 sanity: confirms the arkworks field really is `c0 + c1·u` so the swap
    /// direction in `g2_to_words` is anchored to something checkable.
    #[test]
    fn test_fq2_component_access() {
        let e = Fq2::new(Fq::one(), Fq::zero());
        assert_eq!(e.c0, Fq::one());
        assert_eq!(e.c1, Fq::zero());
    }
}
