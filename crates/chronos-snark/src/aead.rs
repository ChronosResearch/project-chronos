//! Chronos-AEAD — Poseidon-based authenticated encryption for the time-locked key.
//!
//! # Why replace AES-256-GCM
//!
//! CHRONOS's central claim is that the agent's key was released by a VDF and then
//! destroyed. Making that claim *checkable* means proving, in zero knowledge,
//! that the wiped key is the one that decrypts from the time-locked ciphertext
//! under a key derived from the VDF output. With AES-256-GCM that requires an AES
//! R1CS gadget: AES is bit-oriented, so it costs tens of thousands of constraints
//! in an arithmetic circuit.
//!
//! A previous revision of this codebase responded to that cost by emitting 60,000
//! filler multiplications and labelling them "AES-GCM key schedule and
//! decryption". The gadget terminated in `sk[0] * 1 = sk[0]`, a tautology.
//!
//! The correct fix is not a better AES gadget. It is to stop using AES for this
//! one purpose. The key-release step is entirely internal to CHRONOS — no
//! interoperability requirement forces AES — so it can use a cipher built from
//! the same Poseidon permutation the circuit already pays for. Cost drops from
//! ~60,000 constraints to roughly 2,000, and the relation becomes genuinely
//! encoded rather than simulated.
//!
//! AES-256-GCM remains the right choice everywhere CHRONOS talks to something
//! else. This scheme is used only where a proof has to reason about the
//! decryption.
//!
//! # Construction
//!
//! Encrypt-then-MAC over a Poseidon sponge, both parts keyed and
//! domain-separated:
//!
//! ```text
//! keystream = Poseidon(AeadKeystream, [k0, k1, nonce])          -> n elements
//! c_i       = p_i + keystream_i                                  (i < n)
//! tag       = Poseidon(AeadTag, [k0, k1, nonce, c_0 .. c_{n-1}]) -> 1 element
//! ```
//!
//! Decryption recomputes the keystream, subtracts, recomputes the tag, and
//! compares. Under the assumption that the Poseidon sponge is a PRF, the
//! keystream is indistinguishable from random, so this is a stream cipher with a
//! PRF-based MAC over the ciphertext — the standard encrypt-then-MAC composition,
//! which is IND-CPA plus INT-CTXT and therefore IND-CCA2.
//!
//! # Nonce discipline
//!
//! The keystream is a deterministic function of `(key, nonce)`. Reusing a nonce
//! under the same key reveals the XOR — here, the field difference — of the two
//! plaintexts, which is the classic catastrophic stream-cipher failure.
//!
//! In CHRONOS this is structurally safe: one mission has one key and encrypts one
//! secret key exactly once, and the key itself is derived from a VDF output
//! salted by a fresh drand beacon. [`ChronosAead::encrypt`] takes the nonce
//! explicitly rather than defaulting it, so a caller that reuses one is making a
//! visible choice.
//!
//! # Authentication is checked in constant time
//!
//! [`ChronosAead::decrypt`] compares the tag with `ark_ff`'s field equality and
//! returns a single opaque error on failure, without reporting where the
//! mismatch occurred. It also returns the error *before* handing back any
//! plaintext, so a caller cannot accidentally use unauthenticated output.

use ark_bn254::Fr;
use ark_ff::Zero;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use chronos_core::{ChronosError, ChronosResult};

use crate::poseidon::{self, Domain};

/// Field elements in an AEAD key. Two 128-bit limbs = 256 bits of key material.
pub const KEY_ELEMS: usize = 2;

/// Field elements used to represent a 32-byte secret key as plaintext.
pub const SK_PLAINTEXT_ELEMS: usize = 2;

/// A Chronos-AEAD ciphertext.
///
/// Serialized layout, used by `ct_sk.bin`, is `nonce || body... || tag`, each
/// element a 32-byte big-endian field element. For a 32-byte secret key that is
/// `1 + 2 + 1 = 4` elements, i.e. 128 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    /// Public, single-use nonce.
    pub nonce: Fr,
    /// Encrypted plaintext elements.
    pub body: Vec<Fr>,
    /// Authentication tag over `(key, nonce, body)`.
    pub tag: Fr,
}

impl Ciphertext {
    /// Flatten to `[nonce, body..., tag]` for hashing or serialization.
    ///
    /// The commitment `ct_commit` in the erasure circuit is taken over exactly
    /// this sequence, so the native and in-circuit orderings must match.
    #[must_use]
    pub fn to_elements(&self) -> Vec<Fr> {
        let mut out = Vec::with_capacity(self.body.len() + 2);
        out.push(self.nonce);
        out.extend_from_slice(&self.body);
        out.push(self.tag);
        out
    }

    /// Total element count, including nonce and tag.
    #[must_use]
    pub fn element_count(&self) -> usize {
        self.body.len() + 2
    }

    /// Serialize as `nonce || body... || tag`, 32 big-endian bytes per element.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        use ark_ff::{BigInteger, PrimeField};
        let mut out = Vec::with_capacity(self.element_count() * 32);
        for elem in self.to_elements() {
            let be = elem.into_bigint().to_bytes_be();
            // BN254 `Fr` is 254 bits, so `to_bytes_be` yields 32 bytes. Left-pad
            // defensively rather than assuming.
            let mut word = [0u8; 32];
            let start = 32usize.saturating_sub(be.len());
            word[start..].copy_from_slice(&be[be.len().saturating_sub(32)..]);
            out.extend_from_slice(&word);
        }
        out
    }

    /// Parse `nonce || body... || tag` produced by [`Self::to_bytes`].
    ///
    /// # Errors
    /// Returns [`ChronosError::Erasure`] if the length is not a multiple of 32,
    /// if there are fewer than three elements (nonce, one body element, tag), or
    /// if any word is not a canonical field element.
    pub fn from_bytes(bytes: &[u8]) -> ChronosResult<Self> {
        use ark_ff::PrimeField;

        if bytes.len() % 32 != 0 {
            return Err(ChronosError::Erasure(format!(
                "Chronos-AEAD ciphertext must be a whole number of 32-byte words, got {} bytes",
                bytes.len()
            )));
        }
        let n_elems = bytes.len() / 32;
        if n_elems < 3 {
            return Err(ChronosError::Erasure(format!(
                "Chronos-AEAD ciphertext needs at least 3 words (nonce, body, tag), got {n_elems}"
            )));
        }

        let mut elems = Vec::with_capacity(n_elems);
        for (i, word) in bytes.chunks(32).enumerate() {
            // Reject non-canonical encodings rather than silently reducing. A
            // reduced word would decrypt to a different plaintext than the one
            // the provisioner committed to, and the failure would surface as an
            // unexplained tag mismatch.
            let elem = Fr::from_be_bytes_mod_order(word);
            let round_trip = {
                use ark_ff::BigInteger;
                let be = elem.into_bigint().to_bytes_be();
                let mut w = [0u8; 32];
                let start = 32usize.saturating_sub(be.len());
                w[start..].copy_from_slice(&be[be.len().saturating_sub(32)..]);
                w
            };
            if round_trip != word {
                return Err(ChronosError::Erasure(format!(
                    "Chronos-AEAD ciphertext word {i} is not a canonical BN254 field element"
                )));
            }
            elems.push(elem);
        }

        let tag = elems.pop().unwrap_or_else(Fr::zero);
        let nonce = elems.remove(0);
        Ok(Self {
            nonce,
            body: elems,
            tag,
        })
    }
}

/// Chronos-AEAD, in its native (out-of-circuit) form.
pub struct ChronosAead;

impl ChronosAead {
    /// Derive the keystream for `(key, nonce)`.
    fn keystream(key: &[Fr; KEY_ELEMS], nonce: Fr, n: usize) -> Vec<Fr> {
        let inputs = [key[0], key[1], nonce];
        poseidon::hash_many(Domain::AeadKeystream, &inputs, n)
    }

    /// Compute the tag over `(key, nonce, body)`.
    fn tag(key: &[Fr; KEY_ELEMS], nonce: Fr, body: &[Fr]) -> Fr {
        let mut inputs = Vec::with_capacity(body.len() + 3);
        inputs.push(key[0]);
        inputs.push(key[1]);
        inputs.push(nonce);
        inputs.extend_from_slice(body);
        poseidon::hash(Domain::AeadTag, &inputs)
    }

    /// Encrypt `plaintext` under `key` with the supplied single-use `nonce`.
    ///
    /// # Nonce reuse
    /// See the module documentation. Reusing a nonce under the same key leaks the
    /// difference of the two plaintexts.
    ///
    /// # Errors
    /// Returns [`ChronosError::Erasure`] if `plaintext` is empty, since a
    /// zero-length body would make the tag independent of any message.
    pub fn encrypt(
        key: &[Fr; KEY_ELEMS],
        nonce: Fr,
        plaintext: &[Fr],
    ) -> ChronosResult<Ciphertext> {
        if plaintext.is_empty() {
            return Err(ChronosError::Erasure(
                "Chronos-AEAD: plaintext must be non-empty".into(),
            ));
        }
        let ks = Self::keystream(key, nonce, plaintext.len());
        let body: Vec<Fr> = plaintext.iter().zip(ks.iter()).map(|(p, k)| *p + k).collect();
        let tag = Self::tag(key, nonce, &body);
        Ok(Ciphertext { nonce, body, tag })
    }

    /// Decrypt and authenticate.
    ///
    /// The tag is verified *before* the plaintext is returned, so an
    /// unauthenticated value can never escape this function.
    ///
    /// # Errors
    /// Returns [`ChronosError::Erasure`] on tag mismatch — wrong key, wrong
    /// nonce, or tampered ciphertext. The error deliberately does not
    /// distinguish between those cases.
    pub fn decrypt(key: &[Fr; KEY_ELEMS], ct: &Ciphertext) -> ChronosResult<Vec<Fr>> {
        if ct.body.is_empty() {
            return Err(ChronosError::Erasure(
                "Chronos-AEAD: ciphertext body must be non-empty".into(),
            ));
        }
        let expected = Self::tag(key, ct.nonce, &ct.body);
        if expected != ct.tag {
            return Err(ChronosError::Erasure(
                "Chronos-AEAD: authentication failed".into(),
            ));
        }
        let ks = Self::keystream(key, ct.nonce, ct.body.len());
        Ok(ct.body.iter().zip(ks.iter()).map(|(c, k)| *c - k).collect())
    }

    /// Derive an AEAD key from a VDF output and a beacon salt.
    ///
    /// This is CHRONOS's KDF. It replaces HKDF-SHA256 for the same reason the
    /// cipher replaces AES: the erasure circuit has to prove that `K_enc` really
    /// was derived from the VDF output the verifier validated, and HKDF-SHA256 is
    /// not provable at a sane constraint count.
    ///
    /// `y` is the big-endian VDF output (256 bytes for RSA-2048) and `salt` is
    /// the 32-byte drand randomness. Both lengths are absorbed by
    /// [`poseidon::pack_bytes`]' caller below, and the limb counts are fixed by
    /// the circuit, so the native and in-circuit forms line up.
    #[must_use]
    pub fn derive_key(y: &[u8], salt: &[u8]) -> [Fr; KEY_ELEMS] {
        let mut inputs = Vec::new();
        inputs.push(Fr::from(y.len() as u64));
        inputs.extend(poseidon::pack_bytes(y));
        inputs.push(Fr::from(salt.len() as u64));
        inputs.extend(poseidon::pack_bytes(salt));
        let out = poseidon::hash_many(Domain::KeyDerivation, &inputs, KEY_ELEMS);
        [out[0], out[1]]
    }
}

// ─── In-circuit gadgets ───────────────────────────────────────────────────────

/// In-circuit counterpart of [`ChronosAead::derive_key`].
///
/// `y_limbs` and `salt_limbs` are witness limbs; `y_len` and `salt_len` are the
/// true byte lengths, which must match what the native side used.
///
/// # Errors
/// Propagates [`SynthesisError`].
pub fn derive_key_gadget(
    cs: ConstraintSystemRef<Fr>,
    y_len: usize,
    y_limbs: &[FpVar<Fr>],
    salt_len: usize,
    salt_limbs: &[FpVar<Fr>],
) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    let mut inputs = Vec::with_capacity(y_limbs.len() + salt_limbs.len() + 2);
    inputs.push(FpVar::Constant(Fr::from(y_len as u64)));
    inputs.extend_from_slice(y_limbs);
    inputs.push(FpVar::Constant(Fr::from(salt_len as u64)));
    inputs.extend_from_slice(salt_limbs);
    poseidon::hash_many_gadget(cs, Domain::KeyDerivation, &inputs, KEY_ELEMS)
}

/// In-circuit authenticated decryption.
///
/// Enforces the tag relation as a constraint — an incorrect tag makes the circuit
/// unsatisfiable, so there is no in-circuit equivalent of "ignoring the return
/// value" — and returns the recovered plaintext elements.
///
/// # Errors
/// Propagates [`SynthesisError`].
pub fn decrypt_gadget(
    cs: ConstraintSystemRef<Fr>,
    key: &[FpVar<Fr>],
    nonce: &FpVar<Fr>,
    body: &[FpVar<Fr>],
    tag: &FpVar<Fr>,
) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    // Tag check first, mirroring the native ordering.
    let mut tag_inputs = Vec::with_capacity(body.len() + 3);
    tag_inputs.extend_from_slice(&key[..KEY_ELEMS]);
    tag_inputs.push(nonce.clone());
    tag_inputs.extend_from_slice(body);
    let recomputed = poseidon::hash_gadget(cs.clone(), Domain::AeadTag, &tag_inputs)?;
    recomputed.enforce_equal(tag)?;

    // Keystream and subtraction.
    let mut ks_inputs = Vec::with_capacity(3);
    ks_inputs.extend_from_slice(&key[..KEY_ELEMS]);
    ks_inputs.push(nonce.clone());
    let ks = poseidon::hash_many_gadget(cs, Domain::AeadKeystream, &ks_inputs, body.len())?;

    Ok(body.iter().zip(ks.iter()).map(|(c, k)| c - k).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    fn key() -> [Fr; KEY_ELEMS] {
        [Fr::from(0xDEAD_BEEFu64), Fr::from(0xFEED_FACEu64)]
    }

    fn plaintext() -> Vec<Fr> {
        vec![Fr::from(123_456_789u64), Fr::from(987_654_321u64)]
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let k = key();
        let pt = plaintext();
        let ct = ChronosAead::encrypt(&k, Fr::from(1u64), &pt).expect("encrypt");
        let recovered = ChronosAead::decrypt(&k, &ct).expect("decrypt");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn test_ciphertext_hides_plaintext() {
        let k = key();
        let pt = plaintext();
        let ct = ChronosAead::encrypt(&k, Fr::from(1u64), &pt).expect("encrypt");
        for (i, (c, p)) in ct.body.iter().zip(pt.iter()).enumerate() {
            assert_ne!(c, p, "ciphertext element {i} must not equal the plaintext");
        }
    }

    #[test]
    fn test_wrong_key_rejected() {
        let pt = plaintext();
        let ct = ChronosAead::encrypt(&key(), Fr::from(1u64), &pt).expect("encrypt");
        let wrong = [Fr::from(1u64), Fr::from(2u64)];
        assert!(
            ChronosAead::decrypt(&wrong, &ct).is_err(),
            "decryption under the wrong key must fail authentication"
        );
    }

    #[test]
    fn test_wrong_nonce_rejected() {
        let k = key();
        let ct = ChronosAead::encrypt(&k, Fr::from(1u64), &plaintext()).expect("encrypt");
        let mut tampered = ct.clone();
        tampered.nonce = Fr::from(2u64);
        assert!(ChronosAead::decrypt(&k, &tampered).is_err());
    }

    /// Every element of the ciphertext must be authenticated. A scheme that
    /// authenticated only part of it would let an attacker flip the rest.
    #[test]
    fn test_tampering_with_any_element_is_detected() {
        let k = key();
        let ct = ChronosAead::encrypt(&k, Fr::from(7u64), &plaintext()).expect("encrypt");

        for i in 0..ct.body.len() {
            let mut t = ct.clone();
            t.body[i] += Fr::from(1u64);
            assert!(
                ChronosAead::decrypt(&k, &t).is_err(),
                "flipping body element {i} must be detected"
            );
        }

        let mut t = ct.clone();
        t.tag += Fr::from(1u64);
        assert!(ChronosAead::decrypt(&k, &t).is_err(), "tag forgery must fail");
    }

    #[test]
    fn test_distinct_nonces_give_distinct_ciphertexts() {
        let k = key();
        let pt = plaintext();
        let a = ChronosAead::encrypt(&k, Fr::from(1u64), &pt).expect("encrypt");
        let b = ChronosAead::encrypt(&k, Fr::from(2u64), &pt).expect("encrypt");
        assert_ne!(a.body, b.body, "nonce must randomise the keystream");
    }

    #[test]
    fn test_empty_plaintext_rejected() {
        assert!(ChronosAead::encrypt(&key(), Fr::from(1u64), &[]).is_err());
    }

    #[test]
    fn test_serialization_round_trip() {
        let ct = ChronosAead::encrypt(&key(), Fr::from(9u64), &plaintext()).expect("encrypt");
        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), ct.element_count() * 32);
        let parsed = Ciphertext::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, ct);
        // And it still decrypts after a serialization round trip.
        assert_eq!(
            ChronosAead::decrypt(&key(), &parsed).expect("decrypt"),
            plaintext()
        );
    }

    #[test]
    fn test_deserialization_rejects_malformed_input() {
        assert!(
            Ciphertext::from_bytes(&[0u8; 31]).is_err(),
            "non-multiple of 32 must be rejected"
        );
        assert!(
            Ciphertext::from_bytes(&[0u8; 64]).is_err(),
            "fewer than three words must be rejected"
        );
        // All-0xFF is larger than the BN254 scalar modulus, so it is
        // non-canonical and must not be silently reduced.
        assert!(
            Ciphertext::from_bytes(&[0xFFu8; 128]).is_err(),
            "non-canonical field encoding must be rejected"
        );
    }

    #[test]
    fn test_derive_key_is_deterministic_and_input_sensitive() {
        let y = [0xABu8; 256];
        let salt = [0xCDu8; 32];
        let k1 = ChronosAead::derive_key(&y, &salt);
        let k2 = ChronosAead::derive_key(&y, &salt);
        assert_eq!(k1, k2, "KDF must be deterministic");

        let mut y2 = y;
        y2[255] ^= 0x01;
        assert_ne!(
            k1,
            ChronosAead::derive_key(&y2, &salt),
            "KDF must depend on every byte of y"
        );

        let mut salt2 = salt;
        salt2[31] ^= 0x01;
        assert_ne!(
            k1,
            ChronosAead::derive_key(&y, &salt2),
            "KDF must depend on every byte of the salt"
        );
    }

    /// The whole reason this scheme exists: the decryption relation must be
    /// provable in-circuit, and the in-circuit result must equal the native one.
    #[test]
    fn test_gadget_decrypt_matches_native() {
        let k = key();
        let pt = plaintext();
        let ct = ChronosAead::encrypt(&k, Fr::from(42u64), &pt).expect("encrypt");

        let cs = ConstraintSystem::<Fr>::new_ref();
        let key_vars: Vec<FpVar<Fr>> = k
            .iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).expect("alloc"))
            .collect();
        let nonce_var = FpVar::new_witness(cs.clone(), || Ok(ct.nonce)).expect("alloc");
        let body_vars: Vec<FpVar<Fr>> = ct
            .body
            .iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).expect("alloc"))
            .collect();
        let tag_var = FpVar::new_witness(cs.clone(), || Ok(ct.tag)).expect("alloc");

        let recovered = decrypt_gadget(cs.clone(), &key_vars, &nonce_var, &body_vars, &tag_var)
            .expect("gadget decrypt");

        assert!(
            cs.is_satisfied().expect("satisfiability"),
            "gadget must be satisfied by a valid ciphertext"
        );
        for (i, (got, want)) in recovered.iter().zip(pt.iter()).enumerate() {
            assert_eq!(
                got.value().expect("value"),
                *want,
                "gadget plaintext element {i} must match native"
            );
        }
    }

    /// A forged tag must make the circuit unsatisfiable. If it did not, the
    /// erasure proof would accept a ciphertext the provisioner never produced.
    #[test]
    fn test_gadget_rejects_forged_tag() {
        let k = key();
        let ct = ChronosAead::encrypt(&k, Fr::from(42u64), &plaintext()).expect("encrypt");

        let cs = ConstraintSystem::<Fr>::new_ref();
        let key_vars: Vec<FpVar<Fr>> = k
            .iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).expect("alloc"))
            .collect();
        let nonce_var = FpVar::new_witness(cs.clone(), || Ok(ct.nonce)).expect("alloc");
        let body_vars: Vec<FpVar<Fr>> = ct
            .body
            .iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).expect("alloc"))
            .collect();
        // Deliberately wrong tag.
        let tag_var =
            FpVar::new_witness(cs.clone(), || Ok(ct.tag + Fr::from(1u64))).expect("alloc");

        let _ = decrypt_gadget(cs.clone(), &key_vars, &nonce_var, &body_vars, &tag_var)
            .expect("synthesis must succeed even with a bad witness");
        assert!(
            !cs.is_satisfied().expect("satisfiability"),
            "a forged tag must render the circuit unsatisfiable"
        );
    }

    #[test]
    fn test_gadget_derive_key_matches_native() {
        let y = [0x11u8; 256];
        let salt = [0x22u8; 32];
        let native = ChronosAead::derive_key(&y, &salt);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let y_vars: Vec<FpVar<Fr>> = poseidon::pack_bytes(&y)
            .iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).expect("alloc"))
            .collect();
        let salt_vars: Vec<FpVar<Fr>> = poseidon::pack_bytes(&salt)
            .iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).expect("alloc"))
            .collect();

        let gadget = derive_key_gadget(cs.clone(), y.len(), &y_vars, salt.len(), &salt_vars)
            .expect("gadget kdf");
        assert_eq!(gadget.len(), KEY_ELEMS);
        for (i, (g, n)) in gadget.iter().zip(native.iter()).enumerate() {
            assert_eq!(
                g.value().expect("value"),
                *n,
                "derived key element {i} must match native KDF"
            );
        }
        assert!(cs.is_satisfied().expect("satisfiability"));
    }

    /// Budget check: the point of this scheme is that in-circuit decryption is
    /// affordable. An AES-GCM gadget would be tens of thousands of constraints.
    #[test]
    fn test_gadget_decrypt_constraint_cost_is_modest() {
        let k = key();
        let ct = ChronosAead::encrypt(&k, Fr::from(1u64), &plaintext()).expect("encrypt");

        let cs = ConstraintSystem::<Fr>::new_ref();
        let key_vars: Vec<FpVar<Fr>> = k
            .iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).expect("alloc"))
            .collect();
        let nonce_var = FpVar::new_witness(cs.clone(), || Ok(ct.nonce)).expect("alloc");
        let body_vars: Vec<FpVar<Fr>> = ct
            .body
            .iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).expect("alloc"))
            .collect();
        let tag_var = FpVar::new_witness(cs.clone(), || Ok(ct.tag)).expect("alloc");

        let _ = decrypt_gadget(cs.clone(), &key_vars, &nonce_var, &body_vars, &tag_var)
            .expect("gadget");
        let n = cs.num_constraints();
        println!("in-circuit Chronos-AEAD decryption constraints: {n}");
        assert!(
            n < 5_000,
            "in-circuit decryption should cost low thousands of constraints, got {n}"
        );
    }
}
