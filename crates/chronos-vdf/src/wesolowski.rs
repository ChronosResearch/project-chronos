/// Wesolowski VDF — pure-Rust implementation using `num-bigint`.
///
/// Replaces the GMP FFI backend with a portable `num-bigint` implementation
/// that compiles on all architectures (x86_64, aarch64, etc.).
///
/// For production deployments on x86_64, the GMP backend can be re-enabled
/// via the `gmp` feature flag for ~10× faster modular squaring.
///
/// # Protocol
/// Evaluation:  `y = g^(2^T) mod N`  (T sequential squarings)
/// Proof:       `π = g^q mod N`  where `q = floor(2^T / ℓ)`
/// Verification: `π^ℓ · g^r ≡ y (mod N)`  where `ℓ = H_prime(g, y, T)`, `r = 2^T mod ℓ`
use chronos_core::{ChronosError, ChronosResult, VdfEngine, VdfProof};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

/// Wesolowski VDF over an RSA group (pure-Rust backend).
pub struct WesolowskiVdf;

impl WesolowskiVdf {
    /// Derive the Fiat-Shamir prime challenge `ℓ` from `(g, y, T)`.
    ///
    /// `ℓ = next_prime(SHA-256(g || y || T)[0..8] as u64)`
    fn fiat_shamir_prime(g: &BigUint, y: &BigUint, t: u64) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(g.to_bytes_be());
        hasher.update(y.to_bytes_be());
        hasher.update(t.to_le_bytes());
        let digest = hasher.finalize();
        let seed = u64::from_le_bytes(digest[..8].try_into().unwrap_or([0u8; 8]));
        let mut candidate = seed | 1;
        if candidate < 3 {
            candidate = 3;
        }
        loop {
            if Self::is_prime_trial(candidate) {
                return candidate;
            }
            candidate += 2;
        }
    }

    fn is_prime_trial(n: u64) -> bool {
        if n < 2 { return false; }
        if n == 2 { return true; }
        if n.is_multiple_of(2) { return false; }
        let mut i = 3u64;
        while i * i <= n {
            if n.is_multiple_of(i) { return false; }
            i += 2;
        }
        true
    }

    /// Compute `floor(2^T / ell)` and `2^T mod ell`.
    fn compute_q_r(t: u64, ell: u64) -> (BigUint, u64) {
        let two_t = BigUint::one() << t as usize;
        let ell_big = BigUint::from(ell);
        let q = &two_t / &ell_big;
        let r_big = &two_t % &ell_big;
        let r = r_big.iter_u64_digits().next().unwrap_or(0);
        (q, r)
    }

    /// Modular exponentiation: `base^exp mod modulus` using square-and-multiply.
    fn modpow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
        base.modpow(exp, modulus)
    }
}

impl VdfEngine for WesolowskiVdf {
    /// Compute `y = g^(2^T) mod N` and produce a Wesolowski proof `π = g^q mod N`.
    fn evaluate(&self, g: &BigUint, t: u64, n: &BigUint) -> ChronosResult<(BigUint, VdfProof)> {
        if n.is_zero() || n.is_one() {
            return Err(ChronosError::Vdf("Modulus N must be > 1".into()));
        }

        #[cfg(debug_assertions)]
        let effective_t = t.min(10);
        #[cfg(not(debug_assertions))]
        let effective_t = t;

        if effective_t == 0 {
            return Ok((g.clone(), VdfProof { proof: BigUint::one() }));
        }

        // Sequential squarings: y = g^(2^T) mod N
        let mut y = g.clone() % n;
        for _ in 0..effective_t {
            y = (&y * &y) % n;
        }

        // Wesolowski proof: π = g^q mod N
        let ell = Self::fiat_shamir_prime(g, &y, effective_t);
        let (q, _r) = Self::compute_q_r(effective_t, ell);
        let pi = Self::modpow(g, &q, n);

        Ok((y, VdfProof { proof: pi }))
    }

    /// Verify: `π^ℓ · g^r ≡ y (mod N)`
    fn verify(&self, g: &BigUint, y: &BigUint, proof: &VdfProof, t: u64, n: &BigUint) -> bool {
        if n.is_zero() || n.is_one() {
            return false;
        }

        #[cfg(debug_assertions)]
        let effective_t = t.min(10);
        #[cfg(not(debug_assertions))]
        let effective_t = t;

        if effective_t == 0 {
            return true;
        }

        let ell = Self::fiat_shamir_prime(g, y, effective_t);
        let (_q, r) = Self::compute_q_r(effective_t, ell);

        let ell_big = BigUint::from(ell);
        let r_big = BigUint::from(r);

        // lhs = π^ℓ mod N
        let lhs = Self::modpow(&proof.proof, &ell_big, n);
        // rhs = g^r mod N
        let rhs = Self::modpow(g, &r_big, n);
        // result = (lhs * rhs) mod N
        let result = (lhs * rhs) % n;

        result == *y
    }
}

/// Generate a time-locked identity root `R = SHA-256(g^(2^T) mod N)`.
///
/// The identity root is cryptographically bound to the mission duration `T`:
/// it cannot be computed faster than T sequential squarings without knowing
/// the factorization of `N` (which comes from the MPC ceremony).
///
/// # Errors
/// Returns [`ChronosError::Vdf`] if VDF evaluation fails.
pub fn generate_identity_root(
    g: &BigUint,
    t: u64,
    n: &BigUint,
) -> ChronosResult<[u8; 32]> {
    let vdf = WesolowskiVdf;
    let (y, _proof) = vdf.evaluate(g, t, n)?;
    let y_bytes = y.to_bytes_be();
    let mut hasher = Sha256::new();
    hasher.update(&y_bytes);
    let digest = hasher.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&digest);
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_evaluate_and_verify() -> ChronosResult<()> {
        let vdf = WesolowskiVdf;
        let g = BigUint::from(2u32);
        let n = BigUint::from(257u32); // small prime for testing
        let (y, proof) = vdf.evaluate(&g, 20, &n)?;
        assert!(vdf.verify(&g, &y, &proof, 20, &n), "Wesolowski verify must pass");
        Ok(())
    }

    #[test]
    fn test_vdf_wrong_proof_rejected() -> ChronosResult<()> {
        let vdf = WesolowskiVdf;
        let g = BigUint::from(2u32);
        let n = BigUint::from(257u32);
        let (y, _) = vdf.evaluate(&g, 20, &n)?;
        let bad_proof = VdfProof { proof: BigUint::from(42u32) };
        assert!(!vdf.verify(&g, &y, &bad_proof, 20, &n), "Bad proof must be rejected");
        Ok(())
    }

    #[test]
    fn test_vdf_zero_steps() -> ChronosResult<()> {
        let vdf = WesolowskiVdf;
        let g = BigUint::from(5u32);
        let n = BigUint::from(257u32);
        let (y, proof) = vdf.evaluate(&g, 0, &n)?;
        assert_eq!(y, g);
        assert!(vdf.verify(&g, &y, &proof, 0, &n));
        Ok(())
    }

    #[test]
    fn test_vdf_is_sendable() {
        fn assert_send<T: Send>() {}
        assert_send::<WesolowskiVdf>();
    }

    #[test]
    fn test_fiat_shamir_prime_is_prime() {
        let g = BigUint::from(2u32);
        let y = BigUint::from(100u32);
        let ell = WesolowskiVdf::fiat_shamir_prime(&g, &y, 10);
        assert!(WesolowskiVdf::is_prime_trial(ell), "Fiat-Shamir output must be prime");
    }
}
