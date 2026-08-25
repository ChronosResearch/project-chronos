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
///
/// # Cost profile
/// `evaluate` performs `2T` modular squarings: `T` for the output `y` and `T`
/// for the proof `π`, which is computed by the standard long-division recurrence
/// (see [`WesolowskiVdf::prove`]) rather than by materialising the `T`-bit
/// exponent `q`.  `verify` is `O(log T)` — two modular exponentiations with
/// 64-bit exponents plus one `2^T mod ℓ` computation.
use chronos_core::{ChronosError, ChronosResult, VdfEngine, VdfProof};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

/// Miller-Rabin witness set that is deterministic for all `n < 3.3 × 10^24`,
/// which covers the entire `u64` range.
const MILLER_RABIN_BASES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

/// Wesolowski VDF over an RSA group (pure-Rust backend).
pub struct WesolowskiVdf;

impl WesolowskiVdf {
    /// Derive the Fiat-Shamir prime challenge `ℓ` from `(g, y, T)`.
    ///
    /// `ℓ = next_prime(SHA-256(g || y || T)[0..8] as u64)`
    ///
    /// The derivation is byte-identical to the previous implementation; only the
    /// primality test underneath it changed (trial division → Miller-Rabin).
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
            if Self::is_prime(candidate) {
                return candidate;
            }
            // `saturating_add` keeps the scan inside `u64`; a seed within 2 of
            // `u64::MAX` would otherwise wrap to an already-rejected candidate
            // and spin forever.
            let next = candidate.saturating_add(2);
            if next == candidate {
                // Saturated at u64::MAX without finding a prime — fall back to a
                // fixed large prime so the derivation always terminates.
                return 0xFFFF_FFFF_FFFF_FFC5; // largest prime < 2^64
            }
            candidate = next;
        }
    }

    /// `(a · b) mod m`, computed through `u128` so the product cannot overflow.
    #[inline(always)]
    fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
        ((u128::from(a) * u128::from(b)) % u128::from(m)) as u64
    }

    /// `base^exp mod m` by square-and-multiply over `u64`.
    fn pow_mod_u64(mut base: u64, mut exp: u64, m: u64) -> u64 {
        if m <= 1 {
            return 0;
        }
        let mut acc: u64 = 1;
        base %= m;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = Self::mul_mod(acc, base, m);
            }
            base = Self::mul_mod(base, base, m);
            exp >>= 1;
        }
        acc
    }

    /// Deterministic Miller-Rabin primality test for `u64`.
    ///
    /// Replaces the previous `is_prime_trial`, which performed trial division up
    /// to `√n`.  For a hash-derived 64-bit candidate that was on the order of
    /// `2^32` iterations *per candidate*, with roughly 22 candidates scanned on
    /// average before a prime was found — one to two billion modulo operations,
    /// taking seconds.  Because that cost is a function of the seed and not of
    /// `T`, it completely dominated and obscured the sequential squaring work
    /// that the VDF's security actually rests on.
    ///
    /// The old loop condition `while i * i <= n` also overflowed `u64` once `i`
    /// passed `2^32`: in release builds the product wrapped, so the scan ran
    /// past `√n` and could misclassify; in builds with overflow checks enabled
    /// it panicked outright.
    fn is_prime(n: u64) -> bool {
        if n < 2 {
            return false;
        }
        for p in MILLER_RABIN_BASES {
            if n % p == 0 {
                return n == p;
            }
        }

        // n - 1 = d · 2^s with d odd.
        let mut d = n - 1;
        let mut s = 0u32;
        while d % 2 == 0 {
            d /= 2;
            s += 1;
        }

        'witness: for a in MILLER_RABIN_BASES {
            let mut x = Self::pow_mod_u64(a, d, n);
            if x == 1 || x == n - 1 {
                continue;
            }
            for _ in 1..s {
                x = Self::mul_mod(x, x, n);
                if x == n - 1 {
                    continue 'witness;
                }
            }
            return false;
        }
        true
    }

    /// Compute `2^T mod ℓ` in `O(log T)` without materialising `2^T`.
    fn two_pow_t_mod(t: u64, ell: u64) -> u64 {
        Self::pow_mod_u64(2, t, ell)
    }

    /// Compute the Wesolowski proof `π = g^floor(2^T / ℓ) mod N` together with
    /// `r = 2^T mod ℓ`, using the standard long-division recurrence.
    ///
    /// Maintains the invariant, after `i` iterations:
    /// ```text
    /// π = g^floor(2^i / ℓ) mod N        r = 2^i mod ℓ
    /// ```
    /// Stepping `i → i + 1` uses `2^(i+1) = (2·q_i + b)·ℓ + r_(i+1)` where
    /// `b = floor(2·r_i / ℓ) ∈ {0, 1}`, giving `π ← π² · g^b`.
    ///
    /// This replaces the previous approach, which built the full `T`-bit integer
    /// `2^T` with `BigUint::one() << t` and then divided.  That allocation grows
    /// linearly in `T`: 125 KB at `T = 10^6`, and 128 MB at `T = 2^30`, which
    /// made realistic mission lengths unreachable.  The recurrence below runs in
    /// constant memory.
    fn prove(g: &BigUint, t: u64, ell: u64, n: &BigUint) -> (BigUint, u64) {
        let g_mod = g % n;
        let mut pi = BigUint::one() % n;
        let mut r: u64 = 1 % ell;

        for _ in 0..t {
            let two_r = u128::from(r) * 2;
            let b = (two_r / u128::from(ell)) as u64;
            r = (two_r % u128::from(ell)) as u64;

            pi = (&pi * &pi) % n;
            if b == 1 {
                pi = (pi * &g_mod) % n;
            }
        }

        (pi, r)
    }

    /// Modular exponentiation: `base^exp mod modulus` using square-and-multiply.
    fn modpow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
        base.modpow(exp, modulus)
    }

    /// Evaluate with cooperative cancellation.
    ///
    /// # Why this exists
    ///
    /// [`VdfEngine::evaluate`] runs `2T` sequential squarings with no way to stop
    /// it. At the configured default of `t_vdf_steps = 1_000_000` that is a long
    /// uninterruptible block, and the consequence was a real hole in the
    /// time-bound existence claim: the watchdog would flip the state machine to
    /// `Erased` on deadline, but the spawned task kept squaring with the secret
    /// key still live in memory. The agent reported itself erased while holding
    /// the key.
    ///
    /// `abort` is polled every [`ABORT_POLL_INTERVAL`] squarings — often enough
    /// that cancellation is prompt, rarely enough that the atomic load does not
    /// measurably slow the inner loop. On cancellation this returns
    /// [`ChronosError::Vdf`] and the caller must treat the mission as failed and
    /// erase, rather than retrying.
    ///
    /// # Errors
    /// Returns [`ChronosError::Vdf`] if the modulus is degenerate or `abort` is
    /// set before completion.
    pub fn evaluate_interruptible(
        g: &BigUint,
        t: u64,
        n: &BigUint,
        abort: &std::sync::atomic::AtomicBool,
    ) -> ChronosResult<(BigUint, VdfProof)> {
        use std::sync::atomic::Ordering;

        if n.is_zero() || n.is_one() {
            return Err(ChronosError::Vdf("Modulus N must be > 1".into()));
        }
        if t == 0 {
            return Ok((g.clone(), VdfProof { proof: BigUint::one() }));
        }

        let mut y = g % n;
        for i in 0..t {
            if i % ABORT_POLL_INTERVAL == 0 && abort.load(Ordering::Relaxed) {
                return Err(ChronosError::Vdf(format!(
                    "VDF aborted after {i} of {t} squarings — watchdog deadline reached"
                )));
            }
            y = (&y * &y) % n;
        }

        let ell = Self::fiat_shamir_prime(g, &y, t);

        // The proof is another T squarings, so it needs the same cancellation
        // check. Aborting here still means the mission failed: `y` alone is not
        // publishable without the proof that it was honestly derived.
        let g_mod = g % n;
        let mut pi = BigUint::one() % n;
        let mut r: u64 = 1 % ell;
        for i in 0..t {
            if i % ABORT_POLL_INTERVAL == 0 && abort.load(Ordering::Relaxed) {
                return Err(ChronosError::Vdf(format!(
                    "VDF proof aborted after {i} of {t} squarings — watchdog deadline reached"
                )));
            }
            let two_r = u128::from(r) * 2;
            let b = (two_r / u128::from(ell)) as u64;
            r = (two_r % u128::from(ell)) as u64;
            pi = (&pi * &pi) % n;
            if b == 1 {
                pi = (pi * &g_mod) % n;
            }
        }

        Ok((y, VdfProof { proof: pi }))
    }
}

/// Squarings between cancellation checks in [`WesolowskiVdf::evaluate_interruptible`].
///
/// A 2048-bit modular squaring is on the order of a microsecond, so 4096 of them
/// bounds cancellation latency at a few milliseconds while amortising the atomic
/// load to nothing.
const ABORT_POLL_INTERVAL: u64 = 4096;

impl VdfEngine for WesolowskiVdf {
    /// Compute `y = g^(2^T) mod N` and produce a Wesolowski proof `π = g^q mod N`.
    ///
    /// `T` is honoured exactly as given in every build profile.  Earlier revisions
    /// clamped `T` to 10 under `#[cfg(debug_assertions)]`, which silently reduced
    /// the sequential work to a constant in any non-release build — including
    /// under `cargo test` — and, because [`VdfEngine::verify`] applied the same
    /// clamp, produced proofs that verified despite doing almost no work.
    fn evaluate(&self, g: &BigUint, t: u64, n: &BigUint) -> ChronosResult<(BigUint, VdfProof)> {
        if n.is_zero() || n.is_one() {
            return Err(ChronosError::Vdf("Modulus N must be > 1".into()));
        }

        if t == 0 {
            return Ok((g.clone(), VdfProof { proof: BigUint::one() }));
        }

        // Sequential squarings: y = g^(2^T) mod N
        let mut y = g % n;
        for _ in 0..t {
            y = (&y * &y) % n;
        }

        // Wesolowski proof: π = g^floor(2^T / ℓ) mod N
        let ell = Self::fiat_shamir_prime(g, &y, t);
        let (pi, _r) = Self::prove(g, t, ell, n);

        Ok((y, VdfProof { proof: pi }))
    }

    /// Verify: `π^ℓ · g^r ≡ y (mod N)`
    ///
    /// Runs in `O(log T)`; no sequential work is repeated.
    fn verify(&self, g: &BigUint, y: &BigUint, proof: &VdfProof, t: u64, n: &BigUint) -> bool {
        if n.is_zero() || n.is_one() {
            return false;
        }

        if t == 0 {
            return y == g;
        }

        let ell = Self::fiat_shamir_prime(g, y, t);
        let r = Self::two_pow_t_mod(t, ell);

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
    use chronos_core::mpc::MpcCertificate;

    /// The RSA-2048 prototype modulus, for tests that need a group where `g`
    /// has no small order.
    fn rsa_modulus() -> BigUint {
        MpcCertificate::load("/nonexistent")
            .expect("prototype modulus must load")
            .n
    }

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
        assert!(WesolowskiVdf::is_prime(ell), "Fiat-Shamir output must be prime");
    }

    // ── Regression tests for the debug-mode T clamp ───────────────────────────

    /// Distinct `T` must produce distinct output in **every** build profile.
    ///
    /// Under the old `effective_t = t.min(10)` clamp this test failed in debug
    /// builds: both evaluations collapsed to 10 squarings and returned the same
    /// `y`.  Because `cargo test` defaults to a debug profile, no test in the
    /// suite ever exercised a realistic `T`.
    #[test]
    fn test_distinct_t_yields_distinct_output() -> ChronosResult<()> {
        let vdf = WesolowskiVdf;
        let g = BigUint::from(2u32);
        let n = rsa_modulus();

        let (y_100, _) = vdf.evaluate(&g, 100, &n)?;
        let (y_200, _) = vdf.evaluate(&g, 200, &n)?;
        let (y_201, _) = vdf.evaluate(&g, 201, &n)?;

        assert_ne!(y_100, y_200, "T=100 and T=200 must not collide");
        assert_ne!(y_200, y_201, "T=200 and T=201 must not collide");
        Ok(())
    }

    /// A proof produced at one `T` must not verify at another.
    ///
    /// This is the property the clamp destroyed: with `T` pinned to 10, a proof
    /// generated for `T = 100` verified against a claimed `T = 200`, so the
    /// time-bound existence guarantee was unenforced.
    #[test]
    fn test_proof_bound_to_declared_t() -> ChronosResult<()> {
        let vdf = WesolowskiVdf;
        let g = BigUint::from(2u32);
        let n = rsa_modulus();

        let (y, proof) = vdf.evaluate(&g, 100, &n)?;
        assert!(vdf.verify(&g, &y, &proof, 100, &n), "proof must verify at its own T");
        assert!(
            !vdf.verify(&g, &y, &proof, 200, &n),
            "proof must not verify under a larger claimed T"
        );
        assert!(
            !vdf.verify(&g, &y, &proof, 50, &n),
            "proof must not verify under a smaller claimed T"
        );
        Ok(())
    }

    /// `prove` must agree with the naive `floor(2^T / ℓ)` exponentiation it
    /// replaced, so the recurrence is not silently computing something else.
    #[test]
    fn test_prove_matches_naive_exponent() -> ChronosResult<()> {
        let g = BigUint::from(2u32);
        let n = rsa_modulus();

        for t in [1u64, 2, 7, 32, 100, 257] {
            let ell = WesolowskiVdf::fiat_shamir_prime(&g, &BigUint::from(3u32), t);
            let (pi, r) = WesolowskiVdf::prove(&g, t, ell, &n);

            // Naive reference: materialise 2^T, divide, exponentiate.
            let two_t = BigUint::one() << t as usize;
            let ell_big = BigUint::from(ell);
            let q_ref = &two_t / &ell_big;
            let r_ref: u64 = (&two_t % &ell_big).try_into().expect("r < ell fits u64");
            let pi_ref = g.modpow(&q_ref, &n);

            assert_eq!(pi, pi_ref, "π mismatch at T={t}");
            assert_eq!(r, r_ref, "r mismatch at T={t}");
        }
        Ok(())
    }

    /// `two_pow_t_mod` must agree with `2^T mod ℓ` computed via `BigUint`.
    #[test]
    fn test_two_pow_t_mod_matches_bigint() {
        for t in [0u64, 1, 5, 64, 1_000, 4_096] {
            for ell in [3u64, 41, 65_537, 1_000_003, 0xFFFF_FFFF_FFFF_FFC5] {
                let got = WesolowskiVdf::two_pow_t_mod(t, ell);
                let want: u64 = ((BigUint::one() << t as usize) % BigUint::from(ell))
                    .try_into()
                    .expect("2^T mod ell always fits u64");
                assert_eq!(got, want, "2^{t} mod {ell}");
            }
        }
    }

    // ── Cancellation ──────────────────────────────────────────────────────────

    /// With `abort` clear, the interruptible path must agree exactly with
    /// `evaluate`. If it diverged, the watchdog-safe path would produce proofs
    /// that fail verification.
    #[test]
    fn test_interruptible_matches_evaluate() -> ChronosResult<()> {
        use std::sync::atomic::AtomicBool;

        let vdf = WesolowskiVdf;
        let g = BigUint::from(2u32);
        let n = rsa_modulus();
        let abort = AtomicBool::new(false);

        for t in [1u64, 2, 37, 500] {
            let (y_ref, pi_ref) = vdf.evaluate(&g, t, &n)?;
            let (y, pi) = WesolowskiVdf::evaluate_interruptible(&g, t, &n, &abort)?;
            assert_eq!(y, y_ref, "output mismatch at T={t}");
            assert_eq!(pi.proof, pi_ref.proof, "proof mismatch at T={t}");
            assert!(vdf.verify(&g, &y, &pi, t, &n), "interruptible proof must verify at T={t}");
        }
        Ok(())
    }

    /// The hole this closes: the watchdog must be able to stop the squaring loop.
    /// Previously it could not, so the agent reported `Erased` while still
    /// holding the key and squaring.
    #[test]
    fn test_abort_stops_evaluation() {
        use std::sync::atomic::AtomicBool;

        let g = BigUint::from(2u32);
        let n = rsa_modulus();
        let abort = AtomicBool::new(true); // already signalled

        let err = WesolowskiVdf::evaluate_interruptible(&g, 10_000_000, &n, &abort)
            .expect_err("a pre-signalled abort must stop evaluation");
        assert!(
            format!("{err}").contains("aborted"),
            "error must name the abort, got: {err}"
        );
    }

    /// Cancellation must be prompt: a huge `T` with abort set must return without
    /// doing the work. If the poll interval were ignored this would hang.
    #[test]
    fn test_abort_is_prompt() {
        use std::sync::atomic::AtomicBool;
        use std::time::Instant;

        let g = BigUint::from(2u32);
        let n = rsa_modulus();
        let abort = AtomicBool::new(true);

        let start = Instant::now();
        let _ = WesolowskiVdf::evaluate_interruptible(&g, u64::MAX, &n, &abort);
        assert!(
            start.elapsed().as_secs() < 5,
            "abort must be observed within the first poll interval"
        );
    }

    /// `two_pow_t_mod` must stay `O(log T)` — large `T` must return promptly.
    #[test]
    fn test_two_pow_t_mod_handles_huge_t() {
        for t in [1_000_000u64, 1u64 << 40, u64::MAX] {
            let r = WesolowskiVdf::two_pow_t_mod(t, 0xFFFF_FFFF_FFFF_FFC5);
            assert!(r < 0xFFFF_FFFF_FFFF_FFC5);
        }
    }

    // ── Miller-Rabin correctness ──────────────────────────────────────────────

    #[test]
    fn test_is_prime_known_values() {
        for p in [2u64, 3, 5, 7, 41, 97, 65_537, 2_147_483_647, 0xFFFF_FFFF_FFFF_FFC5] {
            assert!(WesolowskiVdf::is_prime(p), "{p} is prime");
        }
        for c in [0u64, 1, 4, 9, 25, 91, 561, 1_105, 2_047, 3_215_031_751, u64::MAX] {
            assert!(!WesolowskiVdf::is_prime(c), "{c} is composite");
        }
    }

    /// Carmichael numbers and strong pseudoprimes to small bases — these are the
    /// inputs a naive or under-witnessed primality test gets wrong.
    #[test]
    fn test_is_prime_rejects_pseudoprimes() {
        for c in [
            561u64, 1_105, 1_729, 2_465, 2_821, 6_601, 8_911, // Carmichael
            2_047, 3_277, 4_033, 4_681, 8_321,                // base-2 strong pseudoprimes
            3_215_031_751,                                     // spsp to 2,3,5,7
            3_825_123_056_546_413_051,                         // spsp to first 9 primes
        ] {
            assert!(!WesolowskiVdf::is_prime(c), "{c} must be rejected");
        }
    }

    /// `is_prime` must not overflow or panic near the top of the `u64` range.
    /// The previous `while i * i <= n` loop overflowed once `i` passed `2^32`.
    #[test]
    fn test_is_prime_no_overflow_at_u64_max() {
        for n in [u64::MAX, u64::MAX - 1, u64::MAX - 2, 0xFFFF_FFFF_FFFF_FFC5] {
            let _ = WesolowskiVdf::is_prime(n);
        }
    }

    // ── Timing ────────────────────────────────────────────────────────────────

    /// Wall time must grow with `T`.
    ///
    /// The v3.0 published benchmark reported T=1,000 at 12,092 ms and
    /// T=100,000 at 9,828 ms — 100× the sequential work finishing faster —
    /// because the measurement was dominated by trial-division prime search,
    /// whose cost is independent of `T`.  This test fails if evaluation ever
    /// becomes constant-time in `T` again.
    ///
    /// Timing-sensitive, so it is not part of the default run:
    /// `cargo test --release -p chronos-vdf -- --ignored`
    #[test]
    #[ignore = "timing-sensitive; run with cargo test --release -- --ignored"]
    fn test_wall_time_scales_with_t() -> ChronosResult<()> {
        use std::time::Instant;

        let vdf = WesolowskiVdf;
        let g = BigUint::from(2u32);
        let n = rsa_modulus();

        let base_t = 20_000u64;
        let factor = 8u64;

        let t0 = Instant::now();
        let _ = vdf.evaluate(&g, base_t, &n)?;
        let small = t0.elapsed().as_secs_f64();

        let t1 = Instant::now();
        let _ = vdf.evaluate(&g, base_t * factor, &n)?;
        let large = t1.elapsed().as_secs_f64();

        let ratio = large / small;
        assert!(
            ratio >= 3.0,
            "wall time must scale with T: {base_t} took {small:.3}s, \
             {} took {large:.3}s (ratio {ratio:.2}, expected >= 3.0)",
            base_t * factor
        );
        Ok(())
    }
}
