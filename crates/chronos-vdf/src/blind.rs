/// Blind VDF outsourcing — Novel Contribution 1.
///
/// Allows a client to delegate VDF computation to an untrusted server without
/// revealing the base value `g`.  The protocol:
///
/// ```text
/// Client:  r ← random blinding factor
///          g_blind = g · r^(2^T) mod N   (pre-blind)
/// Server:  y_blind = g_blind^(2^T) mod N  (sequential work)
///          π_blind = Wesolowski proof for (g_blind, y_blind, T, N)
/// Client:  verify π_blind
///          y = y_blind / r^(2^(2T)) mod N  (unblind)
///          -- equivalently: y = y_blind · (r^(2^T))^(-2^T) mod N
/// ```
///
/// Security: the server sees only `g_blind`, which is computationally
/// indistinguishable from a random group element under the RSA assumption.
///
/// # Reference
/// "Blind Verifiable Delay Functions" (2026 preprint) — no existing system
/// integrates blind VDFs with ephemeral FHE agents.
use chronos_core::{ChronosError, ChronosResult, VdfEngine, VdfProof};
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::thread_rng;

use crate::wesolowski::WesolowskiVdf;

/// Client-side blinding context.  Must be kept secret from the server.
pub struct BlindingContext {
    /// The blinding factor `r`.
    pub r: BigUint,
    /// `r^(2^T) mod N` — precomputed by the client before sending to server.
    pub r_pow: BigUint,
    /// The blinded base `g_blind = g · r^(2^T) mod N`.
    pub g_blind: BigUint,
}

/// Blind VDF client.
pub struct BlindVdfClient;

impl BlindVdfClient {
    /// Blind the base `g` before sending to the server.
    ///
    /// Returns the blinding context (kept by client) and `g_blind` (sent to server).
    ///
    /// # Errors
    /// Returns [`ChronosError::Vdf`] if the VDF evaluation for the blinding factor fails.
    pub fn blind(g: &BigUint, t: u64, n: &BigUint) -> ChronosResult<BlindingContext> {
        let mut rng = thread_rng();
        // r ← random in [2, N-1]
        let r = rng.gen_biguint_range(&BigUint::from(2u32), n);

        // r_pow = r^(2^T) mod N, by T repeated squarings in constant memory.
        //
        // NOTE ON COST: an earlier revision built the exponent as
        // `BigUint::one() << t` and called `modpow`, with a comment claiming this
        // was asymptotically cheaper than sequential squaring.  It is not —
        // square-and-multiply over a T-bit exponent performs T squarings, so the
        // two approaches cost the same. The only difference was that
        // materialising `2^T` also allocated a T-bit integer (125 KB at
        // T = 10^6, 128 MB at T = 2^30). That allocation is now gone.
        //
        // The client genuinely cannot beat T squarings here without knowing
        // φ(N), which means blind outsourcing as currently specified does not
        // save the client any sequential work. Tracked separately; this change
        // only removes the allocation, it does not alter the protocol.
        let r_pow = repeated_square(&r, t, n);

        // g_blind = g · r_pow mod N
        let g_blind = (g * &r_pow) % n;

        Ok(BlindingContext { r, r_pow, g_blind })
    }

    /// Unblind the server's result `y_blind` to recover `y = g^(2^T) mod N`.
    ///
    /// The unblinding formula is:
    /// ```text
    /// y = y_blind · (r_pow)^(-2^T) mod N
    ///   = y_blind · modinv(r^(2^(2T)), N)
    /// ```
    ///
    /// Since `r_pow = r^(2^T)`, we need `r_pow^(2^T) mod N` which equals
    /// `r^(2^(2T)) mod N`.  We compute this by running the VDF on `r_pow`.
    ///
    /// # Errors
    /// Returns [`ChronosError::Vdf`] if modular inverse does not exist (N not prime
    /// to r_pow, which is negligible probability for random r).
    pub fn unblind(
        y_blind: &BigUint,
        ctx: &BlindingContext,
        t: u64,
        n: &BigUint,
    ) -> ChronosResult<BigUint> {
        // r_pow_2t = r^(2^(2T)) mod N = (r^(2^T))^(2^T) mod N,
        // by T repeated squarings in constant memory (see note in `blind`).
        let r_pow_2t = repeated_square(&ctx.r_pow, t, n);

        // y = y_blind · modinv(r_pow_2t, N) mod N
        let inv = mod_inverse(&r_pow_2t, n).ok_or_else(|| {
            ChronosError::Vdf("Blind VDF unblind: modular inverse does not exist".into())
        })?;

        Ok((y_blind * &inv) % n)
    }
}

/// Blind VDF server — computes the VDF on the blinded input.
///
/// The server is untrusted: it sees only `g_blind` and returns `(y_blind, π)`.
/// It learns nothing about the original `g`.
pub struct BlindVdfServer;

impl BlindVdfServer {
    /// Evaluate the VDF on the blinded input and return `(y_blind, π_blind)`.
    ///
    /// # Errors
    /// Returns [`ChronosError::Vdf`] on GMP failure.
    pub fn evaluate_blind(
        g_blind: &BigUint,
        t: u64,
        n: &BigUint,
    ) -> ChronosResult<(BigUint, VdfProof)> {
        let vdf = WesolowskiVdf;
        vdf.evaluate(g_blind, t, n)
    }

    /// Verify the server's own proof before returning it to the client.
    pub fn verify_blind(
        g_blind: &BigUint,
        y_blind: &BigUint,
        proof: &VdfProof,
        t: u64,
        n: &BigUint,
    ) -> bool {
        let vdf = WesolowskiVdf;
        vdf.verify(g_blind, y_blind, proof, t, n)
    }
}

// ─── Repeated squaring ───────────────────────────────────────────────────────

/// Compute `base^(2^t) mod n` by `t` repeated modular squarings.
///
/// Equivalent to `base.modpow(&(BigUint::one() << t), n)` but without
/// materialising the `t`-bit exponent, so memory use is independent of `t`.
fn repeated_square(base: &BigUint, t: u64, n: &BigUint) -> BigUint {
    let mut acc = base % n;
    for _ in 0..t {
        acc = (&acc * &acc) % n;
    }
    acc
}

// ─── Extended Euclidean / modular inverse ────────────────────────────────────

/// Compute `a^(-1) mod m` using the extended Euclidean algorithm.
/// Returns `None` if `gcd(a, m) != 1`.
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    if m.is_one() {
        return Some(BigUint::ZERO);
    }
    // Convert to signed arithmetic for extended GCD.
    use num_bigint::BigInt;
    use num_traits::Zero;
    let a_signed = BigInt::from(a.clone());
    let m_signed = BigInt::from(m.clone());
    let (mut old_r, mut r) = (a_signed.clone(), m_signed.clone());
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());

    while !r.is_zero() {
        let q = &old_r / &r;
        let tmp_r = old_r - &q * &r;
        old_r = r;
        r = tmp_r;
        let tmp_s = old_s - &q * &s;
        old_s = s;
        s = tmp_s;
    }

    if old_r != BigInt::one() {
        return None; // gcd != 1
    }

    // Normalise to positive.
    let result = ((old_s % &m_signed) + &m_signed) % &m_signed;
    result.to_biguint()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_vdf_roundtrip() -> ChronosResult<()> {
        let g = BigUint::from(3u32);
        // Small safe prime for testing.
        let n = BigUint::from(1009u32);
        let t = 8u64;

        // Direct VDF result (ground truth).
        let vdf = WesolowskiVdf;
        let (y_direct, _) = vdf.evaluate(&g, t, &n)?;

        // Blind VDF protocol.
        let ctx = BlindVdfClient::blind(&g, t, &n)?;
        let (y_blind, pi_blind) = BlindVdfServer::evaluate_blind(&ctx.g_blind, t, &n)?;

        // Server verifies its own proof.
        assert!(
            BlindVdfServer::verify_blind(&ctx.g_blind, &y_blind, &pi_blind, t, &n),
            "Server proof must verify"
        );

        // Client unblinds.
        let y_recovered = BlindVdfClient::unblind(&y_blind, &ctx, t, &n)?;
        assert_eq!(y_recovered, y_direct, "Unblinded result must match direct VDF");

        Ok(())
    }

    #[test]
    fn test_mod_inverse_basic() {
        let a = BigUint::from(3u32);
        let m = BigUint::from(11u32);
        let inv = mod_inverse(&a, &m).expect("inverse must exist");
        assert_eq!((&a * &inv) % &m, BigUint::one());
    }
}
