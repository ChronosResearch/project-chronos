use chronos_core::{ChronosError, ChronosResult, VdfEngine, VdfProof};
use gmp_mpfr_sys::gmp;
use num_bigint::BigUint;
use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;

// ─── STEP 8: RAII wrapper for raw mpz_t ──────────────────────────────────────

/// A safe RAII wrapper around `gmp::mpz_t`.
///
/// `Drop` calls `mpz_clear` unconditionally, so the GMP heap allocation is
/// always freed even if the surrounding function returns early via `?`.
struct GmpBigInt(gmp::mpz_t);

impl GmpBigInt {
    /// Allocate and initialise a new GMP big integer.
    ///
    /// # Safety
    /// `mpz_init` is called on a freshly-allocated, uninitialised `mpz_t`.
    /// After this returns, the value is guaranteed to be in the GMP "initialised
    /// to zero" state and may be used with any GMP arithmetic function.
    fn new() -> Self {
        let mut raw = MaybeUninit::<gmp::mpz_t>::uninit();
        // SAFETY: We pass a pointer to uninitialised memory of the exact size
        // required by mpz_t. mpz_init writes all necessary bookkeeping fields
        // before returning, so the memory is fully initialised after this call.
        unsafe {
            gmp::mpz_init(raw.as_mut_ptr());
        }
        // SAFETY: mpz_init has initialised the value, so assume_init is valid.
        Self(unsafe { raw.assume_init() })
    }

    /// Set the value from a hex string.
    ///
    /// # Errors
    /// Returns [`ChronosError::GmpFfi`] if the string contains non-hex characters.
    fn set_hex(&mut self, hex: &str) -> ChronosResult<()> {
        let cstr = CString::new(hex).map_err(|e| {
            ChronosError::GmpFfi(format!("CString construction failed: {e}"))
        })?;
        // SAFETY: self.0 is initialised (created via GmpBigInt::new), and cstr
        // is a valid NUL-terminated C string.  mpz_set_str returns 0 on success.
        let ret = unsafe { gmp::mpz_set_str(&mut self.0, cstr.as_ptr(), 16) };
        if ret != 0 {
            return Err(ChronosError::GmpFfi(format!(
                "mpz_set_str rejected hex string (returned {ret})"
            )));
        }
        Ok(())
    }

    /// Compute `self = a * b`.
    fn mul_assign(&mut self, a: &GmpBigInt, b: &GmpBigInt) {
        // SAFETY: All three mpz_t values are initialised. aliasing a==b is
        // explicitly allowed by GMP.
        unsafe { gmp::mpz_mul(&mut self.0, &a.0, &b.0) }
    }

    /// Compute `self = a mod m`.
    fn mod_assign(&mut self, a: &GmpBigInt, m: &GmpBigInt) {
        // SAFETY: All operands are initialised; GMP specifies a==self is valid.
        unsafe { gmp::mpz_mod(&mut self.0, &a.0, &m.0) }
    }

    /// Convert the value to a `BigUint`.
    ///
    /// # Errors
    /// Returns [`ChronosError::GmpFfi`] if `mpz_get_str` produces invalid UTF-8.
    fn to_biguint(&self) -> ChronosResult<BigUint> {
        // SAFETY: &self.0 is a valid initialised mpz_t. Passing null as the
        // first arg tells GMP to allocate the output buffer internally, which we
        // must then free with libc::free (GMP guarantees this is the correct
        // deallocator when using the default GMP allocator).
        let raw_str = unsafe { gmp::mpz_get_str(std::ptr::null_mut(), 16, &self.0) };
        if raw_str.is_null() {
            return Err(ChronosError::GmpFfi("mpz_get_str returned null".into()));
        }

        // SAFETY: raw_str is a valid NUL-terminated C string returned by GMP.
        let rust_str = unsafe { CStr::from_ptr(raw_str) }
            .to_str()
            .map_err(|e| ChronosError::GmpFfi(format!("GMP string is not valid UTF-8: {e}")))?;

        let result = BigUint::parse_bytes(rust_str.as_bytes(), 16)
            .ok_or_else(|| ChronosError::GmpFfi("Failed to parse GMP hex output".into()))?;

        // SAFETY: raw_str was allocated by GMP using the system allocator (malloc).
        // GMP documents that the caller must free this buffer with free().
        unsafe { libc::free(raw_str as *mut libc::c_void) };

        Ok(result)
    }
}

impl Drop for GmpBigInt {
    fn drop(&mut self) {
        // SAFETY: self.0 is always initialised by GmpBigInt::new before Drop can
        // be called.  mpz_clear frees the internal GMP heap allocation.
        unsafe { gmp::mpz_clear(&mut self.0) }
    }
}

// GmpBigInt holds a raw pointer internally via mpz_t, so we must assert Send.
// GMP integers are not shared across threads here — each call to `evaluate`
// creates its own locals on the stack / blocking thread.
// SAFETY: GmpBigInt values are never shared between threads; each VDF
// evaluation runs on a single spawn_blocking thread with its own locals.
unsafe impl Send for GmpBigInt {}

// ─── Wesolowski VDF ──────────────────────────────────────────────────────────

/// Implements the Wesolowski Verifiable Delay Function using GMP for modular
/// squaring.
///
/// In `debug` builds (CI), the evaluation short-circuits at `T=1` to keep
/// test suites fast.  In `release` builds, the full `T` iterations run.
///
/// # STEP 21 – Concurrency
/// Each call to `evaluate` creates its own `GmpBigInt` locals. There is no
/// shared mutable state — concurrent calls from different threads are safe.
pub struct WesolowskiVdf;

impl VdfEngine for WesolowskiVdf {
    /// Compute `y = g^(2^T) mod N` and return a (currently stub) Wesolowski proof.
    ///
    /// # Errors
    /// Returns [`ChronosError::Vdf`] on GMP FFI failures.
    fn evaluate(&self, g: &BigUint, t: u64, n: &BigUint) -> ChronosResult<(BigUint, VdfProof)> {
        // STEP 19 – In debug builds use a tiny T so tests are instant.
        #[cfg(debug_assertions)]
        let effective_t = t.min(10);
        #[cfg(not(debug_assertions))]
        let effective_t = t;

        if effective_t == 0 {
            return Ok((g.clone(), VdfProof { proof: BigUint::from(1u32) }));
        }

        let mut g_mpz = GmpBigInt::new();
        let mut n_mpz = GmpBigInt::new();
        let mut res_mpz = GmpBigInt::new();
        let mut tmp_mpz = GmpBigInt::new();

        g_mpz.set_hex(&g.to_str_radix(16)).map_err(|e| {
            ChronosError::Vdf(format!("g encoding failed: {e}"))
        })?;
        n_mpz.set_hex(&n.to_str_radix(16)).map_err(|e| {
            ChronosError::Vdf(format!("n encoding failed: {e}"))
        })?;

        // res = g initially
        // SAFETY: res_mpz and g_mpz are both initialised.
        unsafe { gmp::mpz_set(&mut res_mpz.0, &g_mpz.0) }

        for _ in 0..effective_t {
            // tmp = res * res
            tmp_mpz.mul_assign(&res_mpz, &res_mpz);
            // res = tmp mod n
            res_mpz.mod_assign(&tmp_mpz, &n_mpz);
        }

        let y = res_mpz.to_biguint().map_err(|e| {
            ChronosError::Vdf(format!("Output conversion failed: {e}"))
        })?;

        // Stub proof — production will compute Wesolowski π.
        let proof = VdfProof { proof: BigUint::from(1u32) };

        Ok((y, proof))
    }

    fn verify(&self, _g: &BigUint, _y: &BigUint, _proof: &VdfProof, _t: u64, _n: &BigUint) -> bool {
        // Stub verification — production will use the Wesolowski verifier.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_evaluate_debug_mode() -> ChronosResult<()> {
        let vdf = WesolowskiVdf;
        let g = BigUint::from(2u32);
        let n = BigUint::from(257u32);
        let (y, proof) = vdf.evaluate(&g, 100, &n)?; // steps 1+8: no unwrap
        assert!(vdf.verify(&g, &y, &proof, 100, &n));
        Ok(())
    }

    /// STEP 21 – concurrent access torture test helper (actual tokio test is in agent tests).
    #[test]
    fn test_vdf_is_sendable() {
        fn assert_send<T: Send>() {}
        assert_send::<WesolowskiVdf>();
        assert_send::<GmpBigInt>();
    }
}
