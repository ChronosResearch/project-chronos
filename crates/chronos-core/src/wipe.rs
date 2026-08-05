use std::sync::atomic::{compiler_fence, Ordering};

/// Performs a triple-pass volatile overwrite of the memory region.
///
/// Passes: `0xFF → 0x00 → 0xFF`. Each pass is separated by a `compiler_fence`
/// with `SeqCst` ordering to prevent the compiler from eliding any write.
///
/// # Safety
/// The caller must guarantee:
/// - `ptr` is non-null and points to an allocation of at least `len` bytes.
/// - The allocation must be live for the duration of this call.
/// - No other thread may simultaneously read or write the region.
///
/// # Panics
/// This function never panics.
#[inline(never)] // Prevent inlining so the symbol survives stripping in tests.
pub unsafe fn secure_wipe(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: Caller guarantees ptr..ptr+len is a valid, exclusively-owned live allocation.
    unsafe {
        for i in 0..len {
            std::ptr::write_volatile(ptr.add(i), 0xFF);
        }
        compiler_fence(Ordering::SeqCst);
        for i in 0..len {
            std::ptr::write_volatile(ptr.add(i), 0x00);
        }
        compiler_fence(Ordering::SeqCst);
        for i in 0..len {
            std::ptr::write_volatile(ptr.add(i), 0xFF);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STEP 9: Verifies the wipe was NOT optimized away by reading back via
    /// `read_volatile`. The final pass writes `0xFF`, so every byte must equal that.
    #[test]
    fn test_secure_wipe_not_optimized_away() {
        const SZ: usize = 1024;
        let mut buf = vec![0xAAu8; SZ];
        let ptr = buf.as_mut_ptr();

        // Pre-condition: all bytes are 0xAA.
        for i in 0..SZ {
            // SAFETY: ptr is valid and i < SZ.
            assert_eq!(unsafe { std::ptr::read_volatile(ptr.add(i)) }, 0xAA);
        }

        // SAFETY: buf is alive, ptr valid, SZ bytes allocated, single-threaded test.
        unsafe { secure_wipe(ptr, SZ); }

        // Post-condition: final pass writes 0xFF.
        for i in 0..SZ {
            // SAFETY: ptr is still valid; secure_wipe does not free the memory.
            let byte = unsafe { std::ptr::read_volatile(ptr.add(i)) };
            assert_eq!(
                byte, 0xFF,
                "Byte {i} was {byte:#04x} — compiler may have optimized the wipe!"
            );
        }
    }

    #[test]
    fn test_secure_wipe_null_ptr_is_noop() {
        // Must not panic or segfault.
        // SAFETY: null ptr is handled inside secure_wipe as a no-op.
        unsafe { secure_wipe(std::ptr::null_mut(), 64); }
    }

    #[test]
    fn test_secure_wipe_zero_len_is_noop() {
        let mut buf = [0u8; 1];
        // SAFETY: zero len is handled inside secure_wipe as a no-op.
        unsafe { secure_wipe(buf.as_mut_ptr(), 0); }
        assert_eq!(buf[0], 0); // untouched
    }
}
