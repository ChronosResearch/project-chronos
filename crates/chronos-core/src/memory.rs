use crate::error::{ChronosError, ChronosResult};
use crate::wipe::secure_wipe;
use std::ops::Deref;

/// A heap-allocated byte buffer whose pages are memory-locked (mlock/VirtualLock)
/// to prevent swapping to disk.
///
/// On `Drop`, the buffer is triple-pass wiped via [`secure_wipe`] before the
/// page lock is released.  This struct must be created and held on a **real OS
/// thread** (i.e. inside `tokio::task::spawn_blocking`) — not directly in an
/// async task — because the OS associates the mlock with the calling thread's
/// process, and dropping the guard on a different thread is safe but must not
/// happen across a yield point where another async task might observe freed memory.
pub struct LockedBytes {
    data: Vec<u8>,
    /// Length cached so `drop` does not need to borrow `data` after the first wipe.
    len: usize,
}

impl LockedBytes {
    /// Allocates and memory-locks `data`.
    ///
    /// Returns `Err(ChronosError::ExclusivityAssumption)` if the OS refuses
    /// `mlock` — the caller must treat this as a hard failure.
    pub fn new(mut data: Vec<u8>) -> ChronosResult<Self> {
        let ptr = data.as_mut_ptr();
        let len = data.len();

        if len == 0 {
            return Ok(Self { data, len });
        }

        #[cfg(unix)]
        {
            // SAFETY: `ptr` points to the start of a live Vec allocation of exactly
            // `len` bytes. We pass the same values to munlock in Drop.
            let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
            if ret != 0 {
                let os_err = std::io::Error::last_os_error();
                return Err(ChronosError::ExclusivityAssumption(format!(
                    "mlock failed: {os_err}. Ensure CAP_IPC_LOCK is set \
                     (sudo setcap cap_ipc_lock+ep ./chronos-agent)"
                )));
            }
        }

        #[cfg(windows)]
        {
            // SAFETY: `ptr` and `len` describe the same live allocation.
            extern "system" {
                fn VirtualLock(lpAddress: *mut libc::c_void, dwSize: usize) -> i32;
            }
            let ret = unsafe { VirtualLock(ptr as *mut libc::c_void, len) };
            if ret == 0 {
                let os_err = std::io::Error::last_os_error();
                return Err(ChronosError::ExclusivityAssumption(format!(
                    "VirtualLock failed: {os_err}. Ensure SeIncreaseWorkingSetPrivilege is set."
                )));
            }
        }

        Ok(Self { data, len })
    }
}

impl Deref for LockedBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        let ptr = self.data.as_mut_ptr();
        let len = self.len;

        if len == 0 {
            return;
        }

        // Wipe before unlocking so the plaintext never exists in swappable memory.
        secure_wipe(ptr, len);

        #[cfg(unix)]
        {
            // SAFETY: ptr/len are the same values used in `new`. The buffer is
            // still alive (we own it). This is the last use before the Vec drops.
            unsafe { libc::munlock(ptr as *const libc::c_void, len) };
        }

        #[cfg(windows)]
        {
            extern "system" {
                fn VirtualUnlock(lpAddress: *mut libc::c_void, dwSize: usize) -> i32;
            }
            // SAFETY: Same reasoning as the unix branch above.
            unsafe { VirtualUnlock(ptr as *mut libc::c_void, len) };
        }
    }
}
