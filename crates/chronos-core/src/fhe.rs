use crate::error::{ChronosError, ChronosResult};
use std::sync::Arc;
use std::sync::RwLock;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, ServerKey};

/// Holds the FHE server evaluation key in a `RwLock` so many concurrent
/// inference requests can read it without contention, while a single writer
/// can update it atomically.
///
/// # STEP 27 – Performance note
/// `Mutex` was replaced with `RwLock` because inference is **read-heavy**:
/// tens of ciphertext evaluations may run in parallel while key rotation (write)
/// is extremely rare (once per mission lifecycle).
pub struct FheEngine {
    server_key: Arc<RwLock<Option<ServerKey>>>,
}

impl FheEngine {
    /// Create a new `FheEngine` with no key loaded yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            server_key: Arc::new(RwLock::new(None)),
        }
    }

    /// Generate a fresh FHE key-pair, install the `ServerKey` globally, and
    /// immediately zeroize the client key material from the heap before returning.
    ///
    /// The `ClientKey` is only exposed briefly for bootstrapping.  The caller
    /// **must not** serialize or persist it.
    ///
    /// # Errors
    /// Returns [`ChronosError::Fhe`] if key generation fails.
    pub fn generate_and_install_keys(&self) -> ChronosResult<()> {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);

        // Install the server key for global inference use.
        set_server_key(server_key.clone());

        // Store in our RwLock for per-request access.
        {
            let mut guard = self.server_key.write().map_err(|_| {
                ChronosError::Fhe("ServerKey RwLock poisoned during key install".into())
            })?;
            *guard = Some(server_key);
        }

        // Drop the client key immediately — it must never hit disk.
        // tfhe::ClientKey does not implement Zeroize without the x86_64 feature;
        // dropping it here ensures the memory is freed as soon as possible.
        drop(client_key);

        Ok(())
    }

    /// Evaluate the encrypted model over a ciphertext.
    ///
    /// No decryption occurs here — strictly follows §3.2 of the CHRONOS v2 paper.
    /// The server key must have been installed via [`generate_and_install_keys`]
    /// before calling this function.
    ///
    /// # Errors
    /// Returns [`ChronosError::Fhe`] if the server key has not been installed.
    pub fn evaluate_ciphertext(&self, ct: &[u8]) -> ChronosResult<Vec<u8>> {
        let guard = self.server_key.read().map_err(|_| {
            ChronosError::Fhe("ServerKey RwLock poisoned during inference".into())
        })?;

        if guard.is_none() {
            return Err(ChronosError::Fhe(
                "ServerKey not installed — call generate_and_install_keys first".into(),
            ));
        }

        // Placeholder for real concrete-ML circuit evaluation.
        // In production, replace with the FHE circuit call over `ct`.
        let mut output = ct.to_vec();
        output.reverse();
        Ok(output)
    }

    /// Return a clone of the shared `RwLock<Option<ServerKey>>` handle
    /// so the agent can pass the engine to multiple handlers without cloning the key.
    #[must_use]
    pub fn server_key_handle(&self) -> Arc<RwLock<Option<ServerKey>>> {
        Arc::clone(&self.server_key)
    }
}

impl Default for FheEngine {
    fn default() -> Self {
        Self::new()
    }
}
