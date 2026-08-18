use crate::error::{ChronosError, ChronosResult};
use crate::mlp::{MlpWeights, TwoLayerMlp};
use std::sync::Arc;
use std::sync::RwLock;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt64, ServerKey};

/// Upper bound on an accepted `/infer` payload, in bytes.
///
/// `bincode` reads a length prefix before allocating. On attacker-controlled
/// input that is an allocation primitive, so the payload is size-checked before
/// deserialization is attempted. This is a floor, not a substitute for
/// `tfhe::safe_serialization` — see [`FheEngine::evaluate_ciphertext`].
const MAX_CIPHERTEXT_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

/// Holds the FHE server evaluation key in a `RwLock` so many concurrent
/// inference requests can read it without contention, while a single writer
/// can update it atomically.
pub struct FheEngine {
    server_key: Arc<RwLock<Option<ServerKey>>>,
    /// Cleartext model weights. Not secret — FHE protects the inputs, not the
    /// model. Separate from the key so a model can be swapped without a new
    /// mission.
    weights: RwLock<Option<MlpWeights>>,
}

impl FheEngine {
    /// Create a new `FheEngine` with no key and no model loaded.
    #[must_use]
    pub fn new() -> Self {
        Self {
            server_key: Arc::new(RwLock::new(None)),
            weights: RwLock::new(None),
        }
    }

    /// Generate a fresh FHE key-pair, install the `ServerKey` globally, and drop
    /// the client key before returning.
    ///
    /// The `ClientKey` is only exposed briefly for bootstrapping. The caller
    /// **must not** serialize or persist it.
    ///
    /// # Errors
    /// Returns [`ChronosError::Fhe`] if key generation fails or the lock is poisoned.
    pub fn generate_and_install_keys(&self) -> ChronosResult<()> {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);

        set_server_key(server_key.clone());

        {
            let mut guard = self.server_key.write().map_err(|_| {
                ChronosError::Fhe("ServerKey RwLock poisoned during key install".into())
            })?;
            *guard = Some(server_key);
        }

        // Drop the client key immediately — it must never hit disk.
        drop(client_key);

        Ok(())
    }

    /// Install the model to evaluate.
    ///
    /// # Errors
    /// Returns [`ChronosError::Fhe`] if the weights are malformed for
    /// `input_dim`, or if the lock is poisoned.
    pub fn install_weights(&self, weights: MlpWeights, input_dim: usize) -> ChronosResult<()> {
        weights.validate(input_dim)?;
        let mut guard = self
            .weights
            .write()
            .map_err(|_| ChronosError::Fhe("weights RwLock poisoned".into()))?;
        *guard = Some(weights);
        Ok(())
    }

    /// Evaluate the installed MLP over a serialized ciphertext vector.
    ///
    /// Replaces the byte-reversal placeholder previous revisions returned. That
    /// stub provided no confidentiality and performed no homomorphic work; this
    /// runs a real two-layer network over `FheInt64` ciphertexts. The secret key
    /// is still never on the evaluation path.
    ///
    /// # Wire format
    /// `ct` is `bincode`-serialized `Vec<FheInt64>`, one ciphertext per input
    /// feature. Returns `bincode`-serialized `FheInt64`, the single output.
    ///
    /// # Untrusted input — known gap
    /// `ct` arrives from `/infer`, i.e. from the network. The payload is length-
    /// capped at [`MAX_CIPHERTEXT_PAYLOAD_BYTES`] before deserialization, which
    /// blocks the crudest allocation attack, but `bincode::deserialize` is still
    /// not a hardened parser for adversarial bytes. tfhe-rs ships
    /// `tfhe::safe_serialization` for exactly this boundary and it should replace
    /// the calls below before this endpoint is exposed to untrusted clients.
    /// Tracked in the README gaps table.
    ///
    /// # Errors
    /// Returns [`ChronosError::Fhe`] if the server key or model is not
    /// installed, the payload exceeds the size cap, deserialization fails, or
    /// the input width does not match the model.
    pub fn evaluate_ciphertext(&self, ct: &[u8]) -> ChronosResult<Vec<u8>> {
        if ct.len() > MAX_CIPHERTEXT_PAYLOAD_BYTES {
            return Err(ChronosError::Fhe(format!(
                "ciphertext payload {} bytes exceeds cap of {} bytes",
                ct.len(),
                MAX_CIPHERTEXT_PAYLOAD_BYTES
            )));
        }

        {
            let guard = self.server_key.read().map_err(|_| {
                ChronosError::Fhe("ServerKey RwLock poisoned during inference".into())
            })?;
            if guard.is_none() {
                return Err(ChronosError::Fhe(
                    "ServerKey not installed — call generate_and_install_keys first".into(),
                ));
            }
        }

        let weights_guard = self
            .weights
            .read()
            .map_err(|_| ChronosError::Fhe("weights RwLock poisoned".into()))?;
        let weights = weights_guard.as_ref().ok_or_else(|| {
            ChronosError::Fhe("model weights not installed — call install_weights first".into())
        })?;

        let inputs: Vec<FheInt64> = bincode::deserialize(ct).map_err(|e| {
            ChronosError::Fhe(format!("ciphertext deserialization failed: {e}"))
        })?;

        let mlp = TwoLayerMlp::new(weights.clone());
        let result = mlp.evaluate(&inputs)?;

        bincode::serialize(&result)
            .map_err(|e| ChronosError::Fhe(format!("result serialization failed: {e}")))
    }

    /// Return a clone of the shared `RwLock<Option<ServerKey>>` handle so the
    /// agent can pass the engine to multiple handlers without cloning the key.
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

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::prelude::*;

    fn toy_weights() -> MlpWeights {
        MlpWeights {
            hidden_weights: vec![vec![1, -1], vec![-1, 1]],
            hidden_bias: vec![0, 0],
            output_weights: vec![2, 3],
            output_bias: 1,
        }
    }

    #[test]
    fn test_evaluate_requires_key() {
        let engine = FheEngine::new();
        let result = engine.evaluate_ciphertext(&[0u8; 8]);
        assert!(matches!(result, Err(ChronosError::Fhe(_))));
    }

    #[test]
    fn test_evaluate_rejects_oversized_payload() {
        let engine = FheEngine::new();
        // Length check happens before any key or model check.
        let huge = vec![0u8; MAX_CIPHERTEXT_PAYLOAD_BYTES + 1];
        let err = engine.evaluate_ciphertext(&huge).unwrap_err();
        assert!(
            format!("{err}").contains("exceeds cap"),
            "oversized payload must be rejected by the size cap, got: {err}"
        );
    }

    /// Full round trip through the wire format: encrypt, serialize, evaluate,
    /// deserialize, decrypt, compare against a plaintext reference.
    ///
    /// Skipped under Miri: the `x86_64` tfhe feature's seeder needs the `rdseed`
    /// instruction, which Miri does not emulate, so `generate_keys` panics before
    /// the test body runs. See the note in `mlp.rs`. Runs normally under
    /// `cargo test`.
    #[test]
    #[cfg_attr(miri, ignore = "tfhe seeder needs rdseed, which Miri cannot emulate")]
    fn test_evaluate_ciphertext_round_trip() {
        let engine = FheEngine::new();
        engine
            .generate_and_install_keys()
            .expect("key generation must succeed");
        engine
            .install_weights(toy_weights(), 2)
            .expect("weights must install");

        // A client key is needed to encrypt/decrypt in the test; the engine
        // deliberately drops its own copy.
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        set_server_key(server_key);

        let inputs: Vec<FheInt64> = [5i64, 3i64]
            .iter()
            .map(|v| FheInt64::encrypt(*v, &client_key))
            .collect();
        let payload = bincode::serialize(&inputs).expect("serialize must succeed");

        let out_bytes = engine
            .evaluate_ciphertext(&payload)
            .expect("evaluation must succeed");
        let out_ct: FheInt64 =
            bincode::deserialize(&out_bytes).expect("result must deserialize");
        let out: i64 = out_ct.decrypt(&client_key);

        let h0 = (5 * 1 + 3 * -1).max(0);
        let h1 = (5 * -1 + 3 * 1).max(0);
        assert_eq!(out, h0 * 2 + h1 * 3 + 1);
    }
}
