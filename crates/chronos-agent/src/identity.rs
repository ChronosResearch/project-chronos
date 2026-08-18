/// Ephemeral Agent Identity Primitive (EAIP).
///
/// Provides a time-locked, self-destructing identity for autonomous agents.
/// The identity root `R = SHA-256(g^(2^T) mod N)` is cryptographically bound
/// to the mission duration `T` — it cannot be computed before T sequential
/// squarings complete, and it is wiped on mission erasure.
///
/// # Security properties
/// - Time-locked: identity root requires T VDF squarings to derive
/// - Zero-knowledge: agent proves identity without revealing the VDF output
/// - Post-quantum: identity is signed with ML-DSA (Dilithium3, NIST FIPS 204)
/// - Ephemeral: root and PQ keys are wiped on `Drop` via `LockedBytes`
use chronos_core::{memory::LockedBytes, ChronosError, ChronosResult};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use sha2::{Digest, Sha256};
use tracing::info;

// ─── Identity Root ────────────────────────────────────────────────────────────

/// Time-locked identity root for an ephemeral agent mission.
///
/// The root `R = SHA-256(y)` where `y = g^(2^T) mod N` is the VDF output.
/// It is stored in memory-locked pages and wiped on drop.
pub struct IdentityRoot {
    /// SHA-256 of the VDF output — the identity root R.
    root: LockedBytes,
    /// Human-readable mission identifier.
    pub mission_id: String,
    /// Unix timestamp (seconds) when the identity expires.
    pub expires_at: u64,
}

impl IdentityRoot {
    /// Create a new identity root from a 32-byte root value.
    ///
    /// # Errors
    /// Returns [`ChronosError::ExclusivityAssumption`] if `mlock` fails.
    pub fn new(root: [u8; 32], mission_id: String, expires_at: u64) -> ChronosResult<Self> {
        let locked = LockedBytes::new(root.to_vec())?;
        Ok(Self {
            root: locked,
            mission_id,
            expires_at,
        })
    }

    /// Return the raw 32-byte root value.
    pub fn as_bytes(&self) -> &[u8] {
        &self.root
    }

    /// Return the first byte of the root (used as SNARK public input).
    pub fn first_byte(&self) -> u8 {
        self.root.first().copied().unwrap_or(0)
    }

    /// Check whether the identity has expired relative to `now_secs`.
    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs >= self.expires_at
    }
}

// ─── Post-Quantum Key Pair ────────────────────────────────────────────────────

/// ML-DSA (Dilithium3) key pair for post-quantum identity signing.
///
/// Both keys are stored in memory-locked pages and wiped on drop.
pub struct PqKeyPair {
    /// Dilithium3 public key (1952 bytes).
    pub public_key: Vec<u8>,
    /// Dilithium3 secret key — memory-locked.
    secret_key: LockedBytes,
}

impl PqKeyPair {
    /// Generate a fresh Dilithium3 key pair.
    ///
    /// # Errors
    /// Returns [`ChronosError::ExclusivityAssumption`] if `mlock` fails.
    pub fn generate() -> ChronosResult<Self> {
        let (pk, sk) = dilithium3::keypair();
        let pk_bytes = pk.as_bytes().to_vec();
        let sk_bytes = sk.as_bytes().to_vec();
        let locked_sk = LockedBytes::new(sk_bytes)?;
        Ok(Self {
            public_key: pk_bytes,
            secret_key: locked_sk,
        })
    }

    /// Sign a message with the Dilithium3 secret key.
    ///
    /// Returns the detached signature bytes.
    ///
    /// # Errors
    /// Returns [`ChronosError::Erasure`] if the secret key is malformed.
    pub fn sign(&self, message: &[u8]) -> ChronosResult<Vec<u8>> {
        let sk = dilithium3::SecretKey::from_bytes(&self.secret_key)
            .map_err(|e| ChronosError::Erasure(format!("PQ secret key parse failed: {e:?}")))?;
        let signed = dilithium3::sign(message, &sk);
        // signed = signature || message; extract just the signature prefix.
        let sig_len = signed.as_bytes().len() - message.len();
        Ok(signed.as_bytes()[..sig_len].to_vec())
    }

    /// Verify a Dilithium3 signature over `message` using the stored public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> ChronosResult<bool> {
        let pk = dilithium3::PublicKey::from_bytes(&self.public_key)
            .map_err(|e| ChronosError::Erasure(format!("PQ public key parse failed: {e:?}")))?;
        // Reconstruct signed message = signature || message.
        let mut signed_bytes = signature.to_vec();
        signed_bytes.extend_from_slice(message);
        let sm = dilithium3::SignedMessage::from_bytes(&signed_bytes)
            .map_err(|_| ChronosError::Erasure("Invalid signed message format".into()))?;
        match dilithium3::open(&sm, &pk) {
            Ok(recovered) => Ok(recovered == message),
            Err(_) => Ok(false),
        }
    }
}

// ─── Identity Manager ─────────────────────────────────────────────────────────

/// Manages the full EAIP lifecycle: root generation, ZK proof, PQ signing.
pub struct IdentityManager {
    /// The time-locked identity root (set after VDF completes).
    pub identity_root: Option<IdentityRoot>,
    /// Post-quantum key pair (set on init, wiped on erasure).
    pub pq_keys: Option<PqKeyPair>,
}

impl IdentityManager {
    pub fn new() -> Self {
        Self {
            identity_root: None,
            pq_keys: None,
        }
    }

    /// Initialize identity: generate PQ keys and store the identity root.
    ///
    /// Called after VDF completes with `root = SHA-256(y)`.
    ///
    /// # Errors
    /// Returns [`ChronosError::ExclusivityAssumption`] if `mlock` fails.
    pub fn initialize(
        &mut self,
        root: [u8; 32],
        mission_id: String,
        expires_at: u64,
    ) -> ChronosResult<()> {
        self.pq_keys = Some(PqKeyPair::generate()?);
        self.identity_root = Some(IdentityRoot::new(root, mission_id, expires_at)?);
        info!(target: "chronos", "EAIP identity initialized (PQ keys generated, root stored)");
        Ok(())
    }

    /// Sign the identity root with the PQ secret key.
    ///
    /// Returns `signature_bytes` over `SHA-256(root || mission_id)`.
    ///
    /// # Errors
    /// Returns [`ChronosError::Erasure`] if keys are not initialized.
    pub fn sign_identity(&self) -> ChronosResult<Vec<u8>> {
        let ir = self.identity_root.as_ref().ok_or_else(|| {
            ChronosError::Erasure("Identity root not initialized".into())
        })?;
        let keys = self.pq_keys.as_ref().ok_or_else(|| {
            ChronosError::Erasure("PQ keys not initialized".into())
        })?;
        // Message = SHA-256(root || mission_id)
        let msg = identity_message(ir.as_bytes(), &ir.mission_id);
        keys.sign(&msg)
    }

    /// Verify a PQ signature over the identity root.
    pub fn verify_identity_signature(&self, signature: &[u8]) -> ChronosResult<bool> {
        let ir = self.identity_root.as_ref().ok_or_else(|| {
            ChronosError::Erasure("Identity root not initialized".into())
        })?;
        let keys = self.pq_keys.as_ref().ok_or_else(|| {
            ChronosError::Erasure("PQ keys not initialized".into())
        })?;
        let msg = identity_message(ir.as_bytes(), &ir.mission_id);
        keys.verify(&msg, signature)
    }

    /// Wipe all identity material — called on mission erasure.
    ///
    /// Drops `IdentityRoot` and `PqKeyPair` (both trigger `LockedBytes::drop`
    /// which triple-pass wipes the memory-locked pages).
    pub fn wipe(&mut self) {
        self.identity_root = None;
        self.pq_keys = None;
        info!(target: "chronos", "EAIP identity wiped");
    }

    /// Return the public key bytes for inclusion in the mission certificate.
    pub fn public_key_bytes(&self) -> Option<&[u8]> {
        self.pq_keys.as_ref().map(|k| k.public_key.as_slice())
    }
}

impl Default for IdentityManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the identity message: `SHA-256(root || mission_id_bytes)`.
fn identity_message(root: &[u8], mission_id: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(root);
    h.update(mission_id.as_bytes());
    h.finalize().to_vec()
}

// `IdentityStatus` was removed. It exposed `root_binding` as
// `hex::encode([root.first_byte()])` — a single byte of the identity root — which
// was all the old circuit bound. The root is now a full-width field element and
// `main.rs` serves it in full via its own response type, so a struct that
// advertised one byte of it would understate what is actually attested.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_root_generation() -> ChronosResult<()> {
        let root = [0x42u8; 32];
        let ir = IdentityRoot::new(root, "test-mission".into(), 9999999999)?;
        assert_eq!(ir.as_bytes(), &root);
        assert_eq!(ir.first_byte(), 0x42);
        assert!(!ir.is_expired(0));
        Ok(())
    }

    #[test]
    fn test_identity_root_expiration() -> ChronosResult<()> {
        let root = [0x01u8; 32];
        let ir = IdentityRoot::new(root, "test-mission".into(), 100)?;
        assert!(!ir.is_expired(99));
        assert!(ir.is_expired(100));
        assert!(ir.is_expired(101));
        Ok(())
    }

    #[test]
    fn test_identity_root_wipe() -> ChronosResult<()> {
        let root = [0xFFu8; 32];
        let ir = IdentityRoot::new(root, "test-mission".into(), 0)?;
        // Drop triggers LockedBytes::drop which triple-pass wipes the pages.
        drop(ir);
        Ok(())
    }

    #[test]
    fn test_pq_keypair_sign_verify() -> ChronosResult<()> {
        let kp = PqKeyPair::generate()?;
        let msg = b"chronos-eaip-test-message";
        let sig = kp.sign(msg)?;
        assert!(!sig.is_empty());
        assert!(kp.verify(msg, &sig)?);
        Ok(())
    }

    #[test]
    fn test_pq_keypair_wrong_message_rejected() -> ChronosResult<()> {
        let kp = PqKeyPair::generate()?;
        let sig = kp.sign(b"correct-message")?;
        assert!(!kp.verify(b"wrong-message", &sig)?);
        Ok(())
    }

    #[test]
    fn test_identity_manager_full_lifecycle() -> ChronosResult<()> {
        let mut mgr = IdentityManager::new();
        let root = [0xABu8; 32];
        mgr.initialize(root, "mission-alpha".into(), 9999999999)?;

        // Sign and verify.
        let sig = mgr.sign_identity()?;
        assert!(mgr.verify_identity_signature(&sig)?);

        // Public key is available.
        assert!(mgr.public_key_bytes().is_some());

        // Wipe clears everything.
        mgr.wipe();
        assert!(mgr.identity_root.is_none());
        assert!(mgr.pq_keys.is_none());
        Ok(())
    }

    #[test]
    fn test_identity_message_deterministic() {
        let root = [0x01u8; 32];
        let m1 = identity_message(&root, "mission-x");
        let m2 = identity_message(&root, "mission-x");
        assert_eq!(m1, m2);
        assert_eq!(m1.len(), 32);
    }
}
