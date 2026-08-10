/// Mutual TLS (mTLS) configuration for the CHRONOS agent.
///
/// All agent-to-GCS (Ground Control Station) communication is protected by
/// mutual TLS using `rustls`.  Both the agent and the GCS present certificates;
/// the agent refuses connections from clients without a valid certificate signed
/// by the configured CA.
///
/// # Configuration
/// Set the following in `config.toml`:
/// ```toml
/// [tls]
/// ca_cert_path   = "ca.pem"       # CA certificate (PEM)
/// agent_cert_path = "agent.pem"   # Agent certificate (PEM)
/// agent_key_path  = "agent.key"   # Agent private key (PEM)
/// enabled        = true
/// ```
///
/// # Security properties
/// - Server authentication: GCS presents a certificate signed by the CA.
/// - Client authentication: Agent presents a certificate signed by the CA.
/// - Forward secrecy: TLS 1.3 only (rustls default).
/// - No session resumption tickets (stateless agent).
use crate::config::TlsConfig;
use chronos_core::{ChronosError, ChronosResult};
use std::path::Path;
use tracing::{info, warn};

/// Validate that all required TLS files exist and have correct permissions.
///
/// # Errors
/// Returns [`ChronosError::Config`] if any required file is missing or has
/// incorrect permissions (must be 0600 on Unix).
pub fn validate_tls_config(cfg: &TlsConfig) -> ChronosResult<()> {
    if !cfg.enabled {
        warn!(target: "chronos", "mTLS is DISABLED — plain HTTP in use. Not suitable for production.");
        return Ok(());
    }

    let ca = cfg.ca_cert_path.as_deref().ok_or_else(|| {
        ChronosError::Config("mTLS enabled but ca_cert_path not set".into())
    })?;
    let cert = cfg.agent_cert_path.as_deref().ok_or_else(|| {
        ChronosError::Config("mTLS enabled but agent_cert_path not set".into())
    })?;
    let key = cfg.agent_key_path.as_deref().ok_or_else(|| {
        ChronosError::Config("mTLS enabled but agent_key_path not set".into())
    })?;

    for path in [ca, cert] {
        check_file_exists(path)?;
    }
    // Private key must be 0600.
    check_file_permissions(key)?;

    info!(target: "chronos", "mTLS configuration validated");
    Ok(())
}

fn check_file_exists(path: &str) -> ChronosResult<()> {
    if !Path::new(path).exists() {
        return Err(ChronosError::Config(format!(
            "TLS file not found: '{path}'"
        )));
    }
    Ok(())
}

fn check_file_permissions(path: &str) -> ChronosResult<()> {
    check_file_exists(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| ChronosError::Config(format!("Cannot stat '{path}': {e}")))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(ChronosError::Config(format!(
                "TLS key '{path}' has mode {mode:o} — must be 0600. Run: chmod 600 {path}"
            )));
        }
    }

    Ok(())
}

/// Sliding-window nonce cache for replay protection.
///
/// Maintains a fixed-size window of recently seen nonces.  Any nonce seen
/// within the window is rejected as a replay.
///
/// Uses a `HashSet` for O(1) lookup and a `VecDeque` to track insertion order
/// for eviction. At 1024 capacity × 12 bytes = 12 KB memory.
pub struct NonceCache {
    seen: std::collections::HashSet<[u8; 12]>,
    order: std::collections::VecDeque<[u8; 12]>,
    capacity: usize,
}

impl NonceCache {
    /// Create a new nonce cache with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: std::collections::HashSet::with_capacity(capacity),
            order: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Check if a nonce has been seen before and record it.
    ///
    /// Returns `true` if the nonce is fresh (not a replay), `false` if it
    /// has been seen before.
    pub fn check_and_insert(&mut self, nonce: &[u8; 12]) -> bool {
        if self.seen.contains(nonce) {
            return false; // Replay detected.
        }
        if self.order.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        self.seen.insert(*nonce);
        self.order.push_back(*nonce);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_cache_fresh_nonce_accepted() {
        let mut cache = NonceCache::new(16);
        let nonce = [0x01u8; 12];
        assert!(cache.check_and_insert(&nonce), "Fresh nonce must be accepted");
    }

    #[test]
    fn test_nonce_cache_replay_rejected() {
        let mut cache = NonceCache::new(16);
        let nonce = [0x02u8; 12];
        assert!(cache.check_and_insert(&nonce));
        assert!(!cache.check_and_insert(&nonce), "Replay must be rejected");
    }

    #[test]
    fn test_nonce_cache_eviction() {
        let mut cache = NonceCache::new(4);
        for i in 0u8..4 {
            cache.check_and_insert(&[i; 12]);
        }
        // Insert a 5th — evicts the first.
        cache.check_and_insert(&[4u8; 12]);
        // First nonce should now be accepted again (evicted from window).
        assert!(cache.check_and_insert(&[0u8; 12]), "Evicted nonce must be accepted again");
    }

    #[test]
    fn test_tls_config_disabled_is_ok() {
        let cfg = TlsConfig::default();
        assert!(validate_tls_config(&cfg).is_ok());
    }

    #[test]
    fn test_tls_config_enabled_missing_paths_fails() {
        let cfg = TlsConfig {
            enabled: true,
            ca_cert_path: None,
            agent_cert_path: None,
            agent_key_path: None,
        };
        assert!(validate_tls_config(&cfg).is_err());
    }
}
