/// Mutual TLS configuration checks, and the nonce cache.
///
/// # What this module does NOT do
///
/// It does not establish TLS. There is no `rustls` in this crate and the acceptor
/// in `main.rs` is a plain `TcpListener`, so **transport is authenticated but not
/// confidential**. This module only checks that the files named in configuration
/// exist and that the private key is not world-readable.
///
/// An earlier version of this doc comment claimed the opposite, that "all
/// agent-to-GCS communication is protected by mutual TLS using `rustls`" and that
/// "the agent refuses connections from clients without a valid certificate". None
/// of that was implemented. The comment is corrected rather than deleted because
/// the gap between the two is exactly the kind of thing a reader should be able to
/// see was once claimed.
///
/// What [`validate_tls_config`] actually verifies, and nothing more:
/// - the CA and agent certificate paths exist on disk,
/// - the agent key exists and is mode 0600 on Unix.
///
/// It does not parse a single PEM, does not check that the agent certificate
/// chains to the configured CA, and does not configure an acceptor. A successful
/// return means the configuration is well-formed, not that mTLS is in force.
///
/// # Configuration
/// ```toml
/// [tls]
/// ca_cert_path    = "ca.pem"      # CA certificate (PEM)
/// agent_cert_path = "agent.pem"   # Agent certificate (PEM)
/// agent_key_path  = "agent.key"   # Agent private key (PEM), must be 0600
/// enabled         = true
/// ```
///
/// Wiring `rustls` to the axum acceptor is the open work this module is a
/// placeholder for.
use crate::config::TlsConfig;
use chronos_core::{ChronosError, ChronosResult};
use std::path::Path;
use tracing::warn;

/// Validate that all required TLS files exist and have correct permissions.
///
/// # Errors
/// Returns [`ChronosError::Config`] if any required file is missing or has
/// incorrect permissions (must be 0600 on Unix).
pub fn validate_tls_config(cfg: &TlsConfig) -> ChronosResult<()> {
    if !cfg.enabled {
        warn!(target: "chronos", "mTLS is DISABLED, plain HTTP in use. Not suitable for production.");
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

    // Deliberately not "mTLS validated": nothing here puts TLS on the wire, and a
    // log line claiming otherwise is how an operator ends up believing the
    // transport is encrypted when it is plain HTTP.
    warn!(
        target: "chronos",
        "TLS file paths and key permissions check out, but mTLS is NOT enforced: the acceptor \
         is plain HTTP. Requests are authenticated by MAC and are not confidential."
    );
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
                "TLS key '{path}' has mode {mode:o}, must be 0600. Run: chmod 600 {path}"
            )));
        }
    }

    Ok(())
}

/// Default retention window for seen nonces.
///
/// A nonce is remembered for at least this long, so a captured request cannot be
/// replayed inside the window no matter how much other traffic passes through.
pub const DEFAULT_NONCE_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);

/// Time-bounded nonce cache for replay protection.
///
/// A nonce is remembered for `window`, and a request carrying a remembered nonce
/// is refused. When the cache is full of entries that have not yet expired, the
/// request is refused rather than the oldest entry being dropped.
///
/// # Why eviction by count was wrong
///
/// This was a count-bounded FIFO: entry 1025 evicted entry 1. Eviction removed
/// the only record that a nonce had been used, so a captured request became
/// replayable once 1024 further requests had passed through, and the module doc
/// called it a "sliding window" when the window had no relation to time. The
/// replay check in `main.rs` runs after MAC verification, so an attacker cannot
/// flush the cache with unauthenticated junk, but ordinary operator traffic
/// flushes it for them.
///
/// Refusing on a full cache trades availability for soundness: a burst of more
/// than `capacity` authenticated requests inside one window is rejected until
/// entries age out. That is the correct direction for this system, since an
/// admitted replay of `/human-correction` resolves uncertainty the operator never
/// resolved.
///
/// # What this still does not give you
///
/// Requests carry no timestamp, so nothing bounds how old a captured request may
/// be. After `window` its nonce is forgotten and the replay succeeds. Closing
/// that needs a timestamp inside the MAC'd payload and a skew check against it,
/// which is a wire-format change and is not implemented here. Treat `window` as
/// the replay horizon, not as proof of its absence.
pub struct NonceCache {
    seen: std::collections::HashMap<[u8; 12], std::time::Instant>,
    order: std::collections::VecDeque<[u8; 12]>,
    capacity: usize,
    window: std::time::Duration,
}

impl NonceCache {
    /// Create a nonce cache holding up to `capacity` nonces for
    /// [`DEFAULT_NONCE_WINDOW`].
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_window(capacity, DEFAULT_NONCE_WINDOW)
    }

    /// Create a nonce cache with an explicit retention window.
    #[must_use]
    pub fn with_window(capacity: usize, window: std::time::Duration) -> Self {
        Self {
            seen: std::collections::HashMap::with_capacity(capacity),
            order: std::collections::VecDeque::with_capacity(capacity),
            capacity,
            window,
        }
    }

    /// Number of nonces currently retained, after dropping expired entries.
    pub fn len(&mut self) -> usize {
        self.drop_expired(std::time::Instant::now());
        self.order.len()
    }

    /// Whether the cache currently retains no nonces.
    pub fn is_empty(&mut self) -> bool {
        self.len() == 0
    }

    /// Record `nonce` as used, refusing it if it is a replay.
    ///
    /// Returns `true` if the nonce was fresh and is now recorded, `false` if it
    /// is a replay or if the cache is saturated with unexpired entries. The
    /// caller must reject the request on `false` in both cases: the two are not
    /// distinguished because a caller that could tell them apart could probe
    /// cache occupancy.
    pub fn check_and_insert(&mut self, nonce: &[u8; 12]) -> bool {
        let now = std::time::Instant::now();
        self.drop_expired(now);

        if self.seen.contains_key(nonce) {
            return false; // Replay inside the window.
        }
        if self.order.len() >= self.capacity {
            // Fail closed. Dropping the oldest entry here is what made replay
            // possible, so saturation is reported as a refusal instead.
            warn!(
                target: "chronos",
                capacity = self.capacity,
                window_secs = self.window.as_secs(),
                "nonce cache saturated with unexpired entries, refusing the request rather \
                 than forgetting a used nonce"
            );
            return false;
        }
        self.seen.insert(*nonce, now);
        self.order.push_back(*nonce);
        true
    }

    /// Drop entries older than the window.
    ///
    /// `order` is in insertion order and all entries share one window, so the
    /// expired entries are exactly a prefix.
    fn drop_expired(&mut self, now: std::time::Instant) {
        while let Some(front) = self.order.front() {
            let expired = self
                .seen
                .get(front)
                .is_none_or(|inserted| now.duration_since(*inserted) >= self.window);
            if !expired {
                break;
            }
            let front = *front;
            self.order.pop_front();
            self.seen.remove(&front);
        }
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

    /// A full cache must refuse new nonces, not forget old ones. The previous
    /// implementation evicted the oldest entry here, which is what made a
    /// captured request replayable after `capacity` further requests.
    #[test]
    fn test_nonce_cache_fails_closed_when_saturated() {
        let mut cache = NonceCache::new(4);
        for i in 0u8..4 {
            assert!(cache.check_and_insert(&[i; 12]), "nonce {i} must be fresh");
        }

        assert!(
            !cache.check_and_insert(&[4u8; 12]),
            "a saturated cache must refuse rather than evict"
        );
        assert!(
            !cache.check_and_insert(&[0u8; 12]),
            "the oldest nonce must still be remembered after saturation"
        );
        assert_eq!(cache.len(), 4, "a refused request must not take a slot");
    }

    /// Nonces are forgotten on a time bound, not a count bound. Once the window
    /// has passed the cache frees its slots, which is what keeps saturation from
    /// being permanent.
    #[test]
    fn test_nonce_cache_forgets_on_the_time_window() {
        let window = std::time::Duration::from_millis(40);
        let mut cache = NonceCache::with_window(2, window);

        assert!(cache.check_and_insert(&[0xAAu8; 12]));
        assert!(cache.check_and_insert(&[0xBBu8; 12]));
        assert!(
            !cache.check_and_insert(&[0xCCu8; 12]),
            "cache is full of unexpired entries"
        );

        std::thread::sleep(window + std::time::Duration::from_millis(20));

        assert!(cache.is_empty(), "entries past the window must be dropped");
        assert!(
            cache.check_and_insert(&[0xAAu8; 12]),
            "beyond the window the nonce is forgotten; the window is the replay horizon"
        );
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
