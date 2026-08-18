//! Agent configuration.
//!
//! Mission parameters that the *verifier* must agree on — `T`, the budgets, the
//! mission ID — are **not** read from here. They come from `mission_public.json`,
//! written by `chronos-provision`. Anything the agent could change unilaterally is
//! not a security parameter, so duplicating `t_vdf_steps` in a local TOML file
//! would invite the two to disagree, and the artifact is the one the commitments
//! were computed under.
//!
//! What lives here is genuinely local: listen addresses, file paths, timeouts.

use chronos_core::{ChronosError, ChronosResult};
use serde::Deserialize;

/// Top-level agent configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct ChronosConfig {
    pub paths: PathConfig,
    pub network: NetworkConfig,
    pub server: ServerConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub tls: TlsConfig,
}

/// On-disk artifacts.
#[derive(Debug, Deserialize, Clone)]
pub struct PathConfig {
    /// Published mission artifact from `chronos-provision`.
    pub mission_public: String,
    /// Time-locked key ciphertext.
    pub ct_sk: String,
    /// Beacon salt used at provisioning time.
    pub salt: String,
    /// VDF group modulus. Falls back to the published RSA-2048 when absent.
    pub cert_n: String,
    /// Groth16 proving key. Generated on first run if absent, then reused.
    ///
    /// Persistence is what makes external verification possible at all: a setup
    /// run per mission would change the verifying key every time, so no third
    /// party could ever check a proof.
    pub proving_key: String,
}

/// Request authentication.
#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    /// Whether to require an authenticated MAC on every request.
    ///
    /// Defaults to `true`. Disabling it is refused unless the API is bound to
    /// loopback — see [`ChronosConfig::validate`].
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Path to the 32-byte pre-shared operator key.
    #[serde(default)]
    pub key_path: Option<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            key_path: None,
        }
    }
}

fn default_true() -> bool {
    true
}

/// mTLS settings. Validated but not yet enforced by the axum acceptor.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub ca_cert_path: Option<String>,
    pub agent_cert_path: Option<String>,
    pub agent_key_path: Option<String>,
}

/// Outbound network settings.
#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    /// drand HTTP endpoint.
    pub drand_url: String,
    /// Request timeout in seconds.
    pub drand_timeout_secs: u64,
    /// Whether to fetch a live beacon.
    ///
    /// When `false` the agent uses the provisioned `salt.bin`. The salt must match
    /// what the key was sealed under, so a live fetch only works if the
    /// provisioner used that same beacon — see the note in `main.rs`.
    #[serde(default)]
    pub fetch_live_beacon: bool,
}

/// Listen addresses.
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub api_addr: String,
    pub metrics_addr: String,
}

impl ChronosConfig {
    /// Load from `config/default.toml`, an optional `config.toml`, then
    /// `CHRONOS__`-prefixed environment variables.
    ///
    /// # Errors
    /// Returns [`ChronosError::Config`] if any layer fails to parse or validation
    /// fails.
    pub fn load() -> ChronosResult<Self> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name("config/default"))
            .add_source(config::File::with_name("config").required(false))
            .add_source(
                config::Environment::with_prefix("CHRONOS")
                    .prefix_separator("__")
                    .separator("__"),
            )
            .build()
            .map_err(|e| ChronosError::Config(format!("config build failed: {e}")))?;

        let parsed: Self = cfg
            .try_deserialize()
            .map_err(|e| ChronosError::Config(format!("config deserialize failed: {e}")))?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Reject configurations that expose an unauthenticated API to the network.
    ///
    /// Disabling authentication is permitted only on loopback, where the trust
    /// boundary is the machine itself. Binding `0.0.0.0` with `auth.enabled =
    /// false` would put `/mission/init` — which starts a mission and can be made
    /// to abort one — in reach of anyone who can route to the host. That is
    /// refused at startup rather than warned about, because a warning in a log is
    /// not a control.
    ///
    /// # Errors
    /// Returns [`ChronosError::Config`] describing the misconfiguration.
    pub fn validate(&self) -> ChronosResult<()> {
        if self.auth.enabled && self.auth.key_path.is_none() {
            return Err(ChronosError::Config(
                "auth.enabled is true but auth.key_path is not set — \
                 generate a key with: head -c 32 /dev/urandom > operator.key"
                    .into(),
            ));
        }

        if !self.auth.enabled && !self.is_loopback_only() {
            return Err(ChronosError::Config(format!(
                "refusing to start: auth.enabled is false and api_addr is '{}', which is not \
                 loopback. An unauthenticated /mission/init reachable from the network lets any \
                 caller start or abort a mission. Either set auth.enabled = true or bind to \
                 127.0.0.1.",
                self.server.api_addr
            )));
        }

        Ok(())
    }

    /// Whether the API address is a loopback address.
    #[must_use]
    pub fn is_loopback_only(&self) -> bool {
        let host = self
            .server
            .api_addr
            .rsplit_once(':')
            .map_or(self.server.api_addr.as_str(), |(h, _)| h)
            .trim_matches(|c| c == '[' || c == ']');

        // Parse rather than string-match: "127.1", "127.0.0.001" and
        // "0177.0.0.1" are all loopback, and a substring check on "127.0.0.1"
        // would miss them while accepting "127.0.0.1.evil.com".
        host.parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(api_addr: &str, auth_enabled: bool, key: Option<&str>) -> ChronosConfig {
        ChronosConfig {
            paths: PathConfig {
                mission_public: "mission_public.json".into(),
                ct_sk: "ct_sk.bin".into(),
                salt: "salt.bin".into(),
                cert_n: "certN.bin".into(),
                proving_key: "erasure_pk.bin".into(),
            },
            network: NetworkConfig {
                drand_url: "https://example.invalid".into(),
                drand_timeout_secs: 10,
                fetch_live_beacon: false,
            },
            server: ServerConfig {
                api_addr: api_addr.into(),
                metrics_addr: "127.0.0.1:9090".into(),
            },
            auth: AuthConfig {
                enabled: auth_enabled,
                key_path: key.map(Into::into),
            },
            tls: TlsConfig::default(),
        }
    }

    #[test]
    fn test_auth_enabled_requires_a_key() {
        assert!(cfg("127.0.0.1:8080", true, None).validate().is_err());
        assert!(cfg("127.0.0.1:8080", true, Some("operator.key"))
            .validate()
            .is_ok());
    }

    /// The control this adds: no unauthenticated API on a routable address.
    #[test]
    fn test_unauthenticated_non_loopback_is_refused() {
        let err = cfg("0.0.0.0:8080", false, None)
            .validate()
            .expect_err("must refuse");
        assert!(
            format!("{err}").contains("not loopback"),
            "error should explain the refusal, got: {err}"
        );

        assert!(
            cfg("10.0.0.5:8080", false, None).validate().is_err(),
            "a LAN address is still not loopback"
        );
    }

    #[test]
    fn test_unauthenticated_loopback_is_allowed() {
        assert!(cfg("127.0.0.1:8080", false, None).validate().is_ok());
        assert!(cfg("[::1]:8080", false, None).validate().is_ok());
    }

    /// Loopback detection must parse, not substring-match.
    #[test]
    fn test_loopback_detection_is_not_string_matching() {
        // Alternative loopback spellings must be recognised.
        assert!(cfg("127.0.0.2:8080", false, None).is_loopback_only());
        assert!(cfg("[::1]:8080", false, None).is_loopback_only());

        // And a hostname that merely contains a loopback literal must not be.
        assert!(
            !cfg("127.0.0.1.evil.example:8080", false, None).is_loopback_only(),
            "a substring match would wrongly accept this host"
        );
        assert!(!cfg("0.0.0.0:8080", false, None).is_loopback_only());
        assert!(!cfg("example.com:8080", false, None).is_loopback_only());
    }

    #[test]
    fn test_auth_defaults_to_enabled() {
        assert!(AuthConfig::default().enabled, "authentication must default on");
    }
}
