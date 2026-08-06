use chronos_core::{ChronosError, ChronosResult};
use serde::Deserialize;

/// Top-level configuration for the CHRONOS agent.
#[derive(Debug, Deserialize, Clone)]
pub struct ChronosConfig {
    pub mission: MissionConfig,
    pub crypto: CryptoConfig,
    pub network: NetworkConfig,
    pub server: ServerConfig,
    /// mTLS configuration (optional; defaults to disabled).
    #[serde(default)]
    pub tls: TlsConfig,
    /// VDF backend: "wesolowski" or "isogeny".
    #[serde(default = "default_vdf_backend")]
    pub vdf_backend: String,
}

fn default_vdf_backend() -> String {
    "wesolowski".to_string()
}

/// TLS configuration (inlined here to avoid circular module dependency).
#[derive(Debug, Deserialize, Clone, Default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub ca_cert_path: Option<String>,
    pub agent_cert_path: Option<String>,
    pub agent_key_path: Option<String>,
}


/// Mission timing configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct MissionConfig {
    /// Total mission duration in seconds.
    pub t_seconds: u64,
    /// Number of VDF squaring steps.
    pub t_vdf_steps: u64,
}

/// Cryptographic configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct CryptoConfig {
    /// RSA modulus bit-length.
    pub rsa_bits: u32,
    /// Path to the MPC-generated RSA modulus (big-endian binary).
    pub cert_n_path: String,
    /// Path to the FHE-encrypted secret key.
    pub ct_sk_path: String,
}

/// Network configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    /// Drand HTTP API URL.
    pub drand_url: String,
    /// HTTP request timeout in seconds.
    pub drand_timeout_secs: u64,
}

/// HTTP server addresses.
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// Axum API listen address (e.g. `127.0.0.1:8080`).
    pub api_addr: String,
    /// Prometheus metrics listen address.
    pub metrics_addr: String,
}

impl ChronosConfig {
    /// Load configuration from the layered sources:
    ///
    /// 1. `config/default.toml` (compiled-in defaults).
    /// 2. `config.toml` in the current working directory (optional override).
    /// 3. Environment variables prefixed with `CHRONOS__`.
    ///
    /// # Errors
    /// Returns [`ChronosError::Config`] if any layer fails to parse.
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
            .map_err(|e| ChronosError::Config(format!("Config build failed: {e}")))?;

        cfg.try_deserialize::<ChronosConfig>()
            .map_err(|e| ChronosError::Config(format!("Config deserialize failed: {e}")))
    }
}
