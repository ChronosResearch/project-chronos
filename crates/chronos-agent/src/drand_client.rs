use chronos_core::{ChronosError, ChronosResult};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

/// Verified Drand randomness beacon response.
#[derive(Deserialize, Debug)]
pub struct DrandResponse {
    /// Sequential round number.
    pub round: u64,
    /// 32-byte randomness, hex-encoded.
    pub randomness: String,
    /// BLS12-381 signature over the round, hex-encoded.
    pub signature: String,
}

/// Fetch the latest Drand randomness beacon from the configured HTTP endpoint.
///
/// The function performs length-based sanity checks on the response before
/// returning.  Full BLS12-381 signature verification is left for the production
/// integration with the `bls12_381` crate.
///
/// # Arguments
/// * `url`         – Full URL to the Drand HTTP API (from config, not hardcoded).
/// * `timeout_secs` – Request timeout.
///
/// # Errors
/// Returns [`ChronosError::Drand`] on network failure or invalid response.
pub async fn fetch_latest_randomness(
    url: &str,
    timeout_secs: u64,
) -> ChronosResult<DrandResponse> {
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| ChronosError::Drand(format!("HTTP client build failed: {e}")))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| ChronosError::Drand(format!("GET {url} failed: {e}")))?
        .json::<DrandResponse>()
        .await
        .map_err(|e| ChronosError::Drand(format!("JSON decode failed: {e}")))?;

    // Structural validation: 96-byte BLS sig = 192 hex chars; 32-byte randomness = 64 hex chars.
    if resp.signature.len() != 192 {
        return Err(ChronosError::Drand(format!(
            "Signature length {} != 192 hex chars",
            resp.signature.len()
        )));
    }
    if resp.randomness.len() != 64 {
        return Err(ChronosError::Drand(format!(
            "Randomness length {} != 64 hex chars",
            resp.randomness.len()
        )));
    }

    // TODO(production): verify resp.signature over round using bls12_381::G1Affine.
    // Until then, length checks prevent obviously malformed beacons.
    tracing::info!(
        target: "chronos",
        round = resp.round,
        "Drand beacon validated (length check only — full BLS pending)"
    );

    Ok(resp)
}
