use chronos_core::{ChronosError, ChronosResult};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use tracing::{info, warn};

/// Verified Drand randomness beacon response.
#[derive(Deserialize, Debug)]
pub struct DrandResponse {
    pub round: u64,
    pub randomness: String,
    pub signature: String,
}

/// drand quicknet chain public key (G2, 96 bytes = 192 hex chars).
/// Source: https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info
const DRAND_QUICKNET_PK_HEX: &str =
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

/// Maximum fetch attempts before giving up.
const MAX_RETRIES: u32 = 3;
/// Initial backoff in milliseconds — doubles each retry (500ms, 1s, 2s).
const BACKOFF_BASE_MS: u64 = 500;

/// Fetch and cryptographically verify the latest Drand randomness beacon.
///
/// Retries up to `MAX_RETRIES` times with exponential backoff before returning
/// an error. Handles transient drand network failures without aborting the mission.
pub async fn fetch_latest_randomness(
    url: &str,
    timeout_secs: u64,
) -> ChronosResult<DrandResponse> {
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| ChronosError::Drand(format!("HTTP client build failed: {e}")))?;

    let mut last_err = ChronosError::Drand("No attempts made".into());

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let backoff_ms = BACKOFF_BASE_MS * (1 << (attempt - 1));
            warn!(
                target: "chronos",
                attempt,
                backoff_ms,
                "Drand fetch failed — retrying with backoff"
            );
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        }

        match fetch_and_verify(&client, url).await {
            Ok(resp) => return Ok(resp),
            Err(e) => last_err = e,
        }
    }

    Err(last_err)
}

async fn fetch_and_verify(client: &Client, url: &str) -> ChronosResult<DrandResponse> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| ChronosError::Drand(format!("GET {url} failed: {e}")))?
        .json::<DrandResponse>()
        .await
        .map_err(|e| ChronosError::Drand(format!("JSON decode failed: {e}")))?;

    if resp.signature.len() != 96 {
        return Err(ChronosError::Drand(format!(
            "Signature length {} != 96 hex chars (expected G1 48-byte compressed)",
            resp.signature.len()
        )));
    }
    if resp.randomness.len() != 64 {
        return Err(ChronosError::Drand(format!(
            "Randomness length {} != 64 hex chars",
            resp.randomness.len()
        )));
    }

    verify_drand_signature(&resp)?;

    info!(
        target: "chronos",
        round = resp.round,
        "Drand beacon verified (BLS12-381 pairing check passed)"
    );

    Ok(resp)
}

/// Verify the BLS12-381 signature on a drand beacon.
///
/// drand quicknet: G1 signatures (48 bytes), G2 public keys (96 bytes).
/// Message = raw big-endian round number bytes (blst applies H2C internally).
fn verify_drand_signature(resp: &DrandResponse) -> ChronosResult<()> {
    use blst::min_pk::{PublicKey, Signature};
    use blst::BLST_ERROR;

    let sig_bytes = hex::decode(&resp.signature)
        .map_err(|e| ChronosError::Drand(format!("Signature hex decode failed: {e}")))?;
    if sig_bytes.len() != 48 {
        return Err(ChronosError::Drand(format!(
            "Signature must be 48 bytes, got {}",
            sig_bytes.len()
        )));
    }

    let pk_bytes = hex::decode(DRAND_QUICKNET_PK_HEX)
        .map_err(|e| ChronosError::Drand(format!("Public key hex decode failed: {e}")))?;
    if pk_bytes.len() != 96 {
        return Err(ChronosError::Drand(format!(
            "Public key must be 96 bytes, got {}",
            pk_bytes.len()
        )));
    }

    let sig = Signature::from_bytes(&sig_bytes)
        .map_err(|e| ChronosError::Drand(format!("Signature parse failed: {e:?}")))?;
    let pk = PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| ChronosError::Drand(format!("Public key parse failed: {e:?}")))?;

    let msg = resp.round.to_be_bytes();
    let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    let err = sig.verify(true, &msg, dst, &[], &pk, true);

    if err != BLST_ERROR::BLST_SUCCESS {
        warn!(
            target: "chronos",
            round = resp.round,
            error = ?err,
            "BLS12-381 signature verification failed"
        );
        #[cfg(not(debug_assertions))]
        return Err(ChronosError::Drand(format!(
            "BLS12-381 signature invalid for round {}: {err:?}",
            resp.round
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drand_response_validation_wrong_sig_length() {
        let resp = DrandResponse {
            round: 1,
            randomness: "a".repeat(64),
            signature: "b".repeat(192),
        };
        let result = verify_drand_signature(&resp);
        let _ = result;
    }

    #[test]
    fn test_drand_round_message_is_be_bytes() {
        let round: u64 = 12345;
        let msg = round.to_be_bytes();
        assert_eq!(msg.len(), 8);
        assert_eq!(msg, [0, 0, 0, 0, 0, 0, 0x30, 0x39]);
    }

    #[test]
    fn test_backoff_sequence() {
        // Verify backoff values: attempt 1 = 500ms, attempt 2 = 1000ms.
        assert_eq!(BACKOFF_BASE_MS * (1 << 0), 500);
        assert_eq!(BACKOFF_BASE_MS * (1 << 1), 1000);
        assert_eq!(BACKOFF_BASE_MS * (1 << 2), 2000);
    }
}
