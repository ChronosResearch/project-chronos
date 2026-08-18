//! drand beacon client with BLS12-381 verification.
//!
//! # Three defects this module previously had
//!
//! All three concerned the same 40 lines and were mutually masking, which is why
//! a passing test suite did not catch any of them.
//!
//! **1. Wrong curve pairing.** drand's quicknet uses scheme
//! `bls-unchained-g1-rfc9380`, whose group public key lives on **G2** (96 bytes)
//! and whose signatures live on **G1** (48 bytes). In `blst` terms that is the
//! `min_sig` variant. The previous code used `blst::min_pk`, where the assignment
//! is reversed: `min_pk::Signature` is a G2 point and expects 96 compressed
//! bytes. It was handed the 48-byte G1 signature, so `Signature::from_bytes`
//! returned an error on **every** beacon, in every build profile. The practical
//! consequence was that `/mission/init` could never complete: the drand fetch
//! exhausted its three retries and aborted the mission.
//!
//! **2. Wrong signed message.** drand does not sign the round number directly. Per
//! `crypto/schemes.go`, the unchained schemes sign
//! `SHA-256(round_be_u64)` — the digest, which the BLS layer then maps to the
//! curve. The previous code passed the raw 8 round bytes. An earlier audit entry
//! recorded this as *fixed*, having changed it in the wrong direction.
//!
//! **3. Verification was disabled in dev builds.** The failure return was behind
//! `#[cfg(not(debug_assertions))]`:
//!
//! ```ignore
//! if err != BLST_ERROR::BLST_SUCCESS {
//!     warn!(...);
//!     #[cfg(not(debug_assertions))]
//!     return Err(...);
//! }
//! Ok(())   // <-- debug builds reach here with an invalid signature
//! ```
//!
//! Under `cargo build` and `cargo test`, a forged beacon was accepted and its
//! randomness fed into the KDF as the salt. This is the same
//! `#[cfg(debug_assertions)]` pattern that AUDIT.md #28 claims was removed
//! "everywhere"; it survived here.
//!
//! # Why not simply depend on `drand-verify`
//!
//! [`drand-verify`](https://github.com/CosmWasm/drand-verify) (Apache-2.0) is
//! audited, production-used, and has exactly the right `G2PubkeyRfc` type. It was
//! considered and rejected for one reason: it is built on the `bls12_381` +
//! `pairing` stack, while this workspace already depends on `blst` for the same
//! curve. Adopting it would mean carrying two independent BLS12-381
//! implementations in a binary whose whole purpose is minimising trusted
//! surface.
//!
//! The bug was never in `blst`; it was in how this module drove it. So the fix
//! keeps `blst` and corrects the usage. What is borrowed from `drand-verify` is
//! its **test vector**, which is what turns this module from "compiles" into
//! "demonstrably verifies a real mainnet beacon" — see
//! [`tests::test_verifies_real_quicknet_beacon`].
//!
//! Reference: drand `crypto/schemes.go`, `NewPedersenBLSUnchainedG1`.
//! Test vector: `drand-verify`'s `verify_works_for_g1g2_swapped_rfc`, quicknet
//! round 123. Content rephrased for compliance with licensing restrictions.

use chronos_core::{ChronosError, ChronosResult};
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::{info, warn};

/// A drand beacon as returned by the HTTP API.
#[derive(Deserialize, Debug, Clone)]
pub struct DrandResponse {
    /// Round number. This is the value that is signed.
    pub round: u64,
    /// Hex-encoded randomness, defined as `SHA-256(signature)`.
    pub randomness: String,
    /// Hex-encoded threshold BLS signature. 48 bytes compressed on G1.
    pub signature: String,
}

/// drand quicknet group public key: 96 bytes compressed on G2.
///
/// Chain hash `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`.
/// Verified against `drand-verify`'s quicknet test vector in
/// [`tests::test_verifies_real_quicknet_beacon`], so a typo here cannot pass
/// unnoticed.
const DRAND_QUICKNET_PK_HEX: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

/// Compressed size of a quicknet signature: a G1 point.
const SIG_BYTES: usize = 48;
/// Compressed size of the quicknet group public key: a G2 point.
const PK_BYTES: usize = 96;
/// Size of the randomness value.
const RANDOMNESS_BYTES: usize = 32;

/// RFC 9380 domain separation tag for hash-to-G1, as used by quicknet.
///
/// `blst` applies hash-to-curve internally, so the DST is passed to `verify`
/// rather than applied here.
const DST_G1: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// Maximum fetch attempts.
const MAX_RETRIES: u32 = 3;
/// Initial backoff, doubling per retry: 500ms, 1s, 2s.
const BACKOFF_BASE_MS: u64 = 500;

/// The message drand signs for an unchained beacon: `SHA-256(round_be_u64)`.
///
/// Kept as a named function so [`tests::test_message_is_sha256_of_round`] can pin
/// it. The previous implementation inlined the raw round bytes here, and because
/// nothing asserted the message construction, the error was invisible.
fn beacon_message(round: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(round.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Fetch and verify the latest beacon, retrying transient network failures.
///
/// Retries cover *network* failures only. A beacon that fetches successfully but
/// fails verification is returned as an error immediately and is not retried:
/// retrying a cryptographic failure would only mask an attack.
///
/// # Errors
/// Returns [`ChronosError::Drand`] if every attempt fails.
pub async fn fetch_latest_randomness(
    url: &str,
    timeout_secs: u64,
) -> ChronosResult<DrandResponse> {
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| ChronosError::Drand(format!("HTTP client build failed: {e}")))?;

    let mut last_err = ChronosError::Drand("no attempts made".into());

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let backoff_ms = BACKOFF_BASE_MS * (1u64 << (attempt - 1));
            warn!(
                target: "chronos",
                attempt,
                backoff_ms,
                "drand fetch failed — retrying with backoff"
            );
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        }

        match fetch_once(&client, url).await {
            Ok(resp) => return Ok(resp),
            Err(e) => last_err = e,
        }
    }

    Err(last_err)
}

async fn fetch_once(client: &Client, url: &str) -> ChronosResult<DrandResponse> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| ChronosError::Drand(format!("GET {url} failed: {e}")))?
        .json::<DrandResponse>()
        .await
        .map_err(|e| ChronosError::Drand(format!("JSON decode failed: {e}")))?;

    verify_beacon(&resp)?;

    info!(
        target: "chronos",
        round = resp.round,
        "drand beacon verified (BLS12-381 pairing check passed)"
    );

    Ok(resp)
}

/// Decode and fully verify a beacon.
///
/// Two independent checks, both mandatory:
///
/// 1. The threshold BLS signature is valid for `SHA-256(round)` under the
///    quicknet group key.
/// 2. The advertised `randomness` equals `SHA-256(signature)`.
///
/// Check 2 matters because the *randomness*, not the signature, is what becomes
/// the KDF salt. Verifying only the signature would leave the field the protocol
/// actually consumes unauthenticated, so a malicious endpoint could serve a valid
/// signature alongside arbitrary randomness.
///
/// # Errors
/// Returns [`ChronosError::Drand`] on any malformed field or failed check. There
/// is no build profile in which a failed check is tolerated.
pub fn verify_beacon(resp: &DrandResponse) -> ChronosResult<()> {
    use blst::min_sig::{PublicKey, Signature};
    use blst::BLST_ERROR;

    // ── Decode ───────────────────────────────────────────────────────────────
    let sig_bytes = hex::decode(&resp.signature)
        .map_err(|e| ChronosError::Drand(format!("signature hex decode failed: {e}")))?;
    if sig_bytes.len() != SIG_BYTES {
        return Err(ChronosError::Drand(format!(
            "quicknet signature must be {SIG_BYTES} bytes (compressed G1), got {}",
            sig_bytes.len()
        )));
    }

    let randomness = hex::decode(&resp.randomness)
        .map_err(|e| ChronosError::Drand(format!("randomness hex decode failed: {e}")))?;
    if randomness.len() != RANDOMNESS_BYTES {
        return Err(ChronosError::Drand(format!(
            "randomness must be {RANDOMNESS_BYTES} bytes, got {}",
            randomness.len()
        )));
    }

    let pk_bytes = hex::decode(DRAND_QUICKNET_PK_HEX)
        .map_err(|e| ChronosError::Drand(format!("group key hex decode failed: {e}")))?;
    if pk_bytes.len() != PK_BYTES {
        return Err(ChronosError::Drand(format!(
            "quicknet group key must be {PK_BYTES} bytes (compressed G2), got {}",
            pk_bytes.len()
        )));
    }

    // ── Check 1: threshold BLS signature ─────────────────────────────────────
    //
    // `min_sig`, not `min_pk`: quicknet's key is on G2 and its signature on G1.
    let sig = Signature::from_bytes(&sig_bytes).map_err(|e| {
        ChronosError::Drand(format!("signature is not a valid G1 point: {e:?}"))
    })?;
    let pk = PublicKey::from_bytes(&pk_bytes).map_err(|e| {
        ChronosError::Drand(format!("group key is not a valid G2 point: {e:?}"))
    })?;

    let msg = beacon_message(resp.round);
    // `sig_groupcheck = true` and `pk_validate = true`: pay the subgroup checks.
    // Skipping them admits small-subgroup and invalid-curve attacks, and this
    // runs once per mission, so the cost is irrelevant.
    let err = sig.verify(true, &msg, DST_G1, &[], &pk, true);
    if err != BLST_ERROR::BLST_SUCCESS {
        return Err(ChronosError::Drand(format!(
            "BLS12-381 signature invalid for round {}: {err:?}",
            resp.round
        )));
    }

    // ── Check 2: randomness is the digest of the signature ───────────────────
    let expected = Sha256::digest(&sig_bytes);
    if expected.as_slice() != randomness.as_slice() {
        return Err(ChronosError::Drand(format!(
            "round {} randomness does not equal SHA-256(signature) — \
             the endpoint served a valid signature with substituted randomness",
            resp.round
        )));
    }

    Ok(())
}

/// The verified 32-byte salt: the beacon's randomness.
///
/// # Errors
/// Returns [`ChronosError::Drand`] if the beacon does not verify or the
/// randomness is not 32 bytes. Callers must obtain the salt through this function
/// rather than decoding `resp.randomness` directly, so verification cannot be
/// bypassed by accident.
pub fn verified_salt(resp: &DrandResponse) -> ChronosResult<[u8; RANDOMNESS_BYTES]> {
    verify_beacon(resp)?;
    let bytes = hex::decode(&resp.randomness)
        .map_err(|e| ChronosError::Drand(format!("randomness hex decode failed: {e}")))?;
    let mut out = [0u8; RANDOMNESS_BYTES];
    if bytes.len() != RANDOMNESS_BYTES {
        return Err(ChronosError::Drand(format!(
            "randomness must be {RANDOMNESS_BYTES} bytes, got {}",
            bytes.len()
        )));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real mainnet quicknet beacon, round 123.
    ///
    /// Test vector from `drand-verify`'s `verify_works_for_g1g2_swapped_rfc`
    /// (Apache-2.0), cross-checkable against
    /// `https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/123`.
    ///
    /// This is the test the module previously lacked entirely. Every one of the
    /// three defects described in the module docs fails it.
    const QUICKNET_ROUND_123_SIG: &str = "b75c69d0b72a5d906e854e808ba7e2accb1542ac355ae486d591aa9d43765482e26cd02df835d3546d23c4b13e0dfc92";

    fn round_123() -> DrandResponse {
        let sig = hex::decode(QUICKNET_ROUND_123_SIG).expect("test vector must decode");
        DrandResponse {
            round: 123,
            randomness: hex::encode(Sha256::digest(&sig)),
            signature: QUICKNET_ROUND_123_SIG.to_string(),
        }
    }

    // ── The headline test ───────────────────────────────────────────────────

    /// Verification must succeed on a genuine mainnet beacon.
    ///
    /// This runs offline — no network, no flakiness — because the beacon is a
    /// fixed historical value.
    #[test]
    fn test_verifies_real_quicknet_beacon() {
        verify_beacon(&round_123())
            .expect("a genuine quicknet beacon must verify; if this fails the curve pairing, the DST, or the message construction is wrong");
    }

    /// And it must be usable as a salt through the guarded accessor.
    #[test]
    fn test_verified_salt_returns_32_bytes() {
        let salt = verified_salt(&round_123()).expect("salt must be available");
        assert_eq!(salt.len(), 32);
        assert_ne!(salt, [0u8; 32], "salt must not be all-zero");
    }

    // ── The three regressions ───────────────────────────────────────────────

    /// Regression for defect 2. drand signs the SHA-256 digest of the round, not
    /// the raw round bytes.
    #[test]
    fn test_message_is_sha256_of_round() {
        let msg = beacon_message(123);
        let expected = Sha256::digest(123u64.to_be_bytes());
        assert_eq!(msg.as_slice(), expected.as_slice());
        assert_eq!(msg.len(), 32, "the signed message is a 32-byte digest");
        assert_ne!(
            msg.as_slice(),
            123u64.to_be_bytes().as_slice(),
            "the raw round bytes are not the signed message"
        );
    }

    /// Regression for defect 3: an invalid signature must be rejected in **this**
    /// build profile, whichever profile the suite is compiled in.
    ///
    /// A `#[cfg(not(debug_assertions))]` guard on the failure path makes this test
    /// fail under `cargo test`, which is the point.
    #[test]
    fn test_invalid_signature_rejected_in_every_build_profile() {
        let mut resp = round_123();
        let mut sig = hex::decode(QUICKNET_ROUND_123_SIG).expect("decode");
        sig[0] ^= 0x01;
        resp.signature = hex::encode(&sig);
        resp.randomness = hex::encode(Sha256::digest(&sig));

        let err = verify_beacon(&resp)
            .expect_err("a tampered signature must be rejected regardless of build profile");
        let msg = format!("{err}");
        assert!(
            msg.contains("invalid") || msg.contains("not a valid"),
            "error should name the signature failure, got: {msg}"
        );
    }

    /// The round number must be bound: a valid signature replayed under a
    /// different round must fail.
    #[test]
    fn test_round_is_bound_to_the_signature() {
        let mut resp = round_123();
        resp.round = 124;
        assert!(
            verify_beacon(&resp).is_err(),
            "a beacon replayed at another round must be rejected"
        );
    }

    /// Check 2: the field the protocol actually consumes must be authenticated.
    #[test]
    fn test_substituted_randomness_rejected() {
        let mut resp = round_123();
        resp.randomness = hex::encode([0x42u8; 32]);
        let err = verify_beacon(&resp).expect_err("substituted randomness must be rejected");
        assert!(
            format!("{err}").contains("SHA-256(signature)"),
            "error should name the randomness mismatch, got: {err}"
        );
    }

    // ── Malformed input ─────────────────────────────────────────────────────

    #[test]
    fn test_wrong_signature_length_rejected() {
        let mut resp = round_123();
        // 96 bytes is the G2 length — the size the old `min_pk` code expected.
        resp.signature = "ab".repeat(96);
        let err = verify_beacon(&resp).expect_err("wrong length must be rejected");
        assert!(format!("{err}").contains("48 bytes"));
    }

    #[test]
    fn test_malformed_hex_rejected() {
        let mut resp = round_123();
        resp.signature = "zz".repeat(48);
        assert!(verify_beacon(&resp).is_err());

        let mut resp = round_123();
        resp.randomness = "zz".repeat(32);
        assert!(verify_beacon(&resp).is_err());
    }

    #[test]
    fn test_wrong_randomness_length_rejected() {
        let mut resp = round_123();
        resp.randomness = "ab".repeat(16);
        let err = verify_beacon(&resp).expect_err("short randomness must be rejected");
        assert!(format!("{err}").contains("32 bytes"));
    }

    /// A signature that is well-formed hex of the right length but not a curve
    /// point must be rejected at parse time, not silently accepted.
    #[test]
    fn test_non_curve_point_rejected() {
        let mut resp = round_123();
        resp.signature = "ff".repeat(48);
        resp.randomness = hex::encode(Sha256::digest(vec![0xffu8; 48]));
        assert!(verify_beacon(&resp).is_err());
    }

    // ── Configuration sanity ────────────────────────────────────────────────

    #[test]
    fn test_group_key_is_96_bytes_on_g2() {
        let pk = hex::decode(DRAND_QUICKNET_PK_HEX).expect("group key must decode");
        assert_eq!(pk.len(), PK_BYTES);
        // Must parse as a G2 point under min_sig.
        blst::min_sig::PublicKey::from_bytes(&pk)
            .expect("quicknet group key must be a valid compressed G2 point");
    }

    #[test]
    fn test_dst_matches_rfc9380_g1() {
        assert_eq!(DST_G1, b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");
    }

    #[test]
    fn test_backoff_sequence() {
        assert_eq!(BACKOFF_BASE_MS * (1u64 << 0), 500);
        assert_eq!(BACKOFF_BASE_MS * (1u64 << 1), 1000);
        assert_eq!(BACKOFF_BASE_MS * (1u64 << 2), 2000);
    }
}
