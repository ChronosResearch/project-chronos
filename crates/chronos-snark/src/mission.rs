//! The mission provisioning artifact — the public commitments a verifier holds.
//!
//! # Why this file is the load-bearing piece
//!
//! The erasure proof's soundness rests entirely on `sk_commit` and `ct_commit`
//! being fixed by somebody *other than the agent*, before the mission starts. If
//! the agent chose them, it could fabricate a key, encrypt it under a key of its
//! choosing, commit to both, and produce a perfectly valid proof about material
//! that was never time-locked. That is precisely the hole that made earlier
//! revisions of the circuit vacuous, and no amount of constraint-writing closes
//! it — it is closed by *who generates the commitments*.
//!
//! So CHRONOS has three roles, and they must be distinct:
//!
//! | Role | Holds | Produces |
//! |---|---|---|
//! | Provisioner (ground control) | `sk`, the modulus factors | `ct_sk.bin`, this artifact |
//! | Agent | `ct_sk.bin`, this artifact | the VDF output, the erasure proof |
//! | Verifier (anyone) | this artifact | accept / reject |
//!
//! The provisioner publishes [`MissionPublic`] and destroys `sk`. The agent
//! receives it and cannot alter it without invalidating every proof it later
//! produces. The verifier needs nothing but this file and the proof.
//!
//! # What is deliberately absent
//!
//! `containment_commit` is **not** in this artifact. It summarises how the mission
//! actually ran, so it cannot exist until the mission ends; the agent supplies it
//! at attestation time and [`crate::circuit`] constrains its terminal fields
//! against compile-time constants. Everything else is fixed in advance.
//!
//! # Encoding
//!
//! Field elements are 32-byte big-endian hex. JSON rather than a binary format
//! because this file is meant to be read by humans, pasted into grant appendices,
//! and diffed — it is a publication, not a wire format.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use chronos_core::{ChronosError, ChronosResult};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::circuit::PublicInputs;

/// Encode a field element as 32-byte big-endian hex, `0x`-prefixed.
#[must_use]
pub fn fr_to_hex(f: Fr) -> String {
    let be = f.into_bigint().to_bytes_be();
    let mut word = [0u8; 32];
    let start = 32usize.saturating_sub(be.len());
    word[start..].copy_from_slice(&be[be.len().saturating_sub(32)..]);
    format!("0x{}", word.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Parse a field element from `0x`-prefixed 32-byte big-endian hex.
///
/// Rejects non-canonical encodings rather than reducing them. A silently reduced
/// value would produce a commitment the agent cannot match, surfacing as an
/// unexplained proof failure much later.
///
/// # Errors
/// Returns [`ChronosError::Snark`] if the string is not 32 bytes of hex or is not
/// a canonical field element.
pub fn fr_from_hex(s: &str) -> ChronosResult<Fr> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 64 {
        return Err(ChronosError::Snark(format!(
            "field element must be 64 hex chars (32 bytes), got {}",
            stripped.len()
        )));
    }
    let bytes = (0..32)
        .map(|i| u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| ChronosError::Snark(format!("invalid hex in field element: {e}")))?;

    let f = Fr::from_be_bytes_mod_order(&bytes);
    if fr_to_hex(f) != format!("0x{}", stripped.to_lowercase()) {
        return Err(ChronosError::Snark(format!(
            "field element 0x{stripped} is not canonical for BN254 Fr"
        )));
    }
    Ok(f)
}

/// The published mission artifact.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MissionPublic {
    /// Artifact schema version. Bumped when the commitment definitions change,
    /// so an agent cannot silently consume an artifact built under different
    /// domain tags.
    pub version: u32,
    /// Human-readable mission identifier.
    pub mission_id: String,
    /// Sequential squarings the agent must perform.
    pub t_vdf_steps: u64,
    /// Wall-clock mission budget, in seconds.
    pub t_seconds: u64,
    /// Poseidon commitment to the VDF output the agent must reach.
    pub y_commit: String,
    /// Poseidon commitment to the time-locked ciphertext.
    pub ct_commit: String,
    /// Poseidon commitment to the plaintext secret key.
    pub sk_commit: String,
    /// Poseidon commitment to the mission identifier digest.
    pub mission_commit: String,
    /// Operation budget the containment monitor starts with.
    pub op_budget: u64,
    /// Disclosure budget in bits the containment monitor starts with.
    pub disclosure_budget_bits: u64,
}

/// Current [`MissionPublic::version`].
pub const MISSION_ARTIFACT_VERSION: u32 = 1;

impl MissionPublic {
    /// Build from field elements.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        mission_id: String,
        t_vdf_steps: u64,
        t_seconds: u64,
        y_commit: Fr,
        ct_commit: Fr,
        sk_commit: Fr,
        mission_commit: Fr,
        op_budget: u64,
        disclosure_budget_bits: u64,
    ) -> Self {
        Self {
            version: MISSION_ARTIFACT_VERSION,
            mission_id,
            t_vdf_steps,
            t_seconds,
            y_commit: fr_to_hex(y_commit),
            ct_commit: fr_to_hex(ct_commit),
            sk_commit: fr_to_hex(sk_commit),
            mission_commit: fr_to_hex(mission_commit),
            op_budget,
            disclosure_budget_bits,
        }
    }

    /// Validate and decode into the four provisioner-fixed commitments.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] on a version mismatch or a malformed
    /// commitment.
    pub fn commitments(&self) -> ChronosResult<[Fr; 4]> {
        if self.version != MISSION_ARTIFACT_VERSION {
            return Err(ChronosError::Snark(format!(
                "mission artifact version {} is not supported (expected {MISSION_ARTIFACT_VERSION}) — \
                 the commitment definitions changed; re-provision the mission",
                self.version
            )));
        }
        Ok([
            fr_from_hex(&self.y_commit)?,
            fr_from_hex(&self.ct_commit)?,
            fr_from_hex(&self.sk_commit)?,
            fr_from_hex(&self.mission_commit)?,
        ])
    }

    /// Assemble the full public input set by supplying the run-dependent
    /// containment commitment.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] if any stored commitment is malformed.
    pub fn to_public_inputs(&self, containment_commit: Fr) -> ChronosResult<PublicInputs> {
        let [y_commit, ct_commit, sk_commit, mission_commit] = self.commitments()?;
        Ok(PublicInputs {
            y_commit,
            ct_commit,
            sk_commit,
            mission_commit,
            containment_commit,
        })
    }

    /// Write as pretty-printed JSON.
    ///
    /// # Errors
    /// Returns [`ChronosError::Snark`] on serialization failure or
    /// [`ChronosError::Io`] on write failure.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> ChronosResult<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| ChronosError::Snark(format!("mission artifact serialization failed: {e}")))?;
        std::fs::write(path, json).map_err(ChronosError::Io)
    }

    /// Read from JSON, validating the version and every commitment.
    ///
    /// # Errors
    /// Returns [`ChronosError::Io`] if unreadable, or [`ChronosError::Snark`] if
    /// malformed.
    pub fn load<P: AsRef<Path>>(path: P) -> ChronosResult<Self> {
        let path_ref = path.as_ref();
        let text = std::fs::read_to_string(path_ref).map_err(ChronosError::Io)?;
        let parsed: Self = serde_json::from_str(&text).map_err(|e| {
            ChronosError::Snark(format!(
                "mission artifact '{}' is not valid JSON: {e}",
                path_ref.display()
            ))
        })?;
        // Validate eagerly so a malformed artifact fails at load rather than at
        // proof time, hours into a mission.
        parsed.commitments()?;
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MissionPublic {
        MissionPublic::new(
            "mission-alpha-001".into(),
            1_000,
            3_600,
            Fr::from(11u64),
            Fr::from(22u64),
            Fr::from(33u64),
            Fr::from(44u64),
            8,
            128,
        )
    }

    #[test]
    fn test_hex_round_trip() {
        for v in [0u64, 1, 255, u64::MAX] {
            let f = Fr::from(v);
            assert_eq!(fr_from_hex(&fr_to_hex(f)).expect("round trip"), f);
        }
    }

    #[test]
    fn test_hex_is_32_bytes() {
        let h = fr_to_hex(Fr::from(1u64));
        assert_eq!(h.len(), 66, "0x + 64 hex chars");
        assert!(h.ends_with('1'), "big-endian encoding, got {h}");
    }

    #[test]
    fn test_hex_accepts_unprefixed() {
        let h = fr_to_hex(Fr::from(7u64));
        let bare = h.trim_start_matches("0x");
        assert_eq!(fr_from_hex(bare).expect("bare hex"), Fr::from(7u64));
    }

    #[test]
    fn test_hex_rejects_wrong_length() {
        assert!(fr_from_hex("0xab").is_err());
        assert!(fr_from_hex(&"ab".repeat(33)).is_err());
    }

    #[test]
    fn test_hex_rejects_malformed() {
        assert!(fr_from_hex(&"zz".repeat(32)).is_err());
    }

    /// A value above the scalar modulus must be rejected, not reduced. Reduction
    /// would make two distinct artifacts commit to the same element.
    #[test]
    fn test_hex_rejects_non_canonical() {
        assert!(
            fr_from_hex(&"ff".repeat(32)).is_err(),
            "a value larger than the BN254 scalar modulus must be rejected"
        );
    }

    #[test]
    fn test_commitments_decode_in_order() {
        let [y, ct, sk, m] = sample().commitments().expect("decode");
        assert_eq!(y, Fr::from(11u64));
        assert_eq!(ct, Fr::from(22u64));
        assert_eq!(sk, Fr::from(33u64));
        assert_eq!(m, Fr::from(44u64));
    }

    #[test]
    fn test_to_public_inputs_places_containment_last() {
        let pi = sample()
            .to_public_inputs(Fr::from(99u64))
            .expect("assemble");
        let v = pi.to_vec();
        assert_eq!(v.len(), crate::circuit::PUBLIC_INPUT_COUNT);
        assert_eq!(v[0], Fr::from(11u64), "slot 0 is y_commit");
        assert_eq!(v[4], Fr::from(99u64), "slot 4 is containment_commit");
    }

    /// A version bump must be a hard failure. Silently accepting an artifact
    /// built under different domain tags would produce proofs that cannot verify,
    /// with no indication why.
    #[test]
    fn test_version_mismatch_rejected() {
        let mut m = sample();
        m.version = MISSION_ARTIFACT_VERSION + 1;
        let err = m.commitments().expect_err("version mismatch must fail");
        assert!(format!("{err}").contains("not supported"));
    }

    #[test]
    fn test_json_round_trip() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("chronos-mission-test-{}.json", std::process::id()));

        let original = sample();
        original.save(&path).expect("save");
        let loaded = MissionPublic::load(&path).expect("load");
        assert_eq!(loaded, original);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_load_rejects_garbage() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("chronos-mission-bad-{}.json", std::process::id()));
        std::fs::write(&path, b"{ not json").expect("write");
        assert!(MissionPublic::load(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_load_rejects_malformed_commitment() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("chronos-mission-badcommit-{}.json", std::process::id()));
        let mut m = sample();
        m.sk_commit = "0xnope".into();
        let json = serde_json::to_string(&m).expect("serialize");
        std::fs::write(&path, json).expect("write");
        assert!(
            MissionPublic::load(&path).is_err(),
            "a malformed commitment must fail at load, not at proof time"
        );
        std::fs::remove_file(&path).ok();
    }
}
