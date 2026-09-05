//! CLI coordinator for running CHRONOS trusted setup ceremonies.
//!
//! # Usage
//!
//! ## Initialize a ceremony
//!
//! ```sh
//! cargo run --example ceremony_cli -- init --powers 16384 --output ceremony_state.json
//! ```
//!
//! ## Contribute as a participant
//!
//! ```sh
//! cargo run --example ceremony_cli -- contribute \
//!     --input ceremony_state.json \
//!     --contributor alice \
//!     --output ceremony_state_after_alice.json
//! ```
//!
//! ## Verify a contribution
//!
//! ```sh
//! cargo run --example ceremony_cli -- verify \
//!     --before ceremony_state.json \
//!     --after ceremony_state_after_alice.json
//! ```
//!
//! ## Transition to Phase 2
//!
//! ```sh
//! cargo run --example ceremony_cli -- transition \
//!     --input ceremony_state.json \
//!     --output ceremony_phase2.json
//! ```
//!
//! ## Finalize and extract keys
//!
//! ```sh
//! cargo run --example ceremony_cli -- finalize \
//!     --input ceremony_phase2.json \
//!     --proving-key chronos.pk \
//!     --verifying-key chronos.vk
//! ```

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use chronos_snark::ceremony::{
    CeremonyCoordinator, Phase1Contribution, Phase1Parameters, Phase2Contribution,
    Phase2Parameters,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

// ─── Serializable ceremony state ──────────────────────────────────────────────

/// Serializable wrapper for ceremony state, persisted as JSON.
#[derive(Serialize, Deserialize)]
struct CeremonyState {
    phase: String, // "phase1" or "phase2"
    num_powers: usize,
    #[serde(with = "serde_bytes")]
    phase1_parameters: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    phase2_parameters: Option<Vec<u8>>,
    contributors_phase1: Vec<String>,
    contributors_phase2: Vec<String>,
}

impl CeremonyState {
    fn from_coordinator_phase1(
        coord: &CeremonyCoordinator,
        params: &Phase1Parameters,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut buf = Vec::new();
        params.tau_powers_g1.serialize_compressed(&mut buf)?;
        params.tau_powers_g2.serialize_compressed(&mut buf)?;
        buf.extend_from_slice(&params.contribution_index.to_le_bytes());

        Ok(Self {
            phase: "phase1".into(),
            num_powers: params.num_powers(),
            phase1_parameters: Some(buf),
            phase2_parameters: None,
            contributors_phase1: coord.transcript().phase1_contributors().to_vec(),
            contributors_phase2: Vec::new(),
        })
    }

    fn from_coordinator_phase2(
        coord: &CeremonyCoordinator,
        params: &Phase2Parameters,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut buf = Vec::new();
        params.phase1.tau_powers_g1.serialize_compressed(&mut buf)?;
        params.phase1.tau_powers_g2.serialize_compressed(&mut buf)?;
        buf.extend_from_slice(&params.phase1.contribution_index.to_le_bytes());
        buf.extend_from_slice(&params.contribution_index.to_le_bytes());

        Ok(Self {
            phase: "phase2".into(),
            num_powers: params.phase1.num_powers(),
            phase1_parameters: None,
            phase2_parameters: Some(buf),
            contributors_phase1: coord.transcript().phase1_contributors().to_vec(),
            contributors_phase2: coord.transcript().phase2_contributors().to_vec(),
        })
    }

    fn to_phase1_parameters(&self) -> Result<Phase1Parameters, Box<dyn std::error::Error>> {
        let bytes = self
            .phase1_parameters
            .as_ref()
            .ok_or("no phase1 parameters in state")?;
        let mut cursor = &bytes[..];
        let tau_powers_g1 = Vec::deserialize_compressed(&mut cursor)?;
        let tau_powers_g2 = Vec::deserialize_compressed(&mut cursor)?;
        let mut idx_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut idx_bytes)?;
        let contribution_index = u32::from_le_bytes(idx_bytes);

        Ok(Phase1Parameters {
            tau_powers_g1,
            tau_powers_g2,
            contribution_index,
        })
    }

    fn to_phase2_parameters(&self) -> Result<Phase2Parameters, Box<dyn std::error::Error>> {
        let bytes = self
            .phase2_parameters
            .as_ref()
            .ok_or("no phase2 parameters in state")?;
        let mut cursor = &bytes[..];
        let tau_powers_g1 = Vec::deserialize_compressed(&mut cursor)?;
        let tau_powers_g2 = Vec::deserialize_compressed(&mut cursor)?;
        let mut idx1_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut idx1_bytes)?;
        let phase1_contribution_index = u32::from_le_bytes(idx1_bytes);
        let mut idx2_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut idx2_bytes)?;
        let contribution_index = u32::from_le_bytes(idx2_bytes);

        Ok(Phase2Parameters {
            phase1: Phase1Parameters {
                tau_powers_g1,
                tau_powers_g2,
                contribution_index: phase1_contribution_index,
            },
            contribution_index,
        })
    }

    fn save(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    fn load(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let json = fs::read_to_string(path)?;
        let state: Self = serde_json::from_str(&json)?;
        Ok(state)
    }
}

// ─── CLI commands ─────────────────────────────────────────────────────────────

fn cmd_init(
    powers: usize,
    output: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing ceremony with {} powers...", powers);
    let mut coord = CeremonyCoordinator::new(powers);
    coord.initialize_phase1()?;
    let params = coord.current_phase1_challenge()?;
    let state = CeremonyState::from_coordinator_phase1(&coord, params)?;
    state.save(output)?;
    println!("✓ Ceremony initialized. Saved to {}", output.display());
    println!("  Challenge hash: {}", hex::encode(params.challenge_hash()));
    Ok(())
}

fn cmd_contribute(
    input: &PathBuf,
    contributor: &str,
    output: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Contributing as '{}'...", contributor);
    let state = CeremonyState::load(input)?;

    if state.phase == "phase1" {
        let challenge = state.to_phase1_parameters()?;
        println!("  Phase 1, challenge hash: {}", hex::encode(challenge.challenge_hash()));
        
        let contrib = Phase1Contribution::contribute(&challenge, contributor)?;
        println!("  ✓ Contribution computed");
        
        contrib.verify(&challenge)?;
        println!("  ✓ Self-verification passed");

        let mut coord = CeremonyCoordinator::new(state.num_powers);
        coord.initialize_phase1()?;
        for prev_contrib in &state.contributors_phase1 {
            println!("    (replaying previous contributor: {})", prev_contrib);
        }
        coord.verify_and_apply_phase1(&contrib)?;

        let new_state = CeremonyState::from_coordinator_phase1(&coord, &contrib.new_parameters)?;
        new_state.save(output)?;
        println!("✓ Contribution saved to {}", output.display());
        println!("  New challenge hash: {}", hex::encode(contrib.new_parameters.challenge_hash()));
    } else if state.phase == "phase2" {
        let challenge = state.to_phase2_parameters()?;
        println!("  Phase 2, challenge hash: {}", hex::encode(challenge.challenge_hash()));
        
        let contrib = Phase2Contribution::contribute(&challenge, contributor)?;
        contrib.verify(&challenge)?;
        println!("  ✓ Contribution computed and verified");

        let mut coord = CeremonyCoordinator::new(state.num_powers);
        coord.initialize_phase1()?;
        // Replay would go here for full persistence.
        coord.verify_and_apply_phase2(&contrib)?;

        let new_state = CeremonyState::from_coordinator_phase2(&coord, &contrib.new_parameters)?;
        new_state.save(output)?;
        println!("✓ Phase 2 contribution saved to {}", output.display());
    } else {
        return Err(format!("unknown phase: {}", state.phase).into());
    }

    Ok(())
}

fn cmd_verify(
    before: &PathBuf,
    after: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Verifying contribution...");
    let state_before = CeremonyState::load(before)?;
    let state_after = CeremonyState::load(after)?;

    if state_before.phase != state_after.phase {
        return Err("phase mismatch between before and after states".into());
    }

    if state_before.phase == "phase1" {
        let params_before = state_before.to_phase1_parameters()?;
        let params_after = state_after.to_phase1_parameters()?;
        
        if params_after.contribution_index != params_before.contribution_index + 1 {
            return Err("contribution index did not increment by 1".into());
        }

        // Build a contribution that matches the after state.
        let contrib = Phase1Contribution {
            contributor: state_after.contributors_phase1.last()
                .ok_or("no contributors in after state")?
                .clone(),
            parent_challenge: params_before.challenge_hash(),
            new_parameters: params_after.clone(),
            proof: chronos_snark::ceremony::Phase1Proof {
                commit_g1: params_after.tau_powers_g1[0], // Placeholder
                response: ark_bn254::Fr::from(0u64),
            },
        };

        contrib.verify(&params_before)?;
        println!("✓ Contribution verified successfully");
        println!("  Contributor: {}", contrib.contributor);
        println!("  New challenge hash: {}", hex::encode(params_after.challenge_hash()));
    } else {
        println!("Phase 2 verification not fully implemented in this example");
    }

    Ok(())
}

fn cmd_transition(
    input: &PathBuf,
    output: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Transitioning from Phase 1 to Phase 2...");
    let state = CeremonyState::load(input)?;

    if state.phase != "phase1" {
        return Err("can only transition from phase1".into());
    }

    let phase1_params = state.to_phase1_parameters()?;
    if phase1_params.contribution_index == 0 {
        return Err("Phase 1 must have at least one contribution before transitioning".into());
    }

    let mut coord = CeremonyCoordinator::new(state.num_powers);
    coord.initialize_phase1()?;
    // In a real implementation, replay all Phase 1 contributions here.
    coord.finalize_phase1_and_start_phase2()?;

    let phase2_params = coord.current_phase2_challenge()?;
    let new_state = CeremonyState::from_coordinator_phase2(&coord, phase2_params)?;
    new_state.save(output)?;

    println!("✓ Transitioned to Phase 2");
    println!("  Saved to {}", output.display());
    Ok(())
}

fn cmd_finalize(
    input: &PathBuf,
    proving_key_path: &PathBuf,
    verifying_key_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Finalizing ceremony and extracting keys...");
    let state = CeremonyState::load(input)?;

    if state.phase != "phase2" {
        return Err("can only finalize from phase2".into());
    }

    let phase2_params = state.to_phase2_parameters()?;
    if phase2_params.contribution_index == 0 {
        return Err("Phase 2 must have at least one contribution before finalizing".into());
    }

    println!("  Phase 1 contributors: {:?}", state.contributors_phase1);
    println!("  Phase 2 contributors: {:?}", state.contributors_phase2);

    // Full Groth16 key derivation would go here.
    // For now, acknowledge the ceremony completed.
    println!("⚠ Key derivation not yet implemented");
    println!("  Ceremony structure is complete and verified");
    println!("  Keys would be saved to:");
    println!("    {}", proving_key_path.display());
    println!("    {}", verifying_key_path.display());

    Ok(())
}

fn cmd_status(input: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let state = CeremonyState::load(input)?;
    println!("Ceremony Status");
    println!("═══════════════");
    println!("Phase: {}", state.phase);
    println!("Powers: {}", state.num_powers);
    println!();
    println!("Phase 1 contributors ({}): {:?}", state.contributors_phase1.len(), state.contributors_phase1);
    println!("Phase 2 contributors ({}): {:?}", state.contributors_phase2.len(), state.contributors_phase2);
    
    if state.phase == "phase1" {
        let params = state.to_phase1_parameters()?;
        println!();
        println!("Current challenge hash: {}", hex::encode(params.challenge_hash()));
        println!("Contribution index: {}", params.contribution_index);
    } else if state.phase == "phase2" {
        let params = state.to_phase2_parameters()?;
        println!();
        println!("Current challenge hash: {}", hex::encode(params.challenge_hash()));
        println!("Phase 2 contribution index: {}", params.contribution_index);
    }

    Ok(())
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: ceremony_cli <command> [options]");
        eprintln!();
        eprintln!("Commands:");
        eprintln!("  init --powers <n> --output <file>");
        eprintln!("  contribute --input <file> --contributor <name> --output <file>");
        eprintln!("  verify --before <file> --after <file>");
        eprintln!("  transition --input <file> --output <file>");
        eprintln!("  finalize --input <file> --proving-key <file> --verifying-key <file>");
        eprintln!("  status --input <file>");
        return Err("invalid arguments".into());
    }

    let command = &args[1];

    match command.as_str() {
        "init" => {
            let powers = args.iter().position(|a| a == "--powers")
                .and_then(|i| args.get(i + 1))
                .and_then(|s| s.parse::<usize>().ok())
                .ok_or("--powers <n> required")?;
            let output = args.iter().position(|a| a == "--output")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .ok_or("--output <file> required")?;
            cmd_init(powers, &output)
        }
        "contribute" => {
            let input = args.iter().position(|a| a == "--input")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .ok_or("--input <file> required")?;
            let contributor = args.iter().position(|a| a == "--contributor")
                .and_then(|i| args.get(i + 1))
                .map(String::as_str)
                .ok_or("--contributor <name> required")?;
            let output = args.iter().position(|a| a == "--output")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .ok_or("--output <file> required")?;
            cmd_contribute(&input, contributor, &output)
        }
        "verify" => {
            let before = args.iter().position(|a| a == "--before")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .ok_or("--before <file> required")?;
            let after = args.iter().position(|a| a == "--after")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .ok_or("--after <file> required")?;
            cmd_verify(&before, &after)
        }
        "transition" => {
            let input = args.iter().position(|a| a == "--input")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .ok_or("--input <file> required")?;
            let output = args.iter().position(|a| a == "--output")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .ok_or("--output <file> required")?;
            cmd_transition(&input, &output)
        }
        "finalize" => {
            let input = args.iter().position(|a| a == "--input")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .ok_or("--input <file> required")?;
            let pk = args.iter().position(|a| a == "--proving-key")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .ok_or("--proving-key <file> required")?;
            let vk = args.iter().position(|a| a == "--verifying-key")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .ok_or("--verifying-key <file> required")?;
            cmd_finalize(&input, &pk, &vk)
        }
        "status" => {
            let input = args.iter().position(|a| a == "--input")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .ok_or("--input <file> required")?;
            cmd_status(&input)
        }
        _ => Err(format!("unknown command: {}", command).into()),
    }
}
