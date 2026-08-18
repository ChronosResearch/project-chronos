//! Export a Groth16 verifying key and a sample erasure proof in EVM encoding.
//!
//! Run with:
//! ```text
//! cargo run -p chronos-snark --example export_solidity --release
//! ```
//!
//! # Why the proof is verified natively first
//!
//! Two things can go wrong when moving a Groth16 proof on-chain: the proof can be
//! invalid, or the *encoding* can be wrong. The two failure modes look identical
//! from Solidity — `verifyProof` returns false — and the encoding bugs are subtle
//! (arkworks serializes little-endian; the EVM reads big-endian; the pairing
//! precompile wants Fp2 coordinates as `[c1, c0]`, the reverse of arkworks'
//! order).
//!
//! So this example verifies natively before printing anything. If the native check
//! passes and the on-chain check fails, the fault is isolated to the encoding in
//! [`chronos_snark::solidity`], which is a much smaller search space.
//!
//! # Scope
//!
//! The printed key comes from a **single-party** trusted setup. Anyone deploying
//! it can forge proofs that verify against it. See `chronos_snark::prover` and
//! `contracts/Groth16Verifier.sol`.

use ark_bn254::Fr;
use ark_groth16::Proof;
use ark_serialize::CanonicalDeserialize;
use chronos_core::containment::{ContainmentLedger, ContainmentState, Event};
use chronos_snark::aead::ChronosAead;
use chronos_snark::circuit::{
    ContainmentSummary, ErasureWitness, MISSION_BYTES, SALT_BYTES, SK_BYTES, WIPE_PATTERN, Y_BYTES,
};
use chronos_snark::poseidon;
use chronos_snark::prover::{Groth16Prover, SetupContribution, SetupTranscript};
use chronos_snark::solidity::{erasure_public_inputs, export_proof, export_verifying_key};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("CHRONOS — Groth16 EVM export");
    println!("============================\n");

    // ── Trusted setup ────────────────────────────────────────────────────────
    let mut transcript = SetupTranscript::new();
    transcript.contribute(&SetupContribution::generate("export-example"));

    let mut prover = Groth16Prover::new();
    prover.setup_with_transcript(&transcript)?;
    println!("Setup transcript head: 0x{}", hex(&transcript.head()));
    println!("Contributors: {}\n", transcript.len());

    // ── Build a consistent witness, exactly as the agent does ────────────────
    let witness = build_witness();
    witness.check_shape()?;
    let public_inputs = witness.public_inputs();

    let proof_bytes = prover.prove_erasure(&witness)?;

    // ── Native check first ───────────────────────────────────────────────────
    let native_ok = prover.verify_erasure(&proof_bytes, &public_inputs)?;
    if !native_ok {
        return Err("native verification failed — do not attempt on-chain \
                    verification until this passes"
            .into());
    }
    println!("Native verification: PASS ({} byte proof)\n", proof_bytes.len());

    // ── Constructor arguments ────────────────────────────────────────────────
    let vk = export_verifying_key(prover.verifying_key()?)?;
    if vk.public_input_count() != chronos_snark::circuit::PUBLIC_INPUT_COUNT {
        return Err(format!(
            "verifying key expects {} public inputs but the circuit exposes {}",
            vk.public_input_count(),
            chronos_snark::circuit::PUBLIC_INPUT_COUNT
        )
        .into());
    }

    println!("── Groth16Verifier constructor arguments ──\n");
    println!("{}", vk.to_constructor_args());

    // ── Sample calldata ──────────────────────────────────────────────────────
    let proof = Proof::deserialize_compressed(&proof_bytes[..])?;
    let sol_proof = export_proof(&proof)?;
    let inputs = erasure_public_inputs(&public_inputs);

    println!("── Sample attestErasure calldata ──\n");
    println!("proof:  {}", sol_proof.to_calldata_args());
    println!("inputs: [");
    for (name, word) in [
        "yCommit",
        "ctCommit",
        "skCommit",
        "missionCommit",
        "containmentCommit",
    ]
    .iter()
    .zip(inputs.iter())
    {
        println!("    {word}, // {name}");
    }
    println!("]");

    println!(
        "\nNote: this verifying key comes from a single-party setup. \
         Whoever ran it can forge proofs that verify on-chain."
    );

    Ok(())
}

/// Build a fully consistent witness: key, ciphertext, VDF output and containment
/// summary that all agree with one another.
fn build_witness() -> ErasureWitness {
    let y: Vec<u8> = (0..Y_BYTES).map(|i| (i as u8).wrapping_mul(3).wrapping_add(1)).collect();
    let salt: Vec<u8> = (0..SALT_BYTES).map(|i| (i as u8) ^ 0x7E).collect();

    let mut sk = [0u8; SK_BYTES];
    for (i, b) in sk.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(9).wrapping_add(4);
    }

    let k_enc = ChronosAead::derive_key(&y, &salt);
    let ct = ChronosAead::encrypt(&k_enc, Fr::from(0xC0FFEEu64), &poseidon::split32(&sk))
        .expect("encryption of a 32-byte key must succeed");

    // A containment run that reaches the terminal state the circuit requires.
    let mut ledger = ContainmentLedger::new(ContainmentState::new(8, 128, 3600), 32);
    ledger.admit(Event::MissionInit);
    ledger.admit(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 16,
    });
    ledger.admit(Event::KeyReleased);
    ledger.admit(Event::Erase);

    ErasureWitness {
        y,
        salt,
        ct,
        sk,
        m_post: vec![WIPE_PATTERN; SK_BYTES],
        mission_digest: [0x11u8; MISSION_BYTES],
        containment: ContainmentSummary::from_ledger(&ledger),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
