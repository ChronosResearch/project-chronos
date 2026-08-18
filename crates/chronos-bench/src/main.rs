//! CHRONOS benchmark suite.
//!
//! Run with:
//! ```text
//! cargo run -p chronos-bench --release
//! ```
//!
//! Release mode is not optional. A debug build measures `num-bigint` and arkworks
//! with bounds checks and no inlining, which is 10-50x slower and tells you nothing
//! about deployment behaviour.
//!
//! # How to read the VDF rows
//!
//! Wall time must grow close to linearly in `T`, leaving squarings/sec roughly
//! constant. If it does not, the measurement is dominated by something other than
//! sequential squaring — which is exactly what happened to the figures published in
//! the v3 paper.
//!
//! Those figures (T=1,000 → 12,092 ms; T=10,000 → 16,595 ms; T=100,000 → 9,828 ms)
//! were real measurements of the wrong thing: an `O(√n)` trial-division primality
//! test inside the Fiat-Shamir challenge derivation, whose cost depends on the
//! hash-derived seed and **not** on `T`. That is why 100x the sequential work
//! appeared to finish faster. `is_prime` is now deterministic Miller-Rabin, and
//! `chronos-vdf`'s `test_wall_time_scales_with_t` fails if evaluation ever becomes
//! constant-time in `T` again.
//!
//! Note that `evaluate` performs `2T` squarings — `T` for `y`, `T` for the
//! Wesolowski proof — so the squarings/sec column reports `2T / elapsed`.
//!
//! # How to read the Groth16 rows
//!
//! The erasure circuit encodes the whole key-release chain: Poseidon commitments to
//! `y`, the ciphertext and the key; the in-circuit KDF; authenticated decryption;
//! and the containment terminal-state predicates. Earlier revisions reported
//! ~180,000 constraints, of which roughly 160,000 were filler multiplications
//! emitted by `while count < TARGET` loops. The real count is now printed below and
//! should be a few thousand.

use chronos_core::containment::{ContainmentLedger, ContainmentState, Event};
use chronos_core::memory::LockedBytes;
use chronos_core::mpc::MpcCertificate;
use chronos_core::VdfEngine;
use chronos_snark::aead::ChronosAead;
use chronos_snark::circuit::{
    ContainmentSummary, ErasureCircuit, ErasureWitness, SALT_BYTES, SK_BYTES, WIPE_PATTERN, Y_BYTES,
};
use chronos_snark::identity_circuit::{identity_root, mission_id_to_bytes, IdentityProver};
use chronos_snark::poseidon;
use chronos_snark::prover::{Groth16Prover, SetupContribution, SetupTranscript};
use num_bigint::BigUint;
use std::time::Instant;

fn main() {
    println!("CHRONOS benchmark suite");
    println!("=======================");
    if cfg!(debug_assertions) {
        println!();
        println!("WARNING: debug build. These numbers are not meaningful.");
        println!("         Re-run with: cargo run -p chronos-bench --release");
    }
    println!();

    bench_vdf();
    bench_erasure_circuit();
    bench_identity_circuit();
    bench_locked_memory();
}

// ─── VDF ──────────────────────────────────────────────────────────────────────

fn bench_vdf() {
    println!("## VDF — Wesolowski over RSA-2048");
    println!(
        "{:<12} {:>14} {:>16} {:>12}",
        "T (steps)", "Wall (ms)", "Squarings/sec", "y[0..4]"
    );
    println!("{}", "-".repeat(58));

    let n = match MpcCertificate::rsa_2048() {
        Ok(c) => c.n,
        Err(e) => {
            println!("SKIPPED: modulus unavailable: {e}");
            return;
        }
    };
    let g = BigUint::from(2u32);
    let vdf = WesolowskiVdfHandle;

    for &t in &[1_000u64, 10_000, 100_000] {
        let start = Instant::now();
        let y = match vdf.evaluate(&g, t, &n) {
            Ok((y, _)) => y,
            Err(e) => {
                println!("{t:<12} FAILED: {e}");
                continue;
            }
        };
        let elapsed = start.elapsed();

        // 2T: T squarings for y, T more for the proof.
        let sps = if elapsed.as_secs_f64() > 0.0 {
            (2 * t) as f64 / elapsed.as_secs_f64()
        } else {
            f64::INFINITY
        };
        let bytes = y.to_bytes_be();
        let prefix: String = bytes
            .iter()
            .take(4)
            .map(|b| format!("{b:02x}"))
            .collect();

        println!("{:<12} {:>14} {:>16.0} {:>12}", t, elapsed.as_millis(), sps, prefix);
    }
    println!();
}

/// Local alias so the bench does not depend on the concrete VDF type name.
struct WesolowskiVdfHandle;
impl VdfEngine for WesolowskiVdfHandle {
    fn evaluate(
        &self,
        g: &BigUint,
        t: u64,
        n: &BigUint,
    ) -> chronos_core::ChronosResult<(BigUint, chronos_core::VdfProof)> {
        chronos_vdf::wesolowski::WesolowskiVdf.evaluate(g, t, n)
    }
    fn verify(
        &self,
        g: &BigUint,
        y: &BigUint,
        proof: &chronos_core::VdfProof,
        t: u64,
        n: &BigUint,
    ) -> bool {
        chronos_vdf::wesolowski::WesolowskiVdf.verify(g, y, proof, t, n)
    }
}

// ─── Erasure circuit ──────────────────────────────────────────────────────────

/// A consistent witness, built the way the agent builds one.
fn erasure_witness() -> ErasureWitness {
    let y: Vec<u8> = (0..Y_BYTES).map(|i| (i as u8).wrapping_mul(7).wrapping_add(1)).collect();
    let salt: Vec<u8> = (0..SALT_BYTES).map(|i| (i as u8) ^ 0x3C).collect();
    let mut sk = [0u8; SK_BYTES];
    for (i, b) in sk.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13).wrapping_add(5);
    }

    let k_enc = ChronosAead::derive_key(&y, &salt);
    let ct = ChronosAead::encrypt(
        &k_enc,
        ark_bn254::Fr::from(0xBEEFu64),
        &poseidon::split32(&sk),
    )
    .expect("sealing a 32-byte key must succeed");

    let mut ledger = ContainmentLedger::new(ContainmentState::new(8, 128, 3600), 32);
    ledger.admit(Event::MissionInit);
    ledger.admit(Event::Infer { declared_secs: 1, disclosure_bits: 16 });
    ledger.admit(Event::KeyReleased);
    ledger.admit(Event::Erase);

    ErasureWitness {
        y,
        salt,
        ct,
        sk,
        m_post: vec![WIPE_PATTERN; SK_BYTES],
        mission_digest: mission_id_to_bytes("bench-mission"),
        containment: ContainmentSummary::from_ledger(&ledger),
    }
}

fn bench_erasure_circuit() {
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    println!("## Groth16 erasure proof — BN254");

    let witness = erasure_witness();
    if let Err(e) = witness.check_shape() {
        println!("SKIPPED: witness invalid: {e}");
        return;
    }

    // Real constraint count, measured rather than declared.
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    if ErasureCircuit::new_for_proving(witness.clone())
        .generate_constraints(cs.clone())
        .is_err()
    {
        println!("SKIPPED: constraint synthesis failed");
        return;
    }
    println!("{:<28} {:>14}", "R1CS constraints", cs.num_constraints());
    println!("{:<28} {:>14}", "Witness variables", cs.num_witness_variables());
    println!(
        "{:<28} {:>14}",
        "Public inputs",
        cs.num_instance_variables().saturating_sub(1)
    );

    let mut transcript = SetupTranscript::new();
    transcript.contribute(&SetupContribution::generate("bench"));

    let mut prover = Groth16Prover::new();
    let t_setup = Instant::now();
    if let Err(e) = prover.setup_with_transcript(&transcript) {
        println!("SKIPPED: setup failed: {e}");
        return;
    }
    println!("{:<28} {:>14}", "Setup (ms)", t_setup.elapsed().as_millis());

    let t_prove = Instant::now();
    let proof = match prover.prove_erasure(&witness) {
        Ok(p) => p,
        Err(e) => {
            println!("SKIPPED: proving failed: {e}");
            return;
        }
    };
    println!("{:<28} {:>14}", "Prove (ms)", t_prove.elapsed().as_millis());
    println!("{:<28} {:>14}", "Proof size (bytes)", proof.len());

    let public_inputs = witness.public_inputs();
    let t_verify = Instant::now();
    match prover.verify_erasure(&proof, &public_inputs) {
        Ok(true) => println!(
            "{:<28} {:>14}",
            "Verify (ms)",
            t_verify.elapsed().as_millis()
        ),
        Ok(false) => println!("ERROR: proof did not verify"),
        Err(e) => println!("ERROR: verification failed: {e}"),
    }
    println!();
}

// ─── Identity circuit ─────────────────────────────────────────────────────────

fn bench_identity_circuit() {
    println!("## Groth16 EAIP identity proof — BN254");

    let y: Vec<u8> = (0..Y_BYTES).map(|i| (i as u8).wrapping_mul(11)).collect();
    let mission = mission_id_to_bytes("bench-mission");

    let mut prover = IdentityProver::new();
    let t_setup = Instant::now();
    if let Err(e) = prover.setup_local_development() {
        println!("SKIPPED: setup failed: {e}");
        return;
    }
    println!("{:<28} {:>14}", "Setup (ms)", t_setup.elapsed().as_millis());

    let t_prove = Instant::now();
    let proof = match prover.prove_identity(&y, &mission) {
        Ok(p) => p,
        Err(e) => {
            println!("SKIPPED: proving failed: {e}");
            return;
        }
    };
    println!("{:<28} {:>14}", "Prove (ms)", t_prove.elapsed().as_millis());
    println!("{:<28} {:>14}", "Proof size (bytes)", proof.len());

    let root = identity_root(&y, &mission);
    let t_verify = Instant::now();
    match prover.verify_identity(&proof, root) {
        Ok(true) => println!(
            "{:<28} {:>14}",
            "Verify (ms)",
            t_verify.elapsed().as_millis()
        ),
        Ok(false) => println!("ERROR: proof did not verify"),
        Err(e) => println!("ERROR: verification failed: {e}"),
    }
    println!();
}

// ─── Locked memory ────────────────────────────────────────────────────────────

fn bench_locked_memory() {
    println!("## LockedBytes — mlock and wipe overhead");
    println!("{:<16} {:>14} {:>12}", "Size (bytes)", "Alloc+lock (us)", "mlock ok");
    println!("{}", "-".repeat(44));

    for &size in &[32usize, 256, 1024, 4096, 65536] {
        let data = vec![0xAAu8; size];
        let start = Instant::now();
        let locked = LockedBytes::new(data);
        let elapsed = start.elapsed();
        let ok = locked.is_ok();
        // Drop performs the triple-pass wipe and munlock.
        drop(locked);
        println!("{:<16} {:>14} {:>12}", size, elapsed.as_micros(), ok);
    }

    // Isolate the wipe from the allocation.
    if let Ok(lb) = LockedBytes::new(vec![0xFFu8; 32]) {
        let start = Instant::now();
        drop(lb);
        println!("\nTriple-pass wipe + munlock (32 B): {} us", start.elapsed().as_micros());
    }
    println!();
}
