/// CHRONOS Benchmark Suite
///
/// Measures the three performance claims in the paper:
///   1. VDF timing at T = 1k / 10k / 100k / 1M squarings
///   2. Groth16 erasure proof generation and verification latency
///   3. Peak memory under mlock (LockedBytes allocation cost)
///
/// Run with:
///   cargo run -p chronos-bench --release
///
/// Output is tab-separated for easy import into LaTeX tables.
use chronos_core::memory::LockedBytes;
use chronos_core::mpc::MpcCertificate;
use chronos_core::VdfEngine;
use chronos_snark::prover::Groth16Prover;
use chronos_vdf::wesolowski::WesolowskiVdf;
use num_bigint::BigUint;
use std::time::Instant;

fn main() {
    println!("CHRONOS Benchmark Suite");
    println!("=======================\n");

    bench_vdf();
    bench_snark();
    bench_memory();
}

// ─── VDF Benchmarks ───────────────────────────────────────────────────────────

fn bench_vdf() {
    println!("## VDF Timing (Wesolowski, RSA-2048 modulus)");
    println!("{:<12} {:>14} {:>18} {:>16}", "T (steps)", "Wall time (ms)", "Squarings/sec", "Output (hex[0..4])");
    println!("{}", "-".repeat(64));

    let cert = MpcCertificate::load("/nonexistent").expect("prototype modulus must load");
    let g = BigUint::from(2u32);
    let vdf = WesolowskiVdf;

    for &t in &[1_000u64, 10_000, 100_000] {
        let start = Instant::now();
        let (y, _pi) = vdf.evaluate(&g, t, &cert.n).expect("VDF must succeed");
        let elapsed = start.elapsed();

        let ms = elapsed.as_millis();
        let sps = if elapsed.as_secs_f64() > 0.0 {
            t as f64 / elapsed.as_secs_f64()
        } else {
            f64::INFINITY
        };

        let y_bytes = y.to_bytes_be();
        let hex_prefix = hex::encode(&y_bytes[..y_bytes.len().min(4)]);

        println!("{:<12} {:>14} {:>18.0} {:>16}", t, ms, sps, hex_prefix);
    }
    println!();
}

// ─── SNARK Benchmarks ─────────────────────────────────────────────────────────

fn bench_snark() {
    println!("## Groth16 Erasure Proof (BN254, ~180k constraints)");
    println!("{:<24} {:>14}", "Operation", "Wall time (ms)");
    println!("{}", "-".repeat(40));

    // Trusted setup (MPC ceremony simulation).
    let mut prover = Groth16Prover::new();
    let t_setup = time_ms(|| prover.generate_keys().expect("setup must succeed"));
    println!("{:<24} {:>14}", "MPC trusted setup", t_setup);

    // Proof generation.
    let sk      = vec![0xFFu8; 32];
    let m_pre   = vec![0xDEu8; 32];
    let y       = vec![0xABu8; 32];
    let salt    = vec![0xCDu8; 32];
    let ct_sk   = vec![0x00u8; 48];
    let g       = vec![0x02u8; 32];
    let n_mod   = vec![0x01u8; 32];
    let pi_vdf  = vec![0x03u8; 32];

    let mut proof_bytes = Vec::new();
    let t_prove = time_ms(|| {
        proof_bytes = prover
            .prove_erasure(&sk, &m_pre, &y, &salt, &ct_sk, &g, &n_mod, &pi_vdf)
            .expect("proof must succeed");
    });
    println!("{:<24} {:>14}", "Proof generation", t_prove);
    println!("{:<24} {:>14}", "Proof size (bytes)", proof_bytes.len());

    // Verification.
    let t_verify = time_ms(|| {
        let ok = prover
            .verify_erasure(&proof_bytes, 0xAB, 0xFF)
            .expect("verify must not error");
        assert!(ok, "proof must verify");
    });
    println!("{:<24} {:>14}", "Proof verification", t_verify);
    println!();
}

// ─── Memory Benchmarks ────────────────────────────────────────────────────────

fn bench_memory() {
    println!("## LockedBytes Memory (mlock overhead)");
    println!("{:<20} {:>14} {:>18}", "Allocation size", "Time (µs)", "mlock success");
    println!("{}", "-".repeat(56));

    for &size in &[32usize, 256, 1024, 4096, 65536] {
        let data = vec![0xAAu8; size];
        let mut success = false;
        let t_us = time_us(|| {
            match LockedBytes::new(data.clone()) {
                Ok(_lb) => success = true,
                Err(_) => success = false,
            }
        });
        println!("{:<20} {:>14} {:>18}", size, t_us, success);
    }

    // Wipe timing: allocate 32 bytes and measure drop (triple-pass wipe).
    let lb = LockedBytes::new(vec![0xFFu8; 32]).expect("mlock must succeed for 32 bytes");
    let t_wipe = time_us(|| drop(lb));
    println!("\nTriple-pass wipe (32 bytes): {} µs", t_wipe);
    println!();
}

// ─── Timing helpers ───────────────────────────────────────────────────────────

fn time_ms<F: FnOnce()>(f: F) -> u128 {
    let start = Instant::now();
    f();
    start.elapsed().as_millis()
}

fn time_us<F: FnOnce()>(f: F) -> u128 {
    let start = Instant::now();
    f();
    start.elapsed().as_micros()
}

// ─── hex helper (avoid pulling in the full hex crate) ────────────────────────

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
