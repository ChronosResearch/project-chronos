/// Full lifecycle integration tests for the CHRONOS agent.
///
/// STEP 19 – VDF uses T=10 in debug builds via `#[cfg(debug_assertions)]`
///           compile-time flag inside `WesolowskiVdf::evaluate`.
///
/// STEP 20 – Tests the full crypto handshake: FHE keys → VDF → HKDF → erasure.
///
/// STEP 21 – Concurrent FFI torture test: 10 tasks simultaneously call VDF.
use chronos_agent::{
    crypto::derive_k_enc,
    erasure::prove_erasure,
    state::{AgentState, StateMachine},
};
use chronos_core::{
    fhe::FheEngine,
    memory::LockedBytes,
    redacted::Redacted,
    wipe::secure_wipe,
    VdfEngine,
};
use chronos_vdf::wesolowski::WesolowskiVdf;
use num_bigint::BigUint;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

// ─── STEP 20: Full Cryptographic Handshake ───────────────────────────────────

/// Exercises the full Agent lifecycle without a running HTTP server:
/// 1. FHE key generation
/// 2. VDF evaluation (T=10 in debug via cfg flag)
/// 3. HKDF derivation of K_enc
/// 4. Memory erasure proof
#[tokio::test]
async fn test_full_lifecycle_handshake() {
    // ── 1. FHE keys ──────────────────────────────────────────────────────────
    let fhe = FheEngine::new();
    tokio::task::spawn_blocking({
        let fhe = fhe.server_key_handle(); // just borrow the arc to confirm it compiles
        move || drop(fhe)
    })
    .await
    .expect("spawn_blocking must not panic");

    // Measure struct sizes (STEP 20).
    assert!(
        std::mem::size_of::<FheEngine>() > 0,
        "FheEngine must have non-zero size"
    );

    // ── 2. VDF (T=10 in debug via #[cfg(debug_assertions)]) ──────────────────
    let vdf = WesolowskiVdf;
    let g = BigUint::from(2u32);
    let n = BigUint::from(257u32);
    let (y, proof) = vdf
        .evaluate(&g, 100, &n) // effective_t = min(100, 10) = 10 in debug
        .expect("VDF evaluate must succeed in debug mode");

    assert!(vdf.verify(&g, &y, &proof, 100, &n), "VDF verify must succeed");
    println!("VDF output y = {y}");

    // ── 3. HKDF derivation ───────────────────────────────────────────────────
    let salt = [0xBEu8; 32];
    let k_enc = derive_k_enc(&y, &salt).expect("HKDF must not fail");
    let _k_enc_redacted = Redacted::new(&k_enc); // STEP 11: logs would show [REDACTED]
    assert_ne!(k_enc, [0u8; 32], "K_enc must not be all-zero");

    // ── 4. Memory erasure ─────────────────────────────────────────────────────
    let mut sk_buf = vec![0xDEu8; 64];
    let m_pre = sk_buf.clone(); // snapshot before wipe
    secure_wipe(sk_buf.as_mut_ptr(), sk_buf.len());
    let erasure_proof = prove_erasure(&sk_buf, &m_pre, &y).expect("Erasure proof must succeed");
    assert_eq!(erasure_proof.len(), 32, "SHA-256 root must be 32 bytes");

    println!("Full lifecycle test PASSED");
}

// ─── STEP 16: Double-Init Guard ──────────────────────────────────────────────

#[tokio::test]
async fn test_double_init_rejected() {
    let sm = StateMachine::new();
    sm.arm_to_active().await.expect("First init must succeed");
    let err = sm.arm_to_active().await.expect_err("Second init must fail");
    assert!(
        err.to_string().contains("already initialised"),
        "Error must mention double-init: {err}"
    );
}

// ─── STEP 17: Watchdog Timeout ───────────────────────────────────────────────

#[tokio::test]
async fn test_watchdog_forces_erased() {
    use chronos_agent::state::spawn_watchdog;
    let sm = StateMachine::new();
    sm.arm_to_active().await.expect("First init must succeed in test setup");

    // Watchdog with 1-second timeout.
    spawn_watchdog(Arc::clone(&sm), 1);

    // Wait for the notify (fired by force_erased).
    tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        sm.erased_notify.notified(),
    )
    .await
    .expect("Watchdog must fire within 3 seconds");

    assert_eq!(sm.current().await, AgentState::Erased);
}

// ─── STEP 21: Concurrent FFI Torture Test ────────────────────────────────────

/// Spawn 10 concurrent tasks each running the VDF engine.
/// Because WesolowskiVdf creates per-call GmpBigInt locals, there is no
/// shared mutable GMP state and this must complete without panicking.
#[tokio::test]
async fn test_vdf_concurrent_10_tasks() {
    let tasks: Vec<_> = (0..10)
        .map(|i| {
            tokio::task::spawn_blocking(move || {
                let vdf = WesolowskiVdf;
                let g = BigUint::from(2u32 + i);
                let n = BigUint::from(257u32);
                vdf.evaluate(&g, 50, &n)
            })
        })
        .collect();

    for (i, task) in tasks.into_iter().enumerate() {
        let result = task.await.expect("spawn_blocking must not panic");
        assert!(
            result.is_ok(),
            "Task {i} must succeed: {:?}",
            result.err()
        );
    }
    println!("Concurrent FFI test (10 tasks) PASSED");
}

// ─── STEP 9: Secure Wipe Volatile Read ───────────────────────────────────────

#[test]
fn test_wipe_volatile_read_not_optimized() {
    const SZ: usize = 1024;
    let mut buf = vec![0xAAu8; SZ];
    let ptr = buf.as_mut_ptr();
    secure_wipe(ptr, SZ);
    for i in 0..SZ {
        // SAFETY: ptr is still valid; secure_wipe does not free memory.
        let byte = unsafe { std::ptr::read_volatile(ptr.add(i)) };
        assert_eq!(byte, 0xFF, "Byte {i} must be 0xFF after triple-pass wipe");
    }
}

// ─── STEP 18: HKDF Determinism ───────────────────────────────────────────────

#[test]
fn test_hkdf_deterministic_across_calls() {
    let y = BigUint::from(999_u32);
    let salt = [0x55u8; 32];
    let k1 = derive_k_enc(&y, &salt).expect("HKDF must not fail");
    let k2 = derive_k_enc(&y, &salt).expect("HKDF must not fail");
    assert_eq!(k1, k2);
}

// ─── Memory size accounting (STEP 20) ─────────────────────────────────────────

#[test]
fn test_critical_struct_sizes() {
    use chronos_core::VdfProof;
    println!("sizeof VdfProof = {}", std::mem::size_of::<VdfProof>());
    println!("sizeof FheEngine = {}", std::mem::size_of::<FheEngine>());
    // These are sanity checks; the FHE key itself lives on the heap.
    assert!(std::mem::size_of::<FheEngine>() < 1024);
}
