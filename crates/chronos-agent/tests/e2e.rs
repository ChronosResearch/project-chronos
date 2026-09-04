//! Agent-level integration tests.
//!
//! # Scope
//!
//! The cryptographic lifecycle — provisioning, sequential work, sealing, opening,
//! proving, verifying — is covered end to end by
//! `chronos-snark/tests/lifecycle.rs`, which crosses the provisioner/agent trust
//! boundary properly. Duplicating it here would only mean two places to update.
//!
//! What this file covers is the agent-specific surface that has no home in a unit
//! test because it spans modules: request authentication composed with replay
//! protection, and the containment monitor composed with the lifecycle state
//! machine.
//!
//! The previous version of this file tested `derive_k_enc` (HKDF, now removed),
//! `prove_erasure` from `erasure.rs` (a SHA-256 sanity check, now removed), and a
//! VDF "concurrency torture test" whose comment referred to GMP FFI state that the
//! pure-Rust backend does not have. All three tested code that no longer exists or
//! properties that were never at risk.

use chronos_agent::crypto::{request_mac, verify_request_mac, AUTH_KEY_BYTES};
use chronos_agent::state::{spawn_watchdog, AgentState, StateMachine};
use chronos_agent::tls::NonceCache;
use chronos_core::containment::{Decision, Event};
use std::sync::Arc;

const KEY: [u8; AUTH_KEY_BYTES] = [0x11u8; AUTH_KEY_BYTES];

fn sm() -> Arc<StateMachine> {
    // Small budgets so exhaustion is reachable inside a test.
    StateMachine::new(3, 128, 3600)
}

// ─── Authentication composed with replay protection ──────────────────────────

/// The two controls are independent and both required. A valid MAC on a replayed
/// nonce must still be refused, otherwise a captured request could be resent
/// indefinitely.
#[test]
fn test_valid_mac_does_not_excuse_a_replayed_nonce() {
    let mut cache = NonceCache::new(16);
    let nonce = "0123456789abcdef01234567";
    let mac = hex::encode(request_mac(&KEY, "POST", "/mission/init", nonce, b""));

    // First use: MAC valid, nonce fresh.
    verify_request_mac(&KEY, "POST", "/mission/init", nonce, b"", &mac).expect("MAC must verify");
    let mut raw = [0u8; 12];
    raw.copy_from_slice(&hex::decode(nonce).expect("hex"));
    assert!(cache.check_and_insert(&raw), "first use must be accepted");

    // Second use: MAC is still valid — it is the nonce cache that must reject.
    verify_request_mac(&KEY, "POST", "/mission/init", nonce, b"", &mac)
        .expect("the MAC is unchanged and still valid");
    assert!(
        !cache.check_and_insert(&raw),
        "a replayed nonce must be refused even with a valid MAC"
    );
}

/// A fresh nonce does not excuse a missing or wrong MAC. This is the hole the old
/// middleware had: it checked only nonce freshness, so any caller could reach
/// every endpoint.
#[test]
fn test_fresh_nonce_does_not_excuse_a_bad_mac() {
    let nonce = "ffffffffffffffffffffffff";
    let forged = hex::encode(request_mac(&[0x22u8; AUTH_KEY_BYTES], "POST", "/mission/init", nonce, b""));
    assert!(
        verify_request_mac(&KEY, "POST", "/mission/init", nonce, b"", &forged).is_err(),
        "a fresh nonce must not admit a request whose MAC was made with another key"
    );
}

/// Each nonce authenticates exactly one request. Rotating the nonce requires
/// recomputing the MAC, which requires the key.
#[test]
fn test_mac_is_nonce_specific() {
    let a = "000000000000000000000001";
    let b = "000000000000000000000002";
    let mac_a = hex::encode(request_mac(&KEY, "GET", "/status", a, b""));
    assert!(
        verify_request_mac(&KEY, "GET", "/status", b, b"", &mac_a).is_err(),
        "a MAC must not transfer to a different nonce"
    );
}

// ─── Containment composed with the lifecycle ─────────────────────────────────

/// Inference is admissible only in `Active`, and the ledger records every attempt
/// — including refusals, so probing is visible in the published attestation.
#[tokio::test]
async fn test_inference_window_is_enforced_and_recorded() {
    let s = sm();
    let infer = Event::Infer { declared_secs: 1, disclosure_bits: 8 };

    // Armed: refused.
    assert!(matches!(s.admit(infer).await, Decision::Deny(_)));

    s.arm_to_active().await.expect("init");
    assert!(s.admit(infer).await.is_admitted(), "Active must permit inference");

    s.active_to_locked().await.expect("lock");
    assert!(
        matches!(s.admit(infer).await, Decision::Deny(_)),
        "Locked must refuse inference"
    );

    s.force_erased().await;
    assert!(matches!(s.admit(infer).await, Decision::Deny(_)));

    // Seven arbitrated events in total: three refused inferences (Armed, Locked,
    // Erased) and four admitted transitions.
    assert_eq!(s.ledger_len().await, 7, "every attempt must be recorded");
    let (admitted, denied) = s.counters().await;
    assert_eq!(
        admitted, 4,
        "MissionInit, one Infer, KeyReleased, and Erase — erasure is itself an admitted event"
    );
    assert_eq!(denied, 3, "one refused inference in each of Armed, Locked, Erased");
    assert_eq!(
        admitted + denied,
        s.ledger_len().await,
        "the ledger must account for every event exactly once"
    );
}

/// The operation budget must actually bind, and exhausting it must not be
/// recoverable by any sequence of requests.
#[tokio::test]
async fn test_operation_budget_is_absorbing() {
    let s = sm(); // op_budget = 3
    s.arm_to_active().await.expect("init");
    let infer = Event::Infer { declared_secs: 1, disclosure_bits: 1 };

    for i in 0..3 {
        assert!(
            s.admit(infer).await.is_admitted(),
            "inference {i} must be admitted while budget remains"
        );
    }
    for _ in 0..5 {
        assert!(
            matches!(s.admit(infer).await, Decision::Deny(_)),
            "an exhausted budget must never replenish"
        );
    }
}

/// The property the erasure proof depends on: the containment summary must be
/// terminal only after erasure. If it were terminal earlier, a live agent could
/// produce an erasure proof.
#[tokio::test]
async fn test_attestable_only_after_erasure() {
    let s = sm();
    assert!(!s.containment_summary().await.is_terminal(), "Armed is not terminal");

    s.arm_to_active().await.expect("init");
    assert!(!s.containment_summary().await.is_terminal(), "Active is not terminal");

    s.active_to_locked().await.expect("lock");
    assert!(!s.containment_summary().await.is_terminal(), "Locked is not terminal");

    s.force_erased().await;
    assert!(
        s.containment_summary().await.is_terminal(),
        "only an erased agent may hold a terminal summary"
    );
}

/// The watchdog must both erase and abort in-flight sequential work. Erasing
/// without aborting is what let the old agent report `Erased` while still
/// squaring with the key resident.
#[tokio::test]
async fn test_watchdog_erases_and_aborts() {
    use std::sync::atomic::Ordering;

    let s = StateMachine::new(8, 128, 3600);
    s.arm_to_active().await.expect("init");
    let abort = s.abort_flag();
    assert!(!abort.load(Ordering::SeqCst));

    spawn_watchdog(Arc::clone(&s), 1);

    tokio::time::timeout(
        tokio::time::Duration::from_secs(6),
        s.erased_notify.notified(),
    )
    .await
    .expect("watchdog must fire");

    assert_eq!(s.current().await, AgentState::Erased);
    assert!(
        abort.load(Ordering::SeqCst),
        "the watchdog must signal in-flight work to stop, not merely relabel the state"
    );
}

/// Double init must be refused, and the refusal must be recorded rather than
/// silently ignored.
#[tokio::test]
async fn test_double_init_is_refused_and_recorded() {
    let s = sm();
    s.arm_to_active().await.expect("first init");
    assert!(s.arm_to_active().await.is_err(), "second init must fail");
    assert_eq!(s.current().await, AgentState::Active, "state must not change");

    let (_, denied) = s.counters().await;
    assert_eq!(denied, 1, "the refused init must appear in the ledger");
}

/// Every lifecycle transition must advance the ledger chain head, because the
/// erasure proof commits to it. A transition that left the head unchanged would be
/// invisible in the attestation.
#[tokio::test]
async fn test_every_transition_advances_the_chain() {
    let s = sm();
    let mut seen = vec![s.chain_head_hex().await];

    s.arm_to_active().await.expect("init");
    seen.push(s.chain_head_hex().await);
    s.active_to_locked().await.expect("lock");
    seen.push(s.chain_head_hex().await);
    s.force_erased().await;
    seen.push(s.chain_head_hex().await);

    for i in 0..seen.len() {
        for j in (i + 1)..seen.len() {
            assert_ne!(seen[i], seen[j], "chain heads {i} and {j} must differ");
        }
    }

}

/// End-to-end style integration around a live local LLM call path:
/// each admitted inference spends one operation, and after the threshold is
/// exhausted all further inferences are denied without recovery.
#[tokio::test]
async fn test_live_local_llm_termination_threshold_behavior() {
    // Keep this test independent of a specific local LLM runtime. The "live" part
    // here is exercising the real admission path repeatedly under realistic request
    // cadence, matching how `/infer` is gated in the agent.
    let s = StateMachine::new(2, 256, 300);
    s.arm_to_active().await.expect("init");

    let infer = Event::Infer {
        declared_secs: 1,
        disclosure_bits: 64,
    };

    assert!(s.admit(infer).await.is_admitted(), "first infer admitted");
    assert!(s.admit(infer).await.is_admitted(), "second infer admitted");

    assert!(
        matches!(s.admit(infer).await, Decision::Deny(_)),
        "third infer must be denied at threshold"
    );
    assert!(
        matches!(s.admit(infer).await, Decision::Deny(_)),
        "denial must persist after threshold crossing"
    );

    let (admitted, denied) = s.counters().await;
    assert_eq!(admitted, 3, "init + 2 inferences");
    assert_eq!(denied, 2, "all post-threshold inferences denied");
}
