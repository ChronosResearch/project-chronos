//! Agent lifecycle state, backed by the containment ledger.
//!
//! # Why the ledger is the state machine
//!
//! The previous design kept two independent notions of lifecycle: an `AgentState`
//! enum inside `StateMachine`, and — once containment was introduced — a
//! [`Phase`] inside the containment monitor. Two sources of truth for the same
//! fact can diverge, and here divergence would be load-bearing: the erasure proof
//! commits to the *ledger's* terminal state, so an agent whose HTTP layer said
//! `Erased` while its ledger said `Active` would serve a status nobody could
//! attest to, and could not produce a proof at all.
//!
//! So `StateMachine` no longer stores a phase. It owns a [`ContainmentLedger`] and
//! derives the phase from it. Every transition goes through
//! [`ContainmentLedger::admit`], which means every transition is arbitrated
//! against the axioms and recorded in the hash chain that the proof commits to.
//! There is no path that changes lifecycle state without appearing in the
//! attestation.
//!
//! # Watchdog
//!
//! [`spawn_watchdog`] previously flipped the state to `Erased` on deadline and
//! stopped there. The VDF kept running on its blocking thread with the key live,
//! so the agent reported itself erased while still holding the secret. The
//! watchdog now also raises an abort flag that
//! `WesolowskiVdf::evaluate_interruptible` polls, so the sequential work actually
//! stops.

use crate::identity::IdentityManager;
use chronos_core::containment::{
    ContainmentLedger, ContainmentState, Decision, Event, Phase,
};
use chronos_core::{ChronosError, ChronosResult};
use chronos_snark::circuit::ContainmentSummary;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, Notify};
use tracing::{info, warn};

/// Lifecycle state as exposed by `/status`.
///
/// A projection of [`Phase`], kept as a distinct type so the HTTP representation
/// can evolve without touching the containment lattice.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum AgentState {
    /// Provisioned, not started.
    Armed,
    /// Mission running; inference available.
    Active,
    /// Key released, VDF complete, winding down.
    Locked,
    /// Key destroyed. Terminal.
    Erased,
}

impl From<Phase> for AgentState {
    fn from(p: Phase) -> Self {
        match p {
            Phase::Armed => AgentState::Armed,
            Phase::Active => AgentState::Active,
            Phase::Locked => AgentState::Locked,
            Phase::Erased => AgentState::Erased,
        }
    }
}

/// Ledger-backed lifecycle state.
pub struct StateMachine {
    ledger: Mutex<ContainmentLedger>,
    /// Notified on transition to `Erased`, so waiters wake immediately.
    pub erased_notify: Arc<Notify>,
    /// Set when `Armed -> Active` is admitted.
    start_time: Mutex<Option<Instant>>,
    /// EAIP material. Wiped on erasure.
    pub identity: Mutex<IdentityManager>,
    /// Raised on erasure so long-running sequential work stops.
    abort: Arc<AtomicBool>,
}

impl StateMachine {
    /// Retained ledger tail, for `/status` introspection. The hash chain covers
    /// every record regardless; this only bounds what can be inspected locally.
    const LEDGER_TAIL: usize = 256;

    /// Create a state machine over a freshly provisioned containment state.
    #[must_use]
    pub fn new(op_budget: u64, disclosure_budget_bits: u64, deadline_secs: u64) -> Arc<Self> {
        let initial = ContainmentState::new(op_budget, disclosure_budget_bits, deadline_secs);
        Arc::new(Self {
            ledger: Mutex::new(ContainmentLedger::new(initial, Self::LEDGER_TAIL)),
            erased_notify: Arc::new(Notify::new()),
            start_time: Mutex::new(None),
            identity: Mutex::new(IdentityManager::new()),
            abort: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The abort flag, for passing into interruptible sequential work.
    #[must_use]
    pub fn abort_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.abort)
    }

    /// Current lifecycle state.
    pub async fn current(&self) -> AgentState {
        self.ledger.lock().await.state().phase.into()
    }

    /// Submit an event to the containment monitor and record the outcome.
    ///
    /// This is the only way lifecycle state changes. The elapsed clock is pushed
    /// in first so the A4 deadline check sees the real mission time rather than a
    /// stale value.
    pub async fn admit(&self, event: Event) -> Decision {
        let elapsed = self.elapsed_secs().await.unwrap_or(0);
        let mut ledger = self.ledger.lock().await;
        ledger.set_elapsed(elapsed);
        let decision = ledger.admit(event);

        if ledger.state().phase == Phase::Erased {
            // Stop any sequential work still in flight before signalling waiters.
            self.abort.store(true, Ordering::SeqCst);
        }
        decision
    }

    /// Transition `Armed -> Active`.
    ///
    /// # Errors
    /// Returns [`ChronosError::StateMachine`] if the monitor refuses, which
    /// includes the double-init case: `MISSION_INIT` is revoked on use, so a
    /// replayed init is denied by capability rather than by an ad-hoc guard.
    pub async fn arm_to_active(&self) -> ChronosResult<()> {
        match self.admit(Event::MissionInit).await {
            Decision::Admit => {
                *self.start_time.lock().await = Some(Instant::now());
                info!(target: "chronos", "state -> Active");
                Ok(())
            }
            Decision::Deny(reason) => Err(ChronosError::StateMachine(format!(
                "mission init refused: {reason}"
            ))),
        }
    }

    /// Transition `Active -> Locked`, on VDF completion and key release.
    ///
    /// # Errors
    /// Returns [`ChronosError::StateMachine`] if the monitor refuses.
    pub async fn active_to_locked(&self) -> ChronosResult<()> {
        match self.admit(Event::KeyReleased).await {
            Decision::Admit => {
                info!(target: "chronos", "state -> Locked");
                Ok(())
            }
            Decision::Deny(reason) => Err(ChronosError::StateMachine(format!(
                "key release refused: {reason}"
            ))),
        }
    }

    /// Force `Erased` from any state, wiping identity material.
    ///
    /// Always succeeds — [`Event::Erase`] is unconditionally admissible, which is
    /// what makes containment axiom A5 (erasure liveness) hold.
    pub async fn force_erased(&self) {
        let decision = self.admit(Event::Erase).await;
        debug_assert!(
            decision.is_admitted(),
            "Erase must always be admissible (containment axiom A5)"
        );
        info!(target: "chronos", "state -> Erased");
        self.identity.lock().await.wipe();
        self.erased_notify.notify_waiters();
    }

    /// Seconds since `Active` was entered, or `None` if not started.
    pub async fn elapsed_secs(&self) -> Option<u64> {
        self.start_time.lock().await.map(|t| t.elapsed().as_secs())
    }

    /// The containment summary the erasure proof commits to.
    pub async fn containment_summary(&self) -> ContainmentSummary {
        ContainmentSummary::from_ledger(&*self.ledger.lock().await)
    }

    /// Admitted and denied event counts.
    pub async fn counters(&self) -> (u64, u64) {
        self.ledger.lock().await.counters()
    }

    /// Hex-encoded ledger chain head, for `/status`.
    pub async fn chain_head_hex(&self) -> String {
        hex::encode(self.ledger.lock().await.chain_digest())
    }

    /// Number of records in the ledger.
    pub async fn ledger_len(&self) -> u64 {
        self.ledger.lock().await.len()
    }
}

/// Spawn the mission watchdog.
///
/// On deadline it raises the abort flag *and* forces `Erased`. Raising the flag is
/// the part the previous implementation lacked: without it the VDF kept squaring
/// with the key resident while the agent reported itself erased.
pub fn spawn_watchdog(sm: Arc<StateMachine>, t_seconds: u64) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            match sm.current().await {
                AgentState::Erased => return,
                AgentState::Armed => continue,
                _ => {}
            }

            if let Some(elapsed) = sm.elapsed_secs().await {
                if elapsed >= t_seconds {
                    warn!(
                        target: "chronos",
                        elapsed_secs = elapsed,
                        limit_secs = t_seconds,
                        "watchdog deadline reached — aborting sequential work and erasing"
                    );
                    // Order matters: stop the work before declaring erasure, so
                    // the claim is true at the moment it is made. `force_erased`
                    // raises the flag too; doing it first closes the window
                    // between the deadline and the state transition.
                    sm.abort_flag().store(true, Ordering::SeqCst);
                    sm.force_erased().await;
                    return;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sm() -> Arc<StateMachine> {
        StateMachine::new(8, 128, 3600)
    }

    #[tokio::test]
    async fn test_starts_armed() {
        assert_eq!(sm().current().await, AgentState::Armed);
    }

    #[tokio::test]
    async fn test_normal_lifecycle() {
        let s = sm();
        s.arm_to_active().await.expect("init");
        assert_eq!(s.current().await, AgentState::Active);
        s.active_to_locked().await.expect("lock");
        assert_eq!(s.current().await, AgentState::Locked);
        s.force_erased().await;
        assert_eq!(s.current().await, AgentState::Erased);
    }

    /// Double-init is refused by capability revocation, not by an ad-hoc check.
    #[tokio::test]
    async fn test_double_init_rejected() {
        let s = sm();
        s.arm_to_active().await.expect("first init must succeed");
        let err = s.arm_to_active().await.expect_err("second init must fail");
        assert!(
            format!("{err}").contains("refused"),
            "error should come from the containment monitor, got: {err}"
        );
        assert_eq!(s.current().await, AgentState::Active, "state must not change");
    }

    /// Every transition must appear in the ledger, because the erasure proof
    /// commits to it. A transition that bypassed the ledger would be unattestable.
    #[tokio::test]
    async fn test_transitions_are_recorded() {
        let s = sm();
        assert_eq!(s.ledger_len().await, 0);
        let head0 = s.chain_head_hex().await;

        s.arm_to_active().await.expect("init");
        assert_eq!(s.ledger_len().await, 1);
        let head1 = s.chain_head_hex().await;
        assert_ne!(head0, head1, "the chain head must advance");

        s.active_to_locked().await.expect("lock");
        s.force_erased().await;
        assert_eq!(s.ledger_len().await, 3);
        assert_ne!(head1, s.chain_head_hex().await);
    }

    /// The summary the proof commits to must be terminal after erasure, and not
    /// before. This is what makes the erasure proof unforgeable for a live agent.
    #[tokio::test]
    async fn test_summary_terminal_only_after_erasure() {
        let s = sm();
        s.arm_to_active().await.expect("init");
        assert!(
            !s.containment_summary().await.is_terminal(),
            "a running mission must not produce a terminal summary"
        );

        s.active_to_locked().await.expect("lock");
        assert!(!s.containment_summary().await.is_terminal());

        s.force_erased().await;
        assert!(
            s.containment_summary().await.is_terminal(),
            "after erasure the summary must satisfy the circuit's terminal predicates"
        );
    }

    /// Erasure must raise the abort flag, so interruptible sequential work stops.
    #[tokio::test]
    async fn test_erasure_raises_abort_flag() {
        let s = sm();
        s.arm_to_active().await.expect("init");
        assert!(!s.abort_flag().load(Ordering::SeqCst));
        s.force_erased().await;
        assert!(
            s.abort_flag().load(Ordering::SeqCst),
            "erasure must signal in-flight sequential work to stop"
        );
    }

    #[tokio::test]
    async fn test_erased_is_absorbing() {
        let s = sm();
        s.arm_to_active().await.expect("init");
        s.force_erased().await;
        // Further transitions must not resurrect the agent.
        assert!(s.active_to_locked().await.is_err());
        assert_eq!(s.current().await, AgentState::Erased);
        s.force_erased().await;
        assert_eq!(s.current().await, AgentState::Erased);
    }

    #[tokio::test]
    async fn test_inference_denied_outside_active() {
        let s = sm();
        let infer = Event::Infer { declared_secs: 1, disclosure_bits: 1 };

        assert!(
            !s.admit(infer).await.is_admitted(),
            "inference must be denied while Armed"
        );

        s.arm_to_active().await.expect("init");
        assert!(
            s.admit(infer).await.is_admitted(),
            "inference must be admitted while Active"
        );

        s.active_to_locked().await.expect("lock");
        assert!(
            !s.admit(infer).await.is_admitted(),
            "inference must stop once the key is released"
        );
    }

    /// Denials are recorded too, so probing is visible in the attestation.
    #[tokio::test]
    async fn test_denials_are_counted_and_recorded() {
        let s = sm();
        s.admit(Event::Infer { declared_secs: 1, disclosure_bits: 1 })
            .await;
        let (admitted, denied) = s.counters().await;
        assert_eq!((admitted, denied), (0, 1));
        assert_eq!(s.ledger_len().await, 1);
    }

    #[tokio::test]
    async fn test_watchdog_forces_erasure_and_aborts() {
        let s = sm();
        s.arm_to_active().await.expect("init");
        spawn_watchdog(Arc::clone(&s), 1);

        tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            s.erased_notify.notified(),
        )
        .await
        .expect("watchdog must fire within 5 seconds");

        assert_eq!(s.current().await, AgentState::Erased);
        assert!(
            s.abort_flag().load(Ordering::SeqCst),
            "the watchdog must abort in-flight sequential work, not just relabel the state"
        );
    }

    #[test]
    fn test_phase_projection_is_total() {
        for (phase, expected) in [
            (Phase::Armed, AgentState::Armed),
            (Phase::Active, AgentState::Active),
            (Phase::Locked, AgentState::Locked),
            (Phase::Erased, AgentState::Erased),
        ] {
            assert_eq!(AgentState::from(phase), expected);
        }
    }
}
