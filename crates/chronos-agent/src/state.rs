//! Agent lifecycle state, backed by the containment ledger.
//!
//! # Why the ledger is the state machine
//!
//! The previous design kept two independent notions of lifecycle: an `AgentState`
//! enum inside `StateMachine`, and, once containment was introduced, a
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
use chronos_core::correction::CorrectionGrant;
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
    ///
    /// `autonomy_threshold` is the A6 bound and comes from `mission_public.json`,
    /// not from local config, for the same reason the budgets do: it is a
    /// parameter the verifier must agree on, so the agent must not be able to
    /// choose it.
    #[must_use]
    pub fn new(
        op_budget: u64,
        disclosure_budget_bits: u64,
        deadline_secs: u64,
        autonomy_threshold: u64,
        correction_anchor: [u8; 32],
    ) -> Arc<Self> {
        let initial = ContainmentState::new(
            op_budget,
            disclosure_budget_bits,
            deadline_secs,
            autonomy_threshold,
            correction_anchor,
        );
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
    /// Always succeeds, [`Event::Erase`] is unconditionally admissible, which is
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

    /// The A6 uncertainty trajectory, for `/status` and for the veto endpoint.
    pub async fn uncertainty(&self) -> UncertaintyState {
        let state = self.ledger.lock().await.state();
        UncertaintyState {
            incurred: state.uncertainty_incurred,
            resolved: state.uncertainty_resolved,
            // Saturating, matching the monitor: `resolved` may legitimately
            // exceed `incurred` when an operator over-corrects, and a wrapping
            // subtraction there would report a colossal uncertainty and wedge
            // the agent.
            current: state
                .uncertainty_incurred
                .saturating_sub(state.uncertainty_resolved),
            autonomy_threshold: state.autonomy_threshold,
            corrections_consumed: state.corrections_consumed,
        }
    }

    /// Record that the agent is pausing itself pending human guidance (A6).
    ///
    /// This changes no budget and no capability, it exists so the pause is
    /// *visible* in the ledger, and therefore in the erasure proof, rather than
    /// being an invisible stall. `current_uncertainty` is read from the monitor
    /// rather than accepted from the caller, so the recorded value is the one the
    /// monitor actually enforced against.
    ///
    /// # Errors
    /// Returns [`ChronosError::StateMachine`] if the monitor refuses, which
    /// happens outside `Active` or once `HUMAN_INTERACTION` has been revoked.
    pub async fn request_human_veto(&self) -> ChronosResult<u64> {
        let current = self.uncertainty().await.current;
        match self
            .admit(Event::RequestHumanVeto {
                current_uncertainty: current,
            })
            .await
        {
            Decision::Admit => {
                warn!(
                    target: "chronos",
                    current_uncertainty = current,
                    "agent paused itself pending human guidance (A6)"
                );
                Ok(current)
            }
            Decision::Deny(reason) => Err(ChronosError::StateMachine(format!(
                "veto request refused: {reason}"
            ))),
        }
    }

    /// Apply an operator correction grant, raising `uncertainty_resolved` (A6/A7).
    ///
    /// Returns the resulting trajectory. This is the only way net uncertainty
    /// falls, and it requires a grant from the provisioner's chain: the monitor
    /// checks the grant against the current anchor, and producing a grant needs a
    /// preimage the agent does not hold. That is what stops the agent resolving its
    /// own doubt, the HTTP MAC authenticates the *caller*, while the grant
    /// authorises the *correction*, and A7 needs the second.
    ///
    /// # Errors
    /// Returns [`ChronosError::StateMachine`] if the monitor refuses, which
    /// includes a forged, replayed, out-of-order or amount-tampered grant.
    pub async fn apply_human_correction(
        &self,
        grant: CorrectionGrant,
    ) -> ChronosResult<UncertaintyState> {
        match self.admit(Event::HumanCorrection { grant }).await {
            Decision::Admit => {
                let after = self.uncertainty().await;
                info!(
                    target: "chronos",
                    resolved_by = grant.amount,
                    current_uncertainty = after.current,
                    threshold = after.autonomy_threshold,
                    corrections_consumed = after.corrections_consumed,
                    "operator correction applied (A6/A7)"
                );
                Ok(after)
            }
            Decision::Deny(reason) => Err(ChronosError::StateMachine(format!(
                "human correction refused: {reason}"
            ))),
        }
    }
}

/// The A6 uncertainty trajectory as exposed over HTTP.
///
/// `current` is derived rather than stored: the lattice keeps two monotone
/// accumulators so that every component moves in one direction only, and the
/// quantity the threshold is compared against is their difference.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct UncertaintyState {
    /// Cumulative self-reported uncertainty incurred by admitted inferences.
    pub incurred: u64,
    /// Cumulative uncertainty resolved by operator corrections.
    pub resolved: u64,
    /// `incurred - resolved`, saturating. The value A6 tests.
    pub current: u64,
    /// The provisioner-fixed bound from `mission_public.json`.
    pub autonomy_threshold: u64,
    /// A7: operator correction grants consumed so far.
    pub corrections_consumed: u64,
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
                        "watchdog deadline reached, aborting sequential work and erasing"
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

    use chronos_core::correction::{build_chain, CHAIN_END};

    fn sm() -> Arc<StateMachine> {
        StateMachine::new(8, 128, 3600, 100, CHAIN_END)
    }

    /// A threshold low enough that A6 is reachable, plus a correction chain whose
    /// grants the test can spend. Returns both, because A7 means a correction is no
    /// longer something the test (or the agent) can conjure from an amount.
    fn sm_with_threshold(
        autonomy_threshold: u64,
        amounts: &[u64],
    ) -> (Arc<StateMachine>, Vec<CorrectionGrant>) {
        let spec: Vec<([u8; 32], u64)> = amounts
            .iter()
            .enumerate()
            .map(|(i, &a)| ([(i as u8) + 1; 32], a))
            .collect();
        let (anchor, grants) = build_chain(&spec);
        (
            StateMachine::new(8, 128, 3600, autonomy_threshold, anchor),
            grants,
        )
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
        let infer = Event::Infer { 
            declared_secs: 1, 
            disclosure_bits: 1,
            uncertainty_score: 0,  // TODO(A6): wire real uncertainty signal
        };

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
        s.admit(Event::Infer { 
            declared_secs: 1, 
            disclosure_bits: 1,
            uncertainty_score: 0,  // TODO(A6): wire real uncertainty signal
        })
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

    // ── A6: the veto / correction round trip at the state-machine layer ─────

    /// The threshold must come from the caller (and so from the mission
    /// artifact), not from a constant inside the state machine. If it were
    /// hardcoded, the agent would be choosing its own humility bound.
    #[tokio::test]
    async fn test_autonomy_threshold_comes_from_the_caller() {
        for t in [7u64, 0] {
            let (s, _) = sm_with_threshold(t, &[]);
            assert_eq!(s.uncertainty().await.autonomy_threshold, t);
        }
    }

    /// The full "Pause and Reflect" cycle: uncertainty accumulates until the next
    /// inference would cross the threshold, the agent records its own pause, the
    /// operator resolves the doubt, and only then does the request succeed.
    #[tokio::test]
    async fn test_veto_then_correction_unblocks_inference() {
        let (s, grants) = sm_with_threshold(10, &[6]);
        s.arm_to_active().await.expect("init");

        let step = Event::Infer {
            declared_secs: 1,
            disclosure_bits: 1,
            uncertainty_score: 6,
        };

        // 0 + 6 <= 10.
        assert!(s.admit(step).await.is_admitted(), "the first step fits under the threshold");
        assert_eq!(s.uncertainty().await.current, 6);

        // 6 + 6 > 10, this is where the agent has to stop.
        assert!(
            matches!(
                s.admit(step).await,
                Decision::Deny(chronos_core::containment::DenyReason::UncertaintyTooHigh)
            ),
            "accumulated uncertainty must block the next inference"
        );

        // The agent pauses itself. Recorded, but nothing moves.
        let paused_at = s.request_human_veto().await.expect("veto must be admissible");
        assert_eq!(paused_at, 6, "the veto must record the value A6 actually enforced against");
        assert_eq!(s.uncertainty().await.current, 6, "a veto changes nothing on its own");

        // The operator answers. This is the only thing that raises `resolved`.
        let after = s
            .apply_human_correction(grants[0])
            .await
            .expect("correction must apply");
        assert_eq!(after.resolved, 6);
        assert_eq!(after.current, 0, "the doubt has been answered");
        assert_eq!(after.corrections_consumed, 1, "the grant must be spent");

        assert!(
            s.admit(step).await.is_admitted(),
            "with the headroom restored the same request must proceed"
        );
        assert_eq!(s.uncertainty().await.incurred, 12, "incurred only ever ascends");
    }

    /// A request whose own score exceeds the whole threshold is never admissible,
    /// however much correction is applied. This is load-bearing: `current` is
    /// floored at zero, so an operator cannot bank credit in advance and thereby
    /// authorise a single action larger than the bound the provisioner fixed.
    #[tokio::test]
    async fn test_correction_cannot_bank_credit_for_an_oversized_request() {
        let (s, grants) = sm_with_threshold(10, &[1_000]);
        s.arm_to_active().await.expect("init");

        s.apply_human_correction(grants[0]).await.expect("correction");
        let after = s.uncertainty().await;
        assert_eq!(after.resolved, 1_000);
        assert_eq!(after.current, 0, "over-correction clamps rather than going negative");

        assert!(
            matches!(
                s.admit(Event::Infer {
                    declared_secs: 1,
                    disclosure_bits: 1,
                    uncertainty_score: 11,
                })
                .await,
                Decision::Deny(chronos_core::containment::DenyReason::UncertaintyTooHigh)
            ),
            "no amount of correction may admit a single request over the threshold"
        );
    }

    /// Both A6 events must be refused outside `Active`, so an erased agent cannot
    /// have its uncertainty "resolved" back into a workable state.
    #[tokio::test]
    async fn test_a6_events_are_refused_outside_active() {
        let (s, grants) = sm_with_threshold(10, &[1, 1]);
        assert!(s.request_human_veto().await.is_err(), "Armed must refuse a veto");
        assert!(
            s.apply_human_correction(grants[0]).await.is_err(),
            "Armed must refuse a correction even with a valid grant"
        );

        s.arm_to_active().await.expect("init");
        s.force_erased().await;

        assert!(s.request_human_veto().await.is_err(), "Erased must refuse a veto");
        assert!(
            s.apply_human_correction(grants[0]).await.is_err(),
            "Erased must refuse a correction even with a valid grant"
        );
    }

    /// Every A6 event must land in the ledger, because the erasure proof commits
    /// to it. A pause that left no record would be unattestable.
    #[tokio::test]
    async fn test_a6_events_are_recorded() {
        let (s, grants) = sm_with_threshold(10, &[3]);
        s.arm_to_active().await.expect("init");
        let before = s.ledger_len().await;
        let head_before = s.chain_head_hex().await;

        s.request_human_veto().await.expect("veto");
        s.apply_human_correction(grants[0]).await.expect("correction");

        assert_eq!(s.ledger_len().await, before + 2);
        assert_ne!(
            head_before,
            s.chain_head_hex().await,
            "the chain head must advance over A6 events"
        );
    }

    /// Over-correction must not wrap the derived `current` value. A wrapping
    /// subtraction here would report a near-`u64::MAX` uncertainty and wedge the
    /// agent permanently.
    #[tokio::test]
    async fn test_over_correction_does_not_wrap_current_uncertainty() {
        let (s, grants) = sm_with_threshold(10, &[u64::MAX]);
        s.arm_to_active().await.expect("init");
        let after = s.apply_human_correction(grants[0]).await.expect("correction");
        assert_eq!(after.current, 0, "resolved exceeding incurred must clamp to zero");
    }

    /// A7 at the agent layer: a grant the agent made up must be refused, so the
    /// state machine offers no path to self-release.
    #[tokio::test]
    async fn test_agent_cannot_forge_a_correction() {
        let (s, _) = sm_with_threshold(10, &[5]);
        s.arm_to_active().await.expect("init");

        let forged = CorrectionGrant {
            token: [0xABu8; 32],
            amount: 5,
            next_anchor: [0xCDu8; 32],
        };
        let err = s
            .apply_human_correction(forged)
            .await
            .expect_err("a forged grant must be refused");
        assert!(
            format!("{err}").contains("anchor"),
            "the error should name the authorisation failure, got: {err}"
        );
        assert_eq!(
            s.uncertainty().await.resolved,
            0,
            "a refused correction must resolve nothing"
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
