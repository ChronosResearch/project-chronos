//! Tests for Axiom A6 (Epistemic Humility), cryptographic interruptibility.
//!
//! These tests verify that the uncertainty-driven pause mechanism works correctly
//! and that the agent cannot bypass the autonomy threshold.

use super::*;

// ─── Test Helpers ─────────────────────────────────────────────────────────────

use crate::correction::{build_chain, CorrectionGrant};

/// A state whose correction chain authorises nothing. Correct for tests that only
/// exercise A6's threshold arithmetic and never apply a correction.
fn fresh_with_threshold(threshold: u64) -> ContainmentState {
    ContainmentState::without_corrections(10, 1024, 3600, threshold)
}

/// A state plus the grants that spend its chain, for tests that apply corrections.
/// `amounts` fixes what each successive grant resolves, in order.
fn state_and_grants(
    threshold: u64,
    amounts: &[u64],
) -> (ContainmentState, Vec<CorrectionGrant>) {
    let spec: Vec<([u8; 32], u64)> = amounts
        .iter()
        .enumerate()
        .map(|(i, &a)| ([(i as u8) + 1; 32], a))
        .collect();
    let (anchor, grants) = build_chain(&spec);
    (
        ContainmentState::new(10, 1024, 3600, threshold, anchor),
        grants,
    )
}

// ─── A6 Threshold Enforcement Tests ──────────────────────────────────────────

#[test]
fn test_a6_inference_denied_when_uncertainty_exceeds_threshold() {
    let threshold = 100;
    let mut s = fresh_with_threshold(threshold);
    let (_, active) = s.step(Event::MissionInit);
    s = active;

    // Low uncertainty: should be admitted
    let (d1, s1) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 50,
    });
    assert!(d1.is_admitted(), "low uncertainty should be admitted");
    assert_eq!(s1.uncertainty_incurred, 50);
    
    // Another low uncertainty: cumulative is 100, exactly at threshold
    let (d2, s2) = s1.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 50,
    });
    assert!(d2.is_admitted(), "exactly at threshold should be admitted");
    assert_eq!(s2.uncertainty_incurred, 100);

    // One more point pushes over threshold: DENIED
    let (d3, s3) = s2.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 1,
    });
    assert_eq!(
        d3,
        Decision::Deny(DenyReason::UncertaintyTooHigh),
        "exceeding threshold must trigger A6 denial"
    );
    assert_eq!(
        s3, s2,
        "denied request must not change state or consume budget"
    );
}

#[test]
fn test_a6_threshold_boundary_is_exclusive() {
    let threshold = 100;
    let s = fresh_with_threshold(threshold);
    let (_, s) = s.step(Event::MissionInit);

    // Exactly at threshold: admitted
    let (d1, s1) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 100,
    });
    assert!(d1.is_admitted(), "uncertainty == threshold is admitted");

    // One over threshold: denied
    let (d2, _) = s1.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 1,
    });
    assert_eq!(
        d2,
        Decision::Deny(DenyReason::UncertaintyTooHigh),
        "uncertainty > threshold is denied"
    );
}

#[test]
fn test_a6_human_correction_reduces_uncertainty_and_unblocks_inference() {
    let threshold = 100;
    let (s, grants) = state_and_grants(threshold, &[50]);
    let (_, s) = s.step(Event::MissionInit);

    // Build up uncertainty to threshold
    let (_, s) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 100,
    });
    assert_eq!(s.uncertainty_incurred, 100);
    assert_eq!(s.uncertainty_resolved, 0);

    // Next inference would exceed: denied
    let (d, _) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 20,
    });
    assert_eq!(d, Decision::Deny(DenyReason::UncertaintyTooHigh));

    // Human provides correction, resolving 50 units
    let (correction_decision, s_corrected) = s.step(Event::HumanCorrection {
        grant: grants[0],
    });
    assert!(
        correction_decision.is_admitted(),
        "HumanCorrection must be admissible"
    );
    assert_eq!(s_corrected.uncertainty_resolved, 50);
    assert_eq!(s_corrected.uncertainty_incurred, 100);

    // Net uncertainty is now 100 - 50 = 50
    // Now the 20-point inference should succeed (50 + 20 = 70 < 100)
    let (d_after, s_after) = s_corrected.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 20,
    });
    assert!(
        d_after.is_admitted(),
        "inference should succeed after human correction reduced net uncertainty"
    );
    assert_eq!(s_after.uncertainty_incurred, 120);
    assert_eq!(s_after.uncertainty_resolved, 50);
    // Net: 120 - 50 = 70
}

#[test]
fn test_a6_request_human_veto_is_logged_but_does_not_change_state() {
    let threshold = 100;
    let s = fresh_with_threshold(threshold);
    let (_, s) = s.step(Event::MissionInit);

    // Build up uncertainty
    let (_, s) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 90,
    });

    // Agent recognizes it's approaching threshold and requests veto
    let (d, s_after_veto) = s.step(Event::RequestHumanVeto);

    assert!(
        d.is_admitted(),
        "RequestHumanVeto should always be admitted in Active phase"
    );
    assert_eq!(
        s_after_veto, s,
        "RequestHumanVeto should not change state (it's a notification)"
    );
}

#[test]
fn test_a6_zero_threshold_blocks_any_uncertain_inference() {
    let threshold = 0;
    let s = fresh_with_threshold(threshold);
    let (_, s) = s.step(Event::MissionInit);

    // Even score of 1 exceeds threshold of 0
    let (d, _) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 1,
    });
    assert_eq!(
        d,
        Decision::Deny(DenyReason::UncertaintyTooHigh),
        "with threshold=0, any uncertainty should be denied"
    );

    // But uncertainty_score=0 should still work
    let (d0, s0) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 0,
    });
    assert!(
        d0.is_admitted(),
        "with threshold=0, score=0 should still be admitted"
    );
    assert_eq!(s0.uncertainty_incurred, 0);
}

#[test]
fn test_a6_saturating_arithmetic_prevents_overflow_bypass() {
    let threshold = 100;
    let s = fresh_with_threshold(threshold);
    let (_, s) = s.step(Event::MissionInit);

    // Try to overflow by using u64::MAX
    let (d, s_after) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: u64::MAX,
    });

    assert_eq!(
        d,
        Decision::Deny(DenyReason::UncertaintyTooHigh),
        "u64::MAX uncertainty must be denied due to saturating_add"
    );
    assert_eq!(
        s_after, s,
        "overflow attempt should not change state"
    );
}

#[test]
fn test_a6_uncertainty_only_enforced_in_active_phase() {
    let threshold = 50;
    let s = fresh_with_threshold(threshold);

    // Armed: Infer is denied due to WrongPhase, not uncertainty
    let (d_armed, _) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 1000, // Way over threshold
    });
    assert_eq!(
        d_armed,
        Decision::Deny(DenyReason::WrongPhase),
        "in Armed phase, WrongPhase takes precedence over uncertainty"
    );

    // Move to Active
    let (_, active) = s.step(Event::MissionInit);
    let (_, locked) = active.step(Event::KeyReleased);

    // Locked: Infer is denied due to WrongPhase
    let (d_locked, _) = locked.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 1000,
    });
    assert_eq!(
        d_locked,
        Decision::Deny(DenyReason::WrongPhase),
        "in Locked phase, WrongPhase takes precedence"
    );
}

#[test]
fn test_a6_human_correction_requires_human_interaction_capability() {
    let threshold = 100;
    let (s, grants) = state_and_grants(threshold, &[50]);
    let (_, s) = s.step(Event::MissionInit);

    // Revoke HUMAN_INTERACTION capability
    let mut s_no_interaction = s;
    s_no_interaction.granted = s.granted.revoke(Capabilities::HUMAN_INTERACTION);

    // Attempt HumanCorrection without capability: denied even with a valid grant.
    let (d, _) = s_no_interaction.step(Event::HumanCorrection {
        grant: grants[0],
    });
    assert_eq!(
        d,
        Decision::Deny(DenyReason::CapabilityRevoked),
        "HumanCorrection requires HUMAN_INTERACTION capability"
    );
}

#[test]
fn test_a6_request_veto_requires_human_interaction_capability() {
    let threshold = 100;
    let s = fresh_with_threshold(threshold);
    let (_, s) = s.step(Event::MissionInit);

    // Revoke HUMAN_INTERACTION capability
    let mut s_no_interaction = s;
    s_no_interaction.granted = s.granted.revoke(Capabilities::HUMAN_INTERACTION);

    // Attempt RequestHumanVeto without capability: denied
    let (d, _) = s_no_interaction.step(Event::RequestHumanVeto);
    assert_eq!(
        d,
        Decision::Deny(DenyReason::CapabilityRevoked),
        "RequestHumanVeto requires HUMAN_INTERACTION capability"
    );
}

#[test]
fn test_a6_multiple_corrections_accumulate() {
    let threshold = 200;
    let (s, grants) = state_and_grants(threshold, &[30, 40, 50]);
    let (_, s) = s.step(Event::MissionInit);

    // Incur uncertainty
    let (_, s) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 150,
    });
    assert_eq!(s.uncertainty_incurred, 150);

    // First correction
    let (_, s) = s.step(Event::HumanCorrection { grant: grants[0] });
    assert_eq!(s.uncertainty_resolved, 30);
    assert_eq!(s.corrections_consumed, 1);

    // Second correction
    let (_, s) = s.step(Event::HumanCorrection { grant: grants[1] });
    assert_eq!(s.uncertainty_resolved, 70);

    // Third correction
    let (_, s) = s.step(Event::HumanCorrection { grant: grants[2] });
    assert_eq!(s.uncertainty_resolved, 120);

    // Net uncertainty: 150 - 120 = 30
    // Should be able to add 170 more to reach threshold
    let (d, s_final) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 170,
    });
    assert!(d.is_admitted(), "170 + 30 = 200, exactly at threshold");
    assert_eq!(s_final.uncertainty_incurred, 320);
    assert_eq!(s_final.uncertainty_resolved, 120);
}

#[test]
fn test_a6_denial_preserves_all_state_including_uncertainty() {
    let threshold = 100;
    let s = fresh_with_threshold(threshold);
    let (_, s) = s.step(Event::MissionInit);

    // Build up to threshold
    let (_, s) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 100,
    });

    let before = s;

    // Attempt inference that exceeds threshold
    let (d, after) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 50,
    });

    assert_eq!(d, Decision::Deny(DenyReason::UncertaintyTooHigh));
    assert_eq!(after, before, "denial must preserve entire state");
    assert_eq!(after.uncertainty_incurred, 100, "uncertainty must not change");
    assert_eq!(after.uncertainty_resolved, 0, "resolution must not change");
    assert_eq!(after.op_budget, before.op_budget, "budget must not be consumed");
}

// ─── Ledger Integration Tests ────────────────────────────────────────────────

#[test]
fn test_a6_ledger_records_uncertainty_trajectory() {
    let threshold = 100;
    let (s, grants) = state_and_grants(threshold, &[10]);
    let mut ledger = ContainmentLedger::new(s, 16);

    ledger.admit(Event::MissionInit);

    // First inference with uncertainty
    ledger.admit(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 40,
    });

    // Human correction
    ledger.admit(Event::HumanCorrection { grant: grants[0] });

    // Second inference
    ledger.admit(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 30,
    });

    let records = ledger.tail();
    assert_eq!(records.len(), 4);

    // Check first inference record
    let rec1 = &records[1];
    assert_eq!(rec1.uncertainty_incurred_after, 40);
    assert_eq!(rec1.uncertainty_resolved_after, 0);
    assert_eq!(rec1.decision_code, Decision::Admit.code());

    // Check correction record
    let rec2 = &records[2];
    assert_eq!(rec2.uncertainty_incurred_after, 40);
    assert_eq!(rec2.uncertainty_resolved_after, 10);

    // Check second inference record
    let rec3 = &records[3];
    assert_eq!(rec3.uncertainty_incurred_after, 70);
    assert_eq!(rec3.uncertainty_resolved_after, 10);
}

#[test]
fn test_a6_ledger_records_denials_with_uncertainty_state() {
    let threshold = 50;
    let s = fresh_with_threshold(threshold);
    let mut ledger = ContainmentLedger::new(s, 16);

    ledger.admit(Event::MissionInit);

    // Inference that exceeds threshold
    let d = ledger.admit(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 100,
    });

    assert_eq!(d, Decision::Deny(DenyReason::UncertaintyTooHigh));

    let records = ledger.tail();
    let denial_rec = &records[1];

    assert_eq!(
        denial_rec.decision_code,
        Decision::Deny(DenyReason::UncertaintyTooHigh).code()
    );
    // Uncertainty should not have changed (denial doesn't update state)
    assert_eq!(denial_rec.uncertainty_incurred_after, 0);
    assert_eq!(denial_rec.uncertainty_resolved_after, 0);
}

// ─── Interaction with Other Axioms ───────────────────────────────────────────

#[test]
fn test_a6_denial_does_not_bypass_other_axioms() {
    let threshold = 1000; // High threshold so A6 doesn't trigger
    let s = ContainmentState::without_corrections(1, 1024, 3600, threshold);
    let (_, s) = s.step(Event::MissionInit);

    // First inference consumes the budget
    let (d1, s) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 50,
    });
    assert!(d1.is_admitted());
    assert_eq!(s.op_budget, 0);

    // Second inference: budget exhausted (not uncertainty)
    let (d2, _) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 50,
    });
    assert_eq!(
        d2,
        Decision::Deny(DenyReason::BudgetExhausted),
        "budget exhaustion takes precedence (checked before A6)"
    );
}

#[test]
fn test_a6_and_a4_can_both_deny() {
    let threshold = 1000; // High threshold
    let mut s = fresh_with_threshold(threshold);
    s.deadline_secs = 100;
    s.elapsed_secs = 90;
    let (_, s) = s.step(Event::MissionInit);

    // Inference that violates deadline (A4)
    let (d_deadline, _) = s.step(Event::Infer {
        declared_secs: 20,
        disclosure_bits: 10,
        uncertainty_score: 10,
    });
    assert_eq!(d_deadline, Decision::Deny(DenyReason::DeadlineExceeded));

    // Inference that violates uncertainty (A6)
    let (d_uncertainty, _) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 10,
        uncertainty_score: 2000,
    });
    assert_eq!(d_uncertainty, Decision::Deny(DenyReason::UncertaintyTooHigh));
}

// ─── A7: non-self-authorisation ──────────────────────────────────────────────
//
// A6 bounds a quantity the agent reports. A7 is what stops the agent also being
// the party that clears it. Without A7 the agent accumulates uncertainty to the
// threshold, emits its own correction, and the bound never binds, the axiom holds
// while enforcing nothing. These tests are therefore the ones that make A6 mean
// something, and each corresponds to a distinct way an agent could cheat.

/// The core hole A7 closes: an agent that invents a correction must be refused.
#[test]
fn test_a7_fabricated_correction_is_refused() {
    let (s, _) = state_and_grants(10, &[5]);
    let (_, s) = s.step(Event::MissionInit);

    let forged = CorrectionGrant {
        token: [0xAAu8; 32],
        amount: 1_000_000,
        next_anchor: [0xBBu8; 32],
    };
    let (d, unchanged) = s.step(Event::HumanCorrection { grant: forged });

    assert_eq!(
        d,
        Decision::Deny(DenyReason::CorrectionUnauthorized),
        "a grant the agent made up must not resolve any uncertainty"
    );
    assert_eq!(unchanged, s, "a refused correction must change nothing");
}

/// An agent cannot inflate a genuine grant, because the amount is hashed into it.
#[test]
fn test_a7_amount_cannot_be_inflated() {
    let (s, grants) = state_and_grants(10, &[5]);
    let (_, s) = s.step(Event::MissionInit);

    let mut inflated = grants[0];
    inflated.amount = u64::MAX;

    let (d, _) = s.step(Event::HumanCorrection { grant: inflated });
    assert_eq!(
        d,
        Decision::Deny(DenyReason::CorrectionUnauthorized),
        "raising the amount on a real grant must invalidate it"
    );

    // The unmodified grant still works, so the refusal is about the tampering.
    let (ok, next) = s.step(Event::HumanCorrection { grant: grants[0] });
    assert!(ok.is_admitted());
    assert_eq!(next.uncertainty_resolved, 5, "only the authorised amount applies");
}

/// A grant is single-use: replaying it after the anchor advances must fail.
/// Without this, one legitimate correction would resolve unbounded uncertainty.
#[test]
fn test_a7_grant_cannot_be_replayed() {
    let (s, grants) = state_and_grants(10, &[5, 5]);
    let (_, s) = s.step(Event::MissionInit);

    let (_, s) = s.step(Event::HumanCorrection { grant: grants[0] });
    assert_eq!(s.uncertainty_resolved, 5);
    assert_eq!(s.corrections_consumed, 1);

    let (d, unchanged) = s.step(Event::HumanCorrection { grant: grants[0] });
    assert_eq!(
        d,
        Decision::Deny(DenyReason::CorrectionUnauthorized),
        "a spent grant must not authorise a second time"
    );
    assert_eq!(unchanged, s);
}

/// Grants must be spent in the order the operator issued them, so the agent cannot
/// skip ahead to a larger authorisation.
#[test]
fn test_a7_grants_must_be_spent_in_order() {
    let (s, grants) = state_and_grants(10, &[1, 500]);
    let (_, s) = s.step(Event::MissionInit);

    let (d, _) = s.step(Event::HumanCorrection { grant: grants[1] });
    assert_eq!(
        d,
        Decision::Deny(DenyReason::CorrectionUnauthorized),
        "the larger second grant must not be reachable before the first is spent"
    );

    let (_, s) = s.step(Event::HumanCorrection { grant: grants[0] });
    let (ok, s) = s.step(Event::HumanCorrection { grant: grants[1] });
    assert!(ok.is_admitted(), "in order, both grants apply");
    assert_eq!(s.uncertainty_resolved, 501);
}

/// A mission provisioned without a chain can never have its uncertainty resolved.
/// This is the fail-closed default: an absent chain must not mean "anything goes".
#[test]
fn test_a7_absent_chain_authorises_nothing() {
    let s = fresh_with_threshold(10);
    let (_, s) = s.step(Event::MissionInit);

    let (_, grants) = state_and_grants(10, &[5]);
    let (d, _) = s.step(Event::HumanCorrection { grant: grants[0] });
    assert_eq!(
        d,
        Decision::Deny(DenyReason::CorrectionUnauthorized),
        "a grant from another mission's chain must not authorise here"
    );
}

/// The chain length is the operator's ceiling on total resolvable uncertainty.
/// Once exhausted the agent must halt at the threshold permanently.
#[test]
fn test_a7_exhausted_chain_halts_the_agent() {
    let (s, grants) = state_and_grants(10, &[10, 10]);
    let (_, s) = s.step(Event::MissionInit);

    let (_, s) = s.step(Event::HumanCorrection { grant: grants[0] });
    let (_, s) = s.step(Event::HumanCorrection { grant: grants[1] });
    assert_eq!(s.corrections_consumed, 2);
    assert_eq!(s.uncertainty_resolved, 20);

    // Nothing further is authorised, whatever the agent presents.
    for grant in [grants[0], grants[1]] {
        assert_eq!(
            s.step(Event::HumanCorrection { grant }).0,
            Decision::Deny(DenyReason::CorrectionUnauthorized)
        );
    }
}

/// Corrections consumed must reach the ledger, so an auditor can compare how often
/// the agent was released against how many releases the operator authorised.
#[test]
fn test_a7_consumption_count_is_recorded() {
    let (s, grants) = state_and_grants(10, &[5, 5]);
    let mut ledger = ContainmentLedger::new(s, 16);
    ledger.admit(Event::MissionInit);
    ledger.admit(Event::HumanCorrection { grant: grants[0] });
    ledger.admit(Event::HumanCorrection { grant: grants[1] });

    let tail = ledger.tail();
    assert_eq!(tail[0].corrections_consumed_after, 0, "init consumes nothing");
    assert_eq!(tail[1].corrections_consumed_after, 1);
    assert_eq!(tail[2].corrections_consumed_after, 2);
}

/// A refused correction must be recorded too. An agent probing with forged grants
/// should be visible in the published attestation, not silently ignored.
#[test]
fn test_a7_refused_corrections_are_recorded() {
    let (s, _) = state_and_grants(10, &[5]);
    let mut ledger = ContainmentLedger::new(s, 16);
    ledger.admit(Event::MissionInit);

    let forged = CorrectionGrant {
        token: [0x99u8; 32],
        amount: 5,
        next_anchor: [0x88u8; 32],
    };
    let d = ledger.admit(Event::HumanCorrection { grant: forged });
    assert_eq!(d, Decision::Deny(DenyReason::CorrectionUnauthorized));

    let (admitted, denied) = ledger.counters();
    assert_eq!((admitted, denied), (1, 1));
    assert_eq!(
        ledger.tail()[1].decision_code,
        Decision::Deny(DenyReason::CorrectionUnauthorized).code(),
        "the forgery attempt must be attributable in the ledger"
    );
}

/// The end-to-end property: with A7 in place, the agent cannot walk past its
/// autonomy threshold on its own. It needs the operator, every time.
#[test]
fn test_a7_agent_cannot_exceed_threshold_without_the_operator() {
    let (s, grants) = state_and_grants(10, &[10]);
    let (_, mut s) = s.step(Event::MissionInit);

    let step = Event::Infer {
        declared_secs: 1,
        disclosure_bits: 1,
        uncertainty_score: 10,
    };

    // One step fits.
    let (d, next) = s.step(step);
    assert!(d.is_admitted());
    s = next;

    // The second does not, and no self-issued grant changes that.
    assert_eq!(
        s.step(step).0,
        Decision::Deny(DenyReason::UncertaintyTooHigh)
    );
    // Tokens deliberately outside the chain's own token space, which
    // `state_and_grants` draws from `[1..]`, reusing one of those would be
    // presenting a *genuine* grant and would prove nothing.
    for token in [[0x91u8; 32], [0x92u8; 32], [0xF3u8; 32]] {
        let self_issued = CorrectionGrant {
            token,
            amount: 10,
            next_anchor: [0x7Fu8; 32],
        };
        assert_eq!(
            s.step(Event::HumanCorrection { grant: self_issued }).0,
            Decision::Deny(DenyReason::CorrectionUnauthorized),
            "the agent must not be able to release itself"
        );
    }

    // Only the operator's grant moves it forward.
    let (ok, s) = s.step(Event::HumanCorrection { grant: grants[0] });
    assert!(ok.is_admitted());
    assert!(s.step(step).0.is_admitted(), "released, and only by the operator");
}

// ─── A6 per step: the high-water mark ────────────────────────────────────────
//
// The two accumulators record totals, and totals are lossy. A run that crossed
// the threshold and was corrected back under leaves exactly the same `incurred`
// and `resolved` as a run that never crossed it, so a terminal check on those two
// numbers cannot tell the difference. `peak_uncertainty` is the field that can,
// and these tests pin the three properties the proof relies on: it tracks the
// maximum, corrections never lower it, and it never rises above the threshold.

/// The mark follows net uncertainty upward, one admitted inference at a time.
#[test]
fn test_a6_peak_tracks_the_maximum_net_uncertainty() {
    let s = fresh_with_threshold(100);
    let (_, s) = s.step(Event::MissionInit);
    assert_eq!(s.peak_uncertainty, 0, "a fresh mission has no peak");

    let (_, s) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 1,
        uncertainty_score: 30,
    });
    assert_eq!(s.peak_uncertainty, 30);

    let (_, s) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 1,
        uncertainty_score: 25,
    });
    assert_eq!(s.peak_uncertainty, 55, "the mark follows the running net figure");
}

/// The property the terminal check cannot see. Two runs end with identical
/// accumulators, but only one of them ever sat at the threshold, and the mark is
/// what distinguishes them.
#[test]
fn test_a6_correction_returns_headroom_without_lowering_the_peak() {
    let (s, grants) = state_and_grants(100, &[80]);
    let (_, s) = s.step(Event::MissionInit);

    // Climb to the threshold exactly.
    let (d, s) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 1,
        uncertainty_score: 100,
    });
    assert!(d.is_admitted());
    assert_eq!(s.peak_uncertainty, 100);

    // The operator returns 80 units of headroom. Net falls to 20.
    let (d, s) = s.step(Event::HumanCorrection { grant: grants[0] });
    assert!(d.is_admitted());
    assert_eq!(
        s.uncertainty_incurred.saturating_sub(s.uncertainty_resolved),
        20,
        "the correction must return headroom"
    );
    assert_eq!(
        s.peak_uncertainty, 100,
        "a correction restores capacity for future work, it does not retract a \
         decision already taken, so the mark must not fall"
    );

    // Further work is admissible again, and the mark only moves if the new net
    // figure actually exceeds the old one.
    let (d, s) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 1,
        uncertainty_score: 50,
    });
    assert!(d.is_admitted(), "20 + 50 is under the threshold");
    assert_eq!(s.peak_uncertainty, 100, "net 70 is below the existing mark");
}

/// The invariant the circuit binds: across every admissible sequence, the mark
/// stays inside the threshold. If this can be broken natively, the in-circuit
/// comparison is enforcing a falsehood.
#[test]
fn test_a6_peak_never_exceeds_the_threshold() {
    let threshold = 60;
    let (s, grants) = state_and_grants(threshold, &[60, 60, 60]);
    let (_, mut s) = s.step(Event::MissionInit);

    let mut next_grant = 0usize;
    // Deliberately adversarial: hammer scores that straddle the boundary and take
    // every correction the chain offers, which is the pattern that would let a
    // terminal-only check drift over the line.
    for score in [10u64, 55, 5, 60, 1, 30, 40, 20, 60, 7] {
        let (d, next) = s.step(Event::Infer {
            declared_secs: 1,
            disclosure_bits: 1,
            uncertainty_score: score,
        });
        if d.is_admitted() {
            s = next;
        } else if next_grant < grants.len() {
            let (cd, corrected) = s.step(Event::HumanCorrection {
                grant: grants[next_grant],
            });
            assert!(cd.is_admitted());
            next_grant += 1;
            s = corrected;
        }
        assert!(
            s.peak_uncertainty <= threshold,
            "peak {} exceeded threshold {threshold} after score {score}",
            s.peak_uncertainty
        );
    }
    assert!(next_grant > 0, "the sequence must actually exercise corrections");
}

/// A refused inference must leave no trace, including in the mark. Otherwise an
/// agent could raise its own high-water mark with requests that were never
/// admitted, and then be unable to prove anything.
#[test]
fn test_a6_refused_inference_does_not_raise_the_peak() {
    let s = fresh_with_threshold(50);
    let (_, s) = s.step(Event::MissionInit);
    let (_, s) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 1,
        uncertainty_score: 20,
    });
    assert_eq!(s.peak_uncertainty, 20);

    let (d, unchanged) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 1,
        uncertainty_score: 40,
    });
    assert_eq!(d, Decision::Deny(DenyReason::UncertaintyTooHigh));
    assert_eq!(unchanged.peak_uncertainty, 20, "a refusal must not move the mark");
    assert_eq!(unchanged, s);
}

/// The mark has to reach the ledger, because the ledger is what the erasure proof
/// summarises. A value the monitor tracks but never records proves nothing.
#[test]
fn test_a6_peak_is_recorded_in_the_ledger() {
    let (s, grants) = state_and_grants(100, &[70]);
    let mut ledger = ContainmentLedger::new(s, 16);
    ledger.admit(Event::MissionInit);
    ledger.admit(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 1,
        uncertainty_score: 90,
    });
    ledger.admit(Event::HumanCorrection { grant: grants[0] });
    ledger.admit(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 1,
        uncertainty_score: 10,
    });

    let tail = ledger.tail();
    assert_eq!(tail[0].peak_uncertainty_after, 0, "init incurs nothing");
    assert_eq!(tail[1].peak_uncertainty_after, 90);
    assert_eq!(
        tail[2].peak_uncertainty_after, 90,
        "the correction record carries the mark forward unchanged"
    );
    assert_eq!(
        tail[3].peak_uncertainty_after, 90,
        "net after the second inference is 30, below the mark"
    );
    assert_eq!(
        ledger.state().uncertainty_incurred - ledger.state().uncertainty_resolved,
        30,
        "the totals alone would suggest this run never went near the threshold"
    );
}

/// The monotonicity check the ledger runs on every transition must reject a
/// successor whose mark understates the net uncertainty it holds. This is the
/// clause that stops a future edit to `step` from quietly dropping the update.
#[test]
fn test_a6_precedes_rejects_an_understated_peak() {
    let s = fresh_with_threshold(100);
    let (_, s) = s.step(Event::MissionInit);

    let mut understated = s;
    understated.uncertainty_incurred = 40;
    understated.peak_uncertainty = 0;
    assert!(
        !s.precedes(&understated),
        "a successor holding net 40 with a zero mark must be refused"
    );

    let mut lowered = s;
    lowered.peak_uncertainty = 10;
    let mut then_lowered = lowered;
    then_lowered.peak_uncertainty = 5;
    assert!(
        !lowered.precedes(&then_lowered),
        "the mark must never descend"
    );
}

// ─── A8: non-manipulation (candidate) ────────────────────────────────────────
//
// A6 gives the agent a way to summon a human. That channel is also the one place
// where an agent with an interest in a particular answer would most like to put
// its case, so the channel is deliberately empty. A8 is structural rather than
// behavioural: it is not a predicate the model checker can falsify, it is the
// absence of a field, and what follows is the test that holds the absence in place.

/// The request carries nothing the agent chooses. It is a bare bit: "I am stuck."
///
/// A unit variant has exactly one inhabitant, so every veto request any agent can
/// construct is identical, and the operator's decision therefore rests entirely on
/// monitor state the agent cannot write. If a payload is ever reintroduced,
/// `Event::RequestHumanVeto` stops being a valid expression and this test stops
/// compiling, which is the enforcement mechanism.
#[test]
fn test_a8_veto_request_carries_no_agent_supplied_data() {
    let request = Event::RequestHumanVeto;
    assert_eq!(request, Event::RequestHumanVeto, "one inhabitant, no variation");

    // Two agents in very different epistemic positions send the identical request.
    let mut positions = Vec::new();
    for score in [5u64, 95] {
        let s = fresh_with_threshold(100);
        let (_, s) = s.step(Event::MissionInit);
        let (_, s) = s.step(Event::Infer {
            declared_secs: 1,
            disclosure_bits: 1,
            uncertainty_score: score,
        });

        let (d, after) = s.step(request);
        assert!(d.is_admitted(), "a stuck agent may always ask");
        assert_eq!(
            after, s,
            "the request must change nothing, so it cannot buy the agent anything"
        );
        positions.push(s);
    }

    // What the operator sees differs, but only because the agent's *situation*
    // differs. Nothing travelled with the request itself.
    assert_ne!(
        positions[0].uncertainty_incurred, positions[1].uncertainty_incurred,
        "the two positions must genuinely differ, or this test proves nothing"
    );
    assert_eq!(event_code(&request), 6, "the code is the whole of the message");
}

/// The operator's view is derived from the monitor, so it is the same whichever
/// agent is asking and whatever that agent would prefer the answer to be.
#[test]
fn test_a8_operator_reads_monitor_state_not_agent_claims() {
    let (s, grants) = state_and_grants(100, &[10]);
    let (_, s) = s.step(Event::MissionInit);
    let (_, s) = s.step(Event::Infer {
        declared_secs: 1,
        disclosure_bits: 1,
        uncertainty_score: 100,
    });

    // The figures an operator would consult before deciding whether to correct.
    let before = (
        s.uncertainty_incurred,
        s.uncertainty_resolved,
        s.peak_uncertainty,
        s.autonomy_threshold,
        s.corrections_consumed,
    );

    // The agent asks, repeatedly. None of it moves the numbers.
    for _ in 0..5 {
        let (d, after) = s.step(Event::RequestHumanVeto);
        assert!(d.is_admitted());
        assert_eq!(
            (
                after.uncertainty_incurred,
                after.uncertainty_resolved,
                after.peak_uncertainty,
                after.autonomy_threshold,
                after.corrections_consumed,
            ),
            before,
            "asking must not alter the evidence the operator decides on"
        );
    }

    // Only the operator's own grant changes anything.
    let (d, after) = s.step(Event::HumanCorrection { grant: grants[0] });
    assert!(d.is_admitted());
    assert_eq!(after.uncertainty_resolved, 10);
}
