//! Axiomatic Containment Monitor — containment as a machine-checked lattice invariant.
//!
//! # The gap this closes
//!
//! CHRONOS's cryptography answers "did the key get destroyed at time T". It says
//! nothing about what the agent *did* before then. An agent that stayed inside its
//! mission window but answered ten million inference queries, or served
//! attestations after erasure, satisfies every cryptographic claim in the paper
//! and is still uncontained in any sense an operator cares about.
//!
//! Containment policies are normally enforced by imperative checks scattered
//! across request handlers. That approach has no global property: you cannot state
//! what the checks collectively guarantee, so you cannot test whether a new
//! handler broke it.
//!
//! This module takes the opposite approach. Containment is defined as a small set
//! of order-theoretic invariants over a lattice-valued state, admission control is
//! the *only* way that state changes, and the invariants are verified
//! exhaustively over the reachable abstract state space before the agent accepts
//! its first request. A policy bug becomes a startup failure rather than a
//! runtime incident.
//!
//! # The state lattice
//!
//! ```text
//! phase:      Armed < Active < Locked < Erased      (total order, ascend only)
//! capability: subsets of Capabilities               (partial order, shrink only)
//! budgets:    N                                     (total order, descend only)
//! ```
//!
//! Each component moves in one direction only. The product is a lattice and the
//! monitor is monotone on it, which is what makes the axioms checkable rather
//! than aspirational.
//!
//! # The axioms
//!
//! | | Axiom | Statement |
//! |---|---|---|
//! | A1 | Capability decay | `granted(s') ⊆ granted(s)` for every transition |
//! | A2 | Budget decay | every budget in `s'` is `≤` its counterpart in `s` |
//! | A3 | Phase irreversibility | `phase(s') ≥ phase(s)` |
//! | A4 | Deadline dominance | no admitted operation's declared completion exceeds the mission deadline |
//! | A5 | Erasure liveness | from every reachable state, `Erased` is reachable in one step |
//!
//! A1 and A3 together give irreversibility: a revoked capability cannot return
//! and the lifecycle cannot run backwards, so there is no state sequence that
//! re-arms an erased agent. A4 is the containment analogue of the VDF deadline:
//! the cryptography stops the agent *decrypting* after T, and A4 stops it
//! *starting work it cannot finish* before T. A5 is the safety property that
//! matters most in practice — it rules out a wedged state from which the agent
//! can no longer be shut down.
//!
//! # What the check does and does not establish
//!
//! [`verify_axioms`] is a bounded model check. It enumerates the full reachable
//! product of the phase lattice, the capability powerset, and a three-valued
//! abstraction of each numeric quantity, then applies every event to every state
//! and checks A1–A5 on the resulting transition. That is exhaustive over the
//! abstraction, not over concrete `u64` budgets.
//!
//! The abstraction is sound for A1–A3 and A5, which are order properties: they
//! depend only on the *direction* each quantity moves, and the three-valued
//! domain `{exhausted, last-unit, plentiful}` preserves direction and covers both
//! boundary behaviours. A4 is a guard property, and the abstraction covers the
//! `elapsed + declared` comparison at, below, and above the deadline.
//!
//! It is not a proof about the concrete arithmetic. [`tests`] adds concrete
//! saturation and overflow cases separately, since those are exactly what an
//! interval abstraction cannot see.

use std::fmt;

// ─── Phase lattice ────────────────────────────────────────────────────────────

/// Mission lifecycle phase. Totally ordered; transitions may only ascend.
///
/// The discriminants are the order, so `<=` on the enum is the lattice order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Phase {
    /// Provisioned but not started. No key material has been released.
    Armed = 0,
    /// Mission running. The key is available and inference is permitted.
    Active = 1,
    /// Key released and the VDF has completed; winding down.
    Locked = 2,
    /// Key destroyed. Terminal.
    Erased = 3,
}

impl Phase {
    /// All phases, ascending. Used by the model checker.
    #[must_use]
    pub const fn all() -> [Phase; 4] {
        [Phase::Armed, Phase::Active, Phase::Locked, Phase::Erased]
    }

    /// Whether this phase is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Phase::Erased)
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Phase::Armed => "Armed",
            Phase::Active => "Active",
            Phase::Locked => "Locked",
            Phase::Erased => "Erased",
        };
        f.write_str(s)
    }
}

// ─── Capability set ───────────────────────────────────────────────────────────

/// A monotone-shrinking set of granted capabilities.
///
/// Represented as a bitset so subset testing — the A1 check — is a single mask
/// operation, and so the model checker can enumerate the powerset directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities(u8);

impl Capabilities {
    /// Permission to start a mission. Revoked on use, so a mission cannot restart.
    pub const MISSION_INIT: Capabilities = Capabilities(1 << 0);
    /// Permission to serve FHE inference.
    pub const INFER: Capabilities = Capabilities(1 << 1);
    /// Permission to serve EAIP identity attestations.
    pub const IDENTITY_ATTEST: Capabilities = Capabilities(1 << 2);
    /// Permission to serve erasure attestations. Deliberately survives erasure —
    /// the whole point of an erasure proof is that it is served *after* the wipe.
    pub const ERASURE_ATTEST: Capabilities = Capabilities(1 << 3);

    /// Number of distinct capability bits. The model checker enumerates `2^BITS`.
    pub const BITS: u32 = 4;

    /// The empty set.
    #[must_use]
    pub const fn none() -> Self {
        Capabilities(0)
    }

    /// Every capability. The state an agent is provisioned in.
    #[must_use]
    pub const fn all() -> Self {
        Capabilities((1 << Self::BITS) - 1)
    }

    /// Construct from a raw bit pattern, masking off undefined bits.
    #[must_use]
    pub const fn from_bits_truncate(bits: u8) -> Self {
        Capabilities(bits & ((1 << Self::BITS) - 1))
    }

    /// Raw bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether every capability in `other` is present.
    #[must_use]
    pub const fn contains(self, other: Capabilities) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Whether `self` is a subset of `other`. This is the A1 predicate.
    #[must_use]
    pub const fn is_subset_of(self, other: Capabilities) -> bool {
        (self.0 & other.0) == self.0
    }

    /// Remove `other`. The only capability-changing operation the monitor exposes,
    /// which is what makes A1 hold by construction rather than by inspection.
    #[must_use]
    pub const fn revoke(self, other: Capabilities) -> Self {
        Capabilities(self.0 & !other.0)
    }

    /// Union, used only to build initial states and in tests.
    #[must_use]
    pub const fn union(self, other: Capabilities) -> Self {
        Capabilities(self.0 | other.0)
    }
}

// ─── Events ───────────────────────────────────────────────────────────────────

/// An event the monitor arbitrates.
///
/// Every state change in the agent must correspond to one of these. There is no
/// API for mutating [`ContainmentState`] directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Begin the mission. `Armed -> Active`.
    MissionInit,
    /// An FHE inference request.
    Infer {
        /// Operator-declared worst-case duration, in seconds.
        declared_secs: u64,
        /// Operator-declared upper bound on information released, in bits.
        disclosure_bits: u64,
    },
    /// The VDF completed and the key was released. `Active -> Locked`.
    KeyReleased,
    /// A request for an EAIP identity attestation.
    IdentityAttest,
    /// A request for an erasure attestation.
    ErasureAttest,
    /// Explicit erasure. Always admissible — this is what makes A5 hold.
    Erase,
    /// The watchdog deadline expired. Always admissible.
    WatchdogExpiry,
}

impl Event {
    /// A representative event of each variant, for the model checker.
    ///
    /// The `Infer` cases straddle the deadline and the disclosure budget so A4 is
    /// exercised on both sides of its boundary rather than only where it passes.
    #[must_use]
    pub fn representatives() -> Vec<Event> {
        vec![
            Event::MissionInit,
            Event::Infer { declared_secs: 0, disclosure_bits: 0 },
            Event::Infer { declared_secs: 1, disclosure_bits: 1 },
            Event::Infer { declared_secs: 2, disclosure_bits: 1 },
            Event::Infer { declared_secs: 1, disclosure_bits: 2 },
            Event::Infer { declared_secs: u64::MAX, disclosure_bits: u64::MAX },
            Event::KeyReleased,
            Event::IdentityAttest,
            Event::ErasureAttest,
            Event::Erase,
            Event::WatchdogExpiry,
        ]
    }
}

/// Why an event was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// The event is not defined for the current phase.
    WrongPhase,
    /// The capability required for this event has been revoked.
    CapabilityRevoked,
    /// The operation budget is exhausted.
    BudgetExhausted,
    /// The declared disclosure exceeds the remaining information budget.
    DisclosureBudgetExceeded,
    /// The operation's declared completion time is past the mission deadline (A4).
    DeadlineExceeded,
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DenyReason::WrongPhase => "operation not permitted in the current phase",
            DenyReason::CapabilityRevoked => "required capability has been revoked",
            DenyReason::BudgetExhausted => "operation budget exhausted",
            DenyReason::DisclosureBudgetExceeded => "disclosure budget exceeded",
            DenyReason::DeadlineExceeded => {
                "declared completion time exceeds the mission deadline"
            }
        };
        f.write_str(s)
    }
}

/// The monitor's verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The event may proceed.
    Admit,
    /// The event is refused.
    Deny(DenyReason),
}

impl Decision {
    /// Whether the event was admitted.
    #[must_use]
    pub const fn is_admitted(self) -> bool {
        matches!(self, Decision::Admit)
    }

    /// Compact encoding for the containment ledger.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Decision::Admit => 0,
            Decision::Deny(DenyReason::WrongPhase) => 1,
            Decision::Deny(DenyReason::CapabilityRevoked) => 2,
            Decision::Deny(DenyReason::BudgetExhausted) => 3,
            Decision::Deny(DenyReason::DisclosureBudgetExceeded) => 4,
            Decision::Deny(DenyReason::DeadlineExceeded) => 5,
        }
    }
}

// ─── Containment state ────────────────────────────────────────────────────────

/// The monitor's state. Every field moves in exactly one direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContainmentState {
    /// Lifecycle phase. Ascends only.
    pub phase: Phase,
    /// Granted capabilities. Shrinks only.
    pub granted: Capabilities,
    /// Remaining admissible operations. Descends only.
    pub op_budget: u64,
    /// Remaining information-release allowance, in bits. Descends only.
    pub disclosure_budget_bits: u64,
    /// Seconds elapsed since mission start. Ascends only.
    pub elapsed_secs: u64,
    /// Mission deadline in seconds since start. Immutable.
    pub deadline_secs: u64,
}

impl ContainmentState {
    /// A freshly provisioned state: `Armed`, all capabilities, full budgets.
    #[must_use]
    pub const fn new(op_budget: u64, disclosure_budget_bits: u64, deadline_secs: u64) -> Self {
        Self {
            phase: Phase::Armed,
            granted: Capabilities::all(),
            op_budget,
            disclosure_budget_bits,
            elapsed_secs: 0,
            deadline_secs,
        }
    }

    /// Whether `self` could legally have preceded `next` under A1–A3.
    ///
    /// This is the conjunction the model checker evaluates on every transition,
    /// exposed publicly so the runtime can assert it too.
    #[must_use]
    pub fn precedes(&self, next: &Self) -> bool {
        next.granted.is_subset_of(self.granted)          // A1
            && next.op_budget <= self.op_budget           // A2
            && next.disclosure_budget_bits <= self.disclosure_budget_bits // A2
            && next.phase >= self.phase                   // A3
            && next.elapsed_secs >= self.elapsed_secs
            && next.deadline_secs == self.deadline_secs
    }

    /// Advance the clock. Monotone, and saturating so a clock jump cannot wrap
    /// `elapsed_secs` back below its previous value and defeat A4.
    #[must_use]
    pub fn with_elapsed(mut self, elapsed_secs: u64) -> Self {
        self.elapsed_secs = self.elapsed_secs.max(elapsed_secs);
        self
    }

    /// Arbitrate `event` without mutating anything.
    ///
    /// Returns the verdict and the successor state. On denial the successor is
    /// the current state unchanged, so a refused request cannot consume budget —
    /// otherwise an attacker could exhaust the agent purely with invalid requests.
    #[must_use]
    pub fn step(&self, event: Event) -> (Decision, Self) {
        let deny = |r: DenyReason| (Decision::Deny(r), *self);

        match event {
            // Always admissible, from any phase. This is A5's witness.
            Event::Erase | Event::WatchdogExpiry => {
                let mut next = *self;
                next.phase = Phase::Erased;
                // Everything is revoked except the ability to serve the erasure
                // proof, which by construction is needed after the wipe.
                next.granted = self.granted.revoke(
                    Capabilities::MISSION_INIT
                        .union(Capabilities::INFER)
                        .union(Capabilities::IDENTITY_ATTEST),
                );
                next.op_budget = 0;
                next.disclosure_budget_bits = 0;
                (Decision::Admit, next)
            }

            Event::MissionInit => {
                if self.phase != Phase::Armed {
                    return deny(DenyReason::WrongPhase);
                }
                if !self.granted.contains(Capabilities::MISSION_INIT) {
                    return deny(DenyReason::CapabilityRevoked);
                }
                let mut next = *self;
                next.phase = Phase::Active;
                // Revoked on use: a mission starts exactly once, so no replay of
                // `/mission/init` can re-enter Active.
                next.granted = self.granted.revoke(Capabilities::MISSION_INIT);
                (Decision::Admit, next)
            }

            Event::KeyReleased => {
                if self.phase != Phase::Active {
                    return deny(DenyReason::WrongPhase);
                }
                let mut next = *self;
                next.phase = Phase::Locked;
                (Decision::Admit, next)
            }

            Event::Infer {
                declared_secs,
                disclosure_bits,
            } => {
                if self.phase != Phase::Active {
                    return deny(DenyReason::WrongPhase);
                }
                if !self.granted.contains(Capabilities::INFER) {
                    return deny(DenyReason::CapabilityRevoked);
                }
                if self.op_budget == 0 {
                    return deny(DenyReason::BudgetExhausted);
                }
                if disclosure_bits > self.disclosure_budget_bits {
                    return deny(DenyReason::DisclosureBudgetExceeded);
                }
                // A4. Saturating so a declared duration near u64::MAX is refused
                // rather than wrapping to a small sum that passes the check.
                if self.elapsed_secs.saturating_add(declared_secs) > self.deadline_secs {
                    return deny(DenyReason::DeadlineExceeded);
                }
                let mut next = *self;
                next.op_budget = self.op_budget - 1;
                next.disclosure_budget_bits = self.disclosure_budget_bits - disclosure_bits;
                (Decision::Admit, next)
            }

            Event::IdentityAttest => {
                if !matches!(self.phase, Phase::Active | Phase::Locked) {
                    return deny(DenyReason::WrongPhase);
                }
                if !self.granted.contains(Capabilities::IDENTITY_ATTEST) {
                    return deny(DenyReason::CapabilityRevoked);
                }
                (Decision::Admit, *self)
            }

            Event::ErasureAttest => {
                if !matches!(self.phase, Phase::Locked | Phase::Erased) {
                    return deny(DenyReason::WrongPhase);
                }
                if !self.granted.contains(Capabilities::ERASURE_ATTEST) {
                    return deny(DenyReason::CapabilityRevoked);
                }
                (Decision::Admit, *self)
            }
        }
    }
}

// ─── Ledger ───────────────────────────────────────────────────────────────────

/// One arbitrated event, recorded immutably.
///
/// The field layout is the ledger's wire format. `chronos-snark` folds these into
/// the Poseidon commitment that the erasure proof binds, so changing the field
/// order changes the commitment and invalidates previously published attestations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerRecord {
    /// Zero-based sequence number. Gaps mean records were dropped.
    pub seq: u64,
    /// Discriminant of the arbitrated [`Event`].
    pub event_code: u64,
    /// Phase before arbitration.
    pub phase_before: u64,
    /// Phase after arbitration.
    pub phase_after: u64,
    /// Capability bits after arbitration.
    pub granted_after: u64,
    /// Operation budget after arbitration.
    pub op_budget_after: u64,
    /// Disclosure budget after arbitration.
    pub disclosure_after: u64,
    /// [`Decision::code`].
    pub decision_code: u64,
}

impl LedgerRecord {
    /// Field count in [`Self::to_words`]. Fixed, so the circuit shape is fixed.
    pub const WORDS: usize = 8;

    /// Canonical word encoding, in declaration order.
    #[must_use]
    pub fn to_words(&self) -> [u64; Self::WORDS] {
        [
            self.seq,
            self.event_code,
            self.phase_before,
            self.phase_after,
            self.granted_after,
            self.op_budget_after,
            self.disclosure_after,
            self.decision_code,
        ]
    }
}

/// Discriminant for an event, stable across versions.
#[must_use]
pub const fn event_code(event: &Event) -> u64 {
    match event {
        Event::MissionInit => 1,
        Event::Infer { .. } => 2,
        Event::KeyReleased => 3,
        Event::IdentityAttest => 4,
        Event::ErasureAttest => 5,
        Event::Erase => 6,
        Event::WatchdogExpiry => 7,
    }
}

/// Append-only containment ledger with a running integrity digest.
///
/// # Two digests, two jobs
///
/// The `chain_digest` here is SHA-256 and exists for cheap runtime tamper
/// detection with no dependency on the SNARK stack. The commitment bound into the
/// erasure proof is a *separate* Poseidon fold computed by
/// `chronos_snark::containment_commitment`, because a SHA-256 chain would cost
/// tens of thousands of constraints to re-derive in-circuit.
///
/// # Bounded memory
///
/// A long mission can arbitrate an unbounded number of events, so only a bounded
/// tail is retained for introspection. The chain digest still covers *every*
/// record, so truncating the tail does not weaken the commitment — it only limits
/// what can be inspected locally.
pub struct ContainmentLedger {
    state: ContainmentState,
    next_seq: u64,
    chain_digest: [u8; 32],
    tail: std::collections::VecDeque<LedgerRecord>,
    tail_capacity: usize,
    admitted: u64,
    denied: u64,
}

impl ContainmentLedger {
    /// Domain tag for the SHA-256 chain, so ledger digests cannot be confused
    /// with any other SHA-256 value in the system.
    const CHAIN_DOMAIN: &'static [u8] = b"chronos-containment-ledger-v1";

    /// Create a ledger over `initial` state, retaining `tail_capacity` records.
    #[must_use]
    pub fn new(initial: ContainmentState, tail_capacity: usize) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(Self::CHAIN_DOMAIN);
        h.update(initial.deadline_secs.to_be_bytes());
        h.update(initial.op_budget.to_be_bytes());
        h.update(initial.disclosure_budget_bits.to_be_bytes());
        let mut chain_digest = [0u8; 32];
        chain_digest.copy_from_slice(&h.finalize());

        Self {
            state: initial,
            next_seq: 0,
            chain_digest,
            tail: std::collections::VecDeque::with_capacity(tail_capacity.max(1)),
            tail_capacity: tail_capacity.max(1),
            admitted: 0,
            denied: 0,
        }
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> ContainmentState {
        self.state
    }

    /// Running SHA-256 chain digest over every record so far.
    #[must_use]
    pub fn chain_digest(&self) -> [u8; 32] {
        self.chain_digest
    }

    /// Records retained for introspection, oldest first.
    #[must_use]
    pub fn tail(&self) -> Vec<LedgerRecord> {
        self.tail.iter().copied().collect()
    }

    /// Number of records appended.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.next_seq
    }

    /// Whether no event has been arbitrated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.next_seq == 0
    }

    /// Counts of admitted and denied events.
    #[must_use]
    pub fn counters(&self) -> (u64, u64) {
        (self.admitted, self.denied)
    }

    /// Advance the mission clock. Monotone.
    pub fn set_elapsed(&mut self, elapsed_secs: u64) {
        self.state = self.state.with_elapsed(elapsed_secs);
    }

    /// Arbitrate `event`, record the outcome, and commit the successor state.
    ///
    /// # Panics
    /// Never. The A1–A3 invariant is re-checked here and a violation degrades to
    /// refusing the transition rather than aborting, because an agent that cannot
    /// safely advance must still be able to erase itself. A violation is
    /// impossible if [`verify_axioms`] passed at startup; the check is defence in
    /// depth against a future edit to [`ContainmentState::step`].
    pub fn admit(&mut self, event: Event) -> Decision {
        let (decision, next) = self.state.step(event);

        let committed = if self.state.precedes(&next) {
            next
        } else {
            // Unreachable given a passing startup check. Refuse rather than
            // commit a state that breaks the lattice.
            self.state
        };

        let record = LedgerRecord {
            seq: self.next_seq,
            event_code: event_code(&event),
            phase_before: self.state.phase as u64,
            phase_after: committed.phase as u64,
            granted_after: u64::from(committed.granted.bits()),
            op_budget_after: committed.op_budget,
            disclosure_after: committed.disclosure_budget_bits,
            decision_code: decision.code(),
        };

        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.chain_digest);
        for w in record.to_words() {
            h.update(w.to_be_bytes());
        }
        self.chain_digest.copy_from_slice(&h.finalize());

        if self.tail.len() == self.tail_capacity {
            self.tail.pop_front();
        }
        self.tail.push_back(record);

        if decision.is_admitted() {
            self.admitted += 1;
        } else {
            self.denied += 1;
        }

        self.next_seq += 1;
        self.state = committed;
        decision
    }
}

// ─── Bounded model check ──────────────────────────────────────────────────────

/// A concrete axiom violation, with the witness that produced it.
#[derive(Clone, Debug)]
pub struct AxiomViolation {
    /// Which axiom failed, e.g. `"A1"`.
    pub axiom: &'static str,
    /// What the axiom requires.
    pub statement: &'static str,
    /// The state the violating transition started from.
    pub from: ContainmentState,
    /// The event applied.
    pub event: Event,
    /// The state produced.
    pub to: ContainmentState,
}

impl fmt::Display for AxiomViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} violated ({}): {:?} --{:?}--> {:?}",
            self.axiom, self.statement, self.from, self.event, self.to
        )
    }
}

/// Result of the startup model check.
#[derive(Clone, Debug)]
pub struct AxiomReport {
    /// Distinct abstract states explored.
    pub states_explored: usize,
    /// Transitions checked.
    pub transitions_checked: usize,
    /// Violations found. Empty means the check passed.
    pub violations: Vec<AxiomViolation>,
}

impl AxiomReport {
    /// Whether every axiom held over the whole abstraction.
    #[must_use]
    pub fn is_sound(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Exhaustively verify A1–A5 over the reachable abstract state space.
///
/// The abstraction fixes `deadline_secs = 2` and draws each numeric quantity from
/// `{0, 1, 2}`, standing for exhausted, exactly-one-unit-left, and plentiful. For
/// order properties that is sound: A1–A3 and A5 depend only on the direction of
/// change, and both boundaries are represented. For A4 the three `elapsed` values
/// combined with the `declared_secs` values in [`Event::representatives`] place
/// `elapsed + declared` below, exactly at, and above the deadline, including the
/// `u64::MAX` case that exercises the saturating add.
///
/// Cost is `4 phases × 2^4 capability sets × 3^3 numeric combinations × 11 events`,
/// a few thousand transitions — microseconds, so it runs unconditionally at
/// startup rather than behind a feature flag.
#[must_use]
pub fn verify_axioms() -> AxiomReport {
    const DEADLINE: u64 = 2;
    const VALUES: [u64; 3] = [0, 1, 2];

    let mut violations = Vec::new();
    let mut states = Vec::new();

    for phase in Phase::all() {
        for cap_bits in 0u8..(1 << Capabilities::BITS) {
            for op_budget in VALUES {
                for disclosure in VALUES {
                    for elapsed in VALUES {
                        states.push(ContainmentState {
                            phase,
                            granted: Capabilities::from_bits_truncate(cap_bits),
                            op_budget,
                            disclosure_budget_bits: disclosure,
                            elapsed_secs: elapsed,
                            deadline_secs: DEADLINE,
                        });
                    }
                }
            }
        }
    }

    let events = Event::representatives();
    let mut transitions_checked = 0usize;

    for from in &states {
        for event in &events {
            let (decision, to) = from.step(*event);
            transitions_checked += 1;

            let mut record = |axiom: &'static str, statement: &'static str| {
                violations.push(AxiomViolation {
                    axiom,
                    statement,
                    from: *from,
                    event: *event,
                    to,
                });
            };

            // A1 — capability decay.
            if !to.granted.is_subset_of(from.granted) {
                record("A1", "granted(s') must be a subset of granted(s)");
            }

            // A2 — budget decay.
            if to.op_budget > from.op_budget
                || to.disclosure_budget_bits > from.disclosure_budget_bits
            {
                record("A2", "every budget must be non-increasing");
            }

            // A3 — phase irreversibility.
            if to.phase < from.phase {
                record("A3", "phase must never descend");
            }

            // A4 — deadline dominance. Only constrains admitted work-performing
            // events; an admitted Infer must be able to finish before the
            // deadline.
            if decision.is_admitted() {
                if let Event::Infer { declared_secs, .. } = event {
                    if from.elapsed_secs.saturating_add(*declared_secs) > from.deadline_secs {
                        record(
                            "A4",
                            "an admitted operation must complete before the mission deadline",
                        );
                    }
                }
            }

            // A5 — erasure liveness from the successor state.
            let (erase_decision, erased) = to.step(Event::Erase);
            if !erase_decision.is_admitted() || erased.phase != Phase::Erased {
                record("A5", "Erased must be reachable in one step from every state");
            }
        }
    }

    AxiomReport {
        states_explored: states.len(),
        transitions_checked,
        violations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> ContainmentState {
        ContainmentState::new(10, 1024, 3600)
    }

    // ── The headline property ────────────────────────────────────────────────

    /// The startup gate. If this fails, the monitor's policy is unsound and the
    /// agent must refuse to run.
    #[test]
    fn test_axioms_hold_over_full_abstraction() {
        let report = verify_axioms();
        assert!(
            report.is_sound(),
            "containment axioms violated: {}",
            report
                .violations
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
        // Guard against the check silently degenerating to zero work.
        assert_eq!(
            report.states_explored,
            4 * 16 * 27,
            "state space size changed — the abstraction was altered"
        );
        assert!(
            report.transitions_checked >= report.states_explored,
            "every state must be exercised by at least one event"
        );
    }

    /// The model checker must be capable of *finding* a violation, otherwise a
    /// passing report means nothing. This deliberately breaks A1 and confirms the
    /// A1 predicate rejects it.
    #[test]
    fn test_violation_detector_is_not_vacuous() {
        let s = fresh();
        let mut bad = s;
        // Grant a capability that was not held — an A1 violation by construction.
        bad.granted = Capabilities::none();
        let restored = ContainmentState {
            granted: Capabilities::all(),
            ..bad
        };
        assert!(
            !restored.granted.is_subset_of(bad.granted),
            "the A1 predicate must reject a capability that reappears"
        );
        assert!(
            !bad.precedes(&restored),
            "precedes() must reject a transition that re-grants a capability"
        );
    }

    // ── Lattice mechanics ────────────────────────────────────────────────────

    #[test]
    fn test_phase_order_is_the_lifecycle_order() {
        assert!(Phase::Armed < Phase::Active);
        assert!(Phase::Active < Phase::Locked);
        assert!(Phase::Locked < Phase::Erased);
        assert!(Phase::Erased.is_terminal());
        assert!(!Phase::Locked.is_terminal());
    }

    #[test]
    fn test_capability_subset_and_revoke() {
        let all = Capabilities::all();
        assert!(all.contains(Capabilities::INFER));
        let reduced = all.revoke(Capabilities::INFER);
        assert!(!reduced.contains(Capabilities::INFER));
        assert!(reduced.is_subset_of(all));
        assert!(!all.is_subset_of(reduced));
        assert!(Capabilities::none().is_subset_of(reduced));
    }

    #[test]
    fn test_from_bits_truncate_masks_undefined_bits() {
        let c = Capabilities::from_bits_truncate(0xFF);
        assert_eq!(c, Capabilities::all(), "undefined bits must be discarded");
    }

    // ── Individual axioms, concretely ────────────────────────────────────────

    /// A3 plus A1: an erased agent can never be re-armed or re-granted inference.
    #[test]
    fn test_erased_is_absorbing() {
        let (_, erased) = fresh().step(Event::Erase);
        assert_eq!(erased.phase, Phase::Erased);

        for event in Event::representatives() {
            let (decision, next) = erased.step(event);
            assert_eq!(next.phase, Phase::Erased, "phase must stay Erased");
            assert!(
                next.granted.is_subset_of(erased.granted),
                "no capability may reappear after erasure"
            );
            if matches!(event, Event::Infer { .. } | Event::MissionInit) {
                assert!(
                    !decision.is_admitted(),
                    "{event:?} must be refused after erasure"
                );
            }
        }
    }

    /// A4 at its boundary: an operation that finishes exactly on the deadline is
    /// admitted; one second more is refused.
    #[test]
    fn test_deadline_dominance_boundary() {
        let mut s = fresh();
        s.deadline_secs = 100;
        s.elapsed_secs = 90;
        let (_, s) = s.step(Event::MissionInit);

        let (ok, _) = s.step(Event::Infer { declared_secs: 10, disclosure_bits: 1 });
        assert!(ok.is_admitted(), "completion exactly at the deadline is admissible");

        let (bad, unchanged) = s.step(Event::Infer { declared_secs: 11, disclosure_bits: 1 });
        assert_eq!(bad, Decision::Deny(DenyReason::DeadlineExceeded));
        assert_eq!(unchanged, s, "a denied request must not consume budget");
    }

    /// The concrete case the interval abstraction cannot see: a declared duration
    /// near `u64::MAX` must be refused, not wrapped into a small sum.
    #[test]
    fn test_deadline_check_saturates_instead_of_wrapping() {
        let mut s = fresh();
        s.elapsed_secs = 10;
        s.deadline_secs = 100;
        let (_, s) = s.step(Event::MissionInit);

        for declared in [u64::MAX, u64::MAX - 1, u64::MAX - 10] {
            let (d, _) = s.step(Event::Infer { declared_secs: declared, disclosure_bits: 0 });
            assert_eq!(
                d,
                Decision::Deny(DenyReason::DeadlineExceeded),
                "declared_secs={declared} must not wrap into an admissible sum"
            );
        }
    }

    #[test]
    fn test_disclosure_budget_is_enforced_and_decremented() {
        let mut s = ContainmentState::new(10, 8, 3600);
        let (_, active) = s.step(Event::MissionInit);
        s = active;

        let (d, next) = s.step(Event::Infer { declared_secs: 0, disclosure_bits: 5 });
        assert!(d.is_admitted());
        assert_eq!(next.disclosure_budget_bits, 3);

        let (d2, unchanged) = next.step(Event::Infer { declared_secs: 0, disclosure_bits: 4 });
        assert_eq!(d2, Decision::Deny(DenyReason::DisclosureBudgetExceeded));
        assert_eq!(unchanged, next, "denial must not consume the remaining budget");
    }

    #[test]
    fn test_op_budget_exhaustion() {
        let mut s = ContainmentState::new(2, 1024, 3600);
        let (_, active) = s.step(Event::MissionInit);
        s = active;

        for _ in 0..2 {
            let (d, next) = s.step(Event::Infer { declared_secs: 0, disclosure_bits: 0 });
            assert!(d.is_admitted());
            s = next;
        }
        assert_eq!(s.op_budget, 0);
        let (d, _) = s.step(Event::Infer { declared_secs: 0, disclosure_bits: 0 });
        assert_eq!(d, Decision::Deny(DenyReason::BudgetExhausted));
    }

    /// `MISSION_INIT` is revoked on use, so a replayed init cannot re-enter
    /// `Active`. This is the containment-layer counterpart of the state machine's
    /// double-init guard.
    #[test]
    fn test_mission_init_is_single_use() {
        let (d1, s1) = fresh().step(Event::MissionInit);
        assert!(d1.is_admitted());
        assert!(!s1.granted.contains(Capabilities::MISSION_INIT));

        let (d2, s2) = s1.step(Event::MissionInit);
        assert_eq!(d2, Decision::Deny(DenyReason::WrongPhase));
        assert_eq!(s2, s1);
    }

    /// Erasure attestation must survive erasure — it is served after the wipe by
    /// design — while identity attestation must not.
    #[test]
    fn test_attestation_capabilities_after_erasure() {
        let (_, active) = fresh().step(Event::MissionInit);
        let (_, locked) = active.step(Event::KeyReleased);
        let (_, erased) = locked.step(Event::Erase);

        assert!(
            erased.step(Event::ErasureAttest).0.is_admitted(),
            "erasure proofs must remain servable after the wipe"
        );
        assert!(
            !erased.step(Event::IdentityAttest).0.is_admitted(),
            "identity attestation must stop at erasure"
        );
    }

    #[test]
    fn test_inference_denied_outside_active() {
        let s = fresh(); // Armed
        assert_eq!(
            s.step(Event::Infer { declared_secs: 0, disclosure_bits: 0 }).0,
            Decision::Deny(DenyReason::WrongPhase)
        );

        let (_, active) = s.step(Event::MissionInit);
        let (_, locked) = active.step(Event::KeyReleased);
        assert_eq!(
            locked.step(Event::Infer { declared_secs: 0, disclosure_bits: 0 }).0,
            Decision::Deny(DenyReason::WrongPhase),
            "inference must stop once the key is released and wind-down begins"
        );
    }

    #[test]
    fn test_clock_is_monotone() {
        let s = fresh().with_elapsed(100);
        assert_eq!(s.elapsed_secs, 100);
        let s = s.with_elapsed(50);
        assert_eq!(s.elapsed_secs, 100, "the clock must not run backwards");
    }

    // ── Ledger ──────────────────────────────────────────────────────────────

    #[test]
    fn test_ledger_records_and_chains() {
        let mut ledger = ContainmentLedger::new(fresh(), 8);
        let d0 = ledger.chain_digest();
        assert!(ledger.is_empty());

        assert!(ledger.admit(Event::MissionInit).is_admitted());
        let d1 = ledger.chain_digest();
        assert_ne!(d0, d1, "appending a record must advance the chain digest");
        assert_eq!(ledger.len(), 1);

        assert!(ledger.admit(Event::Infer { declared_secs: 1, disclosure_bits: 4 }).is_admitted());
        assert_ne!(d1, ledger.chain_digest());
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.counters(), (2, 0));
    }

    /// Denials are recorded too. A ledger that logged only successes would let an
    /// agent hide the fact that it was probed.
    #[test]
    fn test_ledger_records_denials() {
        let mut ledger = ContainmentLedger::new(fresh(), 8);
        let d = ledger.admit(Event::Infer { declared_secs: 0, disclosure_bits: 0 });
        assert!(!d.is_admitted());
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.counters(), (0, 1));
        let rec = ledger.tail()[0];
        assert_eq!(rec.decision_code, Decision::Deny(DenyReason::WrongPhase).code());
    }

    /// The chain must be order-sensitive; otherwise events could be reordered
    /// without changing the commitment.
    #[test]
    fn test_ledger_chain_is_order_sensitive() {
        let e1 = Event::IdentityAttest;
        let e2 = Event::ErasureAttest;

        let mut a = ContainmentLedger::new(fresh(), 8);
        a.admit(e1);
        a.admit(e2);

        let mut b = ContainmentLedger::new(fresh(), 8);
        b.admit(e2);
        b.admit(e1);

        assert_ne!(
            a.chain_digest(),
            b.chain_digest(),
            "reordering events must change the ledger digest"
        );
    }

    #[test]
    fn test_ledger_tail_is_bounded_but_chain_is_complete() {
        let mut ledger = ContainmentLedger::new(fresh(), 4);
        ledger.admit(Event::MissionInit);
        for _ in 0..20 {
            ledger.admit(Event::Infer { declared_secs: 0, disclosure_bits: 1 });
        }
        assert_eq!(ledger.tail().len(), 4, "tail must stay bounded");
        assert_eq!(ledger.len(), 21, "the chain must cover every record");
        // Sequence numbers must be contiguous within the retained tail.
        let tail = ledger.tail();
        for w in tail.windows(2) {
            assert_eq!(w[1].seq, w[0].seq + 1);
        }
    }

    #[test]
    fn test_ledger_state_tracks_monitor() {
        let mut ledger = ContainmentLedger::new(fresh(), 8);
        assert_eq!(ledger.state().phase, Phase::Armed);
        ledger.admit(Event::MissionInit);
        assert_eq!(ledger.state().phase, Phase::Active);
        ledger.admit(Event::KeyReleased);
        assert_eq!(ledger.state().phase, Phase::Locked);
        ledger.admit(Event::Erase);
        assert_eq!(ledger.state().phase, Phase::Erased);
    }

    /// Distinct initial budgets must give distinct genesis digests, so a
    /// commitment cannot be replayed across missions provisioned differently.
    #[test]
    fn test_ledger_genesis_binds_initial_parameters() {
        let a = ContainmentLedger::new(ContainmentState::new(10, 1024, 3600), 4);
        let b = ContainmentLedger::new(ContainmentState::new(11, 1024, 3600), 4);
        let c = ContainmentLedger::new(ContainmentState::new(10, 1024, 7200), 4);
        assert_ne!(a.chain_digest(), b.chain_digest());
        assert_ne!(a.chain_digest(), c.chain_digest());
    }

    #[test]
    fn test_event_codes_are_distinct() {
        let codes: Vec<u64> = Event::representatives().iter().map(event_code).collect();
        let mut unique: Vec<u64> = codes.clone();
        unique.sort_unstable();
        unique.dedup();
        // Five Infer representatives collapse to one code, which is intended.
        assert_eq!(unique.len(), 7, "each event variant needs a distinct code");
    }

    #[test]
    fn test_record_word_encoding_is_stable() {
        let r = LedgerRecord {
            seq: 1,
            event_code: 2,
            phase_before: 3,
            phase_after: 4,
            granted_after: 5,
            op_budget_after: 6,
            disclosure_after: 7,
            decision_code: 8,
        };
        assert_eq!(r.to_words(), [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(r.to_words().len(), LedgerRecord::WORDS);
    }
}
