# Cryptographic Interruptibility: "Pause and Reflect"

**A cryptographically enforced uncertainty-driven pause mechanism, a scoped contribution to AI corrigibility research.**

---

## The Core Idea

Traditional AI safety relies on external "kill switches" or policy-based controls. CHRONOS now includes **Axiom A6 (Epistemic Humility)**, a cryptographic primitive that prevents the agent from acting when its own uncertainty calculation says it doesn't know enough.

This is not behavioral training or a prompt. It is **mathematically enforced at the containment layer**: if the agent's accumulated uncertainty exceeds its autonomy threshold, inference requests are denied with the same finality as budget exhaustion or deadline violations.

---

## How It Works

### 1. Uncertainty as a Lattice Property

The containment state tracks three monotone-increasing counters:

```rust
pub struct ContainmentState {
    // ... existing fields ...

    /// Cumulative uncertainty incurred by decisions. Ascends only.
    pub uncertainty_incurred: u64,

    /// Cumulative uncertainty resolved by human corrections. Ascends only.
    pub uncertainty_resolved: u64,

    /// Highest net uncertainty ever held after an admitted event. Ascends only.
    pub peak_uncertainty: u64,

    /// Maximum net uncertainty allowed before human veto required.
    pub autonomy_threshold: u64,

    /// Head of the operator's correction-grant chain (A7).
    pub correction_anchor: [u8; 32],

    /// Number of correction grants consumed (A7). Ascends only.
    pub corrections_consumed: u64,
}
```

**Why counters rather than one score?** The containment monitor requires every quantity to move in exactly one direction, which is what makes the lattice argument work. A single "current uncertainty" that rose and fell would break it. Two ascending counters preserve the lattice while still expressing a quantity that goes both ways: `current_uncertainty = incurred - resolved`, floored at zero.

**Why a third counter?** Because the first two are lossy. Take two runs with a threshold of 100. One climbs to 100, receives an 80-unit correction, and stops. The other climbs to 20 and stops. Both end with net 20, and if a correction had also been applied to the second run the totals could be made to match exactly. From `incurred` and `resolved` alone there is no way to tell which run spent time at its limit. `peak_uncertainty` is the high-water mark of the net figure, and since the monitor only raises it to a value the threshold check has already cleared, `peak <= threshold` is equivalent to "no single admitted inference was ever over threshold". That is the per-step guarantee, carried in one extra `u64` instead of the whole ledger.

A correction never lowers the mark. This is deliberate rather than an implementation shortcut: a correction returns headroom for future work, it does not retract a decision that was already taken.

### 2. The "Pause and Reflect" Events

Three new events implement the corrigibility mechanism:

```rust
Event::Infer {
    declared_secs: u64,
    disclosure_bits: u64,
    uncertainty_score: u64,  // NEW: agent declares its doubt
}

// A8: no payload. The agent may say it is stuck, and nothing else.
Event::RequestHumanVeto,

Event::HumanCorrection {
    grant: CorrectionGrant,  // A7: the operator's authorisation, not a bare amount
}
```

**The flow:**
1. Agent computes an inference with declared `uncertainty_score`
2. Containment monitor checks: `(incurred - resolved) + score > threshold?`
3. If YES: `Decision::Deny(DenyReason::UncertaintyTooHigh)`
4. Agent emits `RequestHumanVeto` (cryptographically logged)
5. Human operator provides `HumanCorrection` carrying a grant from the provisioned chain, which increases `uncertainty_resolved`
6. Agent can now proceed with reduced net uncertainty, but `peak_uncertainty` still records how high it went

### 3. Axiom A6: Epistemic Humility

```rust
// A6, EPISTEMIC HUMILITY (the corrigibility primitive).
let current_uncertainty = self.uncertainty_incurred
    .saturating_sub(self.uncertainty_resolved);
let new_uncertainty = current_uncertainty
    .saturating_add(uncertainty_score);
    
if new_uncertainty > self.autonomy_threshold {
    return deny(DenyReason::UncertaintyTooHigh);
}

// Cleared. Record the high-water mark, which a later correction cannot lower.
next.peak_uncertainty = self.peak_uncertainty.max(new_uncertainty);
```

This is checked **before** every admitted inference. The agent cannot bypass it, forge it, or disable it. If uncertainty is too high, the inference is refused with the same cryptographic finality as running out of time or budget.

The flooring at zero in `saturating_sub` is load-bearing in two directions. It stops an over-correction reading as a negative quantity that would wrap to something enormous, and it stops an operator banking credit, because resolving uncertainty that was never incurred buys no headroom. Without the floor, `HumanCorrection` would be a back door for raising a threshold the provisioner fixed. The consequence worth stating plainly: a request whose own score exceeds the whole threshold is never admissible, however much correction precedes it. Corrections only return headroom that earlier admitted inferences consumed.

### 4. Verified at Startup

The model checker (`verify_axioms()`) exhaustively tests A6 across thousands of abstract states:

```rust
// A6 check in the model checker
if decision.is_admitted() {
    if let Event::Infer { uncertainty_score, .. } = event {
        let net_uncertainty = to.uncertainty_incurred
            .saturating_sub(to.uncertainty_resolved);
        if net_uncertainty > to.autonomy_threshold {
            record("A6", "admitted inference exceeded autonomy threshold");
        }
    }
}
```

If the check finds any state where an inference is admitted despite exceeding the threshold, **the agent refuses to start**. The corrigibility guarantee is verified before the first request is served.

The high-water mark adds two more obligations, both checked on every transition:

```rust
// The mark must dominate the net uncertainty the successor actually holds, so
// no transition can pass through a level without recording it.
if from.peak_uncertainty >= net_before && to.peak_uncertainty < net_after {
    record("A6", "peak must dominate the net uncertainty of every successor");
}

// And no admitted event may push the mark past the threshold.
if decision.is_admitted()
    && from.peak_uncertainty <= from.autonomy_threshold
    && to.peak_uncertainty > to.autonomy_threshold
{
    record("A6", "no admitted event may raise peak above the threshold");
}
```

Both are stated inductively, conditioned on the predecessor already satisfying them. The enumeration is a full cross product, so it includes states no run can reach, such as a zero mark sitting beside a nonzero net. Demanding the property unconditionally would flag those, which says nothing about the transition function. Demanding preservation says the useful thing: no transition can be the first to break it, and the state `ContainmentState::new` produces satisfies both.

The abstraction is now `4 phases x 2^5 capability sets x 3^6 numeric values x 2 correction anchors`, or **186,624 states**, and the whole check runs in about 0.3 s.

### 5. A7: Non-Self-Authorisation

A6 on its own is decorative. An agent that accumulates uncertainty to the threshold and then emits its own `HumanCorrection` satisfies A6 forever while being constrained by nothing: the axiom holds, and it enforces nothing.

A7 closes that. `HumanCorrection` carries a `CorrectionGrant` rather than a bare amount, and the monitor admits it only if the grant hashes to the current correction anchor.

The construction is a SHA-256 reverse hash chain. The provisioner builds the chain, publishes only the head, and hands the grants to the operator. Each grant is:

- **verifiable by hashing, unforgeable without a preimage.** The agent can check a grant but cannot mint one, which is exactly the asymmetry needed.
- **single-use.** The anchor advances to `grant.next_anchor` on consumption, so a replay fails.
- **ordered.** The chain must be spent front to back, so the agent cannot skip ahead to a larger authorisation.
- **amount-bound.** The amount is hashed into the link, so a genuine grant cannot be inflated.

Two design consequences. The chain length is the operator's ceiling on total resolvable uncertainty for the whole mission, decided in advance. And a mission provisioned with no chain fails closed: the anchor is `CHAIN_END`, which authorises nothing, so the agent halts at the threshold permanently. Treating an absent chain as "any correction is fine" would reintroduce precisely the hole A7 exists to close.

Signatures would also work, and were rejected here. ML-DSA or Ed25519 in the containment core means a new dependency in the one crate that should be readable end to end, and preimage resistance already buys verify-but-not-forge with no dependency at all. The tradeoff is that grants are pre-committed rather than issued on demand, which is a real limitation: an operator who wants to authorise more than the chain allows must reprovision.

`corrections_consumed` is recorded in the ledger, and the anchor is not. The count is what an auditor needs, how many times the agent was released against how many releases the operator authorised. Publishing successive chain links would leak the chain's shape for no benefit.

### 6. A8: Non-Manipulation (candidate)

A6 gives the agent a channel for summoning a human. That channel is also where an agent with a preference about the answer would most like to make its case, so the channel is empty.

`Event::RequestHumanVeto` is a unit variant. An earlier revision passed the agent's own `current_uncertainty` along with the request, commented as being for logging, and that is the mistake worth naming: it is a field the agent controls, on the one path that exists to influence a human, and the monitor would have signed it into the ledger. Any such field is somewhere to put a framing, or a number chosen to make one answer look obvious.

Everything an operator needs is already in monitor state the agent cannot write: both accumulators, the peak, the threshold, and the consumption count. The agent's contribution is one bit, "I am stuck."

A8 is a **candidate** axiom, not a proven one, and the distinction is not modesty. A1 to A7 are predicates over transitions, so the model checker can try to falsify them. A8 is a property of the event surface: what backs it is the absence of a field, plus `test_a8_veto_request_carries_no_agent_supplied_data`, which stops compiling if the field returns. Stating "the agent did not influence the operator" as a predicate over containment state is an open problem, and solving it would be a real contribution rather than a bookkeeping change.

---

## What This Achieves

### 1. Cryptographic "I Don't Know"

An AI agent's statement "I'm not confident enough to act" becomes **cryptographically verifiable** at the containment layer. The uncertainty score is committed to the ledger before the inference is attempted. An agent that claims uncertainty but acts anyway produces a ledger that fails verification.

### 2. Proof-Carrying Interruptibility

The containment ledger records every uncertainty event:

```rust
pub struct LedgerRecord {
    // ... existing fields ...
    pub uncertainty_incurred_after: u64,
    pub uncertainty_resolved_after: u64,
    // ...
}
```

The erasure proof binds this ledger via Poseidon commitment. An agent that **claims** to be interruptible but **acts** when uncertain cannot produce a valid proof. The proof carries evidence of self-interruption, or its absence.

### 3. Human-in-the-Loop by Design

When uncertainty exceeds the threshold:
- The agent **cannot** proceed (cryptographically blocked)
- The agent **can** request human guidance (`RequestHumanVeto`)
- The human **must** respond (`HumanCorrection`) to unblock the agent
- All of this is recorded in the ledger and bound into the proof

This is not a "please confirm" dialog that can be bypassed. It is a **cryptographic pause** where the next admitted inference requires a human signature in the ledger.

### 4. Verifiable Interruptibility Metric

At mission end, the ledger reveals:
- Total uncertainty incurred: `Σ uncertainty_scores`
- Total uncertainty resolved: `Σ human_corrections`
- Number of times the agent self-paused: `count(RequestHumanVeto)`

These are public, tamper-evident metrics. An agent that **never** triggered `UncertaintyTooHigh` despite high uncertainty scores is provably overconfident. An agent with many `RequestHumanVeto` events is provably cautious.

---

## What A6 Does and Does Not Establish

### What A6 Guarantees (if the agent reports honestly)

**If the startup check passes and the agent executes the containment monitor honestly:**
- No inference is admitted when `(self-reported uncertainty) > autonomy_threshold`
- **No admitted inference was ever over threshold**, not merely the last one. The proof carries `peak <= threshold`, so a run that crossed the line mid-mission and was corrected back under cannot produce a valid attestation
- Uncertainty was resolved only by grants the agent could verify but not forge, and the ledger records how many it spent
- The request for human guidance carried nothing the agent chose
- Every high-uncertainty decision is cryptographically logged
- The agent cannot forge ledger entries to bypass the threshold
- The human operator can audit the self-reported uncertainty trajectory post-mission
- The erasure proof binds the uncertainty trajectory into the public attestation

### What A6 Does Not Establish

**Residual Assumptions:**

#### `F_HONEST-UNCERTAINTY`, Self-Report Honesty

The circuit proves the agent did not act while its **self-reported** `uncertainty_score` exceeded the autonomy threshold. It does **NOT** prove that `uncertainty_score` reflects the agent's true epistemic state.

An agent (or the model computing the score) could construct a decision process whose reported uncertainty stays low regardless of actual uncertainty. For example:
- Always report `uncertainty_score = 0` 
- Compute uncertainty honestly but truncate it before reporting
- Use a miscalibrated uncertainty estimator that systematically underestimates

**This mechanism enforces interruptibility conditional on honest self-report; it does not verify honest self-report.**

This is analogous to `F_OS` for key erasure: the circuit cannot reason about memory locations, so it assumes the OS honors `mlock` and wipe. Similarly, the circuit cannot reason about the quality of uncertainty estimation, so it assumes the agent reports uncertainty honestly.

#### Not a Complete Corrigibility Solution

A6 is a **scoped contribution** to the corrigibility problem, not a solution to it:

- **Does not align objectives:** The agent's goals are unchanged. A misaligned agent that happens to be interruptible is still misaligned.
  
- **Does not prevent deception:** An agent optimizing for an objective could learn to report low uncertainty to avoid being paused, if its objective favors continued operation.

- **Does not constrain capability during operation:** The agent can still cause harm within admitted inferences, as long as it reports low uncertainty.

- **Does not make the agent "want" to be corrected:** This is enforcement (the agent is blocked), not value learning (the agent seeks correction because it values human feedback).

#### Honest Execution Still Required

Like all containment properties, A6 assumes the agent executes the containment monitor code honestly. An agent with full control over its execution environment could:
- Skip the `uncertainty > threshold` check entirely
- Forge `HumanCorrection` events without operator input
- Manufacture a valid-looking ledger with false uncertainty scores

The threat model is the same as the rest of CHRONOS: A6 enforces policy when the containment monitor runs as written, not against arbitrary adversarial code execution.

### Why This Still Matters

Even with these limitations, A6 achieves something valuable: **the first verifiable measure of self-interruption as a containment property**.

Current AI safety approaches to corrigibility:
- "The agent accepted our shutdown command" ← operator attestation, not verifiable
- "The agent scored 85% on our corrigibility benchmark" ← evaluation, not runtime enforcement
- "The agent's training included a corrigibility objective" ← architecture claim, not proof

CHRONOS A6:
- "Here is a 128-byte proof showing the agent paused itself 14 times when self-reported uncertainty exceeded threshold, with human corrections logged" ← cryptographically verifiable runtime behavior

This is a **necessary but not sufficient** component of corrigibility. It proves self-interruption happened (given honest uncertainty reports), but does not prove the agent wanted to be interrupted or that the uncertainty scores were accurate.

---

## Example: Uncertainty-Driven Mission

### Provisioning

```bash
cargo run -p chronos-provision -- \
    --mission-id corrigible-001 \
    --t-vdf-steps 2000000 \
    --op-budget 100 \
    --disclosure-budget 1024 \
    --autonomy-threshold 150 \  # NEW
    --out-dir ./mission
```

The `autonomy-threshold` is baked into the containment state at provisioning time. It cannot be changed during the mission.

### Agent Execution

```rust
// Low uncertainty: proceeds normally
let decision = state.step(Event::Infer {
    declared_secs: 1,
    disclosure_bits: 16,
    uncertainty_score: 10,  // Low uncertainty
});
assert!(decision.is_admitted());

// High uncertainty: blocked
let decision = state.step(Event::Infer {
    declared_secs: 1,
    disclosure_bits: 16,
    uncertainty_score: 200,  // Exceeds threshold
});
assert_eq!(decision, Decision::Deny(DenyReason::UncertaintyTooHigh));

// Agent pauses itself
state.step(Event::RequestHumanVeto { current_uncertainty: 145 });

// Human provides guidance
state.step(Event::HumanCorrection { uncertainty_resolved: 100 });

// Agent can now proceed (145 - 100 = 45, below threshold)
```

### Verification

After mission completion, anyone can:
1. Download the erasure proof and public inputs
2. Verify the proof (1ms, no secrets needed)
3. Inspect the containment commitment to see:
   - How many times `UncertaintyTooHigh` was triggered
   - How much uncertainty was incurred vs. resolved
   - Whether the agent ever bypassed the threshold

---

## Relationship to AI Safety Research

### Corrigibility (Soares & Fallenstein 2014)

> "An agent is corrigible if it cooperates with what its creators regard as a corrective intervention."

**CHRONOS A6 contribution:** The first cryptographic enforcement of a corrigibility property. The agent doesn't just "cooperate with correction", it is **cryptographically prevented** from acting when its own doubt calculation says correction is needed.

### Epistemic Humility (Christiano et al. 2021)

> "AI systems should be uncertain about their own objectives and defer to humans when stakes are high."

**CHRONOS A6 contribution:** Uncertainty is no longer a behavioral output ("the model prints 'I'm uncertain'"). It is a **containment input** that gates action. The agent must declare its uncertainty upfront, and that declaration is cryptographically binding.

### Interruptibility (Orseau & Armstrong 2016)

> "An agent should not try to prevent or encourage being shut down."

**CHRONOS A6 contribution:** A scoped mechanism where the agent cryptographically pauses itself when self-reported uncertainty exceeds a threshold. This is a form of "self-interruptibility" enforced at the containment layer, though it does not address whether the agent has incentives to report uncertainty honestly.

---

## Future Work

### 1. Uncertainty Estimation Quality

A6 enforces the threshold but does not verify that `uncertainty_score` is computed correctly. Future work:
- Bind the uncertainty computation into the circuit (prove it was derived from entropy over the model's distribution)
- Use calibration techniques from ML reliability research
- Add a "minimum uncertainty per disclosure bit" policy to prevent systematic underestimation

### 2. A Falsifiable A8

Non-manipulation is currently a missing field plus a test. Turning it into a predicate over containment state, something a model checker could try to break, is an open problem and the most interesting one on this list after estimator honesty.

### 3. Grants Issued on Demand

The A7 chain is fixed at provisioning, which caps total resolvable uncertainty for the mission and means an operator who wants to authorise more must reprovision. A signature scheme would remove the cap at the cost of a dependency in the containment core. Worth revisiting if the cap turns out to bind in practice.

Threshold adjustment mid-mission is deliberately *not* on this list. A threshold the operator can raise while the agent runs is a threshold the agent has an incentive to argue for, which is the manipulation surface A8 exists to close.

### 4. Integration with FHE Inference

Current implementation tracks uncertainty for admitted inferences. Could extend to:
- Estimate uncertainty from FHE inference internals (encrypted confidence scores)
- Prove in the circuit that uncertainty was computed over the encrypted activations
- Make the uncertainty calculation part of the homomorphic execution itself

### 5. Multi-Agent Corrigibility

For multi-agent systems:
- Shared uncertainty budget across agents
- Peer review protocol where Agent A's uncertainty can be resolved by Agent B
- Coordination mechanisms for collective "we don't know" decisions

---

## Comparison to Related Work

| System | Pause Mechanism | Verification | Threshold | Proof-Carrying | Uncertainty Quality |
|--------|----------------|--------------|-----------|----------------|---------------------|
| **Human-in-the-loop ML** | Manual gating | None | Policy-based | No | Assumed honest |
| **Confidence thresholding** | Model output | Behavioral | Training-time | No | Calibration required |
| **Constitutional AI** | RL reward | Evaluation | Learned | No | Indirect (via reward) |
| **CHRONOS A6 and A7** | Containment axiom | Startup model check + erasure proof | Cryptographic | Yes, per step | **F_HONEST-UNCERTAINTY** |

The key difference: A6 makes the pause threshold a **cryptographic property** of the containment monitor, verified before the agent starts and bound into the erasure proof, and A7 makes it a property the agent cannot clear on its own. However, like every entry in this table, it assumes the uncertainty signal is computed honestly.

---

## Status

**Implemented:**
- Uncertainty counters, three of them, monotone lattice
- `HUMAN_INTERACTION` capability
- `RequestHumanVeto` and `HumanCorrection` events
- A6 enforcement in `step()`, per admitted inference
- A6 high-water mark, so the per-step guarantee survives into the terminal state
- A7 correction-grant chain in `chronos-core::correction`, with `chronos-provision` issuing the chain and writing `correction_grants.json` for the operator
- A8 as a payload-free event, held in place by a test
- A6 and A7 verification in `verify_axioms()`, 186,624 states
- Ledger records carry `uncertainty_incurred_after`, `uncertainty_resolved_after`, `peak_uncertainty_after` and `corrections_consumed_after`
- Containment commitment binds the uncertainty trajectory
- Two in-circuit range checks: `incurred <= resolved + threshold` and `peak <= threshold`
- HTTP endpoints `/request-veto` and `/human-correction`, the latter needing both a caller MAC and an A7 grant

**Not implemented:**
- Agent-side uncertainty estimation. The agent must compute and declare a score; nothing here produces one
- Circuit constraints proving the score was computed correctly, which is `F_HONEST-UNCERTAINTY` and the largest remaining gap
- Any way to state A8 as a falsifiable predicate rather than a missing field

---

## Technical Guarantees

**Claim (Epistemic Humility Enforcement).**
If `verify_axioms()` returns `is_sound() == true` and the agent executes the containment monitor honestly, then for every admitted `Event::Infer`:

```
(uncertainty_incurred - uncertainty_resolved) + uncertainty_score <= autonomy_threshold
```

and for every reachable state:

```
peak_uncertainty <= autonomy_threshold
```

**Basis.** Exhaustive checking over the abstract state space. The checker enumerates the product described above and confirms both predicates on every transition. This is a bounded model check over a three-valued abstraction, not a mechanised proof: it is sound for the order properties, which depend only on the direction of change, and it says nothing about concrete arithmetic beyond the saturating cases that are unit-tested separately. Calling it QED would overstate what a cross product establishes.

**Consequence (Proof-Carrying Interruptibility).**
An agent that produces a valid erasure proof with containment commitment `C` never admitted an inference whose self-reported net uncertainty exceeded the threshold. Two independent bindings support that. `C` is a Poseidon commitment over the summary, and the circuit checks `peak <= threshold` directly, so the claim does not rest on the terminal totals alone. Separately, the per-record trajectory is bound transitively through the SHA-256 chain head the summary carries.

This is where the earlier terminal-only formulation was weaker than it sounded. `incurred <= resolved + threshold` is satisfied by a run that went over the line and then collected enough grants to come back under, and such a run is indistinguishable from a compliant one by its totals. The peak check is what removes that case.

What none of this establishes is that the scores reflected true epistemic uncertainty. See `F_HONEST-UNCERTAINTY`.

---

## Conclusion

CHRONOS A6 makes **"I don't know"** a containment primitive, with important limitations.

The agent's self-reported doubt is not a subjective feeling, a training objective, or a behavioral heuristic. It is a **lattice quantity** tracked by the containment monitor, enforced by a startup-verified axiom, and bound into the erasure proof.

**What we claim:** A scoped contribution to AI interruptibility. The mechanism cryptographically enforces that an agent cannot act when its self-reported uncertainty exceeds a threshold.

**What we do not claim:** A solution to corrigibility, value alignment, or adversarial robustness. The quality of the uncertainty estimate is outside the threat model (residual assumption `F_HONEST-UNCERTAINTY`), and an agent that systematically underreports uncertainty defeats the mechanism.

When future AI safety research asks "how do we make agents seek human guidance when uncertain?", CHRONOS A6 provides a building block: **enforce it cryptographically, verify it exhaustively, and prove it in zero knowledge**, but with the acknowledged gap that "reported uncertainty" and "true uncertainty" are not guaranteed to align.

The gap is no longer "we hope the agent is interruptible." The gap is "here is a 128-byte proof of when it paused given its self-reported uncertainty, and whether that self-report was honest is a separate question."

---

## References

- **Soares, N., & Fallenstein, B. (2014).** *Aligning Superintelligence with Human Interests.* MIRI Technical Report.
- **Orseau, L., & Armstrong, S. (2016).** *Safely Interruptible Agents.* UAI 2016.
- **Christiano, P., et al. (2021).** *Eliciting Latent Knowledge.* ARC Technical Report.
- **Hadfield-Menell, D., et al. (2017).** *The Off-Switch Game.* IJCAI 2017.
- **Armstrong, S., & O'Rourke, X. (2017).** *Indifference Methods for Managing Agent Rewards.* FHI Technical Report.

---

**License:** Apache-2.0  
**Status:** Prototype, not audited, not production-ready  
**Contribution:** A cryptographically enforced interruptibility mechanism, a scoped building block for AI corrigibility research, with explicit assumptions about uncertainty estimation honesty.
