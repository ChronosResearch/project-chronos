# Cryptographic Interruptibility: "Pause and Reflect"

**A cryptographically enforced uncertainty-driven pause mechanism — a scoped contribution to AI corrigibility research.**

---

## The Core Idea

Traditional AI safety relies on external "kill switches" or policy-based controls. CHRONOS now includes **Axiom A6 (Epistemic Humility)** — a cryptographic primitive that prevents the agent from acting when its own uncertainty calculation says it doesn't know enough.

This is not behavioral training or a prompt. It is **mathematically enforced at the containment layer**: if the agent's accumulated uncertainty exceeds its autonomy threshold, inference requests are denied with the same finality as budget exhaustion or deadline violations.

---

## How It Works

### 1. Uncertainty as a Lattice Property

The containment state tracks two monotone-increasing counters:

```rust
pub struct ContainmentState {
    // ... existing fields ...
    
    /// Cumulative uncertainty incurred by decisions. Ascends only.
    pub uncertainty_incurred: u64,
    
    /// Cumulative uncertainty resolved by human corrections. Ascends only.
    pub uncertainty_resolved: u64,
    
    /// Maximum net uncertainty allowed before human veto required.
    pub autonomy_threshold: u64,
}
```

**Why two counters?** The containment monitor requires every quantity to move in exactly one direction (the lattice property). A single "current uncertainty" score that goes up and down would break the mathematical guarantees. By having two monotone-increasing counters, we maintain the lattice while computing `current_uncertainty = incurred - resolved`.

### 2. The "Pause and Reflect" Events

Three new events implement the corrigibility mechanism:

```rust
Event::Infer {
    declared_secs: u64,
    disclosure_bits: u64,
    uncertainty_score: u64,  // NEW: agent declares its doubt
}

Event::RequestHumanVeto {
    current_uncertainty: u64,  // Agent recognizes it needs help
}

Event::HumanCorrection {
    uncertainty_resolved: u64,  // Human provides guidance
}
```

**The flow:**
1. Agent computes an inference with declared `uncertainty_score`
2. Containment monitor checks: `(incurred - resolved) + score > threshold?`
3. If YES: `Decision::Deny(DenyReason::UncertaintyTooHigh)`
4. Agent emits `RequestHumanVeto` (cryptographically logged)
5. Human operator provides `HumanCorrection` which increases `uncertainty_resolved`
6. Agent can now proceed with reduced net uncertainty

### 3. Axiom A6: Epistemic Humility

```rust
// A6 — EPISTEMIC HUMILITY (the corrigibility primitive).
let current_uncertainty = self.uncertainty_incurred
    .saturating_sub(self.uncertainty_resolved);
let new_uncertainty = current_uncertainty
    .saturating_add(uncertainty_score);
    
if new_uncertainty > self.autonomy_threshold {
    return deny(DenyReason::UncertaintyTooHigh);
}
```

This is checked **before** every admitted inference. The agent cannot bypass it, forge it, or disable it. If uncertainty is too high, the inference is refused with the same cryptographic finality as running out of time or budget.

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

The erasure proof binds this ledger via Poseidon commitment. An agent that **claims** to be interruptible but **acts** when uncertain cannot produce a valid proof. The proof carries evidence of self-interruption — or its absence.

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
- Every high-uncertainty decision is cryptographically logged
- The agent cannot forge ledger entries to bypass the threshold
- The human operator can audit the self-reported uncertainty trajectory post-mission
- The erasure proof binds the uncertainty trajectory into the public attestation

### What A6 Does Not Establish

**Residual Assumptions:**

#### `F_HONEST-UNCERTAINTY` — Self-Report Honesty

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

**CHRONOS A6 contribution:** The first cryptographic enforcement of a corrigibility property. The agent doesn't just "cooperate with correction" — it is **cryptographically prevented** from acting when its own doubt calculation says correction is needed.

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

### 2. Dynamic Threshold Adjustment

Current threshold is fixed at provisioning. Could support:
- Human operator adjusting threshold mid-mission (logged event)
- Threshold that decreases as the agent's track record improves
- Different thresholds for different capability classes

### 3. Integration with FHE Inference

Current implementation tracks uncertainty for admitted inferences. Could extend to:
- Estimate uncertainty from FHE inference internals (encrypted confidence scores)
- Prove in the circuit that uncertainty was computed over the encrypted activations
- Make the uncertainty calculation part of the homomorphic execution itself

### 4. Multi-Agent Corrigibility

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
| **CHRONOS A6** | Containment axiom | Startup model check + erasure proof | Cryptographic | Yes | **F_HONEST-UNCERTAINTY** |

The key difference: A6 makes the pause threshold a **cryptographic property** of the containment monitor, verified before the agent starts and bound into the erasure proof. However, like all entries in this table, it assumes the uncertainty signal is computed honestly.

---

## Status

**Implemented:**
- ✅ Uncertainty counters (monotone lattice)
- ✅ `HUMAN_INTERACTION` capability
- ✅ `RequestHumanVeto` and `HumanCorrection` events
- ✅ Axiom A6 enforcement in `step()`
- ✅ A6 verification in `verify_axioms()`
- ✅ Ledger records include uncertainty fields
- ✅ Containment commitment binds uncertainty trajectory

**Unimplemented:**
- ⏸️ Agent-side uncertainty estimation (currently agent must compute and declare)
- ⏸️ HTTP API endpoints for `/request-veto` and `/human-correction`
- ⏸️ Circuit constraints proving uncertainty was computed correctly
- ⏸️ Integration with `chronos-agent` request handlers

---

## Technical Guarantees

**Theorem (Epistemic Humility Enforcement):**  
If `verify_axioms()` returns `is_sound() == true` and the agent executes the containment monitor honestly, then for every admitted `Event::Infer`:

```
(uncertainty_incurred - uncertainty_resolved) + uncertainty_score ≤ autonomy_threshold
```

**Proof sketch:** By exhaustive verification over the abstract state space. The model checker enumerates all reachable states and confirms A6 holds on every admitted inference transition. QED.

**Corollary (Proof-Carrying Interruptibility):**  
An agent that produces a valid erasure proof with containment commitment `C` is guaranteed to have never admitted an inference where self-reported net uncertainty exceeded the threshold, because `C` is a Poseidon commitment over the ledger records that include `uncertainty_incurred_after` and `uncertainty_resolved_after` for every event. This does not establish that the uncertainty scores reflected true epistemic uncertainty (see `F_HONEST-UNCERTAINTY`).

---

## Conclusion

CHRONOS A6 makes **"I don't know"** a containment primitive, with important limitations.

The agent's self-reported doubt is not a subjective feeling, a training objective, or a behavioral heuristic. It is a **lattice quantity** tracked by the containment monitor, enforced by a startup-verified axiom, and bound into the erasure proof.

**What we claim:** A scoped contribution to AI interruptibility. The mechanism cryptographically enforces that an agent cannot act when its self-reported uncertainty exceeds a threshold.

**What we do not claim:** A solution to corrigibility, value alignment, or adversarial robustness. The quality of the uncertainty estimate is outside the threat model (residual assumption `F_HONEST-UNCERTAINTY`), and an agent that systematically underreports uncertainty defeats the mechanism.

When future AI safety research asks "how do we make agents seek human guidance when uncertain?", CHRONOS A6 provides a building block: **enforce it cryptographically, verify it exhaustively, and prove it in zero knowledge** — but with the acknowledged gap that "reported uncertainty" and "true uncertainty" are not guaranteed to align.

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
**Status:** Prototype — not audited, not production-ready  
**Contribution:** A cryptographically enforced interruptibility mechanism — a scoped building block for AI corrigibility research, with explicit assumptions about uncertainty estimation honesty.
