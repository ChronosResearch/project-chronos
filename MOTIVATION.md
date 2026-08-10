# Why CHRONOS Matters for AI Safety

## The Core Problem

As AI systems become more capable and are deployed as autonomous agents — executing
code, managing resources, interacting with external services — a fundamental
oversight problem emerges: **how do we enforce that an agent stops when we tell it to?**

Current approaches rely on software-level controls: API keys, rate limits, process
termination. These are insufficient against a sufficiently capable agent that can
acquire resources, copy itself, or simply refuse to terminate. More importantly,
they provide no *verifiable guarantee* — an operator cannot prove to a third party
that an agent was actually stopped and its secrets destroyed.

CHRONOS addresses this with a cryptographic answer: **the agent's ability to act
is time-locked by a Verifiable Delay Function, and its erasure is proven by a
zero-knowledge SNARK**. The guarantee is mathematical, not procedural.

---

## Connection to AI Safety Research

### 1. Corrigibility and Shutdown

Paul Christiano's work on eliciting latent knowledge and ARC's agent foundations
research identify *corrigibility* — the property that an agent accepts correction
and shutdown — as a core alignment property. CHRONOS provides a *cryptographic
enforcement* of a specific corrigibility property: the agent cannot continue
operating past its mission deadline, and it cannot fake its own erasure.

This is complementary to, not a replacement for, value alignment. Even a
misaligned agent running CHRONOS cannot extend its operational window without
breaking the VDF sequentiality assumption — a hardness assumption that does not
depend on the agent's values or goals.

### 2. Verification and Oversight

A recurring theme in AI safety is the difficulty of *verifying* that safety
properties hold. CHRONOS makes one property — agent erasure — publicly verifiable.
The Groth16 SNARK proof can be checked by any party with the verifying key in
~1ms, without access to the agent's secrets. This is a concrete step toward
the "legible AI" goal articulated by Anthropic, DeepMind Safety, and others.

### 3. Containment of Autonomous Agents

The AI containment problem (Bostrom 2014, Yampolskiy 2020) asks: how do we
prevent a capable AI from escaping its operational boundaries? CHRONOS addresses
the *temporal* dimension of containment: the agent is cryptographically prevented
from operating beyond its authorized window. Combined with network isolation and
capability restrictions, this provides a layered containment architecture.

### 4. Dead Man's Switch as a Safety Primitive

The dead man's switch pattern — "if I stop receiving a signal, take a safe action"
— is a well-understood safety primitive in physical systems (nuclear weapons,
industrial controls). CHRONOS is the first cryptographically sound implementation
of this primitive for AI agents:

- The "signal" is the VDF output, which requires T sequential squarings to compute
- The "safe action" is key erasure, proven by a SNARK
- The "cannot be faked" property comes from the knowledge-soundness of Groth16

---

## Threat Model Relevance

CHRONOS is most relevant for the following deployment scenarios:

| Scenario | CHRONOS Contribution |
|----------|---------------------|
| Autonomous trading agents with time-limited authorization | Cryptographic expiry of signing keys |
| AI research assistants with access to sensitive data | Verifiable deletion of session secrets |
| Multi-agent systems where one agent delegates to another | EAIP provides time-locked identity binding |
| Regulatory compliance (GDPR right to erasure) | SNARK proof of deletion for audit |
| Red-team / capability evaluation agents | Hard time limit on evaluation window |

---

## What CHRONOS Does Not Solve

Intellectual honesty requires stating the limits:

- **Value alignment**: CHRONOS does not make an agent want to be erased. It
  enforces erasure cryptographically, but a sufficiently capable agent that
  controls its own hardware could potentially bypass the VDF. The Exclusivity
  Assumption (EA) is required.

- **Capability containment**: CHRONOS bounds *time*, not *capability*. An agent
  can cause significant harm within its operational window.

- **Cooperative agents only**: The protocol assumes the agent runs the CHRONOS
  code honestly. A fully adversarial agent that controls its execution environment
  is outside the threat model. This is analogous to how cryptographic protocols
  assume honest implementation.

These limitations are acknowledged in the UC security model via the F_OS axiom.
Reducing F_OS to a hardware attestation model (Intel TDX, AMD SEV-SNP) is
identified as the primary direction for future work.

---

## Why Cryptography, Not Policy

Policy-based controls on AI agents (terms of service, regulatory frameworks,
contractual obligations) have a fundamental weakness: they are enforced after
the fact, by humans, with imperfect information. Cryptographic controls are
enforced *before* the fact, by mathematics, with perfect information.

CHRONOS does not replace policy — it makes policy *enforceable*. An operator
who deploys a CHRONOS-protected agent can prove to regulators, auditors, and
the public that the agent was erased at the agreed time, without trusting the
operator's word.

This is the same shift that public-key cryptography made for authentication:
from "trust the certificate authority" to "verify the signature." CHRONOS
attempts to make the same shift for AI agent lifecycle management.

---

## References

- Bostrom, N. (2014). *Superintelligence: Paths, Dangers, Strategies*. Oxford University Press.
- Christiano, P. et al. (2021). *Eliciting Latent Knowledge*. ARC Technical Report.
- Soares, N., Fallenstein, B. (2014). *Aligning Superintelligence with Human Interests*. MIRI Technical Report.
- Yampolskiy, R. (2020). *Unpredictability of AI: On the Impossibility of Accurately Predicting All Actions of a Smarter Agent*. Journal of AI and Consciousness.
- Hadfield-Menell, D. et al. (2017). *The Off-Switch Game*. IJCAI 2017.
- Irving, G., Askell, A. (2019). *AI Safety Needs Social Scientists*. Distill.
