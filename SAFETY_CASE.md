# Safety Case

*Why verifiable agent containment is worth building, what CHRONOS contributes, and
what it does not.*

## The gap

Autonomous agents are being handed real credentials — cloud accounts, payment
rails, code-execution environments, internal APIs — and set to work for bounded
periods. The party that **bears the risk** of such an agent is increasingly not the
party that **operates** it. A vendor runs the agent; a customer's infrastructure is
what it touches. A lab runs an evaluation; a third party's systems are in scope.

In that arrangement, four questions have no verifiable answer today:

1. Did the agent stop when it was supposed to?
2. Did it stay inside the scope it was granted?
3. Was its access actually destroyed, or merely deprovisioned in a console?
4. Can anyone other than the operator confirm 1–3?

The current answer to all four is **the operator says so**. Logs are
operator-controlled, key deletion is operator-attested, and scope enforcement lives
in operator-run code. This is not a claim that operators lie. It is a claim that a
guarantee which depends on the honesty of the party with the strongest incentive to
assert it is not a guarantee, and that as delegation scales, "trust the operator"
stops being an acceptable answer for the party carrying the downside.

## Why existing mechanisms are insufficient

**Revocation from a control plane** is the standard answer and the right default.
It fails in exactly the cases that matter: when the agent is offline, when it has
lost or severed its channel, when the control plane is itself compromised, or when
the operator declines to pull the lever. Revocation is a *liveness* mechanism — it
requires someone to act. A deadline that holds by construction requires nobody.

**Trusted execution environments** hide plaintext from the host, which is
genuinely useful and complementary. But an enclave cannot attest, after the fact,
that a key was destroyed; it offers no mathematical deadline; and it has a history
of microarchitectural compromise. It also relocates trust to a hardware vendor
rather than removing it.

**Audit logs and attestation frameworks** record what the agent reports. They
establish provenance of a *claim*, not the truth of it.

None of these produce an artifact a third party can check without trusting the
operator. That is the gap.

## What CHRONOS contributes

A **published, checkable artifact** — 128 bytes plus five commitments — that
establishes, without trusting the agent or its operator, that the agent held a key
released only by sequential work, and that its capability monitor terminated in a
fully-revoked state.

Two properties are doing the work.

**Time-bound release by construction.** The key is sealed under a value requiring
`T` sequential squarings to compute. No parallelism shortens it, no policy decision
governs it, and no network connection is needed for it to hold. The deadline is a
property of arithmetic rather than of anyone's cooperation.

**Proof-carrying containment.** Containment is expressed as five order-theoretic
invariants over a lattice-valued capability state — capabilities only shrink,
budgets only decrease, the lifecycle only advances, no admitted operation can
outlive the deadline, and shutdown is reachable from every state. These are
verified exhaustively before the agent accepts its first request, and the resulting
execution summary is bound into the same proof that attests key destruction.

That second property is, as far as we are aware, novel. A single record covers both
what the agent destroyed and how it behaved. An agent that ran a mission but never
erased cannot produce the proof at all.

## Scope, honestly

**This is a verification primitive, not an alignment technique.** It does not make
an agent's objectives safer, detect deception, or constrain what a sufficiently
capable system might do inside its window. It narrows one specific thing: the gap
between what an operator asserts about an agent's shutdown and scope, and what a
third party can check.

We think that gap matters because accountability infrastructure tends to be built
after it is needed rather than before, and because "we cannot verify that" is a
poor position from which to negotiate the terms of delegated autonomy.

**Two limitations are load-bearing and we do not minimise them.**

The trusted setup is currently **single-party**, so verification is conditional on
trusting whoever ran it. This is the binding limitation on every claim above, and
it is fixable by a standard multi-party ceremony — engineering, not research.

**No argument in a circuit can establish that memory was freed.** A SNARK
constrains values, not memory locations, so the prover supplies the post-wipe
buffer and could retain a copy elsewhere. The residual assumption is exactly
`F_OS` — memory locking, no swap, no core dumps, volatile overwrite — and nothing
beyond it. Discharging it requires binding a hardware attestation into the proof's
public inputs, which we have not implemented.

Earlier revisions of this work had a much larger gap here: the circuit checked that
a prover-supplied buffer equalled a constant and nothing else, so a prover who had
never seen the key, the ciphertext, or the VDF could produce a passing proof. The
substantive result is reducing an unbounded gap to one stated assumption. We do not
claim to have closed it.

## The strongest objection

*If ground control can sign a revocation, why build a cryptographic deadline?*

Because revocation and expiry fail differently. Revocation fails open when the
channel is gone; expiry fails closed. The interesting deployments are precisely the
ones where the agent is autonomous, intermittently connected, or operating in an
environment the principal does not control — which is where a mechanism requiring
an online decision is weakest.

The honest position is that CHRONOS is a **complement** to revocation, not a
replacement. Both should exist. Only one of them produces evidence a third party
can check afterwards.

## Status

The prototype implements all four properties with a measured artifact: 8,267 real
R1CS constraints, 128-byte proofs verifying in 1 ms, containment axioms checked
over 1,728 abstract states at startup, and an end-to-end test crossing the
provisioner/agent boundary with real sequential squarings. FHE inference works but
only at toy scale, which is the largest gap between the prototype and a deployable
system.

See [README.md](README.md) for the full status and gaps tables, and
[AUDIT.md](AUDIT.md) for every defect found in this codebase, including four
critical ones found in our own prior revisions.
