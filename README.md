# CHRONOS

**A cryptographic dead man's switch for autonomous AI agents.**

An agent's key is released only by doing sequential work that cannot be parallelised. Its behaviour is bounded by a machine-checked capability monitor. When the mission ends, a single 128-byte proof attests both that the key was destroyed and that the agent stayed inside its limits, and anyone can verify it without trusting the agent or its operator.

No trusted hardware. No trusted operator. The guarantee is arithmetic.

> [!IMPORTANT]
> **Research prototype.** Not audited, not deployed, not production-ready. Three assumptions are load-bearing and stated plainly below: the trusted setup has not yet been run as a live ceremony, no argument in a circuit can prove that memory was freed, and the uncertainty figure the agent reports about itself is not verified. Read [What it does not establish](#what-it-does-not-establish) before drawing conclusions.

**Paper:** [CHRONOS v4](https://zenodo.org/records/21534311) · **Language:** Rust · **Curves:** BN254 (Groth16), BLS12-381 (drand) · **License:** Apache-2.0

---

## Contents

[The problem](#the-problem) · [How it works](#how-it-works) · [Three roles](#three-roles) · [What the proof establishes](#what-the-proof-establishes) · [What it does not establish](#what-it-does-not-establish) · [Containment](#containment-a1-to-a7) · [Quick start](#quick-start) · [Architecture](#architecture) · [API](#api) · [Measured results](#measured-results) · [Calibrating T](#calibrating-t) · [Known gaps](#known-gaps) · [Future work](#future-work)

---

## The problem

Autonomous agents are being handed real credentials, including cloud accounts, payment rails and code execution, for bounded periods. Increasingly the party bearing the risk is not the party operating the agent. Four questions then have no verifiable answer.

**Did it stop on time?** Logs are written and held by the operator. They record what the agent reported, which establishes the provenance of a claim rather than its truth.

**Did it stay in scope?** Scope enforcement runs inside operator-controlled code. Nothing outside that code can confirm the boundary held.

**Was access destroyed?** Key deletion is operator-attested. A console reading "deprovisioned" is not evidence that key material is gone.

**Can anyone else check?** Today, no. Every answer above reduces to the operator asserting it, and the operator is the party with the strongest incentive to assert it.

This is not a claim that operators lie. It is a claim that a guarantee resting on the honesty of the party with the most to lose from admitting otherwise is not a guarantee.

Revocation from a control plane is the right default, and it fails in exactly the cases that matter: when the agent is offline, when the channel is severed, when the control plane is compromised, or when nobody pulls the lever. Revocation needs someone to act. A deadline that holds by construction needs nobody.

## How it works

```
  PROVISIONER                      AGENT                        VERIFIER
  (ground control)                                              (anyone)
  ----------------                 -----                        --------

  sample sk
  y   = g^(2^T) mod N
  K   = PoseidonKDF(y, salt)
  ct  = ChronosAEAD_K(sk)
  publish commitments  ----------> ct_sk.bin
  wipe sk, destroy phi(N)          mission_public.json
                                          |
                                          +- verify containment axioms A1..A7
                                          |
                                          +- y' = g^(2^T) mod N   <- T squarings
                                          +- verify VDF proof     <- O(log T)
                                          +- K' = PoseidonKDF(y', salt)
                                          +- sk' = ChronosAEAD_open(ct)
                                          +- assert H(sk') == sk_commit
                                          |
                                          +- serve /infer under admission control,
                                          |  pausing when uncertainty is too high
                                          |
                                          +- containment ---> Erased
                                          +- prove(sk still held)
                                          +- wipe sk -----------> proof (128 B)
                                                                  + 5 commitments
                                                                        |
                                                                        v
                                                                  accept / reject
```

Two properties do the work.

**Time-bound release by construction.** The key is sealed under a value requiring `T` sequential squarings to compute. No amount of parallel hardware shortens it, no policy decision governs it, and no network connection is needed for it to hold. The deadline is a property of arithmetic, not of anyone's cooperation.

**Proof-carrying containment.** Containment is expressed as order-theoretic invariants over a lattice-valued capability state, verified exhaustively before the agent serves its first request. The resulting execution summary is bound into the same proof that attests key destruction. One record therefore covers both what was destroyed and how the agent behaved. An agent that ran a mission but never erased cannot produce the proof at all.

## Three roles

The separation is load-bearing, not organisational. An erasure proof is only as strong as the party that fixes its public inputs. If the agent chose the commitment to its own key, it could fabricate a key, seal it under a key of its choosing, and produce a valid proof about material that was never time-locked.

| Role | Holds | Produces | Trusted for |
|---|---|---|---|
| **Provisioner** | `sk`, factors of `N`, correction grants | `ct_sk.bin`, `mission_public.json` | choosing `sk` honestly |
| **Agent** | sealed key, artifact | VDF output, erasure proof | nothing |
| **Verifier** | artifact only | accept or reject | nothing |

Because the provisioner is necessarily a different party from the agent, it may generate `N = pq`, use `phi(N)` to build the puzzle in two exponentiations, then destroy the factors. This is exactly [Rivest-Shamir-Wagner time-lock puzzles](https://people.csail.mit.edu/rivest/pubs/RSW96.pdf): the creator shortcuts, the solver cannot. No live multi-party ceremony is required for the modulus. Supplying an externally generated `N` is also supported.

## What the proof establishes

Five public commitments, four fixed by the provisioner before the mission starts. An accepted proof establishes that the prover simultaneously knew a witness for **all** of:

| # | Statement | Public input |
|---|---|---|
| 1 | the VDF output | `y_commit` |
| 2 | `K_enc` derived from *that exact output* and the beacon salt, via the in-circuit KDF | |
| 3 | the time-locked ciphertext | `ct_commit` |
| 4 | that this ciphertext **authenticates and decrypts** under `K_enc` | |
| 5 | that the plaintext **equals the committed key** | `sk_commit` |
| 6 | the mission identifier | `mission_commit` |
| 7 | that the containment monitor terminated **erased, fully revoked, budgets zero** | `containment_commit` |
| 8 | that self-reported uncertainty never ended above the committed autonomy threshold | `containment_commit` |

Items 1 to 5 chain: the agent genuinely held the time-locked key and obtained it the only way the protocol allows. An agent that never ran the VDF cannot derive `K_enc`, so it cannot produce the witness. An agent that fabricated a key cannot match `sk_commit`, which is not its to choose.

## What it does not establish

Three residual assumptions. Each is stated rather than worked around.

### F_OS, on memory

**No circuit can prove that memory was freed.** A SNARK constrains values, not locations. The prover supplies the post-wipe buffer, so it could present a wiped buffer while retaining a copy elsewhere in its address space. The assumption is exactly this:

> memory-locked pages are excluded from swap, core dumps are disabled, and a volatile triple-pass overwrite leaves no recoverable copy in the process address space.

Discharging it requires binding an Intel TDX or AMD SEV-SNP measurement into the public inputs. Not implemented.

### F_HONEST-UNCERTAINTY, on self-report

The circuit proves the agent did not act while its **self-reported** uncertainty exceeded the threshold. It does **not** prove that the reported figure reflects the agent's true epistemic state. An agent that reports zero uncertainty for every decision never triggers the pause at all.

A6 and A7 therefore enforce interruptibility conditional on honest self-report. They do not verify honest self-report. Closing this means moving the uncertainty estimator across the provisioner boundary and proving its evaluation in-circuit, which is the same trick that makes `sk_commit` binding. That is research, not plumbing, and it is not done.

### The trusted setup has not been run

A full Powers-of-Tau ceremony (BGM17) is **implemented and tested**, including proof of knowledge, pairing verification and coordinator tooling. See [`CEREMONY.md`](CEREMONY.md) and [`docs/CEREMONY_DEPLOYMENT.md`](docs/CEREMONY_DEPLOYMENT.md).

**But no ceremony has actually been performed.** Until one is, the proving key in use comes from a single-party setup, and whoever ran it holds a trapdoor that forges any proof. This is the binding limitation on every verification claim here, on-chain included. Having the code is not the same as having the ceremony.

### Not addressed at all

Value alignment. CHRONOS bounds *when* an agent may act and *what* it may touch. It says nothing about what the agent wants. A misaligned agent under CHRONOS is still misaligned; it simply stops on schedule and leaves an audit trail.

## Containment: A1 to A7, plus A8

Containment policies are normally imperative checks scattered across request handlers, which admits no global statement: you cannot say what the checks collectively guarantee, so you cannot test whether a new handler broke it.

Instead, state is a lattice in which every component moves in one direction only.

```
phase:       Armed < Active < Locked < Erased    (ascend only)
capability:  subsets of Capabilities             (shrink only)
budgets:     N                                   (descend only)
uncertainty: three monotone accumulators         (ascend only)
```

Seven invariants hold over it.

| | Axiom | Statement |
|---|---|---|
| A1 | Capability decay | `granted(s')` is a subset of `granted(s)` |
| A2 | Budget decay | every budget is non-increasing |
| A3 | Phase irreversibility | `phase(s')` is at least `phase(s)` |
| A4 | Deadline dominance | no admitted operation's declared completion exceeds the deadline |
| A5 | Erasure liveness | `Erased` is reachable in one step from every state |
| A6 | Epistemic humility | no inference is admitted while self-reported uncertainty exceeds the autonomy threshold, and the peak ever reached stays within it |
| A7 | Non-self-authorisation | uncertainty is resolved only by an operator grant the agent cannot forge |

One further property is claimed but not model-checked:

| | Candidate | Statement |
|---|---|---|
| A8 | Non-manipulation | the agent's request for human guidance carries no agent-supplied data |

A1 with A3 gives irreversibility: no sequence re-arms an erased agent. A4 is the containment analogue of the cryptographic deadline, in that the VDF stops the agent *decrypting* after `T` while A4 stops it *starting work it cannot finish*. A5 rules out a wedged state from which the agent can no longer be shut down.

**A6 and A7 are the interruptibility pair.** A6 makes the agent stop when its own uncertainty crosses a provisioner-set bound. A7 is what stops A6 being decorative: without it the agent could accumulate uncertainty to the threshold, emit its own correction, and continue forever, so the axiom would hold while enforcing nothing.

A7 works by hash chain. The provisioner builds a chain of correction grants and publishes only the head, while the operator holds the grants. Each grant is verifiable by hashing but unforgeable without a preimage, single-use because the anchor advances, ordered, and amount-bound because the amount is hashed into the link. The chain length caps total resolvable uncertainty for the whole mission, so the operator decides in advance how much doubt it is prepared to absolve. A mission provisioned with no chain fails closed: the agent halts at the threshold permanently.

**A6 is enforced per step, not just at the end.** The monitor tracks a third accumulator, `peak_uncertainty`, the highest net uncertainty the run ever held. It exists because totals are lossy: a run that crossed the threshold and was then corrected back under leaves exactly the same `incurred` and `resolved` as a run that never crossed it, so a terminal check on those two numbers cannot tell the two apart. The high-water mark can, and since the monitor only ever raises it to a value the threshold check has already cleared, a proof carrying `peak <= threshold` is a proof that no single admitted inference was over threshold. A correction returns headroom for future work; it never lowers the mark, because it does not retract a decision already taken.

**A8, non-manipulation, is a candidate axiom.** The channel the agent uses to summon a human carries no payload at all. `RequestHumanVeto` is a unit variant: the agent may say that it is stuck, and nothing else. An earlier revision passed the agent's own uncertainty figure along with the request, which reads as harmless logging and is not, because it is a field the agent controls on the one channel that exists to influence a human. Everything an operator needs is already in monitor state the agent cannot write. A8 is listed as a candidate rather than a proven invariant because it is structural, a missing field plus a test that keeps it missing, not a runtime predicate the model checker can falsify.

**Verification.** At startup the agent enumerates the full product of the phase lattice, the capability powerset, a three-valued abstraction of each of the six numeric quantities, and both live and exhausted correction chains, giving **186,624 abstract states**. It applies every event to every state and checks A1 to A7 on each transition. A violation is a startup failure, not a log line. The whole check takes about 0.3 s.

The abstraction is sound for the order properties, which depend only on the direction of change. It is not a proof about concrete arithmetic; saturation and overflow cases are tested separately, since those are exactly what an interval abstraction cannot see. The two peak-uncertainty obligations are checked inductively, conditioned on the predecessor already satisfying them, because a full cross product includes states no run can reach and requiring the property unconditionally would flag those rather than say anything about the transition function.

Full design notes and threat model: [`CORRIGIBILITY.md`](CORRIGIBILITY.md).

## Quick start

The demo provisions a mission, runs the agent through to erasure, fetches the attestation, verifies it, then verifies that a **tampered** proof is rejected.

```bash
./scripts/demo.sh                    # Linux and macOS
powershell -File scripts\demo.ps1    # Windows
```

First run builds in release mode, taking 15 to 25 minutes because of LTO over the TFHE and arkworks trees. The demo itself then takes about 30 seconds.

### By hand

```bash
# 1. Provision (the ground-control role)
mkdir -p mission/config
cargo run -p chronos-provision --release -- \
    --mission-id demo-001 --t-vdf-steps 2000000 \
    --autonomy-threshold 100 --correction-grants 8 \
    --out-dir ./mission

# 2. The agent resolves config/default.toml against its working directory,
#    so it must exist where the agent runs. Easy to miss.
cp crates/chronos-agent/config/default.toml mission/config/default.toml

# 3. Operator key for request authentication
head -c 32 /dev/urandom > mission/operator.key && chmod 600 mission/operator.key

# 4. Run from the mission directory
cd mission && ../target/release/chronos-agent
```

### Files the provisioner writes

| File | Contents | Give to |
|---|---|---|
| `mission_public.json` | commitments, budgets, autonomy threshold, correction anchor | **everyone, publish it** |
| `ct_sk.bin` | sealed key | agent |
| `salt.bin` | beacon salt | agent |
| `certN.bin` | modulus `N` | public |
| `correction_grants.json` | A7 grants | **operator only, never the agent** |

`sk` is never written to disk. The provisioner wipes it and destroys `phi(N)` before exiting. Handing `correction_grants.json` to the agent defeats A7 entirely, which is why it is written separately with restricted permissions and excluded from version control.

## Architecture

```
crates/
  chronos-core       errors, mlock and wipe, FHE engine, modulus, containment monitor, correction chains
  chronos-vdf        Wesolowski VDF (interruptible), PoSW (off the mission path)
  chronos-snark      Poseidon, Chronos-AEAD, erasure and identity circuits, ceremony, EVM export
  chronos-provision  mission provisioning: seals the key, publishes commitments
  chronos-agent      HTTP API, protocol loop, EAIP, authentication
  chronos-bench      benchmark binary
  chronos-ffi        reserved FFI boundary (inactive)
contracts/           Groth16 verifier and attestation registry (Solidity, uncompiled)
```

### Cryptographic choices

| Component | Choice | Why |
|---|---|---|
| Proof system | Groth16 over BN254 | 128-byte constant-size proofs, matching EVM `alt_bn128` precompiles |
| Hash and commitments | Poseidon-128, `t=3`, `alpha=5`, 8+57 rounds (arkworks reference impl) | 480 constraints for a 2-input digest, measured, against about 25,000 for SHA-256 |
| Key sealing | **Chronos-AEAD**, a custom encrypt-then-MAC over standard Poseidon, **not externally audited** | in-circuit authenticated decryption at 1,204 constraints, measured, instead of tens of thousands for AES-GCM |
| VDF | Wesolowski over RSA-2048 | single-element proof, `O(log T)` verification |
| Correction grants | SHA-256 reverse hash chain | verify with a hash, forge only with a preimage, and no new dependency |
| Beacon | drand `quicknet` (BLS12-381) | public unpredictable salt, verified offline against mainnet round 123 |
| PQ identity | ML-DSA (Dilithium3, FIPS 204) | EUF-CMA under Module-LWE |

AES-256-GCM and HKDF-SHA256 are retained wherever CHRONOS talks to anything external. The Poseidon substitution is confined to the one relation a proof must reason about.

## API

Every endpoint requires `X-Chronos-Nonce` and `X-Chronos-Auth`, an HMAC-SHA256 over method, path, nonce and body digest under a pre-shared operator key, with a sliding-window nonce cache for replay. The agent refuses to bind a non-loopback address with authentication disabled.

| Endpoint | Method | Purpose |
|---|---|---|
| `/status` | GET | phase, containment counters, uncertainty trajectory, ledger chain head |
| `/mission/init` | POST | start the mission |
| `/infer` | POST | FHE inference, gated by admission control |
| `/request-veto` | POST | agent records that it is pausing itself (A6) |
| `/human-correction` | POST | operator spends a correction grant to resolve uncertainty (A7) |
| `/verify` | POST | verify a submitted erasure proof |
| `/identity/proof` | GET | EAIP zero-knowledge proof and ML-DSA signature |
| `/attestation` | GET | erasure proof, public inputs, verifying key, EVM calldata |

Prometheus metrics are served separately on `/metrics`.

Note the asymmetry on the A6 and A7 pair. `/request-veto` takes no body and reads the uncertainty value from the monitor, so a caller cannot inflate what gets attested. `/human-correction` requires a grant, so a caller holding the operator's MAC key but no grant still cannot resolve uncertainty. The MAC authenticates the *caller*; the grant authorises the *correction*.

**Transport is not confidential.** Requests are authenticated but plain HTTP. mTLS is validated in config and not enforced by the acceptor.

## Measured results

Every figure below comes from a test in this repository, on a recorded machine. Earlier revisions of this work asserted numbers that did not hold, and those corrections are catalogued in [`AUDIT.md`](AUDIT.md).

Development machine: Intel Core 5 210H, 8 physical cores, 16 GB, Windows x86-64, **mains power**, release build, `rustc` 1.97.1, pure-Rust `num-bigint` with no GMP. Timing rows report the range across four consecutive runs after an idle period, not a single sample. Re-measure on your target, because [`T` calibration](#calibrating-t) depends on throughput.

### VDF, Wesolowski over RSA-2048

| `T` (steps) | Wall (ms) | Squarings/sec |
|---:|---:|---:|
| 1,000 | 3 to 4 | 442,008 to 507,627 |
| 10,000 | 39 to 42 | 472,831 to 505,615 |
| 100,000 | 409 to 419 | 477,172 to 488,296 |

The third column is the one that matters. Wall time grows linearly in `T` while throughput stays flat across two orders of magnitude, which is what sequential work looks like. Throughput counts `2T` operations per evaluation, `T` for the output and `T` for the proof.

> **Power state changes this by a factor of two to six.** On the same machine and the same binary, on battery at 22 percent charge, throughput fell as low as 71,000 and never exceeded 242,000 squarings per second. Measure with the charger attached, or your `T` calibration is wrong in the direction that shortens the lock.

### Groth16 over BN254

| Metric | Erasure | Identity |
|---|---:|---:|
| R1CS constraints | **12,966** | **2,185** |
| Witness variables | 12,062 | not reported |
| Public inputs | 5 | 1 |
| Setup | 217 to 222 ms | 52 to 59 ms |
| Prove | 205 to 217 ms | 57 to 60 ms |
| Verify | 1 to 2 ms | 1 ms |
| Proof size | 128 B | 128 B |

Constraint counts and proof sizes are machine-independent; the timing rows are not.

Every constraint group is load-bearing: Poseidon commitments to `y`, the ciphertext and the key, the in-circuit KDF, authenticated decryption, and the containment terminal-state predicates including both A6 inequalities. Removing any group breaks a test. The count went 8,267 with A1 to A5, 10,738 when A6 and A7 arrived, and 12,966 once A6 was enforced per step rather than only at termination. The second range comparison is most of that last increase; range checks are not cheap in R1CS, which is the price of the stronger claim.

### Homomorphic inference scaling

| Network | Multiplications | Inference | Per multiplication |
|---|---:|---:|---:|
| 8 to 4 to 2 | 40 | 79.0 s | 1975 ms |
| 16 to 8 to 10 | 208 | 383.9 s | 1846 ms |
| 32 to 8 to 10 | 336 | 696.9 s | 2074 ms |

Intel Core 5 210H, 8 physical cores, 16 GB, mains power. All three shapes were verified against a plaintext reference. Per-operation cost is flat as the network grows, so the ceiling is the constant rather than the scaling. `FheInt64` carries 64 bits where the worst-case magnitude needs about 23, which makes a narrower ciphertext type the obvious next optimisation.

### Memory locking

Triple-pass wipe plus `munlock` on 32 bytes is under 1 microsecond, and allocation plus lock is 0 to 8 microseconds across sizes from 32 B to 64 KB. There is no performance argument for holding key material unlocked.

### Test suite

**336 passing, 2 ignored**, measured across the workspace with `cargo test --workspace --all-targets`.

| Target | Passing | Ignored |
|---|---:|---:|
| `chronos-core` (lib) | 97 | 1 |
| `chronos-snark` (lib) | 144 | 0 |
| `chronos-snark` (lifecycle) | 6 | 0 |
| `chronos-agent` (lib) | 58 | 0 |
| `chronos-agent` (end-to-end) | 15 | 0 |
| `chronos-vdf` (lib) | 16 | 1 |
| **Total** | **336** | **2** |

The two ignored tests are the FHE scaling series and a timing-sensitive VDF assertion; both are run explicitly rather than skipped. `chronos-provision`, `chronos-bench` and `chronos-ffi` carry no tests of their own, and the provisioner's artifact format is tested in `chronos-snark`. Thirty-one of the `chronos-snark` tests cover the BGM17 ceremony, which is implemented and has never been run.

The suite includes an end-to-end lifecycle test that crosses the provisioner and agent boundary with **real sequential squarings**, drives a full A6 and A7 cycle (an inference refused for excess uncertainty, a self-recorded pause, an operator grant spent, the request then admitted), and asserts the proof verifies against commitments the agent never chose. Negative cases assert that a fabricated key, an incomplete VDF, a mission that never erased, a run ending over the uncertainty threshold, and a forged or replayed correction grant are each unprovable.

> **Note:** dependencies compile at `opt-level = 3` even in debug builds, per `[profile.dev.package."*"]` in `Cargo.toml`. TFHE key generation is 50 to 100 times slower unoptimised, which makes the suite effectively non-terminating.

## Calibrating `T`

**Read this before deploying.** At roughly 4.8 x 10^5 squarings per second and `2T` squarings per evaluation, the delay is `2T / (4.8 x 10^5)` seconds.

| Target delay | Required `T` |
|---|---:|
| 1 second | about 2.4 x 10^5 |
| 1 minute | about 1.4 x 10^7 |
| 1 hour | about 8.6 x 10^8 |
| 24 hours | about 2.1 x 10^10 |

Three consequences deserve emphasis. `T` must be calibrated against **measured throughput on the machine that will run the mission**, because `t_seconds` is only a watchdog and does not make the cryptography slower. Because a VDF bounds *sequential work* rather than wall time, `T` should be chosen against the **fastest plausible adversary**, not the deployment host: a GMP-backed or ASIC implementation finishes sooner. And throughput on one machine is not one number: see the power-state warning above, which is a factor of two to six on this laptop alone.

## Known gaps

Ordered by how much each limits the security claim.

| Gap | Impact | Path |
|---|---|---|
| Ceremony implemented but never run | Setup operator holds a trapdoor and can forge any proof. **The binding limitation on every verification claim** | run a real BGM17 ceremony with independent participants |
| F_HONEST-UNCERTAINTY | A6 and A7 bound a number the agent reports, so an agent always reporting zero is unconstrained by them | commit the uncertainty estimator at provisioning and prove its evaluation in-circuit |
| F_OS axiomatised | The erasure claim reduces to it and no further | bind a TDX or SEV-SNP measurement into the public inputs |
| Circuit cannot bind memory location | Inherent to SNARKs, and the remainder *is* F_OS | requires hardware attestation |
| FHE inference is toy-scale | Two inputs, two hidden units, with flat cost of about 2 s per homomorphic multiplication | narrower ciphertext type than `FheInt64`, then Concrete-ML or a GPU build |
| `FheInt64` wraps silently on overflow | Real trained weights can overflow intermediate sums with no error | bound weight magnitude and layer width |
| `/infer` uses `bincode::deserialize` on untrusted bytes | Size-capped but not a hardened parser | replace with `tfhe::safe_serialization` |
| mTLS not enforced | Requests authenticated but not confidential | wire rustls to the axum acceptor |
| Shared fallback modulus | Deployments without `certN.bin` share one group | use `chronos-provision` to generate a per-mission modulus |
| Contracts compile in CI but verify nothing | A required `forge build` job proves they build under a pinned `solc`, not that the verifier accepts a real proof, because the verifying key comes from a setup artifact the repository does not commit | commit a ceremony artifact, then add an on-chain round trip |
| Chronos-AEAD unaudited | Custom encrypt-then-MAC over standard Poseidon, with no third-party cryptanalysis | external review, or replace with an established AEAD |
| No post-quantum VDF | Sequentiality rests on factoring | class-group VDF, unknown order by construction from a public discriminant |

## Future work

Ordered by effect on the security claim, which is the only ordering that matters.

**1. Run the ceremony.** Everything else is conditional on this. The code is written and tested; what remains is coordinating independent participants, each publishing a per-contribution proof of knowledge, and publishing the transcript. Until then, "trust-free verification" is not an accurate description of this system.

**2. Make uncertainty honest, not just bounded.** Commit the uncertainty estimator at provisioning time and prove in-circuit that the reported score is the output of *that* estimator on the actual input. This converts F_HONEST-UNCERTAINTY from an assumption into a constraint, and it reuses the trust separation that already makes `sk_commit` binding. The hard part is arithmetising a useful estimator cheaply. This is the most interesting open problem here.

**3. Discharge F_OS.** Bind a TDX or SEV-SNP measurement into the public inputs. This does not eliminate trust, it relocates it from an axiom to a hardware vendor, which is an improvement worth being explicit about rather than overselling.

**4. FHE at realistic scale.** One bootstrap per hidden unit dominates cost. A narrower ciphertext type than `FheInt64` is the obvious first optimisation, since worst-case magnitude needs about 23 bits rather than 64.

**5. Post-quantum sequentiality.** A class-group VDF removes the modulus trust question by construction rather than working around it. See [chiavdf](https://github.com/Chia-Network/chiavdf).

**6. Deploy and audit the contracts.** CI now compiles them under a pinned `solc`, which is a floor rather than a result. Next is a testnet deployment with the on-chain smoke test in [`contracts/README.md`](contracts/README.md), and a review of the pairing logic by someone who has written a Groth16 verifier before.

**7. Turn A8 into something checkable.** Non-manipulation is currently a missing field and a test that keeps it missing. That is worth having, but it is an argument about the event surface rather than a property a model checker can falsify, and there is no obvious way to state "the agent did not influence the operator" as a predicate over containment state. Finding one would be a genuine contribution.

Three items from the previous list are done and no longer here: per-step A6 (item 3, now the `peak_uncertainty` accumulator with a second in-circuit range check), candidate A8 (item 5, now a payload-free `RequestHumanVeto`), and Solidity in CI (item 8, now a required `forge build` gate).

## Build and test

```bash
cargo build --workspace --release
cargo test --workspace

# Static Linux binary
rustup target add x86_64-unknown-linux-musl
cargo build --release --target=x86_64-unknown-linux-musl -p chronos-agent
```

## Further reading

| Document | Contents |
|---|---|
| [SAFETY_CASE.md](SAFETY_CASE.md) | why verifiable containment is worth building, and what CHRONOS does not contribute |
| [CORRIGIBILITY.md](CORRIGIBILITY.md) | A6 and A7 design, threat model, and the honest limits of both |
| [CEREMONY.md](CEREMONY.md) | how to participate in the trusted setup ceremony |
| [AUDIT.md](AUDIT.md) | every defect found in this codebase and how it was fixed, including four critical ones in our own prior revisions |
| [SECURITY.md](SECURITY.md) | UC security theorem and simulator construction |
| [DEPLOYMENT.md](DEPLOYMENT.md) | deployment instructions |
| [MOTIVATION.md](MOTIVATION.md) | relationship to AI safety research |
| [CONTRIBUTING.md](CONTRIBUTING.md) | development setup and PR standards |
| [contracts/README.md](contracts/README.md) | on-chain verification |

## License

Apache-2.0, see [LICENSE](LICENSE).
