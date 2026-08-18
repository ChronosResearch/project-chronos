# Working on it
# CHRONOS — Prototype

Cryptographic dead man's switch for AI agents: fully homomorphic inference, a verifiable delay function that gates key release, a SNARK that attests erasure, and a machine-checked containment monitor. No trusted hardware.

**Paper:** [CHRONOS: Ephemeral AI Agents via FHE Time-Locked Secrets](https://zenodo.org/records/21534311) (preprint)

> **The paper is currently behind the code.** Sections 3.3, 3.4, 5 and 6 of the v3
> preprint describe a design that this repository has since been shown to
> implement incorrectly, and which has been replaced. Where the two disagree,
> **this repository is authoritative**. The specific divergences are listed under
> [Paper divergences](#paper-divergences).

## What this is

An agent's secret key is sealed under a key derived from a VDF output, so it cannot be recovered without performing `T` sequential squarings. The agent performs that work, opens the key, serves inference under an explicit capability budget, then destroys the key and produces a Groth16 proof about what it did. Identity is bound to the same VDF output and signed under ML-DSA.

The proof is the interesting part, so it is worth stating precisely what it establishes.

## What the erasure proof proves

Given five public commitments — four fixed by the provisioner *before* the mission starts — an accepted proof establishes that the prover simultaneously knew a witness for all of:

1. the VDF output committed to by `y_commit`;
2. `K_enc` derived from that exact output and the beacon salt, via the in-circuit KDF;
3. the ciphertext committed to by `ct_commit`;
4. that this ciphertext **authenticates and decrypts** under `K_enc`;
5. that the resulting plaintext equals the key committed to by `sk_commit`;
6. the mission identifier behind `mission_commit`;
7. that the containment monitor terminated **erased, fully revoked, both budgets at zero**.

Chained together, 1–5 say the agent genuinely held the time-locked key and obtained it the only way the protocol allows. An agent that never ran the VDF cannot produce this witness; nor can one that fabricated a key, because `sk_commit` is not the agent's to choose.

### What it does not prove

**No circuit can prove that memory was freed.** A SNARK constrains values, not locations. The prover supplies the post-wipe buffer, so it could present an all-`0xFF` buffer while retaining a copy of the key elsewhere in its address space.

The residual assumption is therefore exactly `F_OS` — `mlock`, no swap, no core dumps, volatile triple-pass wipe — and nothing beyond it. That is a real limitation, and it is smaller than it was: an earlier revision of this circuit checked `[0xFF; 32] == 0xFF` and nothing else, so a prover who had never seen the key, the ciphertext, or the VDF could produce a passing proof.

**The trusted setup is single-party.** Whoever runs it holds the trapdoor and can forge proofs that verify, on-chain included. Do not describe verification here as trust-free until a real BGM17 ceremony replaces it.

## Architecture

```
crates/
├── chronos-core       # errors, mlock/wipe, FHE engine, modulus, containment monitor
├── chronos-vdf        # Wesolowski VDF (interruptible); PoSW, off the mission path
├── chronos-snark      # Poseidon, Chronos-AEAD, erasure + identity circuits, EVM export
├── chronos-provision  # mission provisioning: seals the key, publishes commitments
├── chronos-agent      # HTTP API, protocol loop, EAIP, authentication
├── chronos-bench      # benchmark binary
└── chronos-ffi        # reserved FFI boundary (not active)
```

Three roles, and they must be distinct — the proof's soundness depends on it:

| Role | Holds | Produces |
|---|---|---|
| Provisioner (ground control) | `sk`, the modulus factors | `ct_sk.bin`, `mission_public.json` |
| Agent | `ct_sk.bin`, the artifact | the VDF output, the erasure proof |
| Verifier (anyone) | the artifact | accept / reject |

## Quick start

```bash
# 1. Provision a mission (plays the ground-control role)
cargo run -p chronos-provision --release -- \
    --mission-id demo-001 --t-vdf-steps 100000 --out-dir ./mission

# 2. Generate an operator key for request authentication
head -c 32 /dev/urandom > mission/operator.key && chmod 600 mission/operator.key

# 3. Run the agent
cd mission && cargo run -p chronos-agent --release
```

The provisioner writes `mission_public.json` (publish it), `ct_sk.bin` and `salt.bin` (agent only), and `certN.bin` (public). It then wipes `sk` and destroys `φ(N)`.

## Status

| Component | State |
|---|---|
| Poseidon-128 over BN254 — native + R1CS, Grain-LFSR constants | Working — native and in-circuit digests tested identical |
| Chronos-AEAD — Poseidon encrypt-then-MAC | Working — in-circuit decryption ~2k constraints |
| Poseidon KDF `(y, salt) -> K_enc` | Working — encoded in-circuit |
| Groth16 erasure proof (BN254) | Working — full key-release chain encoded, 5 full-width public inputs |
| EAIP identity proof | Working — pre-image relation `Poseidon(y, mission) == R` genuinely encoded |
| Axiomatic Containment Monitor | Working — axioms A1–A5 verified exhaustively over 1,728 abstract states at startup |
| Proof-carrying containment | Working — the erasure proof binds the containment summary and enforces its terminal state |
| Mission provisioning (`chronos-provision`) | Working — generates `N`, seals the key, publishes commitments, destroys `φ(N)` |
| Wesolowski VDF (pure `num-bigint`, RSA-2048) | Working — interruptible, so the watchdog can stop it |
| Native VDF verification, `O(log T)` | Working — checked outside the SNARK, which is why the circuit needs no 2048-bit arithmetic |
| BLS12-381 drand verification (quicknet) | Working — verified against a real mainnet beacon offline |
| FHE key generation (`tfhe-rs`) | Working |
| FHE inference — two-layer MLP over `FheInt64` | Working — verified against a plaintext reference at toy scale |
| ML-DSA (Dilithium3) PQ identity signing | Working |
| Secret key in `mlock`'d memory, triple-pass wipe | Working — no plaintext copy outside `LockedBytes` |
| Request authentication (HMAC over method, path, nonce, body) | Working |
| Replay protection (O(1) nonce cache) | Working |
| Persisted proving key | Working — setup once, publish the verifying key |
| `/attestation` endpoint with EVM calldata | Working |
| Prometheus metrics, graceful shutdown | Working |
| On-chain verification | Contracts written for the 5-input ABI; **unaudited, uncompiled, not in CI** |
| Groth16 trusted setup | **Single-party.** Auditable hash-chained transcript, but not ceremony security |
| `F_OS` (no swap, no core dumps, no residual copies) | **Axiomatized**, not reduced to hardware attestation |
| mTLS client certificates | Config validated, **not enforced** by the axum acceptor |

## Build and test

```bash
cargo build --workspace --release
cargo test --workspace

# Static Linux binary
rustup target add x86_64-unknown-linux-musl
cargo build --release --target=x86_64-unknown-linux-musl
```

The suite includes an end-to-end lifecycle test (`crates/chronos-snark/tests/lifecycle.rs`) that crosses the provisioner/agent boundary with real sequential squarings and asserts the proof verifies against commitments the agent never chose. It also asserts the three negative cases: a fabricated key, an incomplete VDF, and a mission that never erased are each unprovable.

## Benchmarks

```bash
cargo run -p chronos-bench --release
```

Measured on the development machine (Windows x86_64, release build, pure-Rust
`num-bigint` backend, no GMP). Re-measure on your own target: the `T` calibration
below depends on throughput, so these numbers are a method, not a constant.

### VDF — Wesolowski over RSA-2048

| T (steps) | Wall (ms) | Squarings/sec |
|---|---|---|
| 1,000 | 4 | 497,661 |
| 10,000 | 39 | 505,156 |
| 100,000 | 395 | 505,564 |

The load-bearing column is the third one. Wall time grows linearly in `T` while
throughput stays flat at ~505k squarings/sec, which is what sequential work is
supposed to look like. Squarings/sec counts `2T` operations per evaluation — `T`
for the output, `T` more for the Wesolowski proof.

### Groth16 erasure proof — BN254

| Metric | Value |
|---|---|
| R1CS constraints | **8,267** |
| Witness variables | 8,290 |
| Public inputs | 5 |
| Setup | 163 ms |
| Prove | 157 ms |
| Verify | 1 ms |
| Proof size | 128 bytes |

All 8,267 constraints are load-bearing: Poseidon commitments to `y`, the
ciphertext and the key; the in-circuit KDF; authenticated decryption; and the
containment terminal-state predicates. Removing any one breaks a test.

### Groth16 EAIP identity proof — BN254

| Metric | Value |
|---|---|
| Setup | 48 ms |
| Prove | 56 ms |
| Verify | 1 ms |
| Proof size | 128 bytes |

### LockedBytes — `mlock` and wipe overhead

| Size (bytes) | Alloc + lock (µs) | `mlock` succeeded |
|---|---|---|
| 32 | 8 | yes |
| 256 | 1 | yes |
| 1,024 | 0 | yes |
| 4,096 | 0 | yes |
| 65,536 | 1 | yes |

Triple-pass wipe plus `munlock` on 32 bytes: under 1 µs. Memory locking is free
enough that there is no argument for holding key material unlocked.

### Calibrating `T` — read this before deploying

At ~505k squarings/sec and `2T` squarings per evaluation, the delay is
`2T / 505,564` seconds. That makes the shipped default of `t_vdf_steps = 1,000,000`
a **≈4 second** time-lock, not the hour its `t_seconds` companion implies.

| Target delay | Required `T` |
|---|---|
| 1 second | ~2.5 × 10⁵ |
| 1 minute | ~1.5 × 10⁷ |
| 1 hour | ~9.1 × 10⁸ |
| 24 hours | ~2.2 × 10¹⁰ |

Two things follow. First, `T` must be calibrated against measured throughput on
the machine that will run the mission — `t_seconds` is only a watchdog, and it does
not make the cryptography slower. Second, an adversary with faster hardware
finishes sooner; the VDF bounds *sequential* work, not wall time, so `T` should be
chosen against the fastest plausible attacker rather than the deployment host.

This calibration gap existed because the previous benchmark understated VDF
throughput by roughly 50×, which made `T = 10⁶` look like a reasonable default.

### What the previous figures measured

Both earlier tables were withdrawn rather than adjusted, because both measured
something other than what they claimed.

**VDF** (was: T=1,000 → 12,092 ms; T=10,000 → 16,595 ms; T=100,000 → 9,828 ms).
Real measurements of the wrong thing: wall time was dominated by an `O(√n)`
trial-division primality test inside the Fiat-Shamir challenge derivation, whose
cost depends on the hash-derived seed and **not** on `T`. That is why 100× the
sequential work appeared to finish *faster*. `is_prime` is now deterministic
Miller-Rabin, and `test_wall_time_scales_with_t` fails if evaluation ever becomes
constant-time in `T` again.

**Groth16** (was: setup 3.2 s, proving 1.6 s, ~180,000 constraints). Measured
against a circuit padded with roughly 160,000 filler multiplications. Setup is now
20× faster and proving 10× faster because the work removed was never doing
anything. Proof size is unchanged at 128 bytes — Groth16 proofs are constant-size
regardless of circuit size.

## Gaps

Ordered by how much they limit the security claim.

| Gap | Impact |
|-----|--------|
| Trusted setup is single-party, not a ceremony | Setup operator holds the trapdoor and can forge any proof. This is the binding limitation on every verification claim, on-chain included. Needs BGM17 with independent participants publishing per-contribution proofs of knowledge |
| `F_OS` axiomatized, not attested | The erasure claim reduces to it and no further. Needs Intel TDX or AMD SEV-SNP attestation bound into the proof's public inputs |
| Circuit cannot bind memory location | Inherent to SNARKs: the prover supplies the post-wipe buffer. Narrowed as far as cryptography allows; the remainder is `F_OS` |
| One fixed public modulus when `certN.bin` is absent | All fallback deployments share a group. `chronos-provision` generates a per-mission modulus instead; the fallback is RSA-2048, published and unfactored |
| mTLS not enforced by axum | Requests are authenticated but not confidential. Do not expose to an untrusted network |
| `/infer` uses `bincode::deserialize` on untrusted bytes | Size-capped, but not a hardened parser. Replace with `tfhe::safe_serialization` before exposing the endpoint |
| `FheInt64` wraps silently on overflow | Real trained weights can overflow intermediate sums with no error; weight magnitude and layer width must be bounded |
| MLP verified only at toy scale | Two inputs, two hidden units. No accuracy or latency data at real model sizes; one PBS per hidden unit dominates cost |
| Contracts uncompiled and unaudited | No `solc`/`forge` in CI. The 5-input ABI matches `chronos_snark::circuit::PUBLIC_INPUT_COUNT`, which a test pins, but nothing has been deployed |
| Benchmarks unmeasured | See above |
| No post-quantum VDF | The Wesolowski VDF rests on factoring. A class-group VDF is the realistic path — groups of imaginary quadratic orders have unknown order by construction from a public discriminant, which removes the modulus trust question rather than working around it. See [chiavdf](https://github.com/Chia-Network/chiavdf) |

## Paper divergences

Where the v3 preprint and this repository disagree, the repository is correct.

| Paper claim | Reality |
|---|---|
| Erasure circuit has ~180,000 R1CS constraints | ~160,000 were filler multiplications from `while count < TARGET` loops. The real circuit is a few thousand constraints and encodes strictly more |
| Gadget 3 is "AES-GCM key schedule and decryption" | It terminated in `sk[0] * 1 = sk[0]`, a tautology. AES-GCM is replaced by Chronos-AEAD so decryption is genuinely encoded |
| Gadget 2 is "HKDF via Poseidon x^5 sponge" | The sponge had no round constants and a non-invertible linear layer, and its output was discarded. Replaced with real Poseidon; the KDF is now encoded and checked |
| EAIP root is `R = SHA-256(y)`, proven in ~10,000 constraints | A SHA-256 pre-image proof was never implemented. The root is now a Poseidon digest and the pre-image relation is genuinely proven |
| Trusted setup is a "3-party simulated MPC ceremony" where "no single party's contribution is sufficient" | One process, three local RNGs, one party, one trapdoor. XOR-folding local RNGs adds no security property |
| MPC generation of `N` is mandatory | Only when the agent is its own puzzle creator. With a distinct provisioner — which the protocol requires anyway — that party may generate `N` and retain `φ(N)`, which is exactly RSW time-lock puzzles. See `chronos-provision` |
| Benchmark figures in §6 | Withdrawn; see above |
| Public inputs `y[0]`, `wipe_pattern` | Single bytes, giving 8 bits of binding. Now five full-width field elements |

## Further reading

- [AUDIT.md](AUDIT.md) — full code audit log, including the defects found in this codebase and how they were fixed
- [SECURITY.md](SECURITY.md) — UC security theorem and simulator
- [DEPLOYMENT.md](DEPLOYMENT.md) — deployment instructions
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — third-party code and attribution
- [contracts/README.md](contracts/README.md) — on-chain verification

## License

AGPL-3.0 — see [LICENSE](LICENSE).
