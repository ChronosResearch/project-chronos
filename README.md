# CHRONOS

**A cryptographic dead man's switch for AI agents.** An agent's key is released only by sequential work, its behaviour is bounded by a machine-checked capability monitor, and both its key destruction and its conduct are attested in a single 128-byte proof anyone can verify. No trusted hardware.

**Paper:** [CHRONOS v4: Compositional Architecture for Ephemeral FHE Agents with Proof-Carrying Containment](https://zenodo.org/records/21534311)

**Language:** Rust · **Curve:** BN254 (Groth16) / BLS12-381 (drand) · **License:** AGPL-3.0

---

## Contents

- [The idea](#the-idea) · [Protocol](#protocol) · [Three roles](#three-roles)
- [What the proof establishes](#what-the-proof-establishes) · [What it does not](#what-it-does-not-establish)
- [Quick start](#quick-start) · [Architecture](#architecture) · [API](#api)
- [Status](#status) · [Benchmarks](#benchmarks) · [Calibrating-T](#calibrating-t) · [Gaps](#gaps)

---

## The idea

Give an agent a key and a deadline, and nobody outside the operator can verify what it did or that it stopped. The operator simply says so.

CHRONOS makes that claim checkable. A secret key is sealed under a key derived from a verifiable delay function, so it cannot be opened without performing `T` sequential squarings — no amount of parallel hardware shortens the wait. The agent does that work, opens the key, serves homomorphic inference under an explicit capability budget, destroys the key, and emits a Groth16 proof establishing both that it held the genuine time-locked key and that its containment monitor terminated in a fully-revoked state.

The proof is the contribution. Everything else is machinery in service of it.

## Protocol

```
  PROVISIONER                      AGENT                        VERIFIER
  (ground control)                                              (anyone)
  ────────────────                 ─────                        ────────

  sample sk
  y   = g^(2^T) mod N
  K   = PoseidonKDF(y, salt)
  ct  = ChronosAEAD_K(sk)
  publish 4 commitments  ────────► ct_sk.bin
  wipe sk, destroy phi(N)          mission_public.json
                                          │
                                          ├─ verify containment axioms A1..A5
                                          │
                                          ├─ y' = g^(2^T) mod N   ← T squarings
                                          ├─ verify VDF proof     ← O(log T)
                                          ├─ K' = PoseidonKDF(y', salt)
                                          ├─ sk' = ChronosAEAD_open(ct)
                                          ├─ assert H(sk') == sk_commit
                                          │
                                          ├─ serve /infer under admission control
                                          │
                                          ├─ containment ──► Erased
                                          ├─ prove(sk still held)
                                          └─ wipe sk ────────────► proof (128 B)
                                                                  + 5 commitments
                                                                        │
                                                                        ▼
                                                                  accept / reject
```

## Three roles

The separation is load-bearing. An erasure proof is only as strong as the party that fixes its public inputs — if the agent chose the commitment to its own key, it could fabricate a key, seal it under a key of its choosing, and produce a valid proof about material that was never time-locked.

| Role | Holds | Produces | Trusted for |
|---|---|---|---|
| **Provisioner** | `sk`, factors of `N` | `ct_sk.bin`, `mission_public.json` | choosing `sk` honestly |
| **Agent** | sealed key, artifact | VDF output, erasure proof | nothing |
| **Verifier** | artifact only | accept / reject | nothing |

The provisioner must be a different party from the agent. Given that, it may generate `N = pq` and use `phi(N)` to build the puzzle cheaply, then destroy the factors — this is exactly Rivest–Shamir–Wagner time-lock puzzles, and it removes any need for a live multi-party ceremony. Supplying an externally generated `N` is also supported.

## What the proof establishes

Five public commitments, four of them fixed by the provisioner before the mission starts. An accepted proof establishes that the prover simultaneously knew a witness for **all** of:

| # | Statement | Public input |
|---|---|---|
| 1 | the VDF output | `y_commit` |
| 2 | `K_enc` derived from *that exact output* and the beacon salt, via the in-circuit KDF | — |
| 3 | the time-locked ciphertext | `ct_commit` |
| 4 | that this ciphertext **authenticates and decrypts** under `K_enc` | — |
| 5 | that the plaintext **equals the committed key** | `sk_commit` |
| 6 | the mission identifier | `mission_commit` |
| 7 | that the containment monitor terminated **erased, fully revoked, budgets zero** | `containment_commit` |

Chained, 1–5 say the agent genuinely held the time-locked key and obtained it the only way the protocol allows. An agent that never ran the VDF cannot derive `K_enc` and so cannot produce the witness. An agent that fabricated a key cannot match `sk_commit`, which is not its to choose. Item 7 is *proof-carrying containment*: the same record that attests destruction attests discipline.

## What it does not establish

**No circuit can prove that memory was freed.** A SNARK constrains values, not locations. The prover supplies the post-wipe buffer, so it could present a wiped buffer while retaining a copy of the key elsewhere in its address space.

The residual assumption is therefore exactly this, and nothing beyond it:

> **`F_OS`** — memory-locked pages are excluded from swap; core dumps are disabled; and a volatile triple-pass overwrite leaves no recoverable copy in the process address space.

**The trusted setup is single-party.** Whoever runs it holds the trapdoor and can forge proofs that verify, on-chain included. The setup transcript is hash-chained, tamper-evident and publishable, and contributions can be collected from separate machines — but it combines *seeds*, so the party running the final step can reconstruct the trapdoor. That is not phase-2 ceremony security. Do not describe verification here as trust-free until a [BGM17](https://eprint.iacr.org/2017/1050) ceremony replaces it.

## Quick start

```bash
# 1. Provision a mission (the ground-control role)
cargo run -p chronos-provision --release -- \
    --mission-id demo-001 --t-vdf-steps 100000 --out-dir ./mission

# 2. Operator key for request authentication
head -c 32 /dev/urandom > mission/operator.key && chmod 600 mission/operator.key

# 3. Run the agent
cd mission && cargo run -p chronos-agent --release
```

| File | Contents | Distribute to |
|---|---|---|
| `mission_public.json` | the four commitments | **everyone — publish it** |
| `ct_sk.bin` | sealed key | agent only |
| `salt.bin` | beacon salt | agent only |
| `certN.bin` | modulus `N` | public |

`sk` is never written to disk. The provisioner wipes it and destroys `phi(N)` before exiting.

## Architecture

```
crates/
├── chronos-core       errors · mlock/wipe · FHE engine · modulus · containment monitor
├── chronos-vdf        Wesolowski VDF (interruptible) · PoSW (off the mission path)
├── chronos-snark      Poseidon · Chronos-AEAD · erasure + identity circuits · EVM export
├── chronos-provision  mission provisioning: seals the key, publishes commitments
├── chronos-agent      HTTP API · protocol loop · EAIP · authentication
├── chronos-bench      benchmark binary
└── chronos-ffi        reserved FFI boundary (not active)
contracts/             Groth16 verifier + attestation registry (Solidity)
```

### Cryptographic choices

| Component | Choice | Why |
|---|---|---|
| Proof system | Groth16 / BN254 | 128-byte constant-size proofs; matches EVM `alt_bn128` precompiles |
| Hash / commitments | Poseidon-128, `t=3`, `alpha=5`, 8+57 rounds | ~300 constraints per permutation vs ~25,000 for SHA-256 |
| Key sealing | **Chronos-AEAD** (Poseidon encrypt-then-MAC) | makes in-circuit authenticated decryption ~2k constraints instead of ~60k for AES-GCM |
| VDF | Wesolowski over RSA-2048 | single-element proof, `O(log T)` verification |
| Beacon | drand `quicknet` (BLS12-381) | public, unpredictable salt; verified offline against a real mainnet beacon |
| PQ identity | ML-DSA (Dilithium3, FIPS 204) | EUF-CMA under Module-LWE |

AES-256-GCM and HKDF-SHA256 are retained everywhere CHRONOS talks to something external. The Poseidon substitution is confined to the one relation a proof must reason about.

## API

All endpoints require `X-Chronos-Nonce` and `X-Chronos-Auth` — an HMAC-SHA256 over method, path, nonce and body digest under a pre-shared operator key. The agent refuses to bind a non-loopback address with authentication disabled.

| Endpoint | Method | Purpose |
|---|---|---|
| `/status` | GET | phase, containment counters, ledger chain head |
| `/mission/init` | POST | start the mission |
| `/infer` | POST | FHE inference, gated by admission control |
| `/verify` | POST | verify a submitted erasure proof |
| `/identity/proof` | GET | EAIP zero-knowledge proof + ML-DSA signature |
| `/attestation` | GET | erasure proof, public inputs, verifying key, EVM calldata |

## Status

### Working

| Component | Notes |
|---|---|
| Poseidon-128 over BN254 | native + R1CS; digests tested bit-identical |
| Chronos-AEAD | in-circuit decryption ~2k constraints |
| Poseidon KDF `(y, salt) -> K_enc` | encoded in-circuit |
| Groth16 erasure proof | full key-release chain, 5 full-width public inputs |
| EAIP identity proof | pre-image relation `Poseidon(y, mission) == R` genuinely encoded |
| Axiomatic Containment Monitor | axioms A1–A5 verified over 1,728 abstract states at startup |
| Proof-carrying containment | erasure proof binds the containment summary and enforces its terminal state |
| Mission provisioning | generates `N`, seals the key, publishes commitments, destroys `phi(N)` |
| Wesolowski VDF | interruptible, so the watchdog can actually stop it |
| Native VDF verification | `O(log T)`, outside the SNARK — why the circuit needs no 2048-bit arithmetic |
| drand verification | quicknet `min_sig`; verified offline against mainnet round 123 |
| FHE key generation | `tfhe-rs` |
| FHE inference | two-layer MLP over `FheInt64`, checked against a plaintext reference |
| ML-DSA identity signing | Dilithium3 |
| Key in `mlock`'d memory | triple-pass volatile wipe; no plaintext copy outside `LockedBytes` |
| Request authentication | HMAC over method, path, nonce, body |
| Replay protection | `O(1)` sliding-window nonce cache |
| Persisted proving key | setup once, publish the verifying key |
| `/attestation` with EVM calldata | — |
| Prometheus metrics, graceful shutdown | — |

### Partial or unverified

| Component | State |
|---|---|
| On-chain verification | contracts match the 5-input ABI (pinned by a test) but are **uncompiled, unaudited, undeployed** |
| Groth16 trusted setup | **single-party** — auditable transcript, not ceremony security |
| `F_OS` | **axiomatized**, not reduced to hardware attestation |
| mTLS client certificates | config validated, **not enforced** by the axum acceptor |
| FHE inference scale | toy only — two inputs, two hidden units |

## Benchmarks

```bash
cargo run -p chronos-bench --release
```

Measured on the development machine: Windows x86-64, release build, pure-Rust `num-bigint` (no GMP). Re-measure on your target — [`T` calibration](#calibrating-t) depends on throughput.

### VDF — Wesolowski over RSA-2048

| `T` (steps) | Wall (ms) | Squarings/sec |
|---:|---:|---:|
| 1,000 | 4 | 497,661 |
| 10,000 | 39 | 505,156 |
| 100,000 | 395 | 505,564 |

The third column is the one that matters: wall time grows linearly in `T` while throughput stays flat, which is what sequential work looks like. Throughput counts `2T` operations per evaluation — `T` for the output, `T` for the proof.

### Groth16 — BN254

| Metric | Erasure | Identity |
|---|---:|---:|
| R1CS constraints | **8,267** | ~1,500 |
| Witness variables | 8,290 | — |
| Public inputs | 5 | 1 |
| Setup | 163 ms | 48 ms |
| Prove | 157 ms | 56 ms |
| Verify | 1 ms | 1 ms |
| Proof size | 128 B | 128 B |

Every one of the 8,267 constraints is load-bearing — Poseidon commitments to `y`, the ciphertext and the key; the in-circuit KDF; authenticated decryption; the containment terminal-state predicates. Removing any group breaks a test.

### LockedBytes — `mlock` and wipe overhead

| Size (B) | Alloc + lock (µs) | `mlock` |
|---:|---:|:---:|
| 32 | 8 | ok |
| 256 | 1 | ok |
| 1,024 | 0 | ok |
| 4,096 | 0 | ok |
| 65,536 | 1 | ok |

Triple-pass wipe plus `munlock` on 32 bytes is under 1 µs. There is no performance argument for holding key material unlocked.

## Calibrating `T`

**Read this before deploying.** At ~505k squarings/sec and `2T` squarings per evaluation, the delay is `2T / 505,564` seconds.

| Target delay | Required `T` |
|---|---:|
| 1 second | ~2.5 × 10⁵ |
| 1 minute | ~1.5 × 10⁷ |
| 1 hour | ~9.1 × 10⁸ |
| 24 hours | ~2.2 × 10¹⁰ |

Two consequences. `T` must be calibrated against **measured throughput on the machine that will run the mission** — `t_seconds` is only a watchdog and does not make the cryptography slower. And because a VDF bounds *sequential work* rather than wall time, `T` should be chosen against the **fastest plausible adversary**, not the deployment host: a GMP-backed or ASIC implementation finishes sooner.

## Gaps

Ordered by how much each limits the security claim.

| Gap | Impact | Path |
|---|---|---|
| Single-party trusted setup | Setup operator can forge any proof. **The binding limitation on every verification claim, on-chain included** | BGM17 ceremony with independent participants publishing per-contribution proofs of knowledge |
| `F_OS` axiomatized | The erasure claim reduces to it and no further | Bind an Intel TDX or AMD SEV-SNP measurement into the public inputs |
| Circuit cannot bind memory location | Inherent to SNARKs — narrowed as far as cryptography allows; the remainder *is* `F_OS` | none; requires hardware attestation |
| FHE inference is toy-scale | Two inputs, two hidden units. No accuracy or latency data at real model sizes | one PBS per hidden unit dominates; needs Concrete-ML or a GPU build |
| `FheInt64` wraps silently on overflow | Real trained weights can overflow intermediate sums with no error | bound weight magnitude and layer width |
| `/infer` uses `bincode::deserialize` on untrusted bytes | Size-capped but not a hardened parser | replace with `tfhe::safe_serialization` |
| mTLS not enforced | Requests are authenticated but not confidential | wire rustls to the axum acceptor |
| Shared fallback modulus | All deployments without `certN.bin` share one group | use `chronos-provision` to generate a per-mission modulus |
| Contracts uncompiled | Nothing deployed; no `solc`/`forge` in CI | add a Foundry job |
| No post-quantum VDF | Sequentiality rests on factoring | class-group VDF — unknown order by construction from a public discriminant. See [chiavdf](https://github.com/Chia-Network/chiavdf) |

## Build and test

```bash
cargo build --workspace --release
cargo test --workspace

# Static Linux binary
rustup target add x86_64-unknown-linux-musl
cargo build --release --target=x86_64-unknown-linux-musl -p chronos-agent
```

The suite includes an end-to-end lifecycle test (`crates/chronos-snark/tests/lifecycle.rs`) that crosses the provisioner/agent boundary with **real sequential squarings** and asserts the proof verifies against commitments the agent never chose. It also asserts three negative cases: a fabricated key, an incomplete VDF, and a mission that never erased are each unprovable.

> **Note:** dependencies are compiled at `opt-level = 3` even in debug builds
> (see `[profile.dev.package."*"]` in `Cargo.toml`). TFHE key generation is
> 50–100× slower unoptimised, which makes the suite effectively non-terminating.

## Further reading

| Document | Contents |
|---|---|
| [AUDIT.md](AUDIT.md) | full audit log — every defect found in this codebase and how it was fixed |
| [SECURITY.md](SECURITY.md) | UC security theorem and simulator construction |
| [DEPLOYMENT.md](DEPLOYMENT.md) | deployment instructions |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | third-party code and attribution |
| [contracts/README.md](contracts/README.md) | on-chain verification |

## License

AGPL-3.0 — see [LICENSE](LICENSE).
