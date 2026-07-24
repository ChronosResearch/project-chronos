> [!NOTE]
> 🔧 **Rust prototype underway.** The Python implementation is the current reference. Active development in progress — not production ready.

# Project CHRONOS - Prototype

**A Compositional Architecture for Ephemeral FHE Agents with VDF Time-Locking and Attestable Software Erasure**

> Research prototype under active development. The Python implementation is the foundational reference model. The Rust implementation is the high-performance successor.

## Proprietary and Confidential

**Copyright (c) 2026 Shashank Kumar. All Rights Reserved.**

This repository and all its contents, including code, documentation, and architecture, are strictly proprietary. No one is permitted to use, copy, modify, distribute, or commercially exploit this software without explicit written permission from the author.

See [LICENSE](LICENSE) for full terms.

**Contact:** shashankchoudhary792@gmail.com | [github.com/sidthebuilder](https://github.com/sidthebuilder)

---

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20847864.svg)](https://doi.org/10.5281/zenodo.20847864)
[![SSRN](https://img.shields.io/badge/SSRN-Preprint-blue)](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6950898)
[![Rust QA](https://github.com/sidthebuilder/project-chronos/actions/workflows/rust-qa.yml/badge.svg)](https://github.com/sidthebuilder/project-chronos/actions/workflows/rust-qa.yml)
[![Python QA](https://github.com/sidthebuilder/project-chronos/actions/workflows/qa.yml/badge.svg)](https://github.com/sidthebuilder/project-chronos/actions/workflows/qa.yml)

> Kumar, S. (2026). *Project CHRONOS: A Compositional Architecture for Ephemeral FHE Agents with VDF Time-Locking and Attestable Software Erasure.* Revised v2.

---

## What CHRONOS Does

CHRONOS is a research prototype for cryptographic agent containment. It gives an autonomous AI agent three simultaneous guarantees:

1. **Plaintext Blindness** - The agent processes inputs under Fully Homomorphic Encryption and never observes plaintext.
2. **Verifiable Time-Bound Existence** - A Verifiable Delay Function enforces a mission duration that cannot be bypassed through parallelism.
3. **Attestable Software Erasure** - A cryptographic commitment proves the key was destroyed after the deadline.

The goal is structural containment enforced by mathematics, not behavioural alignment.

---

## Repository Structure

```
project-chronos/
├── chronos-rust/               # Rust prototype (active development)
│   ├── chronos-agent/          # Async Tokio orchestrator (main binary)
│   ├── chronos-core/           # Secure memory (volatile zeroization), anti-tamper daemon
│   ├── chronos-crypto/         # FHE engine, VDF, erasure commitment
│   └── chronos-net/            # Drand randomness beacon client + libp2p P2P layer
│
├── chronos_agent.py            # Python prototype orchestrator
├── fhe_engine.py               # Paillier FHE engine
├── posw.py                     # SHA-256 Proof-of-Sequential-Work + Merkle tree
├── drand_client.py             # drand League of Entropy oracle client
├── memory_sanitizer.py         # Triple-pass C-level memory erasure
├── interfaces.py               # Protocol interfaces and prototype stubs
├── security/
│   ├── anti_tamper.py
│   └── secure_string.py
└── tests/
```

---

## Architecture (Prototype)

```text
drand quicknet ──► deadline round
                     │
                     ▼
FHE engine ──► encrypted inference ──► mission phase
                     │
                     ▼
SHA-256 PoSW (Python) / VDF engine (Rust prototype target)
                     │
                     ▼
pre-erasure commitment (Schnorr NIZK, Python) + memory wipe
                     │
                     ▼
SNARK prover interface (ISNARKProver; production backend required)
```

---

## Prototype vs. Paper Specification

This is a research prototype. The table below documents where the implementation diverges from the formal paper and why.

| Subsystem | Paper Specification | Current Implementation | Status |
|-----------|--------------------|-----------------------|--------|
| FHE | TFHE-rs boolean circuits | Paillier additively-homomorphic path in Python reference; TFHE-rs path in Rust prototype | Prototype |
| Sequential time-lock | Wesolowski VDF over MPC RSA modulus | SHA-256 PoSW hash chain in Python; Wesolowski backend is a production target behind `IVDFEngine` | Prototype Stub |
| Erasure attestation | Groth16 SNARK | Schnorr pre-erasure commitment in Python; Groth16 backend is a production target behind `ISNARKProver` | Prototype Stub |
| Modulus Generation | Diogenes MPC | Local hardcoded constants | Prototype Stub |
| Time Oracle | drand quicknet chain | drand quicknet chain | Prototype |
| Memory Erasure | Triple-pass volatile wipe | Triple-pass write_volatile + compiler_fence (Rust) | Prototype |
| Anti-Tamper | Timing detection daemon | Dedicated OS thread timing daemon | Prototype |
| P2P Network | - | libp2p Gossipsub + Kademlia DHT | Prototype |

---

## v2 Changes (July 2026)

### Paper
| Issue | Fix |
|-------|-----|
| Broken ZK compositeness proof (circular reasoning) | Removed. Trust delegated to Diogenes MPC certificate |
| UC theorem had no PPT reductions | All hybrids include explicit adversary constructions B1, B2, B3 |
| Fabricated GPU SNARK timing numbers | Removed. Limitations table added |
| Claimed "new ZK protocol" while also saying "no new primitives" | Removed contradiction; framing corrected to "systematic integration" |

### Code
| File | Fix |
|------|-----|
| `posw.py` | mp.Queue changed to mp.Pipe to fix deadlock on large checkpoint payloads |
| `chronos_agent.py` | Schnorr NIZK correctly labelled as pre-erasure commitment |
| `drand_client.py` | BLS key format corrected for quicknet chain |
| `memory_sanitizer.py` | Wipe verification uses ctypes.string_at |
| `security/anti_tamper.py` | Anomaly threshold raised to 5 consecutive hits |

### Rust Prototype (new in v2)
| Component | What it implements |
|-----------|-------------------|
| `chronos-crypto/fhe.rs` | Production TFHE-rs FheUint32. Homomorphic dot product and matrix-vector multiplication for encrypted neural network inference. |
| `chronos-crypto/vdf.rs` | Wesolowski VDF with evaluate() and verify(). Uses Fiat-Shamir heuristic for the challenge. |
| `chronos-crypto/snark.rs` | Arkworks Groth16 over BLS12-381. Proves knowledge of pre-erasure secret x * y = z. |
| `chronos-crypto/posw.rs` | Pure Rust SHA-256 hash chain PoSW with checkpoint recording and determinism tests. |
| `chronos-core/memory.rs` | SecureString with DoD 5220.22-M triple-pass write_volatile zeroization on Drop. |
| `chronos-core/tamper.rs` | CPU timing anomaly daemon on a dedicated OS thread. Triggers erasure after 5 consecutive drifts. |
| `chronos-net/drand.rs` | Async drand beacon fetch via reqwest. Mixes network randomness with Intel RDRAND hardware entropy. |
| `chronos-net/p2p.rs` | libp2p Gossipsub + Kademlia DHT for decentralised compute task broadcasting. |
| `chronos-agent/main.rs` | Tokio async orchestrator. Full 6-phase agent lifecycle. |

---

## Security Properties

| Property | Mechanism | Assumption |
|----------|-----------|------------|
| Plaintext blindness | TFHE-rs FHE inference | TFHE CPA security |
| Time-bound key access | SHA-256 PoSW (Python reference) / Wesolowski VDF (Rust production target) | Sequential-work hardness / factoring hardness (for Wesolowski path) |
| Erasure attestation | Schnorr pre-erasure commitment (Python) / Groth16 via `ISNARKProver` (production target) | Schnorr discrete-log assumptions / Groth16 q-PKE |
| Tamper detection | CPU timing daemon + mlock | OS memory model |

### What CHRONOS Does NOT Guarantee
- Physical erasure against cold-boot or DMA attacks
- Post-quantum security (RSA VDF modulus relies on factoring hardness)
- Erasure if the OS swaps the key to disk before mlock is called

---

## Installation

### Rust Prototype

Requires Rust stable and the Visual Studio C++ Build Tools (Windows) or build-essential (Linux).

```bash
cd chronos-rust
cargo build --release
cargo test
```

### Python Prototype

```bash
pip install -e ".[dev]"
CHRONOS_DISABLE_ANTI_TAMPER=true pytest tests/ -v
```

---

## Reproducibility and Benchmark Guardrails

- Use a clean virtual environment and run `pip install -e ".[dev]"`.
- Run tests with `CHRONOS_DISABLE_ANTI_TAMPER=true pytest tests/ -q`.
- Run benchmark harness with `python benchmark.py`.
- Report measured outputs only; rows without executed measurements must be marked **not measured**.
- Do not present prototype-only stubs (`NoopVDFEngine`, `NoopSNARKProver`) as production cryptographic evidence.

---

## Running the Rust Agent

```bash
cd chronos-rust
cargo run --bin chronos-agent
```

Expected output:

```
=== CHRONOS RUST AGENT BOOTSTRAP ===
[1/6] Initializing libp2p Decentralized Swarm (Gossipsub + Kademlia)...
[2/6] Fetching Drand randomness beacon...
[3/6] Generating TFHE-rs Production FHE keypair, pinning secret key to secure memory...
[4/6] Fetching Telecom Customer Churn Dataset (7,043 records) over network...
[5/6] Encrypting features and evaluating a 2-Layer Neural Network over TFHE...
[6/6] Spawning Wesolowski VDF time-lock (10k sequential squarings)...
      Arkworks Groth16 NIZK verified: true
=== AGENT LIFECYCLE COMPLETE ===
```

---

## Citation

```bibtex
@misc{kumar2026chronos,
  title  = {Project CHRONOS: A Compositional Architecture for Ephemeral FHE Agents
             with VDF Time-Locking and Attestable Software Erasure},
  author = {Kumar, Shashank},
  year   = {2026},
  note   = {Revised v2. \url{https://github.com/sidthebuilder/project-chronos}},
  doi    = {10.5281/zenodo.20847864}
}
```

---

## Contributors

- **Shashank Kumar** ([@sidthebuilder](https://github.com/sidthebuilder)) - shashankchoudhary792@gmail.com
- <img src="chronos_bot_logo.png" width="20" height="20" align="top"/> **Chronoos Bot** ([@Chronoos-Bot](https://github.com/apps/chronoos-bot)) - AI Repository Manager
