# CHRONOS — Prototype

[![CI](https://github.com/ChronosResearch/project-chronos/actions/workflows/rust-qa.yml/badge.svg)](https://github.com/ChronosResearch/project-chronos/actions/workflows/rust-qa.yml)

Cryptographic dead man's switch using FHE, Verifiable Delay Functions, and SNARK-based erasure proofs.

**Paper:** [CHRONOS: Ephemeral AI Agents via FHE Time-Locked Secrets](https://zenodo.org/records/21534311) (preprint)

## What this is

A Rust prototype of the CHRONOS protocol. An AI agent encrypts its secret key under FHE, time-locks it with a VDF, and proves it wiped the plaintext via a Groth16 SNARK. No trusted hardware required.

## Architecture

```
crates/
├── chronos-core    # shared types, error handling, mlock, secure wipe
├── chronos-vdf     # Wesolowski VDF (GMP FFI), PoSW hash-chain
├── chronos-snark   # Groth16 erasure circuit (arkworks)
├── chronos-ffi     # GMP FFI boundary types
└── chronos-agent   # binary — HTTP API, orchestration, signal handling
```

## Status

| Component | State |
|---|---|
| FHE key generation (`tfhe-rs`) | Working |
| VDF squaring (GMP) | Working |
| HKDF key derivation (RFC 5869) | Working |
| Drand HTTP polling | Working |
| Secure memory wipe + unit test | Working |
| Graceful shutdown (SIGTERM) | Working |
| Prometheus metrics | Working |
| SNARK erasure proof | Working |
| BLS drand signature verification | Working |
| FHE evaluation circuit | Stubbed |

## Build

```bash
# Linux (recommended)
rustup target add x86_64-unknown-linux-musl
cargo build --release

# Windows (requires GNU toolchain for GMP)
rustup toolchain install stable-x86_64-pc-windows-gnu
cargo build --release
```

## Gaps

- FHE evaluation endpoint reverses bytes — needs actual Concrete-ML circuit.
- `certN.bin` is a placeholder RSA modulus — needs MPC ceremony.
- mTLS and replay protection are stubbed.

See [DEPLOYMENT.md](DEPLOYMENT.md) for setup. See [AUDIT.md](AUDIT.md) for the full code audit.

## Roadmap & Future Plans

- **Phase 1 (Current):** Working prototype of the CHRONOS protocol with VDF and SNARK erasure proofs.
- **Phase 2 (Integration):** Merge with CELLHAWK navigation stack for resilient UAV agents.
- **Phase 3 (Hardware):** True biological storage integration (DNA-Attest) for cryptographic key storage.

## License

AGPL-3.0 — see [LICENSE](LICENSE).
