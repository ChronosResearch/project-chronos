# CHRONOS Agent

A Rust-native dead man's switch. Implements FHE-locked secrets with a Verifiable Delay Function time-lock, SNARK-based erasure proof, and a Drand time-oracle. Replaces the original Python prototype.

## Architecture

```
crates/
├── chronos-core    # shared traits, error types, secure memory wipe, mlock
├── chronos-vdf     # Wesolowski VDF (GMP FFI), PoSW hash-chain
├── chronos-snark   # Groth16 erasure circuit (arkworks)
└── chronos-agent   # main binary — HTTP API, orchestration, signal handling
```

## What it does

- **FHE engine** (`tfhe-rs`): FHE key generation and ciphertext evaluation.
- **VDF** (`gmp-mpfr-sys`): Wesolowski modular squaring `y = g^(2^T) mod N`, time-locked key release.
- **Time oracle**: Drand randomness fetched via HTTP (`reqwest`), no Go binary required.
- **SNARK erasure**: Groth16 circuit skeleton proving the secret key was wiped.
- **Memory security**: `mlock`, triple-pass volatile wipe (`0xFF → 0x00 → 0xFF`), compiler fences, core dump disabled at startup via `prctl`.

## Current status

| Component | Status |
|---|---|
| FHE key generation | Working |
| VDF squaring (GMP) | Working |
| HKDF key derivation | Working (RFC 5869) |
| Drand HTTP polling | Working |
| Secure memory wipe | Working + unit tested |
| Graceful shutdown (SIGTERM) | Working |
| Prometheus metrics | Working |
| SNARK erasure proof | Stubbed — needs full Groth16 constraints |
| BLS signature verification | Stubbed — needs `bls12_381` pairing |
| FHE evaluation circuit | Stubbed — needs Concrete-ML model |

## Build

Requires the GNU toolchain on Windows (for GMP):

```bash
# Windows
rustup toolchain install stable-x86_64-pc-windows-gnu

# Linux (recommended)
rustup target add x86_64-unknown-linux-musl

cargo build --release
```

## Known gaps before production use

- BLS pairing for Drand signature verification not implemented.
- FHE evaluation endpoint needs a real Concrete-ML circuit.
- Groth16 constraints are mocked (single trivial R1CS constraint).
- `certN.bin` must come from an MPC ceremony (placeholder RSA modulus used in tests).
- mTLS and replay protection nonce window are stubbed.

See [DEPLOYMENT.md](DEPLOYMENT.md) for setup and OS capability requirements.
