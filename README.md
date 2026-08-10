# CHRONOS — Prototype

Cryptographic dead man's switch for AI agents using FHE, Verifiable Delay Functions, and SNARK-based erasure proofs.

**Paper:** [CHRONOS: Ephemeral AI Agents via FHE Time-Locked Secrets](https://zenodo.org/records/21534311) (preprint)

## What this is

A Rust prototype of the CHRONOS protocol. An AI agent encrypts its secret key under AES-256-GCM, time-locks the decryption key with a Wesolowski VDF, and proves it wiped the plaintext via a Groth16 SNARK over BN254. Identity is bound to the VDF output via a zero-knowledge proof and signed with ML-DSA (Dilithium3). No trusted hardware required.

## Architecture

```
crates/
├── chronos-core    # shared types, errors, mlock/wipe, FHE engine, MPC cert
├── chronos-vdf     # Wesolowski VDF, Blind VDF, PoSW hash-chain
├── chronos-snark   # Groth16 erasure circuit, identity circuit, Dynark updater
├── chronos-bench   # benchmark binary (VDF timing, proof latency, memory)
├── chronos-ffi     # reserved FFI boundary (not active)
└── chronos-agent   # HTTP API, orchestration, EAIP, signal handling
```

## Status

| Component | State |
|---|---|
| FHE key generation (`tfhe-rs`) | Working |
| Wesolowski VDF (pure `num-bigint`, RSA-2048) | Working |
| AES-256-GCM decryption of `ct_sk` | Working |
| HKDF-SHA256 key derivation (RFC 5869) | Working |
| Groth16 erasure proof (BN254, ~180k constraints) | Working |
| Poseidon x^5 sponge gadget | Working |
| 3-party simulated MPC trusted setup | Working |
| EAIP identity root + ZK proof | Working |
| ML-DSA (Dilithium3) PQ identity signing | Working |
| BLS12-381 drand signature verification | Working |
| Drand fetch with exponential backoff retry | Working |
| Replay protection (O(1) nonce cache) | Working |
| Verify endpoint rate limiting | Working |
| Secure memory wipe (triple-pass volatile) | Working |
| mlock on all secret-bearing pages | Working |
| Prometheus metrics | Working |
| Graceful shutdown (SIGTERM/Ctrl-C) | Working |
| FHE evaluation circuit | Stub — byte-reversal placeholder |
| mTLS client certificate enforcement | Config validated, not enforced by axum |

## Build

```bash
# Linux (recommended — fully static, no system libs required)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target=x86_64-unknown-linux-musl

# Dev build
cargo build
cargo test
```

## Benchmarks

Run with `cargo run -p chronos-bench --release`. Results on Linux x86_64 (release build):

**VDF — Wesolowski over RSA-2048**

| T (steps) | Wall time | Squarings/sec |
|-----------|-----------|---------------|
| 1,000 | 12 s | 83 |
| 10,000 | 16 s | 603 |
| 100,000 | 9.8 s | 10,174 |

**Groth16 Erasure Proof — BN254 (~180k constraints)**

| Operation | Time |
|-----------|------|
| MPC trusted setup | 3.2 s |
| Proof generation | 1.6 s |
| Proof verification | 4 ms |
| Proof size | 128 bytes |

**LockedBytes — mlock overhead**

| Size | Alloc time | mlock |
|------|-----------|-------|
| 32 B | 19 µs | ✅ |
| 4 KB | 13 µs | ✅ |
| 64 KB | 121 µs | ✅ |
| Triple-pass wipe (32 B) | 1 µs | — |

## Gaps

| Gap | Impact |
|-----|--------|
| FHE evaluation is a stub (byte-reversal) | Inference not cryptographically sound |
| Groth16 circuit gadgets simulate AES-GCM/Merkle constraints | Proof not binding to actual computation |
| `certN.bin` falls back to hardcoded RSA-2048 | VDF group order not from MPC ceremony |
| MPC trusted setup is simulated (3-party local) | Toxic waste not distributed across real parties |
| `F_OS` axiomatized, not reduced to hardware attestation | Strongest security claim unproven |
| mTLS not enforced by axum server | Plain HTTP in default config |

See [SECURITY.md](SECURITY.md) for the UC security theorem and simulator. See [DEPLOYMENT.md](DEPLOYMENT.md) for setup instructions. See [AUDIT.md](AUDIT.md) for the full code audit log.

## License

AGPL-3.0 — see [LICENSE](LICENSE).
