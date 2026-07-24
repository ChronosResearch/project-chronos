# Security Policy

## Supported Versions

Please see the following list of supported versions.

| Version | Supported          |
| ------- | ------------------ |
| v1.0.x  | :white_check_mark: |
| < 1.0   | :x:                |

## Threat Model Assumptions (Research Prototype)

This repository is a **research prototype**, not a production deployment artifact.
Security claims are conditioned on explicit assumptions:

- **EA (Exclusivity Assumption)**: sensitive key material resides only in the committed in-memory region intended for wipe.
- **FOS (Trusted OS Functionality)**: operating system semantics for page locking and process memory are trusted (e.g., `mlock(2)` / `VirtualLock()` behavior).
- **Prototype backend caveat**: Python stubs and adapters (`NoopVDFEngine`, `NoopSNARKProver`) are development placeholders and must not be treated as production cryptographic proofs.

## Out of Scope

The following are explicitly out of scope for this prototype security model:

- Physical attacks (cold-boot, DMA, invasive hardware extraction).
- Microarchitectural side-channel attacks (cache timing, speculative execution leakage).
- OS/kernel compromise and hypervisor compromise.
- Post-quantum adversaries against RSA-factoring-based assumptions.

## Reproducibility and Claim Integrity

- Only report benchmark values obtained from measured runs.
- Any unexecuted configuration (GPU/FPGA/MPC/prover backends) must be labeled **not measured**.
- Include environment details and commands when publishing results so claims can be reproduced.

## Reporting a Vulnerability

If you discover a security vulnerability within this project, please send an e-mail to Shashank Kumar at [shashankchoudhary792@gmail.com]. All security vulnerabilities will be promptly addressed.

We take security seriously and appreciate your efforts to responsibly disclose your findings.
