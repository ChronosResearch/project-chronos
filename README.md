> [!NOTE]
> **Rust prototype underway.** The Python implementation is the current reference. Active development in progress — not production ready.

# Project CHRONOS

**Research Prototype v1.0.0**  
A compositional architecture for deadline-bounded AI execution with encrypted-compute workflows, time-lock controls, and post-mission erasure/attestation boundaries.

## Status
This repository is a research prototype and not production software.

It is intended for:
- architecture evaluation,
- reproducibility and testing,
- security-model discussion.

It is not intended for:
- safety-critical deployment,
- production containment guarantees.

## Overview
Project CHRONOS explores how to combine three containment-oriented properties in one system design:
1. Plaintext minimization/blindness path through encrypted-compute components.
2. Time-bounded execution control using delay/work-gated mechanisms.
3. Post-mission erasure/attestation workflow with explicit cryptographic interface boundaries.

The design emphasizes composability: each cryptographic subsystem is isolated behind typed interfaces so prototype implementations can be replaced by stronger production-target backends.

## Design Goals
- Define a lifecycle for bounded agent execution under cryptographic constraints.
- Separate orchestration logic from cryptographic primitives through stable interfaces.
- Make claims auditable by keeping implementation status explicit (prototype vs target).
- Support reproducible validation through deterministic tests and CI gates.

## Architecture
CHRONOS is organized around orchestrators plus pluggable crypto/time subsystems.

### Core responsibilities
- Agent orchestration: mission lifecycle, deadline control, teardown path.
- Time-lock/work gate: enforces mission deadline progression.
- Encrypted-compute path: prototype encrypted data handling/evaluation flow.
- Erasure/attestation path: post-mission key/material destruction and proof boundary.
- External time oracle: drand integration for independent timing signals.
- Hardening/validation: invariants, input validation, CI checks.

### Lifecycle (prototype flow)
1. Initialize mission context and constraints.
2. Prepare encrypted workload inputs.
3. Apply time-lock/work-gated mission execution.
4. Execute mission logic within bounded window.
5. Trigger memory/key erasure path at deadline.
6. Produce prototype attestation artifacts and verification outputs.

## Prototype vs Production-Target Boundaries
The repository intentionally distinguishes current prototype behavior from production-target interfaces.
- `IVDFEngine`: boundary for production-grade VDF backend integration.
- `ISNARKProver`: boundary for production-grade SNARK backend integration.

### Terminology and claim discipline
To avoid overstatement:
- In current Python reference paths, timing/work checks are represented with SHA-256 PoSW-style mechanisms; do not treat this as equivalent to a full Wesolowski deployment in all paths.
- In current Python reference paths, proof wiring may use pre-erasure commitment flows; do not present this as full production Groth16 attestation in that same path unless explicitly implemented and verified there.

## Implementation Status
| Subsystem | Current Status | Notes |
|---|---|---|
| Python orchestration lifecycle | Prototype | Reference lifecycle and validation flow |
| Rust orchestration/components | Prototype (WIP hardening) | Performance-oriented path under active iteration |
| FHE integration path | Prototype | Scope and guarantees bounded by current implementation |
| Time-lock / VDF interface | Prototype + target boundary | `IVDFEngine` defines production backend seam |
| SNARK/attestation interface | Prototype + target boundary | `ISNARKProver` defines production backend seam |
| drand oracle client | Prototype | External timing input integration |
| Memory erasure routines | Prototype | Includes verification/hardening checks |
| Anti-tamper checks | Prototype | Defensive signals, not a complete physical security solution |
| Distributed/network extensions | Stub/Prototype | Not production-ready |

## Security Model (Summary)
CHRONOS should be read with explicit threat assumptions.
- Threat assumptions include adversarial pressure on runtime and deadline semantics.
- Out-of-scope areas include full physical compromise and broader host/infra guarantees not explicitly implemented in this repository.

See `SECURITY.md` for assumptions, limits, and measured-claims guidance.

## Reproducibility and Verification

### Prerequisites
- Python 3.11 or 3.12
- Git
- Platform support as described by current CI matrix

*(If using Rust components)*
- Stable Rust toolchain
- cargo

### Install (Python)
```bash
git clone https://github.com/sidthebuilder/project-chronos.git
cd project-chronos
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Validate locally
```bash
# tests
pytest tests/ -q --tb=short

# lint (example; use project-configured options)
flake8 .
```

### Rust formatting/lint/test (when working in Rust path)
```bash
cd chronos-rust
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

## CI and Quality Gates
Repository CI is expected to enforce:
- Python tests across supported versions/platforms,
- lint/format gates,
- Rust formatting/lint/test checks on Rust prototype paths,
- regression tests for previously identified defect classes.

A change should be considered acceptable only when required checks are green.

## Repository Layout
Adjust paths below if your tree differs; keep this section synchronized with actual structure.
- `chronos/` or equivalent: Python core modules (orchestration, crypto adapters, validation)
- `tests/`: Python unit/integration/regression tests
- `chronos-rust/`: Rust prototype components (orchestrator/dashboard/crypto integration path)
- `.github/workflows/`: CI workflows
- `docs/`: supporting technical documentation
- `SECURITY.md`: threat model, assumptions, limitations

## Limitations
- This is not a complete production containment system.
- Some subsystems are prototype-grade or stubs behind production-target interfaces.
- Security claims are limited to what is explicitly implemented and measured.
- External dependencies (host OS, hardware, supply chain, runtime integrity) remain significant risk factors.

## Roadmap (Short)
- Continue hardening invariant checks and failure-path handling.
- Replace/upgrade prototype crypto backends behind stable interfaces.
- Expand reproducible benchmarking and evidence reporting.
- Tighten deployment guidance for controlled evaluation environments.

## Publication
Kumar, S. (2026).
*Project CHRONOS: A Compositional Architecture for Ephemeral FHE Agents with VDF Time-Locking and Attestable Software Erasure.*

- DOI: https://doi.org/10.5281/zenodo.20847864
- SSRN: https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6950898

## Release Notes
For release-specific claim language and artifact scope, use GitHub Releases and keep wording aligned with this README and SECURITY.md.

## License
Proprietary — All Rights Reserved.
No use, copying, modification, or distribution is permitted without explicit written permission from the author.

**Contact:** shashankchoudhary792@gmail.com
