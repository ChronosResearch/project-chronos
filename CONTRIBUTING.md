# Contributing to CHRONOS

We need help scaling CHRONOS. If you are an engineer who wants to work on deterministic AI safety, applied cryptography (FHE/SNARKs), and high-performance Rust, you are in the right place.

**We are thrilled to have you here!** If you want to contribute, please follow these setup steps. If you get stuck or need any help at all, don't hesitate to open an issue or reach out!


## 1. Quickstart (Local Setup)

You need the nightly Rust toolchain. We use `#![feature(portable_simd)]` for crypto acceleration.

```bash
# 1. Clone the repo
git clone https://github.com/sidthebuilder/project-chronos.git
cd project-chronos

# 2. Build the workspace (this will automatically pull the nightly toolchain via rust-toolchain.toml)
cargo build --release

# 3. Run the test suite (must pass before you submit a PR)
cargo test --all-features
```

## 2. Where We Need Help (Good First Issues)

Check the GitHub Issues tab for the `good first issue` label. Right now, our highest priorities are:
* **GPU Acceleration:** Porting the `chronos-core/src/fhe.rs` TFHE multiplication logic from CPU (SIMD) to GPU (CUDA/Metal).
* **MPC Setup Phase:** Building a multi-party computation ceremony implementation for our Groth16 trusted setup.
* **Agent Integration Test:** Writing an e2e test that wraps a live local LLM and verifies the termination threshold.

## 3. Pull Request Standards

If you submit a PR, it must meet these standards or it will be closed:
1. **Tests Pass:** Run `cargo fmt --all --check` and `cargo test --all-features`.
2. **Docs:** Any new cryptographic primitive must include inline comments explaining the math.
3. **Benchmarks:** If you are optimizing something (like the FHE layer), you must include the `cargo bench` output in the PR description proving it is faster.

## Ready?
Fork the repo, pick an issue, and submit a PR. We review daily.
