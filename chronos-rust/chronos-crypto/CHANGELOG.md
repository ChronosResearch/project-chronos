# Changelog

## [0.1.1](https://github.com/sidthebuilder/project-chronos/compare/chronos-crypto-v0.1.0...chronos-crypto-v0.1.1) (2026-07-25)


### Features

* add Rust prototype and QA workflow ([089e67c](https://github.com/sidthebuilder/project-chronos/commit/089e67c18564ac6d7fa71ce9718f6fcb00e63847))
* align Rust prototype with v2 paper specifications ([6bfc137](https://github.com/sidthebuilder/project-chronos/commit/6bfc13767ba1e5ffa5b49b02bc2f9eab38dae0b9))
* implement TFHE-rs CUDA GPU acceleration feature flag ([c1f48cc](https://github.com/sidthebuilder/project-chronos/commit/c1f48cc3a23da39e33ab8b271976de2c4a46062f))
* implement ZkMlCircuit for proving neural network inferences in zero-knowledge ([879fb08](https://github.com/sidthebuilder/project-chronos/commit/879fb082af7a663eb337b01b3e4c6556e4c8b36e))
* integrate arkworks-rs Groth16 zk-SNARK for mathematically sound Pre-Erasure Commitment ([e33a690](https://github.com/sidthebuilder/project-chronos/commit/e33a690456ed390422d5fe287a4fc57831afeafd))
* integrate arkworks-rs Groth16 zk-SNARK for mathematically sound… ([a4d168f](https://github.com/sidthebuilder/project-chronos/commit/a4d168ff435fa282ed155593f5c3cbd361c01352))
* replace DummyFhe with PrototypeFhe demonstrating multiplicative homomorphism ([530eef2](https://github.com/sidthebuilder/project-chronos/commit/530eef2ff5cdde43bfc368b399aaece8237ad099))
* upgrade TFHE inference to Multi-Layer Perceptron (Matrix-Vector Multiplication) ([4fd16ba](https://github.com/sidthebuilder/project-chronos/commit/4fd16ba64869ed7081829b422eca7f5a3c3d829c))
* upgrade to TFHE-rs production inference and integrate Iris dataset ([e68bd5e](https://github.com/sidthebuilder/project-chronos/commit/e68bd5e564fe19f85d001ad6f08497a70f9728fe))


### Bug Fixes

* all 5 audit bugs resolved ([9baf8fc](https://github.com/sidthebuilder/project-chronos/commit/9baf8fc025b435ac5cef927ead254727d8f3a5a1))
* correct import path for Num trait from num-traits ([d853f8e](https://github.com/sidthebuilder/project-chronos/commit/d853f8e89ebb5a7e100e036a06a77d3e0a2af333))
* correct import path for Num trait from num-traits ([db2b7d8](https://github.com/sidthebuilder/project-chronos/commit/db2b7d80cd1a14b747444883183354d545f22dc5))
* format code and remove vulnerable legacy kzen dependencies ([bc585fb](https://github.com/sidthebuilder/project-chronos/commit/bc585fbf9ce5cdd76fae3e7373b4f13efb699e0b))
* make gpu feature optional to fix CUDA missing in CI and update aya version ([669cfd4](https://github.com/sidthebuilder/project-chronos/commit/669cfd43643c0f2253100d77b90198aeaed45f59))
* make gpu feature optional to fix CUDA missing in CI and update aya version ([41021d9](https://github.com/sidthebuilder/project-chronos/commit/41021d9dc65944ad15c1a88e1f42b76cd948e2e4))
* remove pyo3 from Rust library crates, fix snake_case fields, fix step counters, rewrite posw.rs as pure Rust, clean README ([5a7fcf7](https://github.com/sidthebuilder/project-chronos/commit/5a7fcf7ee1a5dc1214b0528550d445d4f86aafc9))
* resolve ambiguous from_str_radix trait methods and missing rand_core ([b59bcb7](https://github.com/sidthebuilder/project-chronos/commit/b59bcb7ff98c867a7359b790fe7afce5e307b5af))
* resolve curve25519-dalek Scalar compilation errors ([c363dba](https://github.com/sidthebuilder/project-chronos/commit/c363dba149d0958524bbd23dad940e4e5a8e04af))
* resolve E0277 trait errors by bridging num_bigint and kzen_paillier types ([61995b3](https://github.com/sidthebuilder/project-chronos/commit/61995b3c373cafbd8970788ebd9fee892e5976cc))
* resolve kzen-paillier trait import errors ([0c3beaf](https://github.com/sidthebuilder/project-chronos/commit/0c3beaf7bd050d6fc99935b7eb12a29b99733f62))
* resolve missing paillier traits and unused imports ([a2924d4](https://github.com/sidthebuilder/project-chronos/commit/a2924d4197f843a175419029f0628884998771e4))
* restore missing BigUint import in vdf.rs ([88ebf6b](https://github.com/sidthebuilder/project-chronos/commit/88ebf6b655a4844c7cca34894d001ba70126fd90))
* uncomment fhe module and add missing math dependencies to chronos-agent ([2745601](https://github.com/sidthebuilder/project-chronos/commit/274560187249d86830f883fd48d073486c416eaa))
* use Converter trait for hex-based BigInt parsing and restore dependencies ([8a15e74](https://github.com/sidthebuilder/project-chronos/commit/8a15e74dd8638e33d57ac2ae11b57f8787e79e9e))
