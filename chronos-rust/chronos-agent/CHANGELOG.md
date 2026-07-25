# Changelog

## [0.1.1](https://github.com/sidthebuilder/project-chronos/compare/chronos-agent-v0.1.0...chronos-agent-v0.1.1) (2026-07-25)


### Features

* add Rust prototype and QA workflow ([089e67c](https://github.com/sidthebuilder/project-chronos/commit/089e67c18564ac6d7fa71ce9718f6fcb00e63847))
* implement decentralized libp2p networking with Gossipsub and Ka… ([34d7287](https://github.com/sidthebuilder/project-chronos/commit/34d7287779827c16184e2b63cbaa2eb4c1520529))
* implement decentralized libp2p networking with Gossipsub and Kademlia ([a3f4f40](https://github.com/sidthebuilder/project-chronos/commit/a3f4f406c2ac2dc7a1656c27bb54772fe2ef96d3))
* ingest massive Telecom Customer Churn dataset for FHE Neural Network evaluation ([ec1c893](https://github.com/sidthebuilder/project-chronos/commit/ec1c89378ba8660c6ba535607be7d9814b0551f8))
* integrate arkworks-rs Groth16 zk-SNARK for mathematically sound Pre-Erasure Commitment ([e33a690](https://github.com/sidthebuilder/project-chronos/commit/e33a690456ed390422d5fe287a4fc57831afeafd))
* integrate arkworks-rs Groth16 zk-SNARK for mathematically sound… ([a4d168f](https://github.com/sidthebuilder/project-chronos/commit/a4d168ff435fa282ed155593f5c3cbd361c01352))
* integrate CPU hardware entropy (Intel RDRAND/RDSEED) directly into the cryptographic seed ([0d69755](https://github.com/sidthebuilder/project-chronos/commit/0d697554d91106cafe9481ccb5642635419e2325))
* replace DummyFhe with PrototypeFhe demonstrating multiplicative homomorphism ([530eef2](https://github.com/sidthebuilder/project-chronos/commit/530eef2ff5cdde43bfc368b399aaece8237ad099))
* upgrade TFHE inference pipeline to stream massive California Ho… ([ccfb5ac](https://github.com/sidthebuilder/project-chronos/commit/ccfb5ac7150278c65079701469a8605029faa392))
* upgrade TFHE inference pipeline to stream massive California Housing real estate dataset ([a97dc96](https://github.com/sidthebuilder/project-chronos/commit/a97dc96aa545ac6297dee722d9f1274ad6876897))
* upgrade TFHE inference to Multi-Layer Perceptron (Matrix-Vector Multiplication) ([4fd16ba](https://github.com/sidthebuilder/project-chronos/commit/4fd16ba64869ed7081829b422eca7f5a3c3d829c))
* upgrade TFHE inference to use Credit Risk financial dataset ([6adce45](https://github.com/sidthebuilder/project-chronos/commit/6adce454ee7369ea7ea8b4aadcfacbbb7bb6af65))
* upgrade to TFHE-rs production inference and integrate Iris dataset ([e68bd5e](https://github.com/sidthebuilder/project-chronos/commit/e68bd5e564fe19f85d001ad6f08497a70f9728fe))


### Bug Fixes

* add missing arkworks and rand dependencies to chronos-agent ([2e3eede](https://github.com/sidthebuilder/project-chronos/commit/2e3eede8d7f78ac62eab3ea8b866ad80f23e2cc5))
* add missing hex dependency to chronos-agent ([bc91614](https://github.com/sidthebuilder/project-chronos/commit/bc9161468fa1444acbab526a69de46ad0c18fc61))
* add missing serde dependency for credit record struct ([ba2ec7a](https://github.com/sidthebuilder/project-chronos/commit/ba2ec7a3c8912cee74e0b3547008624d42147576))
* all 5 audit bugs resolved ([9baf8fc](https://github.com/sidthebuilder/project-chronos/commit/9baf8fc025b435ac5cef927ead254727d8f3a5a1))
* correct import path for Num trait from num-traits ([d853f8e](https://github.com/sidthebuilder/project-chronos/commit/d853f8e89ebb5a7e100e036a06a77d3e0a2af333))
* format code and remove vulnerable legacy kzen dependencies ([bc585fb](https://github.com/sidthebuilder/project-chronos/commit/bc585fbf9ce5cdd76fae3e7373b4f13efb699e0b))
* remove invalid string argument to DrandClient initialization ([00b64dd](https://github.com/sidthebuilder/project-chronos/commit/00b64dd7beef4ec858701b69c1ab007b5ee279a6))
* remove pyo3 from Rust library crates, fix snake_case fields, fix step counters, rewrite posw.rs as pure Rust, clean README ([5a7fcf7](https://github.com/sidthebuilder/project-chronos/commit/5a7fcf7ee1a5dc1214b0528550d445d4f86aafc9))
* resolve keygen method error and unused imports in chronos-agent ([4d2ca81](https://github.com/sidthebuilder/project-chronos/commit/4d2ca8105bfa52156204365db045d072ad4d8053))
* uncomment fhe module and add missing math dependencies to chronos-agent ([2745601](https://github.com/sidthebuilder/project-chronos/commit/274560187249d86830f883fd48d073486c416eaa))
