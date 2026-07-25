# Changelog

## [0.1.1](https://github.com/sidthebuilder/project-chronos/compare/chronos-core-v0.1.0...chronos-core-v0.1.1) (2026-07-25)


### Features

* add Rust prototype and QA workflow ([089e67c](https://github.com/sidthebuilder/project-chronos/commit/089e67c18564ac6d7fa71ce9718f6fcb00e63847))
* implement Aya eBPF kernel anti-tamper probe ([531ea44](https://github.com/sidthebuilder/project-chronos/commit/531ea44f9210d2ef9ac4c10d4f2bb4aef2bd1080))


### Bug Fixes

* all 5 audit bugs resolved ([9baf8fc](https://github.com/sidthebuilder/project-chronos/commit/9baf8fc025b435ac5cef927ead254727d8f3a5a1))
* correct import path for Num trait from num-traits ([d853f8e](https://github.com/sidthebuilder/project-chronos/commit/d853f8e89ebb5a7e100e036a06a77d3e0a2af333))
* ignore mlock sys calls during Miri interpretation ([cb30c17](https://github.com/sidthebuilder/project-chronos/commit/cb30c177238ec4989f8224c83942d422fcc3e641))
* ignore unactionable tracing-subscriber vulnerability in cargo audit ([05be364](https://github.com/sidthebuilder/project-chronos/commit/05be3649ce320cc7cf7c9f1cd4275ba9535b2dc2))
* make gpu feature optional to fix CUDA missing in CI and update aya version ([669cfd4](https://github.com/sidthebuilder/project-chronos/commit/669cfd43643c0f2253100d77b90198aeaed45f59))
* remove pyo3 from Rust library crates, fix snake_case fields, fix step counters, rewrite posw.rs as pure Rust, clean README ([5a7fcf7](https://github.com/sidthebuilder/project-chronos/commit/5a7fcf7ee1a5dc1214b0528550d445d4f86aafc9))
