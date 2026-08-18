/// Groth16 erasure circuit (~700 R1CS constraints, no filler).
pub mod circuit;

/// Groth16 prover, verifier, and Dynark incremental updater.
pub mod prover;

/// EVM encoding for verifying keys and proofs, so erasure attestations can be
/// checked on-chain rather than by a trusted server. See `contracts/`.
pub mod solidity;

/// EAIP identity circuit. Binds the mission ID; the SHA-256 pre-image relation
/// is not yet encoded — see the module docs.
pub mod identity_circuit;
