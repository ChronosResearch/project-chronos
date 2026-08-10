/// Full Groth16 erasure circuit (~180,000 R1CS constraints).
pub mod circuit;

/// Groth16 prover, verifier, and Dynark incremental updater.
pub mod prover;

/// EAIP zero-knowledge identity proof circuit (~10,000 R1CS constraints).
pub mod identity_circuit;
