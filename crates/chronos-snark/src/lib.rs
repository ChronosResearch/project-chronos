/// Groth16 erasure circuit (~700 R1CS constraints, no filler).
pub mod circuit;

/// Groth16 prover, verifier, and Dynark incremental updater.
pub mod prover;

/// EAIP identity circuit. Binds the mission ID; the SHA-256 pre-image relation
/// is not yet encoded — see the module docs.
pub mod identity_circuit;
