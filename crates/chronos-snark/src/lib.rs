/// Poseidon-128 over BN254: the shared algebraic substrate. Every commitment,
/// the KDF, and the AEAD are built from it, and every helper has a native form
/// and an R1CS form that are tested to agree.
pub mod poseidon;

/// Chronos-AEAD: Poseidon-based authenticated encryption, chosen so that
/// decrypting the time-locked key is provable in a few hundred constraints
/// instead of the tens of thousands an AES-GCM gadget would cost.
pub mod aead;

/// Groth16 erasure circuit (~700 R1CS constraints, no filler).
pub mod circuit;

/// Groth16 prover, verifier, and Dynark incremental updater.
pub mod prover;

/// EVM encoding for verifying keys and proofs, so erasure attestations can be
/// checked on-chain rather than by a trusted server. See `contracts/`.
pub mod solidity;

/// EAIP identity circuit: a real zero-knowledge proof of knowledge of the VDF
/// output behind the published, time-locked identity root.
pub mod identity_circuit;

/// The published mission artifact. Carries the commitments a verifier holds and
/// that the agent cannot alter — which is what makes the erasure proof binding.
pub mod mission;
