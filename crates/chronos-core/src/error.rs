use thiserror::Error;

/// Unified error type for the CHRONOS codebase.
/// All library crates return subtypes; the agent binary converts via `anyhow`.
#[derive(Debug, Error)]
pub enum ChronosError {
    /// Wraps I/O failures (file reads, cert loading, checkpoint writes).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// VDF evaluation or verification failed.
    #[error("VDF error: {0}")]
    Vdf(String),

    /// SNARK proof generation or verification failed.
    #[error("SNARK error: {0}")]
    Snark(String),

    /// FHE key generation or evaluation failed.
    #[error("FHE error: {0}")]
    Fhe(String),

    /// GMP FFI call returned an error code or produced invalid output.
    #[error("GMP FFI error: {0}")]
    GmpFfi(String),

    /// MPC certificate is absent or malformed.
    #[error("MPC certificate error: {0}")]
    MpcCert(String),

    /// Drand beacon fetch or signature verification failed.
    #[error("Drand error: {0}")]
    Drand(String),

    /// Agent state machine violation (e.g., double-init).
    #[error("State machine error: {0}")]
    StateMachine(String),

    /// Configuration parse error.
    #[error("Config error: {0}")]
    Config(String),

    /// EA (Exclusivity Assumption) not satisfied – agent refuses to start.
    #[error("Exclusivity Assumption violated: {0}")]
    ExclusivityAssumption(String),

    /// Memory erasure proof failed verification.
    #[error("Erasure error: {0}")]
    Erasure(String),

    /// Multi-party ceremony error (contribution verification, sequencing).
    #[error("Ceremony error: {0}")]
    Ceremony(String),
}

/// Convenience alias for library `Result` types.
pub type ChronosResult<T> = Result<T, ChronosError>;
