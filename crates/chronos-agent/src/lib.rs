//! CHRONOS agent library surface.
//!
//! Exposed so integration tests can drive the same code the binary runs, rather
//! than a parallel reimplementation.
//!
//! Two modules were removed rather than kept:
//!
//! * `erasure` computed a SHA-256 root over the pre-wipe buffer and checked the
//!   post-wipe bytes with `libc::memcmp`. It was never on the proof path and is
//!   entirely superseded by `chronos_snark::circuit`. Keeping it would imply a
//!   guarantee it does not provide.
//! * `vdf_task` wrapped the VDF in a channel and checked an abort flag *once,
//!   before starting*, which cannot interrupt `T` squarings already underway. It
//!   was never called. `WesolowskiVdf::evaluate_interruptible` replaces it and
//!   polls during the loop.

pub mod config;
pub mod crypto;
pub mod drand_client;
pub mod identity;
pub mod metrics;
pub mod state;
pub mod tls;
