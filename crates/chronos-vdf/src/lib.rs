//! Verifiable delay functions for CHRONOS.
//!
//! # Two modules were removed
//!
//! Both were presented as novel contributions and neither functioned as
//! specified. Deleting them is a correction, not a reduction in scope: an
//! unreachable module that claims a property it does not have costs more
//! credibility than an absent feature.
//!
//! **`blind.rs` — "Blind VDF outsourcing, Novel Contribution 1".** The premise was
//! that a client could delegate `T` sequential squarings to an untrusted server.
//! To construct the blinded base the client had to compute `r^(2^T) mod N`, which
//! is `T` sequential squarings — exactly the work being outsourced. Its own module
//! documentation conceded this. The blinding was cryptographically sound; the
//! delegation goal was unmet by construction.
//!
//! **`isogeny.rs` — "Post-quantum isogeny VDF, Novel Contribution 2".** It was a
//! SHA-256 hash chain. `is_post_quantum()` returned `false`, and `verify_isogeny`
//! re-ran the full evaluation, so verification was `O(T)` rather than sublinear.
//! Sublinear verification is definitional for a VDF, so it was not one. It also
//! carried the only consumer of `VdfBackend`, a config enum that nothing read.
//!
//! A genuine post-quantum VDF remains worthwhile and is tracked as future work.
//! The realistic path is a class-group VDF — groups of imaginary quadratic orders
//! have unknown order by construction from a public discriminant, which removes the
//! RSA modulus trust question entirely rather than simulating around it. See
//! [`chiavdf`](https://github.com/Chia-Network/chiavdf) (Apache-2.0).

/// Wesolowski VDF over an RSA group. The only VDF on the mission path.
pub mod wesolowski;

/// Proof of Sequential Work via a SHA-256 hash chain (Cohen, EUROCRYPT 2018).
///
/// Correct and tested, but **not currently on the mission path** — the agent uses
/// [`wesolowski`], which gives sublinear verification that a hash chain cannot.
/// Retained as a standalone primitive because PoSW is a genuinely different
/// trade-off: no trusted setup and no group of unknown order, at the cost of
/// `O(T)` verification. Labelled explicitly so it is not mistaken for part of the
/// protocol.
pub mod posw;
