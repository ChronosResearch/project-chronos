/// FFI boundary types for CHRONOS C interop.
///
/// This crate is a thin, audited FFI boundary layer. All unsafe code in
/// this crate must have a `// SAFETY:` comment.  No raw pointers escape
/// this crate boundary without being wrapped in a safe abstraction.
pub mod gmp_utils;
