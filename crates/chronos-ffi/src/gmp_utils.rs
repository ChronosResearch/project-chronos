/// Placeholder for future GMP utility FFI wrappers.
///
/// The actual GMP RAII wrapper (`GmpBigInt`) lives in `chronos-vdf::wesolowski`
/// to avoid circular dependency — it imports `chronos_core::ChronosError`.
/// This module is reserved for any standalone GMP helpers needed by other crates.
pub struct GmpUtilsPlaceholder;
