use std::fmt;

/// A newtype wrapper that redacts sensitive values from logs and debug output.
///
/// Any `Display` or `Debug` of a `Redacted<T>` will emit `"[REDACTED]"` rather
/// than the inner value.  This prevents secret keys, VDF outputs, and derived
/// encryption keys from leaking into structured logs or stack traces.
///
/// # Example
/// ```rust
/// use chronos_core::redacted::Redacted;
/// let secret = Redacted::new(vec![0u8; 32]);
/// assert_eq!(format!("{secret}"), "[REDACTED]");
/// ```
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wrap a value so it is never emitted by `Display` or `Debug`.
    #[must_use]
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    /// Obtain a reference to the inner value.
    ///
    /// Callers should only do this in non-logging code paths.
    pub fn inner(&self) -> &T {
        &self.0
    }

    /// Consume the wrapper and return the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redacted").field("inner", &"[REDACTED]").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redacted_display_hides_value() {
        let r = Redacted::new("super_secret_key_material");
        assert_eq!(format!("{r}"), "[REDACTED]");
    }

    #[test]
    fn test_redacted_debug_hides_value() {
        let r = Redacted::new(42_u32);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("42"));
    }

    #[test]
    fn test_redacted_inner_accessible() {
        let r = Redacted::new(vec![1u8, 2, 3]);
        assert_eq!(r.inner(), &[1, 2, 3]);
    }
}
