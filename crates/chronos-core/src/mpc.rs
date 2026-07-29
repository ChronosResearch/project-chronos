use crate::error::{ChronosError, ChronosResult};
use num_bigint::BigUint;
use std::path::Path;

/// Holds the RSA modulus `N` from a multi-party computation ceremony.
///
/// The VDF engine requires this certificate at startup.  If the file is absent
/// or unreadable the agent must fail hard — there is no safe fallback.
#[derive(Debug)]
pub struct MpcCertificate {
    /// The RSA modulus N used as the VDF group order.
    pub n: BigUint,
}

impl MpcCertificate {
    /// Load the MPC certificate (big-endian encoded `N`) from `path`.
    ///
    /// # Errors
    /// Returns [`ChronosError::MpcCert`] if the file cannot be read or is empty.
    pub fn load<P: AsRef<Path>>(path: P) -> ChronosResult<Self> {
        let path_ref = path.as_ref();
        let cert_data = std::fs::read(path_ref).map_err(|e| {
            ChronosError::MpcCert(format!(
                "Cannot read certN at '{}': {e}. VDF requires an MPC certificate.",
                path_ref.display()
            ))
        })?;

        if cert_data.is_empty() {
            return Err(ChronosError::MpcCert(format!(
                "certN file at '{}' is empty — corrupt or wrong path.",
                path_ref.display()
            )));
        }

        Ok(Self {
            n: BigUint::from_bytes_be(&cert_data),
        })
    }
}
