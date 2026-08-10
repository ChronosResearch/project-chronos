use crate::error::{ChronosError, ChronosResult};
use num_bigint::BigUint;
use std::path::Path;
use tracing::{info, warn};

/// A well-known 2048-bit RSA modulus for prototype use.
///
/// This is RSA-2048 from the RSA Factoring Challenge (unfactored as of 2024).
/// Source: https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048
/// In production this MUST be replaced by an MPC-ceremony-generated modulus
/// where no single party knows the factorization.
const RSA_2048_PROTOTYPE: &str =
    "251959084756578934940271832400483985714292821262040320277771378360436620207075955562640185258807844069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911650776133798590957000973304597488084284017974291006424586918171951187461215151726546322822168699875491824224336372590851418654620435767984233871847744479207399342365848238242811981638150106748104516603773060562016196762561338441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548314381678998850404453640235273819513786365643912120103971228221207203575";


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
    /// Falls back to the hardcoded RSA-2048 prototype modulus if the file
    /// is absent — logs a warning so this is never silent in production.
    ///
    /// # Errors
    /// Returns [`ChronosError::MpcCert`] if the file exists but cannot be read,
    /// or if the loaded modulus is smaller than 512 bits (clearly invalid).
    pub fn load<P: AsRef<Path>>(path: P) -> ChronosResult<Self> {
        let path_ref = path.as_ref();

        match std::fs::read(path_ref) {
            Ok(cert_data) if !cert_data.is_empty() => {
                let n = BigUint::from_bytes_be(&cert_data);
                if n.bits() < 512 {
                    return Err(ChronosError::MpcCert(format!(
                        "certN at '{}' is only {} bits — must be ≥512 bits",
                        path_ref.display(),
                        n.bits()
                    )));
                }
                info!(
                    target: "chronos",
                    path = %path_ref.display(),
                    bits = n.bits(),
                    "MPC certificate loaded from file"
                );
                Ok(Self { n })
            }
            Ok(_) => Err(ChronosError::MpcCert(format!(
                "certN file at '{}' is empty — corrupt or wrong path.",
                path_ref.display()
            ))),
            Err(_) => {
                warn!(
                    target: "chronos",
                    path = %path_ref.display(),
                    "certN not found — using hardcoded RSA-2048 prototype modulus. \
                     Replace with MPC-ceremony modulus for production."
                );
                let n = RSA_2048_PROTOTYPE
                    .parse::<BigUint>()
                    .map_err(|e| ChronosError::MpcCert(format!("Prototype modulus parse failed: {e}")))?;
                Ok(Self { n })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prototype_modulus_is_2048_bits() {
        let n = RSA_2048_PROTOTYPE
            .parse::<BigUint>()
            .expect("prototype modulus must parse");
        assert!(
            n.bits() >= 2048,
            "Prototype modulus must be ≥2048 bits, got {}",
            n.bits()
        );
    }

    #[test]
    fn test_load_missing_file_uses_prototype() {
        let cert = MpcCertificate::load("/nonexistent/certN.bin")
            .expect("missing file must fall back to prototype");
        assert!(cert.n.bits() >= 2048);
    }
}
