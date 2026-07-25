use anyhow::Result;
use rdrand::RdRand;
use reqwest;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize, Debug, Default)]
#[serde(default)]
pub struct DrandBeacon {
    pub round: u64,
    pub randomness: String,
    pub signature: String,
    pub previous_signature: String,
}

pub struct DrandClient {
    base_url: String,
}

impl DrandClient {
    pub fn new() -> Self {
        Self {
            base_url: "https://api.drand.sh".to_string(),
        }
    }

    pub async fn fetch_latest(&self) -> Result<String> {
        // drand quicknet chain (unchained, G1 signatures, G2 pubkey)
        let url = format!(
            "{}/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/latest",
            self.base_url
        );
        let client = reqwest::Client::new();
        let res = client
            .get(&url)
            .header("User-Agent", "project-chronos-rust/0.1.0")
            .send()
            .await?
            .json::<DrandBeacon>()
            .await?;

        println!("[DRAND] Fetched beacon round {}", res.round);

        let random_hex = Self::mix_hardware_entropy(&res.randomness);
        Ok(random_hex)
    }

    /// Mixes the League of Entropy randomness with hardware CPU entropy
    fn mix_hardware_entropy(network_randomness: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(network_randomness.as_bytes());

        // Attempt to read from CPU Hardware RNG (Intel RDRAND)
        let mut hw_entropy = [0u8; 32];
        if let Ok(mut generator) = RdRand::new() {
            if generator.try_fill_bytes(&mut hw_entropy).is_ok() {
                hasher.update(&hw_entropy);
            }
        }

        let mixed_seed = hasher.finalize();
        hex::encode(mixed_seed)
    }
}
