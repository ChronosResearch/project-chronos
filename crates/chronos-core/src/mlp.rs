/// FHE MLP — signed end-to-end.
///
/// Replaces the byte-reversal stub that `fhe.rs::evaluate_ciphertext` used to
/// return. `FheInt64` throughout, because a dot product with real trained
/// weights goes negative and that is precisely the case ReLU exists to clip;
/// `FheUint64` cannot represent it.
///
/// ReLU is built from encrypted comparison plus select rather than a hand-built
/// lookup table. Programmable bootstrapping still happens — inside `.ge()` and
/// `.select()` — but tfhe-rs owns it. A raw univariate LUT would have to operate
/// on individual `shortint` blocks, which means handling radix decomposition by
/// hand for no gain here.
///
/// # Cost
/// One PBS per hidden unit. PBS is milliseconds, not microseconds like the
/// arithmetic, so hidden-layer width is the dominant term in inference latency.
/// This is the wall the CHRONOS benchmarking milestone is meant to find.
use tfhe::prelude::*;
use tfhe::{FheBool, FheInt64};

use crate::error::{ChronosError, ChronosResult};

/// Compute `sum(inputs[i] * weights[i]) + bias` homomorphically.
///
/// `weights` and `bias` are cleartext — they are the trained model, not a
/// secret. `inputs` are ciphertexts; their plaintext is never observed.
///
/// # Errors
/// Returns [`ChronosError::Fhe`] on length mismatch or empty input.
///
/// # Overflow
/// `FheInt64` wraps like a native `i64`. It does not saturate and does not
/// error. Bound weight magnitude and layer width so intermediate sums stay
/// inside `i64` before running on real trained weights.
pub fn dot_product(
    inputs: &[FheInt64],
    weights: &[i64],
    bias: i64,
) -> ChronosResult<FheInt64> {
    if inputs.len() != weights.len() {
        return Err(ChronosError::Fhe(format!(
            "dot_product: inputs.len()={} != weights.len()={}",
            inputs.len(),
            weights.len()
        )));
    }
    if inputs.is_empty() {
        return Err(ChronosError::Fhe(
            "dot_product: inputs must be non-empty".into(),
        ));
    }

    let mut terms = inputs.iter().zip(weights.iter());

    // Seed with the first term rather than an encrypted zero: there is no
    // encrypted zero available without an active key context, and synthesising
    // one would just be a slower route to the same ciphertext.
    let (first_ct, first_w) = terms.next().expect("checked non-empty above");
    let mut acc = first_ct.clone() * *first_w;

    for (ct, w) in terms {
        // Ciphertext-by-cleartext scalar multiplication, then ciphertext addition.
        acc = acc + (ct.clone() * *w);
    }

    // Cleartext bias add — no PBS.
    Ok(acc + bias)
}

/// ReLU: `max(x, 0)` over an encrypted signed integer.
///
/// PBS occurs inside `.ge()` and `.select()`.
pub fn relu(x: &FheInt64) -> FheInt64 {
    let zero = FheInt64::encrypt_trivial(0i64);
    let is_positive: FheBool = x.ge(&zero);
    is_positive.select(x, &zero)
}

/// Cleartext weights for a two-layer MLP.
///
/// Model configuration, not secret material — analogous to a SNARK verifying
/// key. FHE protects the *inputs*, not the model.
#[derive(Clone, Debug)]
pub struct MlpWeights {
    /// `hidden_weights[j]` is the weight vector for hidden unit `j`.
    pub hidden_weights: Vec<Vec<i64>>,
    /// `hidden_bias[j]` is the bias for hidden unit `j`.
    pub hidden_bias: Vec<i64>,
    /// Weights combining hidden activations into the single output.
    pub output_weights: Vec<i64>,
    pub output_bias: i64,
}

impl MlpWeights {
    /// Validate shapes so a malformed model fails at load time, not mid-inference.
    ///
    /// # Errors
    /// Returns [`ChronosError::Fhe`] describing the first shape mismatch found.
    pub fn validate(&self, input_dim: usize) -> ChronosResult<()> {
        if self.hidden_weights.is_empty() {
            return Err(ChronosError::Fhe(
                "MlpWeights: no hidden units defined".into(),
            ));
        }
        if self.hidden_weights.len() != self.hidden_bias.len() {
            return Err(ChronosError::Fhe(format!(
                "MlpWeights: {} hidden units but {} biases",
                self.hidden_weights.len(),
                self.hidden_bias.len()
            )));
        }
        if self.hidden_weights.len() != self.output_weights.len() {
            return Err(ChronosError::Fhe(format!(
                "MlpWeights: {} hidden units but output_weights has {}",
                self.hidden_weights.len(),
                self.output_weights.len()
            )));
        }
        for (j, hw) in self.hidden_weights.iter().enumerate() {
            if hw.len() != input_dim {
                return Err(ChronosError::Fhe(format!(
                    "MlpWeights: hidden unit {j} expects {input_dim} inputs, has {}",
                    hw.len()
                )));
            }
        }
        Ok(())
    }

    /// Number of hidden units, i.e. the number of PBS calls per inference.
    #[must_use]
    pub fn hidden_width(&self) -> usize {
        self.hidden_weights.len()
    }
}

/// Two-layer MLP: `input -> [dot + bias -> ReLU] × hidden -> dot + bias -> output`.
pub struct TwoLayerMlp {
    weights: MlpWeights,
}

impl TwoLayerMlp {
    #[must_use]
    pub fn new(weights: MlpWeights) -> Self {
        Self { weights }
    }

    /// Evaluate the network over encrypted inputs.
    ///
    /// # Errors
    /// Returns [`ChronosError::Fhe`] if the weights do not match `inputs.len()`.
    pub fn evaluate(&self, inputs: &[FheInt64]) -> ChronosResult<FheInt64> {
        self.weights.validate(inputs.len())?;

        let hidden: Vec<FheInt64> = self
            .weights
            .hidden_weights
            .iter()
            .zip(self.weights.hidden_bias.iter())
            .map(|(hw, &hb)| {
                let z = dot_product(inputs, hw, hb)?;
                Ok(relu(&z))
            })
            .collect::<ChronosResult<Vec<_>>>()?;

        dot_product(
            &hidden,
            &self.weights.output_weights,
            self.weights.output_bias,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::{generate_keys, set_server_key, ConfigBuilder};

    fn toy_weights() -> MlpWeights {
        // 2 inputs -> 2 hidden units (ReLU) -> 1 output.
        MlpWeights {
            hidden_weights: vec![vec![1, -1], vec![-1, 1]],
            hidden_bias: vec![0, 0],
            output_weights: vec![2, 3],
            output_bias: 1,
        }
    }

    #[test]
    fn test_two_layer_mlp_matches_plaintext_reference() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        set_server_key(server_key);

        let mlp = TwoLayerMlp::new(toy_weights());

        let inputs_plain: [i64; 2] = [5, 3];
        let inputs: Vec<FheInt64> = inputs_plain
            .iter()
            .map(|v| FheInt64::encrypt(*v, &client_key))
            .collect();

        let result_ct = mlp.evaluate(&inputs).expect("evaluate must succeed");
        let result: i64 = result_ct.decrypt(&client_key);

        // Reference computed independently of the FHE path.
        let h0 = (5 * 1 + 3 * -1).max(0); // 2
        let h1 = (5 * -1 + 3 * 1).max(0); // 0
        let expected = h0 * 2 + h1 * 3 + 1; // 5

        assert_eq!(result, expected);
    }

    /// ReLU must actually clip, not pass through. If `relu` ever degrades to
    /// identity this fails.
    #[test]
    fn test_relu_clips_negative() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        set_server_key(server_key);

        let neg = FheInt64::encrypt(-42i64, &client_key);
        let clipped: i64 = relu(&neg).decrypt(&client_key);
        assert_eq!(clipped, 0, "ReLU must clip negative input to zero");

        let pos = FheInt64::encrypt(42i64, &client_key);
        let passed: i64 = relu(&pos).decrypt(&client_key);
        assert_eq!(passed, 42, "ReLU must pass positive input unchanged");
    }

    /// A hidden unit whose pre-activation is negative must contribute zero —
    /// this is the case that distinguishes a real ReLU from a no-op.
    #[test]
    fn test_negative_preactivation_contributes_zero() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        set_server_key(server_key);

        // Single hidden unit, forced strongly negative.
        let weights = MlpWeights {
            hidden_weights: vec![vec![-10]],
            hidden_bias: vec![-5],
            output_weights: vec![7],
            output_bias: 0,
        };
        let mlp = TwoLayerMlp::new(weights);

        let inputs = vec![FheInt64::encrypt(3i64, &client_key)];
        let result: i64 = mlp
            .evaluate(&inputs)
            .expect("evaluate must succeed")
            .decrypt(&client_key);

        // pre-activation = 3*-10 + -5 = -35 -> ReLU -> 0 -> 0*7 + 0 = 0
        assert_eq!(result, 0);
    }

    #[test]
    fn test_rejects_length_mismatch() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        set_server_key(server_key);

        let inputs = vec![FheInt64::encrypt(1i64, &client_key)];
        let result = dot_product(&inputs, &[1i64, 2i64], 0);
        assert!(matches!(result, Err(ChronosError::Fhe(_))));
    }

    #[test]
    fn test_rejects_empty_input() {
        let inputs: Vec<FheInt64> = vec![];
        let result = dot_product(&inputs, &[], 0);
        assert!(matches!(result, Err(ChronosError::Fhe(_))));
    }

    #[test]
    fn test_weights_validate_catches_shape_errors() {
        let mut w = toy_weights();
        assert!(w.validate(2).is_ok());
        assert!(w.validate(3).is_err(), "wrong input_dim must be rejected");

        w.hidden_bias.pop();
        assert!(w.validate(2).is_err(), "bias/unit count mismatch must be rejected");
    }
}
