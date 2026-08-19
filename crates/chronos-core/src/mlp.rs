//! FHE multi-layer perceptron over encrypted signed integers.
//!
//! `FheInt64` throughout, because a dot product with real trained weights goes
//! negative and that is precisely the case ReLU exists to clip; `FheUint64`
//! cannot represent it.
//!
//! # Where the cost is
//!
//! Two operations dominate, and they scale differently:
//!
//! | Operation | Cost | Scales with |
//! |---|---|---|
//! | ciphertext × cleartext scalar | cheap, no bootstrap | `input_dim × hidden_width` |
//! | ReLU (`.ge()` then `.select()`) | **one PBS**, milliseconds | `hidden_width` |
//!
//! Weights are cleartext, so every multiplication is ciphertext-by-scalar rather
//! than ciphertext-by-ciphertext. That distinction is worth stating plainly: the
//! latter costs orders of magnitude more, and a network built that way is not
//! viable at any interesting width. FHE here protects the *inputs*, not the model
//! — the model is public, like a SNARK verifying key.
//!
//! Programmable bootstrapping still happens inside `.ge()` and `.select()`, but
//! `tfhe-rs` owns it. A hand-built univariate LUT would have to operate on
//! individual `shortint` blocks, which means handling radix decomposition
//! manually for no gain.
//!
//! # Parallelism
//!
//! Hidden units are mutually independent, as are output units given the hidden
//! layer, so both layers are evaluated with `rayon`. This is close to linear
//! speedup because PBS is compute-bound and does not contend on shared state.
//!
//! `tfhe-rs` keeps the server key in thread-local storage, so **every rayon
//! worker must have it installed** or evaluation panics on the first operation
//! off the main thread. [`crate::fhe::FheEngine::generate_and_install_keys`]
//! broadcasts it across the pool for exactly this reason. If you drive this
//! module directly, call [`install_server_key_on_rayon_threads`] first.
//!
//! # Overflow
//!
//! `FheInt64` wraps like a native `i64`. It does not saturate and it does not
//! error, so an overflowing intermediate sum silently returns the wrong answer
//! with no indication. [`MlpWeights::max_intermediate_magnitude`] computes the
//! worst case statically and [`MlpWeights::validate`] rejects any model that
//! could overflow for a declared input bound. Check the model once at load time
//! rather than discovering this from a wrong classification.

use rayon::prelude::*;
use tfhe::prelude::*;
use tfhe::{FheBool, FheInt64, ServerKey};

use crate::error::{ChronosError, ChronosResult};

/// Install `server_key` into the thread-local storage of every rayon worker.
///
/// `tfhe-rs` stores the server key per-thread. Without this, any operation
/// dispatched to a rayon worker panics with "server key not set", and the panic
/// surfaces from inside a parallel iterator where it is awkward to attribute.
///
/// Idempotent and cheap enough to call after each key installation.
pub fn install_server_key_on_rayon_threads(server_key: &ServerKey) {
    let key = server_key.clone();
    rayon::broadcast(|_| tfhe::set_server_key(key.clone()));
}

/// Compute `sum(inputs[i] * weights[i]) + bias` homomorphically.
///
/// `weights` and `bias` are cleartext. `inputs` are ciphertexts; their plaintext
/// is never observed.
///
/// # Errors
/// Returns [`ChronosError::Fhe`] on length mismatch or empty input.
pub fn dot_product(inputs: &[FheInt64], weights: &[i64], bias: i64) -> ChronosResult<FheInt64> {
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
    // one is a slower route to the same ciphertext.
    let (first_ct, first_w) = terms.next().expect("checked non-empty above");
    let mut acc = first_ct.clone() * *first_w;

    for (ct, w) in terms {
        acc = acc + (ct.clone() * *w);
    }

    Ok(acc + bias)
}

/// ReLU: `max(x, 0)` over an encrypted signed integer. One PBS.
pub fn relu(x: &FheInt64) -> FheInt64 {
    let zero = FheInt64::encrypt_trivial(0i64);
    let is_positive: FheBool = x.ge(&zero);
    is_positive.select(x, &zero)
}

/// Cleartext weights for a two-layer MLP with any number of outputs.
///
/// Model configuration, not secret material.
#[derive(Clone, Debug)]
pub struct MlpWeights {
    /// `hidden_weights[j]` is the weight vector for hidden unit `j`.
    pub hidden_weights: Vec<Vec<i64>>,
    /// `hidden_bias[j]` is the bias for hidden unit `j`.
    pub hidden_bias: Vec<i64>,
    /// `output_weights[k]` combines hidden activations into output `k`.
    ///
    /// One row per output class, so a classifier returns a logit vector rather
    /// than a single value.
    pub output_weights: Vec<Vec<i64>>,
    /// `output_bias[k]` is the bias for output `k`.
    pub output_bias: Vec<i64>,
}

impl MlpWeights {
    /// Number of hidden units — i.e. the number of PBS calls per inference.
    #[must_use]
    pub fn hidden_width(&self) -> usize {
        self.hidden_weights.len()
    }

    /// Number of output units.
    #[must_use]
    pub fn output_width(&self) -> usize {
        self.output_weights.len()
    }

    /// Input dimension the model expects.
    #[must_use]
    pub fn input_dim(&self) -> usize {
        self.hidden_weights.first().map_or(0, Vec::len)
    }

    /// Worst-case magnitude of any intermediate value, given `|input| <= input_abs_max`.
    ///
    /// Computed in `i128` so the check itself cannot overflow. Returns `None` if
    /// the bound exceeds `i64::MAX`, meaning the model can wrap and must not be
    /// used at this input range.
    ///
    /// The bound is deliberately loose — it assumes every term attains its
    /// maximum with the same sign, which real inputs will not do. A model that
    /// passes is safe; a model that fails might still be fine in practice, but
    /// not provably, and silent wraparound is not a failure mode worth accepting
    /// for a marginal increase in usable weight range.
    #[must_use]
    pub fn max_intermediate_magnitude(&self, input_abs_max: i64) -> Option<i128> {
        let input_max = i128::from(input_abs_max).abs();

        // Hidden layer: worst case over all units.
        let mut hidden_max: i128 = 0;
        for (weights, bias) in self.hidden_weights.iter().zip(self.hidden_bias.iter()) {
            let mut acc: i128 = i128::from(*bias).abs();
            for w in weights {
                acc = acc.checked_add(i128::from(*w).abs().checked_mul(input_max)?)?;
            }
            hidden_max = hidden_max.max(acc);
        }

        // Output layer takes post-ReLU activations, which are in [0, hidden_max].
        let mut output_max: i128 = 0;
        for (weights, bias) in self.output_weights.iter().zip(self.output_bias.iter()) {
            let mut acc: i128 = i128::from(*bias).abs();
            for w in weights {
                acc = acc.checked_add(i128::from(*w).abs().checked_mul(hidden_max)?)?;
            }
            output_max = output_max.max(acc);
        }

        let worst = hidden_max.max(output_max);
        if worst > i128::from(i64::MAX) {
            None
        } else {
            Some(worst)
        }
    }

    /// Validate shapes, and reject models that could overflow `i64`.
    ///
    /// `input_abs_max` is the largest absolute input value the caller will
    /// supply. Pass a real bound: quantised 8-bit activations are typically 127,
    /// and pixel intensities 255.
    ///
    /// # Errors
    /// Returns [`ChronosError::Fhe`] describing the first problem found.
    pub fn validate(&self, input_dim: usize, input_abs_max: i64) -> ChronosResult<()> {
        if self.hidden_weights.is_empty() {
            return Err(ChronosError::Fhe("MlpWeights: no hidden units defined".into()));
        }
        if self.output_weights.is_empty() {
            return Err(ChronosError::Fhe("MlpWeights: no output units defined".into()));
        }
        if self.hidden_weights.len() != self.hidden_bias.len() {
            return Err(ChronosError::Fhe(format!(
                "MlpWeights: {} hidden units but {} biases",
                self.hidden_weights.len(),
                self.hidden_bias.len()
            )));
        }
        if self.output_weights.len() != self.output_bias.len() {
            return Err(ChronosError::Fhe(format!(
                "MlpWeights: {} output units but {} biases",
                self.output_weights.len(),
                self.output_bias.len()
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
        for (k, ow) in self.output_weights.iter().enumerate() {
            if ow.len() != self.hidden_weights.len() {
                return Err(ChronosError::Fhe(format!(
                    "MlpWeights: output unit {k} expects {} hidden activations, has {}",
                    self.hidden_weights.len(),
                    ow.len()
                )));
            }
        }

        if self.max_intermediate_magnitude(input_abs_max).is_none() {
            return Err(ChronosError::Fhe(format!(
                "MlpWeights: intermediate sums can exceed i64::MAX for |input| <= {input_abs_max}. \
                 FheInt64 wraps silently rather than erroring, so this model would return wrong \
                 results with no indication. Reduce weight magnitude, narrow the input range, or \
                 reduce layer width."
            )));
        }

        Ok(())
    }

    /// A deterministic pseudo-random quantised model, for benchmarking.
    ///
    /// Weights land in `[-w_abs_max, w_abs_max]` from a fixed-seed LCG, so
    /// benchmark runs are reproducible. This is *not* a trained model and makes
    /// no accuracy claim — it exists to measure latency at a realistic shape,
    /// which depends on dimensions rather than on weight values.
    #[must_use]
    pub fn pseudorandom_quantized(
        input_dim: usize,
        hidden_width: usize,
        output_width: usize,
        w_abs_max: i64,
        seed: u64,
    ) -> Self {
        // SplitMix64. An earlier version seeded an LCG with `seed | 1`, which
        // collapses every even seed onto its odd successor — seeds 42 and 43 both
        // became 43 and produced byte-identical models. SplitMix64 accepts any
        // seed including zero, needs no such guard, and gives distinct streams for
        // distinct seeds.
        let mut state = seed;
        let mut next = move || -> i64 {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let span = 2 * w_abs_max + 1;
            ((z >> 1) as i64).rem_euclid(span) - w_abs_max
        };

        let hidden_weights = (0..hidden_width)
            .map(|_| (0..input_dim).map(|_| next()).collect())
            .collect();
        let hidden_bias = (0..hidden_width).map(|_| next()).collect();
        let output_weights = (0..output_width)
            .map(|_| (0..hidden_width).map(|_| next()).collect())
            .collect();
        let output_bias = (0..output_width).map(|_| next()).collect();

        Self {
            hidden_weights,
            hidden_bias,
            output_weights,
            output_bias,
        }
    }
}

/// Two-layer MLP: `input -> [dot + bias -> ReLU] × hidden -> [dot + bias] × outputs`.
pub struct TwoLayerMlp {
    weights: MlpWeights,
}

impl TwoLayerMlp {
    #[must_use]
    pub fn new(weights: MlpWeights) -> Self {
        Self { weights }
    }

    /// Borrow the model.
    #[must_use]
    pub fn weights(&self) -> &MlpWeights {
        &self.weights
    }

    /// Evaluate over encrypted inputs, returning one ciphertext per output unit.
    ///
    /// For a classifier these are logits. **Argmax is deliberately left to the
    /// client**, which decrypts and compares in the clear: an encrypted argmax
    /// over `k` classes costs `k-1` further comparisons, each a PBS, to reveal
    /// something the client learns anyway on decryption.
    ///
    /// # Errors
    /// Returns [`ChronosError::Fhe`] if the model does not match `inputs.len()`,
    /// or if it could overflow at `input_abs_max`.
    ///
    /// # Panics
    /// Panics if the server key is not installed on the rayon worker threads —
    /// see [`install_server_key_on_rayon_threads`].
    pub fn evaluate(
        &self,
        inputs: &[FheInt64],
        input_abs_max: i64,
    ) -> ChronosResult<Vec<FheInt64>> {
        self.weights.validate(inputs.len(), input_abs_max)?;

        // Hidden layer: independent per unit, one PBS each. This is the dominant
        // term in latency, so it is the layer worth parallelising.
        let hidden: Vec<FheInt64> = self
            .weights
            .hidden_weights
            .par_iter()
            .zip(self.weights.hidden_bias.par_iter())
            .map(|(hw, &hb)| dot_product(inputs, hw, hb).map(|z| relu(&z)))
            .collect::<ChronosResult<Vec<_>>>()?;

        // Output layer: no activation, so no PBS. Still parallel because each
        // output is an independent dot product over the full hidden layer.
        self.weights
            .output_weights
            .par_iter()
            .zip(self.weights.output_bias.par_iter())
            .map(|(ow, &ob)| dot_product(&hidden, ow, ob))
            .collect()
    }

    /// Plaintext reference implementation.
    ///
    /// Exists so tests can check the encrypted path against an independent
    /// computation rather than against itself. Uses `i128` internally so a
    /// reference value is never itself the thing that wrapped.
    ///
    /// # Errors
    /// Returns [`ChronosError::Fhe`] on shape mismatch.
    pub fn evaluate_plaintext(&self, inputs: &[i64]) -> ChronosResult<Vec<i64>> {
        if inputs.len() != self.weights.input_dim() {
            return Err(ChronosError::Fhe(format!(
                "evaluate_plaintext: expected {} inputs, got {}",
                self.weights.input_dim(),
                inputs.len()
            )));
        }

        let hidden: Vec<i128> = self
            .weights
            .hidden_weights
            .iter()
            .zip(self.weights.hidden_bias.iter())
            .map(|(hw, &hb)| {
                let sum: i128 = hw
                    .iter()
                    .zip(inputs.iter())
                    .map(|(w, x)| i128::from(*w) * i128::from(*x))
                    .sum::<i128>()
                    + i128::from(hb);
                sum.max(0)
            })
            .collect();

        Ok(self
            .weights
            .output_weights
            .iter()
            .zip(self.weights.output_bias.iter())
            .map(|(ow, &ob)| {
                let sum: i128 = ow
                    .iter()
                    .zip(hidden.iter())
                    .map(|(w, h)| i128::from(*w) * h)
                    .sum::<i128>()
                    + i128::from(ob);
                sum as i64
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::{generate_keys, set_server_key, ConfigBuilder};

    /// 2 inputs -> 2 hidden -> 1 output.
    fn toy_weights() -> MlpWeights {
        MlpWeights {
            hidden_weights: vec![vec![1, -1], vec![-1, 1]],
            hidden_bias: vec![0, 0],
            output_weights: vec![vec![2, 3]],
            output_bias: vec![1],
        }
    }

    /// One key pair shared by every test in this module.
    ///
    /// # Why this must be shared
    ///
    /// `tfhe-rs` holds the server key in thread-local storage, and rayon's pool is
    /// process-global. Generating a fresh key per test meant each test broadcast
    /// *its own* server key across the same shared pool, so a test's parallel
    /// evaluation could land on a worker still holding a different test's key.
    /// Decryption then returned noise — the observed symptom was
    /// `[5368744488275843309, -3304781710212550179, ...]` where `[4, 109, 6]` was
    /// expected, which reads like a homomorphic arithmetic bug and is not one.
    ///
    /// Because `cargo test` runs tests on multiple threads, this race was
    /// scheduling-dependent: the same code passed or failed run to run. Sharing a
    /// single key makes the broadcast idempotent and the pool consistent, and has
    /// the side benefit that key generation is paid once rather than per test.
    fn shared_keys() -> &'static (tfhe::ClientKey, tfhe::ServerKey) {
        use std::sync::OnceLock;
        static KEYS: OnceLock<(tfhe::ClientKey, tfhe::ServerKey)> = OnceLock::new();
        KEYS.get_or_init(|| {
            let config = ConfigBuilder::default().build();
            let (client_key, server_key) = generate_keys(config);
            install_server_key_on_rayon_threads(&server_key);
            (client_key, server_key)
        })
    }

    /// Install the shared server key on the calling test thread and return the
    /// client key.
    ///
    /// The rayon workers are handled once in [`shared_keys`]; this covers the test
    /// thread itself, which needs the key for any operation performed outside a
    /// parallel iterator — `relu` called directly, for instance.
    ///
    /// Returns an owned clone rather than a `&'static` reference so call sites can
    /// keep writing `encrypt(v, &client_key)`. `FheTryEncrypt` is implemented for
    /// `&ClientKey`, so handing back a reference makes every call site pass
    /// `&&ClientKey` and fail to resolve the trait. Cloning the client key is far
    /// cheaper than generating one, which is the cost this shared setup removes.
    fn setup_keys() -> tfhe::ClientKey {
        let (client_key, server_key) = shared_keys();
        set_server_key(server_key.clone());
        client_key.clone()
    }

    // Tests calling `generate_keys` are skipped under Miri: the `x86_64` tfhe
    // feature supplies an RDSEED-backed seeder, and Miri does not emulate
    // `rdseed`, so seeder construction panics before any test logic runs. Miri is
    // here for the `unsafe` code in LockedBytes and secure_wipe; nothing in this
    // module contains `unsafe`.

    #[test]
    #[cfg_attr(miri, ignore = "tfhe seeder needs rdseed, which Miri cannot emulate")]
    fn test_matches_plaintext_reference() {
        let client_key = setup_keys();
        let mlp = TwoLayerMlp::new(toy_weights());

        let plain: [i64; 2] = [5, 3];
        let inputs: Vec<FheInt64> = plain
            .iter()
            .map(|v| FheInt64::encrypt(*v, &client_key))
            .collect();

        let out = mlp.evaluate(&inputs, 8).expect("evaluate must succeed");
        assert_eq!(out.len(), 1);
        let got: i64 = out[0].decrypt(&client_key);

        // Independent reference: h0 = max(5-3,0) = 2, h1 = max(-5+3,0) = 0,
        // output = 2*2 + 0*3 + 1 = 5.
        assert_eq!(got, 5);
        assert_eq!(mlp.evaluate_plaintext(&plain).expect("reference"), vec![5]);
    }

    /// Multi-output is the shape a classifier needs. Each output must be an
    /// independent dot product, not a copy of the first.
    #[test]
    #[cfg_attr(miri, ignore = "tfhe seeder needs rdseed, which Miri cannot emulate")]
    fn test_multi_output_heads_are_independent() {
        let client_key = setup_keys();

        let weights = MlpWeights {
            hidden_weights: vec![vec![1, 0], vec![0, 1]],
            hidden_bias: vec![0, 0],
            // Three distinct heads over the same hidden layer.
            output_weights: vec![vec![1, 0], vec![0, 1], vec![1, 1]],
            output_bias: vec![0, 100, -7],
        };
        let mlp = TwoLayerMlp::new(weights);

        let plain: [i64; 2] = [4, 9];
        let inputs: Vec<FheInt64> = plain
            .iter()
            .map(|v| FheInt64::encrypt(*v, &client_key))
            .collect();

        let out = mlp.evaluate(&inputs, 16).expect("evaluate");
        let got: Vec<i64> = out.iter().map(|c| c.decrypt(&client_key)).collect();

        // h = [4, 9]; heads: 4, 9+100, 4+9-7.
        assert_eq!(got, vec![4, 109, 6]);
        assert_eq!(got, mlp.evaluate_plaintext(&plain).expect("reference"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "tfhe seeder needs rdseed, which Miri cannot emulate")]
    fn test_relu_clips_negative() {
        let client_key = setup_keys();

        let neg = FheInt64::encrypt(-42i64, &client_key);
        let clipped: i64 = relu(&neg).decrypt(&client_key);
        assert_eq!(clipped, 0, "ReLU must clip negative input to zero");

        let pos = FheInt64::encrypt(42i64, &client_key);
        let passed: i64 = relu(&pos).decrypt(&client_key);
        assert_eq!(passed, 42, "ReLU must pass positive input unchanged");
    }

    /// The case distinguishing a real ReLU from a no-op.
    #[test]
    #[cfg_attr(miri, ignore = "tfhe seeder needs rdseed, which Miri cannot emulate")]
    fn test_negative_preactivation_contributes_zero() {
        let client_key = setup_keys();

        let mlp = TwoLayerMlp::new(MlpWeights {
            hidden_weights: vec![vec![-10]],
            hidden_bias: vec![-5],
            output_weights: vec![vec![7]],
            output_bias: vec![0],
        });

        let inputs = vec![FheInt64::encrypt(3i64, &client_key)];
        let out = mlp.evaluate(&inputs, 8).expect("evaluate");
        let got: i64 = out[0].decrypt(&client_key);

        // 3*-10 + -5 = -35 -> ReLU -> 0 -> 0*7 + 0 = 0
        assert_eq!(got, 0);
    }

    /// Latency across increasing network shapes, with correctness checked at each.
    ///
    /// # Why a series rather than one large shape
    ///
    /// A single 64-16-10 measurement takes long enough to be impractical to sit
    /// through, and reporting one number says nothing about *why* it costs what it
    /// does. A series gives the per-multiplication cost directly, which is the
    /// figure that transfers to other shapes and other hardware.
    ///
    /// The dominant term is **not** bootstrapping. It is the `input_dim x hidden`
    /// scalar multiplications: each one operates on a 32-block radix integer with
    /// carry propagation across blocks, and there are two orders of magnitude more
    /// of them than there are PBS calls.
    ///
    /// Every shape is verified against the plaintext reference, so a fast wrong
    /// answer fails rather than flattering the benchmark.
    ///
    /// ```text
    /// cargo test -p chronos-core --release -- --ignored mlp_scaling_series --nocapture
    /// ```
    #[test]
    #[ignore = "minutes; run with --ignored --release --nocapture"]
    #[cfg_attr(miri, ignore = "tfhe seeder needs rdseed, which Miri cannot emulate")]
    fn test_mlp_scaling_series() {
        use std::time::{Duration, Instant};

        const INPUT_ABS_MAX: i64 = 255;
        // Stop starting new shapes once the cumulative budget is spent, so the
        // test always terminates and always reports what it did measure.
        const BUDGET: Duration = Duration::from_secs(600);

        let keygen = Instant::now();
        let client_key = setup_keys();
        println!("\nkey generation : {:?}", keygen.elapsed());
        println!("threads        : {}", rayon::current_num_threads());

        println!(
            "\n{:>5} {:>7} {:>8} {:>9} {:>6} {:>12} {:>11}",
            "in", "hidden", "classes", "mults", "PBS", "inference", "per mult"
        );
        println!("{}", "-".repeat(68));

        let shapes: [(usize, usize, usize); 4] =
            [(8, 4, 2), (16, 8, 10), (32, 8, 10), (64, 16, 10)];

        let started = Instant::now();
        let mut completed = 0usize;

        for (input_dim, hidden, classes) in shapes {
            if started.elapsed() > BUDGET {
                println!("\n(budget exhausted after {completed} shapes; remaining skipped)");
                break;
            }

            let weights =
                MlpWeights::pseudorandom_quantized(input_dim, hidden, classes, 8, 0xC0FFEE);
            weights
                .validate(input_dim, INPUT_ABS_MAX)
                .expect("model must be overflow-safe");

            let mlp = TwoLayerMlp::new(weights);
            let plain: Vec<i64> = (0..input_dim).map(|i| ((i * 37) % 256) as i64).collect();

            let inputs: Vec<FheInt64> = plain
                .iter()
                .map(|v| FheInt64::encrypt(*v, &client_key))
                .collect();

            let infer = Instant::now();
            let out = mlp.evaluate(&inputs, INPUT_ABS_MAX).expect("evaluate");
            let elapsed = infer.elapsed();

            let got: Vec<i64> = out.iter().map(|c| c.decrypt(&client_key)).collect();
            let expected = mlp.evaluate_plaintext(&plain).expect("reference");

            let mults = input_dim * hidden + hidden * classes;
            println!(
                "{input_dim:>5} {hidden:>7} {classes:>8} {mults:>9} {hidden:>6} {:>12} {:>11}",
                format!("{:.2}s", elapsed.as_secs_f64()),
                format!("{:.1}ms", elapsed.as_secs_f64() * 1000.0 / mults as f64),
            );

            assert_eq!(
                got, expected,
                "shape {input_dim}->{hidden}->{classes}: encrypted output must match the \
                 plaintext reference exactly"
            );

            // Argmax is the client's job, and it is the answer a classifier
            // actually returns, so check it agrees too.
            let arg = |v: &[i64]| {
                v.iter()
                    .enumerate()
                    .max_by_key(|(_, x)| **x)
                    .map(|(i, _)| i)
                    .expect("non-empty")
            };
            assert_eq!(
                arg(&got),
                arg(&expected),
                "shape {input_dim}->{hidden}->{classes}: predicted class must match"
            );

            completed += 1;
        }

        assert!(
            completed > 0,
            "no shape completed - the series measured nothing"
        );
        println!("\nverified {completed} shapes against the plaintext reference");
        println!(
            "note: `FheInt64` carries 64 bits where the worst-case magnitude needs ~23,\n\
             so a narrower ciphertext type is the obvious next optimisation."
        );
    }

    // ── Overflow guard ──────────────────────────────────────────────────────

    #[test]
    fn test_overflow_bound_is_computed_not_guessed() {
        // 2 inputs, weights ±3, bias 1, |input| <= 10 -> hidden <= 3*10+3*10+1 = 61.
        let w = MlpWeights {
            hidden_weights: vec![vec![3, -3]],
            hidden_bias: vec![1],
            output_weights: vec![vec![2]],
            output_bias: vec![5],
        };
        // Output: 2*61 + 5 = 127. Worst case overall is 127.
        assert_eq!(w.max_intermediate_magnitude(10), Some(127));
    }

    /// The gap this closes: `FheInt64` wraps silently, so a model that can
    /// overflow must be refused at load time rather than returning wrong answers.
    #[test]
    fn test_overflowing_model_is_rejected() {
        let w = MlpWeights {
            hidden_weights: vec![vec![i64::MAX / 2, i64::MAX / 2]],
            hidden_bias: vec![0],
            output_weights: vec![vec![1]],
            output_bias: vec![0],
        };
        assert_eq!(w.max_intermediate_magnitude(1000), None);

        let err = w.validate(2, 1000).expect_err("must be rejected");
        assert!(
            format!("{err}").contains("exceed i64::MAX"),
            "error should name the overflow risk, got: {err}"
        );
    }

    /// A wide layer with modest weights must still be caught if it overflows.
    #[test]
    fn test_width_contributes_to_overflow() {
        let wide = MlpWeights {
            hidden_weights: vec![vec![i64::MAX / 4096; 4096]],
            hidden_bias: vec![0],
            output_weights: vec![vec![1]],
            output_bias: vec![0],
        };
        assert!(
            wide.validate(4096, 127).is_err(),
            "width times weight magnitude must be accounted for, not just weight magnitude"
        );
    }

    // ── Shape validation ────────────────────────────────────────────────────

    #[test]
    fn test_validate_catches_shape_errors() {
        let w = toy_weights();
        assert!(w.validate(2, 100).is_ok());
        assert!(w.validate(3, 100).is_err(), "wrong input_dim must be rejected");

        let mut w2 = toy_weights();
        w2.hidden_bias.pop();
        assert!(w2.validate(2, 100).is_err(), "bias count mismatch must be rejected");

        let mut w3 = toy_weights();
        w3.output_bias.push(0);
        assert!(w3.validate(2, 100).is_err(), "output bias mismatch must be rejected");

        let mut w4 = toy_weights();
        w4.output_weights = vec![vec![1, 2, 3]];
        assert!(
            w4.validate(2, 100).is_err(),
            "output row must match hidden width"
        );
    }

    #[test]
    fn test_rejects_empty_input() {
        let inputs: Vec<FheInt64> = vec![];
        assert!(dot_product(&inputs, &[], 0).is_err());
    }

    #[test]
    fn test_pseudorandom_model_is_deterministic_and_well_shaped() {
        let a = MlpWeights::pseudorandom_quantized(64, 16, 10, 8, 42);
        let b = MlpWeights::pseudorandom_quantized(64, 16, 10, 8, 42);
        let c = MlpWeights::pseudorandom_quantized(64, 16, 10, 8, 43);

        assert_eq!(a.input_dim(), 64);
        assert_eq!(a.hidden_width(), 16);
        assert_eq!(a.output_width(), 10);
        a.validate(64, 255).expect("must be overflow-safe at 8-bit weights");

        assert_eq!(a.hidden_weights, b.hidden_weights, "same seed must reproduce");
        assert_ne!(a.hidden_weights, c.hidden_weights, "different seed must differ");

        // Regression: an earlier LCG seeded with `seed | 1` mapped every even seed
        // onto its odd successor, so 42 and 43 produced byte-identical models. Any
        // two adjacent seeds must differ, and seed 0 must be usable.
        for s in 0u64..8 {
            let x = MlpWeights::pseudorandom_quantized(8, 4, 2, 8, s);
            let y = MlpWeights::pseudorandom_quantized(8, 4, 2, 8, s + 1);
            assert_ne!(
                x.hidden_weights, y.hidden_weights,
                "seeds {s} and {} must produce different models",
                s + 1
            );
        }

        assert!(
            a.hidden_weights.iter().flatten().all(|w| (-8..=8).contains(w)),
            "weights must respect the requested bound"
        );
    }

    #[test]
    fn test_plaintext_reference_shape_mismatch_rejected() {
        let mlp = TwoLayerMlp::new(toy_weights());
        assert!(mlp.evaluate_plaintext(&[1]).is_err());
        assert!(mlp.evaluate_plaintext(&[1, 2, 3]).is_err());
    }
}
