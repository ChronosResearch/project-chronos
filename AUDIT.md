# Code Audit — CHRONOS Agent
**Last updated:** 2026-07-29 (commit 6c2f199)

---

## Result: Go ✅

Full audit completed across all crates. Zero `expect()`/`unwrap()` in production source. Test files use `expect()` as assertions — intentional.

---

## Bugs Fixed (All Commits)

| # | Bug | Severity | File | Fix |
|---|-----|----------|------|-----|
| 1 | GMP FFI `.expect()` calls in library | Critical | `wesolowski.rs` | Replaced GMP FFI with pure `num-bigint`; all errors propagated via `?` |
| 2 | `mlock()` return value ignored | Critical | `memory.rs` | Returns `ChronosResult`, propagated to caller |
| 3 | `is_multiple_of` nightly-only method | High | `wesolowski.rs` | Replaced with `n % i == BigUint::zero()` (stable) |
| 4 | Unbounded `mpsc::channel` under long VDF | High | `posw.rs` | `channel(32)` with back-pressure |
| 5 | No SIGTERM handler | High | `main.rs` | `tokio::signal::unix::signal(SIGTERM)` + graceful shutdown |
| 6 | `std::process::exit(1)` in non-main path | High | `main.rs` | EA check returns `Err` via `anyhow` |
| 7 | No unified `ChronosError` type | High | (absent) | Created `chronos-core/src/error.rs` with 11 variants |
| 8 | No HKDF derivation | High | (absent) | RFC 5869 HKDF-SHA256 in `crypto.rs` |
| 9 | State machine allows double-init | High | `main.rs` | `arm_to_active()` rejects if not in `Armed` state |
| 10 | No watchdog timeout | High | (absent) | `spawn_watchdog()` polls elapsed vs `t_seconds` |
| 11 | No `#[inline(never)]` on `secure_wipe` | High | `wipe.rs` | Added — prevents compiler elision |
| 12 | Hardcoded seed `0xC4_0C_0D_05` in trusted setup | Critical | `prover.rs` | Replaced with 3-party simulated MPC ceremony |
| 13 | `merkle_zero_gadget` hardcoded public input 255 | High | `circuit.rs` | Public input derived from actual witness byte |
| 14 | Blind VDF client used sequential squaring for blinding | High | `blind.rs` | Fixed to `r.modpow(&(BigUint::one() << t), n)` |
| 15 | HKDF salt used as both salt and IKM | High | `crypto.rs` | Fixed per RFC 5869 §2 — IKM=y, salt=separate |
| 16 | BLS message pre-hashed before passing to blst | High | `drand_client.rs` | Raw `round.to_be_bytes()` passed; blst applies H2C internally |
| 17 | `verify_handler` used hardcoded `y_first_byte=0` | High | `main.rs` | Real `y[0]` from VDF output stored in `AppState` |
| 18 | `ct_sk` never decrypted — `K_enc` derived but unused | Critical | `main.rs` | `crypto::decrypt_ct_sk()` wired; AES-256-GCM decryption |
| 19 | `certN.bin` placeholder with no fallback | High | `mpc.rs` | Falls back to hardcoded RSA-2048 challenge modulus with `warn!` |
| 20 | Poseidon gadget used fake squaring chain | High | `circuit.rs` | Real x^5 S-box + MDS mix matching BN254 Poseidon spec |
| 21 | Drand fetch had no retry on network failure | Medium | `drand_client.rs` | Exponential backoff: 3 attempts at 500ms/1s/2s |
| 22 | `verify_handler` had no rate limiting | Medium | `main.rs` | Locks after 5 consecutive failures, returns HTTP 429 |
| 23 | Replay protection used O(n) `VecDeque::contains` | Medium | `tls.rs` | Refactored to `HashSet + VecDeque` for O(1) lookup |
| 24 | Fallback metric naming caused potential panic | Medium | `metrics.rs` | Fixed unique names per fallback metric |
| 25 | `NonceCache` missing from `AppState` | High | `main.rs` | Added; middleware now actually checks cache |
| 26 | `ct_sk` not wiped after use | High | `main.rs` | `secure_wipe` called on `ct_sk_owned` before drop |
| 27 | VDF benchmark measured prime search, not sequential squaring — published timings were non-monotonic in `T` | Critical | `wesolowski.rs` | `is_prime_trial` (trial division to √n, ~10⁹ ops, cost independent of `T`) replaced with deterministic Miller-Rabin |
| 28 | `T` silently clamped to 10 in debug builds, in **both** `evaluate` and `verify` — time-bound existence unenforced and untested under `cargo test` | Critical | `wesolowski.rs`, `posw.rs`, `isogeny.rs` | Clamp removed everywhere; added `test_proof_bound_to_declared_t` and `test_distinct_t_yields_distinct_output` |
| 29 | `while i * i <= n` overflowed `u64` for `n` near 2^64 — scan ran past √n in release, panicked under overflow checks | High | `wesolowski.rs` | Eliminated with Miller-Rabin; `mul_mod` routes all products through `u128` |
| 30 | `BigUint::one() << t` materialised a `T`-bit integer (125 KB at T=10⁶, 128 MB at T=2³⁰) | High | `wesolowski.rs`, `blind.rs` | Long-division recurrence for `π` and `repeated_square` for blinding; memory now independent of `T` |

**Note on check #30 below ("Benchmark suite ✅"):** that row predates bug #27. The
suite ran and produced output, but the VDF timings it produced did not measure
sequential work. Treat the benchmark table as unverified until re-measured.

---

## Checklist

| # | Check | Result |
|---|-------|--------|
| 1 | No `unwrap()`/`expect()` in library source | ✅ |
| 2 | `ChronosError` enum, 11 variants | ✅ |
| 3 | All deps pinned to patch versions | ✅ |
| 4 | No `panic!`/`exit()` in library crates | ✅ |
| 5 | Bounded channel (32); `spawn_blocking` for CPU-heavy work | ✅ |
| 6 | SIGTERM + Ctrl-C; keys zeroized on shutdown | ✅ |
| 7 | FHE key gen on `spawn_blocking` thread | ✅ |
| 8 | Pure `num-bigint` backend — no unsafe FFI | ✅ |
| 9 | `secure_wipe` `#[inline(never)]`; triple-pass volatile | ✅ |
| 10 | `Redacted<T>` newtype; secrets never logged | ✅ |
| 11 | JSON logging via `tracing-subscriber` | ✅ |
| 12 | Prometheus metrics on port 9090 | ✅ |
| 13 | `config/default.toml` + typed `ChronosConfig` | ✅ |
| 14 | `read_secret_file` checks `0o600` mode on Unix | ✅ |
| 15 | `StateMachine::arm_to_active` rejects double-init | ✅ |
| 16 | `spawn_watchdog` forces `Erased` on timeout | ✅ |
| 17 | RFC 5869 HKDF-SHA256 via `hkdf` crate | ✅ |
| 18 | AES-256-GCM decryption of `ct_sk` wired | ✅ |
| 19 | Real VDF output `y[0]` used as SNARK public input | ✅ |
| 20 | 3-party simulated MPC trusted setup | ✅ |
| 21 | RSA-2048 challenge modulus fallback (≥2048 bits validated) | ✅ |
| 22 | Poseidon x^5 S-box + MDS mix gadget | ✅ |
| 23 | Drand retry with exponential backoff (3 attempts) | ✅ |
| 24 | Verify endpoint rate-limited (5 failures → HTTP 429) | ✅ |
| 25 | O(1) nonce cache (`HashSet + VecDeque`) | ✅ |
| 26 | EAIP: identity root, ZK proof, ML-DSA signing | ✅ |
| 27 | `mlock` on all `LockedBytes`; triple-pass wipe on `Drop` | ✅ |
| 28 | `lto=true`, `codegen-units=1`, `strip="symbols"` | ✅ |
| 29 | `getrlimit(RLIMIT_CORE)` check at startup | ✅ |
| 30 | Benchmark suite (`chronos-bench`) | ✅ |

---

## Remaining Gaps

| Gap | What's needed |
|-----|---------------|
| FHE evaluation is byte-reversal stub | Real TFHE-rs circuit |
| Groth16 AES-GCM gadget simulates constraints | Real AES-GCM R1CS gadget |
| MPC ceremony is simulated (3-party local) | Real Powers-of-Tau ceremony |
| `F_OS` axiomatized | Hardware attestation (TDX/SEV-SNP) reduction |
| mTLS not enforced by axum | Wire `rustls` acceptor with client cert verification |

---

## Recovery

If `chronos-agent` crashes:

1. `systemd` restarts it (`Restart=on-failure`).
2. Core dumps are blocked (`LimitCORE=0` + `prctl(PR_SET_DUMPABLE, 0)`).
3. If the mission already reached `Erased`, exit code is 0 — systemd won't restart.
4. To re-run: re-provision `certN.bin` and `ct_sk.bin`, then restart.


---

## SNARK circuit audit (2026-08-17)

| # | Bug | Severity | File | Fix |
|---|-----|----------|------|-----|
| 31 | Gadgets 1, 3 and 4 were `while count < TARGET` loops emitting filler multiplications to reach a hardcoded count. Encoded no VDF verification, no AES-GCM, no SHA-256. ~160,000 of ~180,000 constraints were padding. | Critical | `circuit.rs` | Filler removed. Circuit is now ~700 real constraints. |
| 32 | `aes_gcm_gadget` terminated in `sk[0] * 1 = sk[0]` — a tautology constraining nothing. | Critical | `circuit.rs` | Gadget removed rather than faked; gap documented. |
| 33 | `merkle_zero_gadget` derived its "expected wipe pattern" public input *from the witness it was checking*, reducing the check to `sk[0] == sk[0]`. Only 1 of 32 bytes was referenced. | Critical | `circuit.rs` | `WIPE_PATTERN` is now a compile-time constant public input; all 32 bytes enforced against it. |
| 34 | Poseidon squeeze emitted 32 **unconstrained** witness variables. | High | `circuit.rs` | Each output now constrained as `lane + y[i]`. |
| 35 | `IdentityCircuit` computed `y[0]*mid[0]` and `root_pub*mid_pub` into separate witnesses and never constrained them equal — no binding to either public input existed. | Critical | `identity_circuit.rs` | Mission-ID binding enforced directly. Pre-image relation documented as unencoded. |
| 36 | `IdentityCircuit` padded to 10,000 constraints described as a SHA-256 pre-image proof. | Critical | `identity_circuit.rs` | Filler removed; circuit is now 1 real constraint with the gap stated. |
| 37 | `mpc_ceremony_rng` documented as 3-party MPC where "a single honest party guarantees security". All three RNGs run in one process; there is one party and it holds the trapdoor. | Critical (docs) | `prover.rs` | Documentation corrected to state no ceremony security is provided. |
| 38 | Proof size documented as 192 bytes; compressed Groth16 on BN254 is 128. | Low | `prover.rs` | Corrected. |
| 39 | `DynarkUpdater::update_salt` documented as O(20,000) incremental update; it re-proves the whole circuit. | Medium (docs) | `prover.rs` | Documentation corrected. |

**Constraint count is now a regression guard, not a target.** `test_constraint_count_is_real`
asserts the erasure circuit stays in the 500–2,000 range and the identity circuit
under 100. The previous tests asserted `>= 150_000` and `>= 9_000`, which
validated the padding rather than any computation.

**Remaining gaps in the erasure proof**, unchanged by this pass and tracked in the
README: `ct_sk` → `sk` decryption is not encoded (fix is Poseidon-based AEAD, not
an AES gadget); `m_pre` is not bound to a verifier-held commitment, so the proof
attests that *a* buffer was zeroized rather than that *the* key was; the trusted
setup is single-party.


---

## FHE inference (2026-08-17)

| # | Change | File |
|---|--------|------|
| 40 | `evaluate_ciphertext` returned `ct` with its bytes reversed. No homomorphic work, no confidentiality — a development placeholder that the README and paper both described as an FHE evaluation path. | `fhe.rs` |
| 41 | Replaced with a real two-layer MLP over `FheInt64`: homomorphic dot product with cleartext signed weights, ReLU via encrypted comparison and select. Signed throughout because a dot product with real trained weights goes negative, which is the case ReLU exists to handle. | `mlp.rs`, `fhe.rs` |
| 42 | Added a payload size cap before `bincode::deserialize` on `/infer` input. `bincode` reads a length prefix before allocating, which is an allocation primitive on attacker-controlled bytes. | `fhe.rs` |
| 43 | Model weights moved behind `install_weights` with shape validation, so a malformed model fails at load rather than mid-inference. | `fhe.rs`, `mlp.rs` |

**Not closed by this change:** `bincode` is still not a hardened parser for
adversarial input — `tfhe::safe_serialization` should replace it before `/infer`
is exposed to untrusted clients. `FheInt64` wraps silently on overflow. The MLP
is verified at toy scale only (2 inputs, 2 hidden units); there is no accuracy or
latency data at real model sizes, and one PBS per hidden unit will dominate
inference cost.

---

## On-chain verification (2026-08-18)

| # | Change | File |
|---|--------|------|
| 44 | Added a Solidity Groth16 verifier using the EVM `alt_bn128` precompiles, so erasure attestations can be checked by any Ethereum node rather than by a server the verifier must trust. | `contracts/Groth16Verifier.sol` |
| 45 | Added an append-only attestation registry: one record per mission, replay-resistant, reverting rather than returning false so a failed attestation cannot be mistaken for a successful one. | `contracts/ChronosRegistry.sol` |
| 46 | Added the EVM export path. `verifying_key_bytes()` returns arkworks' little-endian encoding, which the EVM cannot consume; `export_verifying_key` emits big-endian 32-byte words and swaps Fp2 coordinates to the `[c1, c0]` order the pairing precompile expects. Both are standard causes of a verifier that deploys cleanly then rejects every valid proof. | `solidity.rs` |
| 47 | Added `Groth16Prover::verifying_key()` to borrow the raw key, since only the serialized form was previously reachable. | `prover.rs` |
| 48 | Added `export_solidity` example that generates a setup, prints constructor arguments, and emits a sample proof — verified natively first, so an on-chain failure isolates to the encoding rather than the proof. | `examples/export_solidity.rs` |

**Scope of what on-chain verification adds.** An accepted proof shows someone knew
a witness satisfying the erasure circuit under the deployed key. It does not show
the agent was contained. The trusted setup remains single-party, so the setup
operator can forge proofs that verify on-chain; the circuit still binds a
prover-supplied buffer; decryption is still not encoded. Publishing on-chain
removes the need to trust the operator's *claim*, not the need to trust the
*ceremony*. What it adds unconditionally: immutability, public timestamps, replay
resistance, and a revision-proof audit trail.

**Not verified.** The Solidity is unaudited, has not been compiled, and has not
been tested against a live EVM. The Rust export path has not been compiled in
this environment either.
## Development process

This codebase is developed with AI assistance, including bug identification and
patch authoring in the VDF, SNARK and FHE modules. All changes are reviewed,
built and merged by the author. Where a fix was produced with assistance and
validated by a test run, the test output is the claim being made — not the
authorship of the diff.

---

## Cryptographic core rewrite (2026-08-18)

This pass closed the gaps left open by the 2026-08-17 SNARK audit and found four
further defects, three of them in code that the previous audit rows had recorded as
*fixed*. That pattern is the main lesson from this pass: every module examined had a
defect its own test suite passed over, because the tests asserted that the code ran
rather than that it computed the right thing.

### Defects found

| # | Bug | Severity | File | Fix |
|---|-----|----------|------|-----|
| 49 | The constant documented as "RSA-2048 from the RSA Factoring Challenge (unfactored as of 2024)" had **618** decimal digits; RSA-2048 has 617. It ended `...207203575` where the genuine value ends `...20720357` — a spurious trailing `5`. The value was therefore `RSA-2048 × 10 + 5`: not the challenge number, no published hardness analysis, **divisible by 5**, and 257 bytes rather than 256. A VDF group modulus with discoverable factors yields `φ(N)`, which collapses sequentiality — the one property CHRONOS exists to provide. Found by a length assertion in a new integration test, not by cryptographic review. | **Critical** | `mpc.rs` | Correct 617-digit value restored. `validate_modulus` now enforces exactly 2048 bits, exactly 256 bytes, and screens 25 small primes. `test_validate_rejects_the_previous_buggy_constant` reconstructs the old value and asserts rejection |
| 50 | drand verification used `blst::min_pk`, where the public key is a G1 point (48 bytes) and the signature a G2 point (96 bytes). quicknet is `bls-unchained-g1-rfc9380`: key on **G2** (96 bytes), signature on **G1** (48 bytes) — `min_sig` in `blst` terms. `Signature::from_bytes` was handed 48 bytes where it expected 96, so it returned an error on **every** beacon in every build profile. Consequence: `/mission/init` could never complete, because the drand fetch exhausted its retries and aborted the mission | **Critical** | `drand_client.rs` | Switched to `blst::min_sig`. `test_verifies_real_quicknet_beacon` now verifies a genuine mainnet beacon offline |
| 51 | The BLS message was the raw 8 round bytes. Per drand's `crypto/schemes.go`, the unchained schemes sign `SHA-256(round_be_u64)`. Audit row #16 recorded this as fixed, having changed it in the wrong direction | **Critical** | `drand_client.rs` | `beacon_message()` computes the digest, pinned by `test_message_is_sha256_of_round` |
| 52 | The invalid-signature return was behind `#[cfg(not(debug_assertions))]`, so under `cargo build` and `cargo test` a forged beacon was **accepted** and its randomness fed to the KDF as salt. This is the same debug-clamp pattern row #28 claims was removed "everywhere" | **Critical** | `drand_client.rs` | Guard removed. `test_invalid_signature_rejected_in_every_build_profile` fails if it returns |
| 53 | The advertised `randomness` field was decoded and used as the KDF salt without ever being checked against `SHA-256(signature)`. The signature was verified; the field the protocol actually consumes was not. A malicious endpoint could serve a valid signature alongside arbitrary randomness | High | `drand_client.rs` | Both checks are now mandatory; `verified_salt()` is the only way to obtain the salt |
| 54 | On AEAD failure the protocol loop logged a warning and used `ct_sk` **as the raw key**. Supplying a malformed `ct_sk.bin` therefore bypassed the VDF entirely — the time-lock became decorative | **Critical** | `main.rs` | Fallback removed; decryption failure is fatal |
| 55 | `sk_plaintext` was cloned into `sk_buf` and again into `m_pre`: three plain `Vec<u8>` copies of the key, of which exactly one was wiped. The other two dropped into the allocator intact and swappable, directly contradicting the `F_OS` axiom that Theorem 2 rests on. `LockedBytes` existed but was used only for the identity root | **Critical** | `main.rs` | The key exists only inside `LockedBytes` and is never cloned |
| 56 | The erasure proof was generated **after** the wipe, with the wiped buffer passed as the `sk` witness. The circuit attested that erased bytes were erased | **Critical** | `main.rs` | Proof is generated while the key is held, then the witness is dropped. Ordering is now load-bearing and documented |
| 57 | The VDF ran `4T` squarings for a `T`-step mission: `evaluate` does `2T` (output plus proof), then `generate_identity_root` re-ran the entire VDF | High | `main.rs` | EAIP derives its root from the `y` already computed |
| 58 | The watchdog set state to `Erased` while the blocking thread kept squaring with the key resident. The agent reported itself erased while holding the secret. `posw.rs` had an abort signal; Wesolowski had none | **Critical** | `wesolowski.rs`, `state.rs` | `evaluate_interruptible` polls an abort flag every 4,096 squarings; the watchdog raises it before transitioning |
| 59 | `X-Chronos-Nonce` required 24 hex characters — *any* 24 hex characters. It was a replay window, not a credential, so `/mission/init`, `/infer` and `/verify` were reachable by anyone who could open a TCP connection. Starting and aborting a mission were unauthenticated operations | **Critical** | `main.rs`, `crypto.rs` | HMAC-SHA256 over method, path, nonce and body digest under a pre-shared operator key, verified in constant time. Config refuses to start unauthenticated on a non-loopback address |
| 60 | The trusted setup ran inside `/mission/init`, so the verifying key changed every mission and no third party could ever check a proof. The agent was prover and sole verifier | **Critical** | `main.rs` | Proving key is a persisted artifact; `/attestation` publishes proof, public inputs and verifying key |
| 61 | Public inputs were two `u8` values (`y[0]`, `wipe_pattern`), giving the on-chain verifier 8 bits of binding to the VDF — forgeable by brute force over 256 candidates | **Critical** | `circuit.rs`, `solidity.rs`, `*.sol` | Five full-width BN254 scalars; `test_public_input_count_tracks_the_circuit` pins the ABI against the Solidity constant |
| 62 | The "Poseidon x^5 sponge" had no round constants, and its MDS mix summed three lanes into lane 0 while leaving lanes 1–2 untouched — a non-invertible, non-MDS linear layer, trivially open to invariant-subspace attack. Its derived `K_enc` was bound to `let _k_enc = ...` and discarded, so ~650 of ~700 constraints were decorative | **Critical** | `circuit.rs` → `poseidon.rs` | Replaced with `ark-crypto-primitives`' audited Poseidon, Grain-LFSR constants, Cauchy MDS. `test_native_and_gadget_agree` pins native/in-circuit equality; `test_mds_is_cauchy_wellformed` checks the preconditions that make the matrix provably MDS |
| 63 | `IdentityCircuit` enforced one constraint — `mid_vars[0] == mid_pub` — comparing one byte of a *public* value with itself. `y_vars` was allocated then discarded via `let _ = (&y_vars, root_pub);`. Separately, `identity_proof_handler` passed the root `R` as the `y` argument, so even the intended relation was fed `(R, R)` | **Critical** | `identity_circuit.rs`, `main.rs` | Pre-image relation `Poseidon(y, mission) == R` genuinely encoded, ~1,500 constraints. Root changed from SHA-256 to Poseidon: a **protocol change**, documented, because a SHA-256 pre-image proof costs ~25,000 constraints and is why the previous revisions faked it |
| 64 | `test_ledger_history_is_bound` asserted a witness-only perturbation makes the circuit unsatisfiable. It cannot: `generate_constraints` derives the public inputs from the witness, so any witness change is self-consistent within one synthesis. The test was structurally incapable of detecting the bug it claimed to guard | Medium (test) | `circuit.rs`, `prover.rs` | Split into a commitment-injectivity test and a proof-level binding test where the verifier supplies inputs independently |

### What was added

| Component | Purpose |
|---|---|
| `poseidon.rs` | Poseidon-128 over BN254, native and R1CS, with a test asserting the two produce identical digests. Every commitment in the system is built from it |
| `aead.rs` | **Chronos-AEAD** — Poseidon encrypt-then-MAC. Replaces AES-256-GCM *for the key-release step only*, so in-circuit decryption costs ~2,000 constraints instead of the tens of thousands an AES gadget needs. AES-GCM remains correct everywhere CHRONOS talks to something else; it was simply the wrong choice at a point where a proof must reason about the decryption |
| `containment.rs` | **Axiomatic Containment Monitor.** Containment as order-theoretic invariants over a lattice-valued state: capability decay (A1), budget decay (A2), phase irreversibility (A3), deadline dominance (A4), erasure liveness (A5). `verify_axioms` model-checks all five exhaustively over 1,728 abstract states and 19,000 transitions at startup; the agent refuses to boot on violation. A policy bug becomes a startup failure rather than a runtime incident |
| `mission.rs` | The published mission artifact. Carries the four provisioner-fixed commitments, which is what makes the erasure proof binding rather than self-asserted |
| `chronos-provision` | The missing third role. Generates the modulus, seals the key, publishes commitments, then wipes `sk` and destroys `φ(N)` |
| `tests/lifecycle.rs` | End-to-end test across the provisioner/agent boundary with real sequential squarings. Asserts the proof verifies against commitments the agent never chose, and that a fabricated key, an incomplete VDF, and an unerased mission are each unprovable |

### The circuit's claim, restated

The erasure proof now establishes that the prover simultaneously knew: the VDF
output behind `y_commit`; `K_enc` derived from that exact output via the in-circuit
KDF; the ciphertext behind `ct_commit`; that it authenticates and decrypts under
`K_enc`; that the plaintext equals the key behind `sk_commit`; and that the
containment monitor terminated erased with all capabilities revoked and both
budgets at zero.

**Proof-carrying containment** — binding the containment summary into the erasure
attestation, so one record covers both key destruction and capability discipline —
appears to have no precedent in the ephemeral-agent literature.

**What is still not proven, precisely.** A SNARK constrains values, not memory
locations, so the prover supplies the post-wipe buffer and could retain a copy of
the key elsewhere. No circuit can close this. What changed is the size of the
residual assumption: it is now exactly `F_OS` and nothing more, where previously
the gap was total — a prover who had never seen the key, the ciphertext or the VDF
could produce a passing proof.

### Removed

| Module | Reason |
|---|---|
| `agent/erasure.rs` | SHA-256 root over the pre-wipe buffer plus a `libc::memcmp` check. Never on the proof path, entirely superseded, and its presence implied a guarantee it did not provide |
| `agent/vdf_task.rs` | Checked an abort flag once *before* starting, which cannot interrupt squarings already underway. Never called from anywhere |
| `IdentityStatus` | Exposed `root_binding` as one byte of the identity root — all the old circuit bound. The root is now full-width, so a struct advertising one byte understates what is attested |

### Still open

Unchanged by this pass, and tracked in the README:

- **The trusted setup is single-party.** `SetupTranscript` gives hash-chained,
  tamper-evident, publishable contributions that can be collected from separate
  machines — but it combines *seeds*, so whoever runs the final setup call sees the
  combined seed and can reconstruct the trapdoor. That is not phase-2 ceremony
  security, and the distinction is stated in `prover.rs`, both contracts, and every
  `/attestation` response. It is the binding limitation on every verification claim
  this system makes.
- **`F_OS` is axiomatized.** Needs TDX or SEV-SNP attestation bound into the
  public inputs.
- ~~**`BlindVdf`, `IsogenyVdfSimulator`, `DynarkUpdater` remain present.**~~
  **Resolved.** All three were deleted later the same day — see *Removal of
  non-functional contributions* below for why each claim did not hold.
- **Contracts are uncompiled and unaudited.** No `solc` or `forge` in CI.
- **Benchmarks are unmeasured.** Both tables withdrawn; causes fixed.

### Method note

Three of the four new critical findings were in code that earlier audit rows
recorded as fixed (#16 → #51, #28 → #52, #19/#21 → #49). In each case a test
existed and passed. The tests asserted that a function returned `Ok`, or that a
constraint count exceeded a threshold, rather than that the computation was
correct — `test_constraint_count_is_real` previously asserted `>= 150_000`, which
validated the padding.

The tests added in this pass are written to fail if the *value* is wrong:
native-versus-gadget digest equality, a real mainnet beacon, reconstruction of the
previously shipped bad modulus, and negative cases asserting that a fabricated key
and an unerased mission are unprovable.

---

## Removal of non-functional contributions (2026-08-18)

Three modules were presented in the paper and README as novel contributions. None
functioned as specified, and none was reachable from any configuration path. They
are removed.

This is a correction rather than a reduction in scope. An unreachable module that
claims a property it does not have costs more credibility than an absent feature —
a reviewer who checks one of these finds a claim that does not hold and reasonably
discounts the others.

| # | Module | Claim | Why it did not hold | Action |
|---|---|---|---|---|
| 65 | `chronos-vdf/src/blind.rs` — "Blind VDF outsourcing, Novel Contribution 1" | A client delegates `T` sequential squarings to an untrusted server | To build the blinded base the client must compute `r^(2^T) mod N` — `T` sequential squarings, exactly the work being outsourced. The blinding was cryptographically sound; the delegation goal was unmet by construction. The module's own documentation conceded this | Deleted |
| 66 | `chronos-vdf/src/isogeny.rs` — "Post-quantum isogeny VDF, Novel Contribution 2" | Post-quantum VDF with `O(T / log T)` verification | A SHA-256 hash chain. `is_post_quantum()` returned `false`, and `verify_isogeny` re-ran the full evaluation, making verification `O(T)`. Sublinear verification is definitional for a VDF, so it was not one. It also carried the only consumer of `VdfBackend`, a config enum nothing read | Deleted |
| 67 | `chronos-snark` — `DynarkUpdater`, "Novel Contribution 3" | `O(20,000)` incremental proof update on salt rotation | Re-proved the entire circuit; no incremental structure existed | Already removed in the prover rewrite (2026-08-18) |
| 68 | `chronos-vdf/Cargo.toml` | — | `rand` was used only by `blind.rs` for `RandBigInt`; `thiserror` was never used in this crate at all, since error types come from `chronos_core::ChronosError` | Both dependencies dropped |

### Retained, with the label corrected

`posw.rs` (`PoswEngine`) is **not** deleted. It is a correct, tested SHA-256
hash-chain Proof of Sequential Work (Cohen, EUROCRYPT 2018 — reference [13] in the
paper), and unlike the two modules above it does exactly what it says. It is,
however, **not on the mission path**: the agent uses the Wesolowski VDF, because a
hash chain cannot give sublinear verification.

It is retained because PoSW is a genuinely different trade-off worth keeping
available — no trusted setup and no group of unknown order, at the cost of `O(T)`
verification — and it is now labelled explicitly in `chronos-vdf/src/lib.rs` so it
cannot be mistaken for part of the protocol. Honest unused code is a different
category from misrepresented unused code.

### Post-quantum VDF, restated as future work

Removing the simulator does not remove the goal. The Wesolowski VDF rests on
factoring, so a quantum adversary recovers `φ(N)` and the sequentiality guarantee
with it.

The realistic path is a **class-group VDF** rather than an isogeny walk. Groups of
imaginary quadratic orders have unknown order by construction from a public
discriminant, so there is no modulus whose factorisation anyone must be trusted not
to know — which would also retire the `certN.bin` fallback and the Diogenes
dependency in one step, rather than simulating around them.
[`chiavdf`](https://github.com/Chia-Network/chiavdf) (Apache-2.0) is a mature
implementation. Tracked in the README gaps table.

### Not completed in this pass

**Benchmarks remain unmeasured.** `cargo run -p chronos-bench --release` could not
be executed: the shell in this environment stopped accepting commands partway
through the session. Both withdrawn tables in the README and paper §6 therefore
still carry the "pending re-measurement" note, and the underlying causes are fixed
(`is_prime` is now deterministic Miller-Rabin; the circuit no longer contains
filler). The benchmark binary itself was rewritten against the current APIs and
compiles, but its output has not been observed.
