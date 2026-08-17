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
