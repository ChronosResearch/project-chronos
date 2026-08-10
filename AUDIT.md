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
