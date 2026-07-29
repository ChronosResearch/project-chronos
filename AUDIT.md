# Code Audit — CHRONOS Agent
**Date:** 2026-07-29

---

## Result: Go ✅

30-point audit completed. Zero `expect()`/`unwrap()` in any production source file. Test files use `expect()` as assertions — that's fine.

---

## Bugs Fixed

| # | Bug | Severity | File | Fix |
|---|-----|----------|------|-----|
| 1 | `.expect("CString conversion failed")` in library | Critical | `wesolowski.rs` | Replaced with `?` via `ChronosError::GmpFfi` |
| 2 | `.expect("Invalid UTF8 from GMP")` in library | Critical | `wesolowski.rs` | `map_err(ChronosError::GmpFfi)` |
| 3 | `.expect("Parse error")` in library | Critical | `wesolowski.rs` | `ok_or_else(ChronosError::GmpFfi)` |
| 4 | `.expect("certN file missing")` in library | Critical | `mpc.rs` | `MpcCertificate::load()` returns `ChronosResult` |
| 5 | `mlock()` return value ignored | Critical | `memory.rs` | Returns `ChronosResult`, propagated to caller |
| 6 | No GMP RAII wrapper — memory leak on early return | Critical | `wesolowski.rs` | `GmpBigInt` struct with `Drop → mpz_clear()` |
| 7 | `libc::free` after `CStr::from_ptr` in wrong order (UAF) | Critical | `wesolowski.rs` | Moved inside `GmpBigInt::to_biguint()` |
| 8 | `mpsc::channel(100)` — unbounded under long VDF | High | `posw.rs` | `channel(32)` with back-pressure |
| 9 | No SIGTERM handler | High | `main.rs` | `tokio::signal::unix::signal(SIGTERM)` + graceful shutdown + `→ Result<()>` |
| 10 | `std::process::exit(1)` in non-main path | High | `main.rs` | EA check now returns `Err` via `anyhow` |
| 11 | No `ChronosError` unified type — `Box<dyn Error>` everywhere | High | (absent) | Created `chronos-core/src/error.rs` |
| 12 | No HKDF derivation | High | (absent) | RFC 5869 HKDF-SHA256 in `src/crypto.rs` |
| 13 | State machine allows double-init | High | `main.rs` | `arm_to_active()` rejects if not in `Armed` state |
| 14 | No watchdog timeout | High | (absent) | `spawn_watchdog()` polls elapsed vs `t_seconds` |
| 15 | No `#[inline(never)]` on `secure_wipe` | High | `wipe.rs` | Added — prevents compiler elision |
| 16 | Hardcoded drand URL, port 8080 | Medium | multiple | All in `config/default.toml` |
| 17 | No JSON logging | Medium | `main.rs` | `tracing-subscriber` with `.json()` layer |
| 18 | No Prometheus metrics | Medium | (absent) | `metrics.rs` + `/metrics` endpoint on port 9090 |
| 19 | CI workflow pointed at wrong directory | Medium | `rust-qa.yml` | Rewritten to target workspace root |
| 20 | `tracing-subscriber` missing `json` feature | Medium | `Cargo.toml` | Fixed |
| 21 | No release profile hardening | Medium | `Cargo.toml` | `lto=true`, `codegen-units=1`, `strip="symbols"` |
| 22 | No `.cargo/config.toml` | Medium | (absent) | Added with `cargo security` alias and musl flags |
| 23 | `ServerKey` behind `Mutex` (read-heavy path) | Medium | `fhe.rs` | Changed to `RwLock` |
| 24 | `generate_keys()` infallible return type | Medium | `fhe.rs` | `generate_and_install_keys() -> ChronosResult<()>` |
| 25 | Missing doc comments on public items | Medium | everywhere | Added; `RUSTDOCFLAGS=-D missing-docs` in CI |
| 26 | Prometheus `Lazy<Histogram>` statics use `expect()` | Medium | `metrics.rs` | Replaced with `OnceCell` + `make_*()` helpers that log errors |

---

## Gaps Before Real Deployment

| Area | State | What's needed |
|------|-------|---------------|
| Wesolowski VDF proof | Modular squaring only, no Pietrzak π | Implement verifier |
| Groth16 circuit | Single trivial R1CS constraint | Real AES-GCM constraints |
| BLS12-381 drand verification | Hex length check only | `bls12_381` pairing |
| `certN.bin` | Placeholder RSA modulus | MPC ceremony |
| `ct_sk.bin` | Not loaded in main orchestration | Wire into init path |
| mTLS | Stubbed | CA cert + rustls config |

---

## Checklist

| # | Check | Result |
|---|-------|--------|
| 1 | No `unwrap()`/`expect()` in library source | ✅ |
| 2 | `ChronosError` enum, 11 variants | ✅ |
| 3 | All deps pinned to patch versions | ✅ |
| 4 | No `panic!`/`exit()` in library crates | ✅ |
| 5 | Bounded channel (32); `spawn_blocking` for hashing | ✅ |
| 6 | SIGTERM + Ctrl-C; keys zeroized on shutdown | ✅ |
| 7 | FHE key gen on `spawn_blocking` thread | ✅ |
| 8 | `GmpBigInt` RAII; `Drop` calls `mpz_clear` | ✅ |
| 9 | `secure_wipe` `#[inline(never)]`; volatile-read unit test | ✅ |
| 10 | `drop(pk)` after proof; no Arc cycles | ✅ |
| 11 | `Redacted<T>` newtype; secrets never logged | ✅ |
| 12 | JSON logging via `tracing-subscriber` | ✅ |
| 13 | Prometheus metrics on port 9090 | ✅ |
| 14 | `config/default.toml` + typed `ChronosConfig` | ✅ |
| 15 | `read_secret_file` checks `0o600` mode on Unix | ✅ |
| 16 | `StateMachine::arm_to_active` rejects double-init | ✅ |
| 17 | `spawn_watchdog` forces `Erased` on timeout | ✅ |
| 18 | RFC 5869 HKDF-SHA256 via `hkdf` crate | ✅ |
| 19 | `#[cfg(debug_assertions)]` caps VDF T at 10 in tests | ✅ |
| 20 | Handshake test: keys → VDF → HKDF → erasure | ✅ |
| 21 | 10 concurrent `WesolowskiVdf` tasks; no shared GMP state | ✅ |
| 22 | `deny.toml` + `cargo security` alias in `.cargo/config.toml` | ✅ |
| 23 | `lto=true`, `codegen-units=1`, `strip="symbols"` | ✅ |
| 24 | `getrlimit(RLIMIT_CORE)` check at startup; fail if non-zero | ✅ |
| 25 | All public items have `///` doc comments | ✅ |
| 26 | `DEPLOYMENT.md` written | ✅ |
| 27 | `RwLock` instead of `Mutex` for `ServerKey` | ✅ |
| 28 | Binary size enforcement in CI (musl build + size check job) | ✅ |
| 29 | `rust-qa.yml` covers all checks on every PR | ✅ |
| 30 | This document | ✅ |

---

## Recovery

If `chronos-agent` crashes:

1. `systemd` restarts it (`Restart=on-failure`).
2. Core dumps are blocked (`LimitCORE=0` + `prctl(PR_SET_DUMPABLE, 0)`).
3. If the mission already reached `Erased`, exit code is 0 — systemd won't restart.
4. To re-run a pre-erase mission: re-provision `certN.bin` and `ct_sk.bin`, then restart.

```
./chronos-agent --config config.toml
```
