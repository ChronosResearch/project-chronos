# Third-Party Notices

CHRONOS is licensed under AGPL-3.0. This file records third-party code and data it
relies on, and the licences under which they are used.

All permissive licences listed here (MIT, Apache-2.0, BSD-3-Clause-Clear, ISC,
MPL-2.0) are one-way compatible with AGPL-3.0: their terms permit inclusion in a
copyleft work, provided copyright notices and licence text are preserved. That is
the purpose of this file.

**Nothing in `crates/` is vendored third-party source.** Every dependency is
consumed through Cargo, so `Cargo.lock` records exact versions and provenance, and
upstream security fixes reach this project by version bump rather than by manual
patching. The one exception is a borrowed *test vector*, documented below.

---

## Borrowed test data

### drand-verify — quicknet beacon test vector

**Source:** <https://github.com/CosmWasm/drand-verify>
**Licence:** Apache-2.0
**Used in:** `crates/chronos-agent/src/drand_client.rs`, in
`tests::test_verifies_real_quicknet_beacon`

The round-123 quicknet signature used as a fixed test vector is taken from
drand-verify's `verify_works_for_g1g2_swapped_rfc` test. It is a historical
mainnet beacon, independently checkable against
`https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/123`,
and it is what allows drand verification to be tested offline rather than against
a live network.

The surrounding implementation is CHRONOS's own and drives `blst` directly; the
drand-verify library itself is not a dependency. Its documentation and test suite
were consulted to establish the correct curve assignment for the quicknet scheme.
Content was rephrased for compliance with licensing restrictions.

### drand — protocol specification

**Source:** <https://github.com/drand/drand>, `crypto/schemes.go`
**Licence:** Apache-2.0 / MIT dual
**Consulted for:** `crates/chronos-agent/src/drand_client.rs`

The `bls-unchained-g1-rfc9380` scheme definition — public key on G2, signature on
G1, message `SHA-256(round_be_u64)`, DST
`BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` — was read from drand's own source
to establish correct verification. No code was copied; the specification was
implemented independently. Content was rephrased for compliance with licensing
restrictions.

### RSA-2048 — RSA Factoring Challenge

**Source:** RSA Security, 1991. Published; see
<https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048>
**Status:** Public data, not subject to copyright
**Used in:** `crates/chronos-core/src/mpc.rs`

The 617-digit RSA-2048 challenge modulus, used as a nothing-up-my-sleeve group of
unknown order when no per-mission modulus is provided. Its factors were destroyed
at generation and it has never been factored.

---

## Cryptographic dependencies

| Crate | Licence | Role |
|---|---|---|
| `ark-bn254`, `ark-ff`, `ark-ec`, `ark-poly`, `ark-std`, `ark-serialize` | MIT OR Apache-2.0 | BN254 curve and field arithmetic |
| `ark-groth16`, `ark-snark`, `ark-relations`, `ark-r1cs-std` | MIT OR Apache-2.0 | Groth16 proof system and R1CS constraint construction |
| `ark-crypto-primitives` | MIT OR Apache-2.0 | **Poseidon sponge**, native and R1CS, with Grain-LFSR round constants |
| `tfhe` (TFHE-rs, Zama) | BSD-3-Clause-Clear | Fully homomorphic encryption over the torus |
| `blst` (Supranational) | Apache-2.0 | BLS12-381 pairings, for drand beacon verification |
| `pqcrypto-dilithium`, `pqcrypto-traits` | MIT OR Apache-2.0 | ML-DSA (Dilithium3), NIST FIPS 204 |
| `sha2`, `hmac`, `hkdf`, `aes-gcm` (RustCrypto) | MIT OR Apache-2.0 | Hashing, request authentication, symmetric encryption |
| `zeroize` | MIT OR Apache-2.0 | Memory zeroization primitives |
| `num-bigint`, `num-traits` | MIT OR Apache-2.0 | Arbitrary-precision arithmetic for the VDF |
| `rand` | MIT OR Apache-2.0 | Randomness |

The Poseidon dependency is worth singling out. CHRONOS previously hand-rolled a
"Poseidon x^5 sponge" that had no round constants and a non-invertible linear
layer — it was not Poseidon, and it was not secure. Replacing it with the audited
arkworks implementation, instantiated with constants from the reference Grain LFSR,
is the reason the erasure and identity circuits can make claims that hold.

---

## Runtime and tooling dependencies

| Crate | Licence | Role |
|---|---|---|
| `tokio`, `tokio-util` | MIT | Async runtime |
| `axum`, `axum-core`, `tower`, `tower-http`, `hyper` | MIT | HTTP server |
| `reqwest` | MIT OR Apache-2.0 | HTTP client, for drand |
| `rustls`, `tokio-rustls`, `rustls-pemfile` | Apache-2.0 OR ISC OR MIT | TLS |
| `serde`, `serde_json` | MIT OR Apache-2.0 | Serialization |
| `tracing`, `tracing-subscriber` | MIT | Structured logging |
| `prometheus` | Apache-2.0 | Metrics |
| `config` | MIT OR Apache-2.0 | Layered configuration |
| `clap` | MIT OR Apache-2.0 | Command-line parsing |
| `anyhow`, `thiserror` | MIT OR Apache-2.0 | Error handling |
| `libc` | MIT OR Apache-2.0 | `mlock`, `getrlimit`, `prctl` |
| `hex`, `bincode` | MIT | Encoding |

---

## Academic attribution

The constructions CHRONOS composes are not original to it, and the paper cites
them. Recorded here because the implementation follows these specifications
directly:

- **Wesolowski VDF** — Wesolowski, *Efficient Verifiable Delay Functions*,
  EUROCRYPT 2019. `crates/chronos-vdf/src/wesolowski.rs`.
- **Poseidon** — Grassi, Khovratovich, Rechberger, Roy, Schofnegger, *Poseidon: A
  New Hash Function for Zero-Knowledge Proof Systems*, USENIX Security 2021.
  Parameters generated by the reference Grain LFSR.
- **Groth16** — Groth, *On the Size of Pairing-Based Non-Interactive Arguments*,
  EUROCRYPT 2016.
- **TFHE** — Chillotti, Gama, Georgieva, Izabachène, *TFHE: Fast Fully Homomorphic
  Encryption over the Torus*, J. Cryptology 2020.
- **Time-lock puzzles** — Rivest, Shamir, Wagner, *Time-lock Puzzles and
  Timed-release Crypto*, 1996. The provisioner's use of `φ(N)` to shortcut puzzle
  construction is theirs.
- **drand** — League of Entropy, *Distributed Randomness Beacon*.
- **ML-DSA** — NIST FIPS 204.

---

## Verifying this file

```bash
# Full dependency tree with licences
cargo install cargo-license
cargo license --avoid-dev-deps

# Licence policy
cargo deny check licenses
```

`deny.toml` does **not** use an explicit allow-list. It sets
`allow-osi-fsf-free = "either"`, which accepts any licence marked OSI-approved or
FSF-free in SPDX metadata, and denies unlicensed crates. That is deliberately
broad, and it has one consequence worth stating: `BSD-3-Clause-Clear` — the TFHE-rs
licence — is an SPDX-registered variant of BSD-3-Clause that is not itself
OSI-approved, so depending on the `cargo-deny` version it may require an explicit
exception rather than passing automatically. If `cargo deny check licenses` flags
it, add it to an `allow` list rather than loosening the policy.

Two further caveats on that file, both pre-existing:

- The `unlicensed` and `copyleft` keys were removed in `cargo-deny` 2.x and are
  ignored (with a deprecation warning) on current versions. The `[licenses]`
  section should be migrated.
- `advisories.ignore` carries five RUSTSEC entries, each with a justification
  comment. Those are transitive-dependency advisories, not accepted risk in
  CHRONOS's own code, but they should be re-checked whenever `tfhe` or the
  arkworks stack is upgraded.

If you find an attribution missing or wrong here, please open an issue — it will be
treated as a correctness bug, not a documentation nit.
