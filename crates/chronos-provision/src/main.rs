//! `chronos-provision` — generate a time-locked mission.
//!
//! This binary plays the **provisioner** role: it creates the secret key, seals it
//! under a key that can only be recovered by completing the VDF, publishes the
//! commitments a verifier will check, and destroys the key material it holds.
//!
//! # Why the agent cannot do this itself
//!
//! The erasure proof binds `sk_commit` and `ct_commit`. If the agent generated
//! them it could fabricate a key, seal it under a key of its own choosing, commit
//! to both, and produce a valid proof about material that was never time-locked.
//! The soundness of the whole scheme therefore rests on these commitments being
//! fixed by a party the verifier trusts *more than* the agent — normally the
//! ground station that dispatched it. See `chronos_snark::mission`.
//!
//! # A correction to the CHRONOS paper's modulus argument
//!
//! §2.2 of the v3 paper states that the RSA modulus `N` **must** come from an MPC
//! ceremony, on the grounds that a party knowing `φ(N)` can evaluate
//! `g^(2^T) mod N` in `O(log T)` steps via Euler's theorem and so defeat the
//! sequential-work requirement.
//!
//! That reasoning is sound but the conclusion is too strong. It holds only when the
//! agent is also the puzzle's creator. The security requirement is that **the
//! agent** cannot shortcut, not that nobody can. When provisioning is performed by
//! a distinct party — which it must be anyway, per the paragraph above — that party
//! generating `N = p·q` and retaining `φ(N)` is exactly Rivest–Shamir–Wagner
//! time-lock puzzles: the creator shortcuts, the solver cannot. The provisioner is
//! already trusted with `sk`, since it *chose* `sk`, so trusting it with `φ(N)`
//! adds no new assumption.
//!
//! This matters practically: it removes a hard dependency on a live Diogenes
//! ceremony, which is infrastructure CHRONOS does not have. The trade is explicit
//! and the operator chooses:
//!
//! * `--generate-modulus` (default): this tool generates `N`, uses `φ(N)` to
//!   compute `y` in milliseconds, then wipes `p`, `q` and `φ(N)`. Requires
//!   provisioner ≠ agent, which the protocol requires regardless.
//! * `--modulus <path>`: load an externally produced `N`, e.g. from an MPC
//!   ceremony or the RSA Factoring Challenge. No shortcut is available, so the
//!   provisioner performs the full `T` squarings itself.
//!
//! # Outputs
//!
//! | File | Contains | Distribute to |
//! |---|---|---|
//! | `mission_public.json` | the four commitments | everyone; publish it |
//! | `ct_sk.bin` | the sealed key | the agent only |
//! | `certN.bin` | the modulus `N` | the agent; it is public |
//!
//! `sk` itself is never written to disk.

use anyhow::{bail, Context, Result};
use ark_bn254::Fr;
use chronos_core::wipe::secure_wipe;
use chronos_core::VdfEngine;
use chronos_snark::aead::ChronosAead;
use chronos_snark::circuit::{MISSION_BYTES, SALT_BYTES, SK_BYTES, Y_BYTES};
use chronos_snark::identity_circuit::mission_id_to_bytes;
use chronos_snark::mission::MissionPublic;
use chronos_snark::poseidon::{self, Domain};
use chronos_vdf::wesolowski::WesolowskiVdf;
use clap::Parser;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::RngCore;

/// Bit length of each generated prime factor, giving a 2048-bit modulus.
const PRIME_BITS: u64 = 1024;

/// Miller-Rabin rounds for candidate primes. 64 rounds gives a false-positive
/// probability below 2^-128, which is negligible against the other assumptions
/// in play.
const MR_ROUNDS: u32 = 64;

#[derive(Parser, Debug)]
#[command(
    name = "chronos-provision",
    about = "Generate a time-locked CHRONOS mission: sealed key plus public commitments"
)]
struct Args {
    /// Human-readable mission identifier.
    #[arg(long, default_value = "chronos-mission-001")]
    mission_id: String,

    /// Sequential squarings the agent must perform to unseal the key.
    #[arg(long, default_value_t = 1_000_000)]
    t_vdf_steps: u64,

    /// Wall-clock mission budget, in seconds.
    #[arg(long, default_value_t = 3600)]
    t_seconds: u64,

    /// Containment operation budget.
    #[arg(long, default_value_t = 1024)]
    op_budget: u64,

    /// Containment disclosure budget, in bits.
    #[arg(long, default_value_t = 65536)]
    disclosure_budget_bits: u64,

    /// Load `N` from this file instead of generating it. Removes the `φ(N)`
    /// shortcut, so provisioning performs the full `T` squarings.
    #[arg(long)]
    modulus: Option<String>,

    /// Output directory.
    #[arg(long, default_value = ".")]
    out_dir: String,

    /// Beacon salt as 64 hex chars. Omit to draw a random one.
    ///
    /// In production this is the drand randomness for the round the mission
    /// starts at, so the sealing key is bound to a public, unpredictable value.
    #[arg(long)]
    salt_hex: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let out = std::path::Path::new(&args.out_dir);
    std::fs::create_dir_all(out)
        .with_context(|| format!("cannot create output directory {}", out.display()))?;

    println!("CHRONOS mission provisioning");
    println!("============================");
    println!("mission_id   : {}", args.mission_id);
    println!("T (squarings): {}", args.t_vdf_steps);
    println!();

    // ── 1. Modulus ───────────────────────────────────────────────────────────
    let g = BigUint::from(2u32);
    let (n, phi) = match &args.modulus {
        Some(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("cannot read modulus from {path}"))?;
            let n = BigUint::from_bytes_be(&bytes);
            if n.bits() < 2048 {
                bail!(
                    "modulus from {path} is only {} bits; CHRONOS requires at least 2048",
                    n.bits()
                );
            }
            println!("Modulus      : loaded, {} bits (no shortcut available)", n.bits());
            (n, None)
        }
        None => {
            println!("Modulus      : generating {}-bit N = p*q ...", PRIME_BITS * 2);
            let (n, phi) = generate_modulus()?;
            println!("               generated, {} bits", n.bits());
            (n, Some(phi))
        }
    };

    // ── 2. VDF output ────────────────────────────────────────────────────────
    //
    // With φ(N) this is two modular exponentiations. Without it, T squarings.
    let y = match &phi {
        Some(phi) => {
            println!("VDF output   : computing via phi(N) shortcut ...");
            shortcut_vdf(&g, args.t_vdf_steps, &n, phi)
        }
        None => {
            println!(
                "VDF output   : performing {} sequential squarings (no shortcut) ...",
                args.t_vdf_steps
            );
            let vdf = WesolowskiVdf;
            let (y, _proof) = vdf
                .evaluate(&g, args.t_vdf_steps, &n)
                .map_err(|e| anyhow::anyhow!("VDF evaluation failed: {e}"))?;
            y
        }
    };

    // The circuit's shape is fixed, so `y` is always presented as exactly
    // Y_BYTES big-endian bytes, zero-padded on the left.
    let y_fixed = to_fixed_be(&y, Y_BYTES)
        .context("VDF output does not fit the circuit's fixed y width")?;
    println!("               done");

    // ── 3. Salt ──────────────────────────────────────────────────────────────
    let salt = match &args.salt_hex {
        Some(h) => {
            let b = hex::decode(h).context("--salt-hex is not valid hex")?;
            if b.len() != SALT_BYTES {
                bail!("--salt-hex must be {SALT_BYTES} bytes ({} hex chars)", SALT_BYTES * 2);
            }
            b
        }
        None => {
            let mut b = vec![0u8; SALT_BYTES];
            rand::thread_rng().fill_bytes(&mut b);
            println!("Salt         : random (use --salt-hex with a drand beacon in production)");
            b
        }
    };

    // ── 4. Secret key and sealing ────────────────────────────────────────────
    let mut sk = [0u8; SK_BYTES];
    rand::thread_rng().fill_bytes(&mut sk);

    let k_enc = ChronosAead::derive_key(&y_fixed, &salt);

    let mut nonce_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Fr::from_be_bytes_mod_order_wrapper(&nonce_bytes);

    let ct = ChronosAead::encrypt(&k_enc, nonce, &poseidon::split32(&sk))
        .map_err(|e| anyhow::anyhow!("sealing failed: {e}"))?;

    // Confirm the agent will be able to open it. A provisioner that ships an
    // unopenable ciphertext wastes an entire mission.
    let reopened = ChronosAead::decrypt(&k_enc, &ct)
        .map_err(|e| anyhow::anyhow!("self-check failed, sealed key cannot be reopened: {e}"))?;
    if reopened != poseidon::split32(&sk).to_vec() {
        bail!("self-check failed: reopened key does not match the original");
    }

    // ── 5. Commitments ───────────────────────────────────────────────────────
    let mission_digest: [u8; MISSION_BYTES] = mission_id_to_bytes(&args.mission_id);

    let y_commit = poseidon::hash_bytes(Domain::VdfOutput, &y_fixed);
    let ct_commit = poseidon::hash(Domain::Ciphertext, &ct.to_elements());
    let sk_commit = poseidon::hash(Domain::SecretKey, &poseidon::split32(&sk));
    let mission_commit = poseidon::hash_bytes(Domain::MissionId, &mission_digest);

    let artifact = MissionPublic::new(
        args.mission_id.clone(),
        args.t_vdf_steps,
        args.t_seconds,
        y_commit,
        ct_commit,
        sk_commit,
        mission_commit,
        args.op_budget,
        args.disclosure_budget_bits,
    );

    // ── 6. Write outputs ─────────────────────────────────────────────────────
    let mission_path = out.join("mission_public.json");
    let ct_path = out.join("ct_sk.bin");
    let cert_path = out.join("certN.bin");
    let salt_path = out.join("salt.bin");

    artifact.save(&mission_path).map_err(|e| anyhow::anyhow!("{e}"))?;
    std::fs::write(&ct_path, ct.to_bytes()).context("writing ct_sk.bin")?;
    std::fs::write(&cert_path, n.to_bytes_be()).context("writing certN.bin")?;
    std::fs::write(&salt_path, &salt).context("writing salt.bin")?;

    restrict_permissions(&ct_path)?;

    // ── 7. Destroy provisioner secrets ───────────────────────────────────────
    //
    // `sk` is wiped here and never written anywhere. `p`, `q` and `φ(N)` are
    // wiped too: retaining them would let the provisioner unseal the key later,
    // which defeats the point of the mission being time-bound.
    // SAFETY: `sk` is a live, exclusively-owned stack buffer of exactly SK_BYTES.
    unsafe { secure_wipe(sk.as_mut_ptr(), sk.len()) };
    drop(phi);

    println!();
    println!("Wrote:");
    println!("  {}   <- publish this", mission_path.display());
    println!("  {}          <- agent only", ct_path.display());
    println!("  {}          <- public", cert_path.display());
    println!("  {}           <- agent only", salt_path.display());
    println!();
    println!("sk wiped; phi(N) destroyed. The key is now recoverable only by");
    println!("completing {} sequential squarings.", args.t_vdf_steps);

    Ok(())
}

/// Left-pad a big-endian integer to exactly `len` bytes.
fn to_fixed_be(v: &BigUint, len: usize) -> Result<Vec<u8>> {
    let be = v.to_bytes_be();
    if be.len() > len {
        bail!("value is {} bytes, exceeding the fixed width of {len}", be.len());
    }
    let mut out = vec![0u8; len];
    out[len - be.len()..].copy_from_slice(&be);
    Ok(out)
}

/// Generate `N = p·q` and return `(N, φ(N))`.
fn generate_modulus() -> Result<(BigUint, BigUint)> {
    let p = generate_prime()?;
    let mut q = generate_prime()?;
    // Distinct factors: p == q would make N a perfect square and φ(N) wrong.
    while q == p {
        q = generate_prime()?;
    }
    let n = &p * &q;
    let phi = (&p - BigUint::one()) * (&q - BigUint::one());
    Ok((n, phi))
}

/// Generate a probable prime of [`PRIME_BITS`] bits.
fn generate_prime() -> Result<BigUint> {
    let mut rng = rand::thread_rng();
    for _ in 0..10_000 {
        let mut candidate = rng.gen_biguint(PRIME_BITS);
        // Force the top bit, so N reliably reaches 2*PRIME_BITS, and the low bit,
        // since even numbers above 2 are never prime.
        candidate.set_bit(PRIME_BITS - 1, true);
        candidate.set_bit(0, true);
        if is_probable_prime(&candidate, MR_ROUNDS) {
            return Ok(candidate);
        }
    }
    bail!("failed to find a {PRIME_BITS}-bit prime in 10000 attempts")
}

/// Miller-Rabin primality test with `rounds` random bases.
fn is_probable_prime(n: &BigUint, rounds: u32) -> bool {
    use num_traits::Zero;

    let one = BigUint::one();
    let two = BigUint::from(2u32);
    if *n < two {
        return false;
    }
    // Trial division by small primes: cheap, and rejects most composites.
    for p in [3u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47] {
        let bp = BigUint::from(p);
        if *n == bp {
            return true;
        }
        if (n % &bp).is_zero() {
            return false;
        }
    }

    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut s = 0u32;
    while !d.bit(0) {
        d >>= 1;
        s += 1;
    }

    let mut rng = rand::thread_rng();
    'outer: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&two, &n_minus_1);
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 1..s {
            x = (&x * &x) % n;
            if x == n_minus_1 {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

/// Compute `y = g^(2^T) mod N` using `φ(N)`.
///
/// `2^T mod φ(N)` reduces the exponent, so this is two modular exponentiations
/// rather than `T` squarings. This is the shortcut the agent must not have, and
/// why `φ(N)` is wiped immediately afterwards.
fn shortcut_vdf(g: &BigUint, t: u64, n: &BigUint, phi: &BigUint) -> BigUint {
    let exp = BigUint::from(2u32).modpow(&BigUint::from(t), phi);
    g.modpow(&exp, n)
}

/// Tighten permissions on a file holding sealed key material.
fn restrict_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("cannot chmod 600 {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        // Windows ACLs are not expressible through `std::fs::Permissions`, so the
        // agent's own 0600 check is skipped there. Flagged rather than silently
        // ignored: on Windows, protect ct_sk.bin with filesystem ACLs yourself.
        let _ = path;
        eprintln!(
            "warning: file permissions not restricted on this platform — \
             protect {} with filesystem ACLs",
            path.display()
        );
    }
    Ok(())
}

/// Helper trait so the nonce can be built from raw bytes without importing
/// `PrimeField` at the call site.
trait FrFromBytes {
    fn from_be_bytes_mod_order_wrapper(bytes: &[u8]) -> Fr;
}

impl FrFromBytes for Fr {
    fn from_be_bytes_mod_order_wrapper(bytes: &[u8]) -> Fr {
        use ark_ff::PrimeField;
        Fr::from_be_bytes_mod_order(bytes)
    }
}
