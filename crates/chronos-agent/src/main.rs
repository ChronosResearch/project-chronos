//! CHRONOS agent.
//!
//! # The protocol loop, and what was wrong with the previous one
//!
//! The mission sequence is:
//!
//! 1. Load the published mission artifact, the sealed key, the salt, the modulus.
//! 2. Generate FHE keys.
//! 3. Evaluate the VDF — `T` sequential squarings, interruptible.
//! 4. Verify the VDF proof natively in `O(log T)`.
//! 5. Derive `K_enc` from `(y, salt)` and open the sealed key.
//! 6. Check the opened key against the provisioner's `sk_commit`.
//! 7. Initialise EAIP from the *same* `y`.
//! 8. Serve inference until the deadline or the budget runs out.
//! 9. Prove erasure **while the key is still held**, then wipe.
//!
//! Six defects in the previous loop are fixed here, and step 9's ordering is the
//! subtle one:
//!
//! **The proof was generated after the wipe.** The old loop wiped `sk_buf`, then
//! passed that wiped buffer to the prover as the `sk` witness. The circuit
//! dutifully attested that erased bytes were erased. Since the witness must now
//! decrypt from the committed ciphertext and match `sk_commit`, the proof has to be
//! produced while the genuine key is in hand, and the witness wiped immediately
//! after. Proving after the wipe is no longer merely weak — it is impossible.
//!
//! **The key lived in unlocked memory.** `sk_plaintext` was cloned into `sk_buf`
//! and again into `m_pre`, three plain `Vec<u8>` copies of which exactly one was
//! wiped. The other two dropped into the allocator intact and swappable, directly
//! contradicting the `F_OS` axiom that Theorem 2 rests on. The key now lives in
//! [`LockedBytes`] — `mlock`ed, triple-pass wiped on drop — and is never cloned.
//!
//! **Decryption failure fell back to using the ciphertext as the key.** See
//! [`crate::crypto`]. Now fatal.
//!
//! **The VDF ran four times over.** `evaluate` performs `2T` squarings (`T` for
//! `y`, `T` for the proof), and the old loop then called `generate_identity_root`,
//! which ran the entire VDF again — `4T` squarings for a `T`-step mission. EAIP now
//! derives its root from the `y` already computed.
//!
//! **The watchdog could not stop anything.** It set the state to `Erased` while the
//! blocking thread kept squaring with the key resident. Step 3 now uses
//! `evaluate_interruptible` against the state machine's abort flag.
//!
//! **The verifying key changed every mission.** Setup ran inside `/mission/init`,
//! so no external party could ever check a proof — the agent was prover and sole
//! verifier, which is not attestation. The proving key is now a persisted artifact.
//!
//! # Security posture of the HTTP surface
//!
//! Requests carry an HMAC over method, path, nonce and body digest. That
//! authenticates the operator and prevents replay, but the transport is plain
//! HTTP: an eavesdropper reads bodies, and mTLS is validated in config yet not
//! wired to the acceptor. Do not expose this to an untrusted network.

// The binary consumes the library rather than re-declaring the modules with
// `mod`. Declaring them in both places compiles every module twice — once into
// the lib, once into the bin — which doubles build time and produces spurious
// dead-code warnings for items the binary happens not to call.
use chronos_agent::{config, crypto, drand_client, metrics, state, tls};

use anyhow::{Context, Result};
use ark_bn254::Fr;
use axum::{
    body::Bytes,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chronos_core::containment::{verify_axioms, Event};
use chronos_core::{
    fhe::FheEngine, memory::LockedBytes, mpc::MpcCertificate, VdfEngine,
};
use chronos_snark::aead::ChronosAead;
use chronos_snark::circuit::{ErasureWitness, SK_BYTES, WIPE_PATTERN};
use chronos_snark::identity_circuit::{identity_root, mission_id_to_bytes, IdentityProver};
use chronos_snark::mission::{fr_to_hex, MissionPublic};
use chronos_snark::poseidon;
use chronos_snark::prover::{Groth16Prover, SetupContribution, SetupTranscript};
use chronos_snark::solidity::{erasure_public_inputs, export_proof_bytes};
use chronos_vdf::wesolowski::WesolowskiVdf;
use num_bigint::BigUint;
use serde::Serialize;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use config::ChronosConfig;
use crypto::AUTH_KEY_BYTES;
use metrics::render_metrics;
use state::{AgentState, StateMachine};
use tls::NonceCache;

/// The completed attestation, published once erasure finishes.
struct Attestation {
    proof: Vec<u8>,
    public_inputs: chronos_snark::circuit::PublicInputs,
    verifying_key: Vec<u8>,
}

#[derive(Clone)]
struct AppState {
    sm: Arc<StateMachine>,
    fhe: Arc<FheEngine>,
    cfg: Arc<ChronosConfig>,
    mission: Arc<MissionPublic>,
    nonce_cache: Arc<Mutex<NonceCache>>,
    auth_key: Arc<Option<[u8; AUTH_KEY_BYTES]>>,
    /// Present after erasure completes.
    attestation: Arc<Mutex<Option<Attestation>>>,
    /// Present after the VDF completes; used by `/identity/proof`.
    ///
    /// The *proof* is cached rather than the witness. Regenerating it per request
    /// would require keeping `y` alive after erasure, which would defeat the point;
    /// a Groth16 proof reveals nothing about its witness, so caching it is safe.
    identity_prover: Arc<Mutex<Option<IdentityProver>>>,
    identity_proof: Arc<Mutex<Option<Vec<u8>>>>,
    identity_root: Arc<Mutex<Option<Fr>>>,
    verify_failures: Arc<Mutex<u32>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("chronos=info,warn"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json())
        .init();

    info!(target: "chronos", "chronos-agent starting");

    // ── Containment axioms, before anything else ─────────────────────────────
    //
    // If the monitor's policy is unsound there is no safe way to proceed: the
    // agent would be admitting requests under rules that do not guarantee
    // capability decay or erasure liveness. Refusing to start is the only correct
    // response, so this runs before config, before key material, before the
    // listener.
    let report = verify_axioms();
    if !report.is_sound() {
        for v in &report.violations {
            error!(target: "chronos", violation = %v, "containment axiom violated");
        }
        anyhow::bail!(
            "containment axioms failed verification ({} violations over {} states) — refusing to start",
            report.violations.len(),
            report.states_explored
        );
    }
    info!(
        target: "chronos",
        states = report.states_explored,
        transitions = report.transitions_checked,
        "containment axioms A1-A5 verified"
    );

    let cfg = ChronosConfig::load().context("configuration invalid")?;
    verify_exclusivity_assumption()?;
    disable_core_dumps();
    tls::validate_tls_config(&cfg.tls).context("TLS configuration invalid")?;

    // ── Mission artifact ─────────────────────────────────────────────────────
    //
    // No fallback. Without the provisioner's commitments the agent cannot produce
    // a proof anyone can check, so starting would be theatre.
    let mission = MissionPublic::load(&cfg.paths.mission_public).with_context(|| {
        format!(
            "cannot load mission artifact '{}'. Generate one with: chronos-provision --out-dir .",
            cfg.paths.mission_public
        )
    })?;
    info!(
        target: "chronos",
        mission_id = %mission.mission_id,
        t_vdf_steps = mission.t_vdf_steps,
        "mission artifact loaded"
    );

    let auth_key = if cfg.auth.enabled {
        let path = cfg
            .auth
            .key_path
            .as_deref()
            .context("auth.enabled but auth.key_path unset")?;
        Some(
            crypto::load_auth_key(path)
                .await
                .with_context(|| format!("cannot load operator auth key '{path}'"))?,
        )
    } else {
        warn!(
            target: "chronos",
            "request authentication DISABLED — permitted only because api_addr is loopback"
        );
        None
    };

    let sm = StateMachine::new(
        mission.op_budget,
        mission.disclosure_budget_bits,
        mission.t_seconds,
    );
    let fhe = Arc::new(FheEngine::new());

    let app_state = AppState {
        sm: Arc::clone(&sm),
        fhe: Arc::clone(&fhe),
        cfg: Arc::new(cfg.clone()),
        mission: Arc::new(mission.clone()),
        nonce_cache: Arc::new(Mutex::new(NonceCache::new(1024))),
        auth_key: Arc::new(auth_key),
        attestation: Arc::new(Mutex::new(None)),
        identity_prover: Arc::new(Mutex::new(None)),
        identity_proof: Arc::new(Mutex::new(None)),
        identity_root: Arc::new(Mutex::new(None)),
        verify_failures: Arc::new(Mutex::new(0)),
    };

    state::spawn_watchdog(Arc::clone(&sm), mission.t_seconds);

    let metrics_addr = cfg.server.metrics_addr.clone();
    tokio::spawn(async move { serve_metrics(&metrics_addr).await });

    let shutdown_sm = Arc::clone(&sm);
    let shutdown = async move {
        if let Err(e) = wait_for_shutdown_signal().await {
            error!(target: "chronos", error = %e, "signal handler failed — shutting down anyway");
        }
        warn!(target: "chronos", "shutdown signal — erasing and exiting");
        shutdown_sm.force_erased().await;
    };

    let app = Router::new()
        .route("/status", get(status_handler))
        .route("/mission/init", post(init_handler))
        .route("/infer", post(infer_handler))
        .route("/verify", post(verify_handler))
        .route("/identity/proof", get(identity_proof_handler))
        .route("/attestation", get(attestation_handler))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ))
        .with_state(app_state);

    let listener = TcpListener::bind(&cfg.server.api_addr)
        .await
        .with_context(|| format!("cannot bind {}", cfg.server.api_addr))?;
    info!(target: "chronos", addr = %cfg.server.api_addr, "API listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("axum server error")?;
    Ok(())
}

// ─── Exclusivity Assumption ───────────────────────────────────────────────────

/// Check the OS-level preconditions the `F_OS` axiom assumes.
///
/// On non-Unix this cannot be checked, and the previous implementation simply
/// logged and continued. That silently voids `F_OS`, so the situation is now
/// reported as an explicit, prominent warning naming what is unverified.
fn verify_exclusivity_assumption() -> Result<()> {
    #[cfg(unix)]
    {
        let mut rlim = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        // SAFETY: getrlimit writes a fully initialised rlimit through the pointer.
        let ret = unsafe { libc::getrlimit(libc::RLIMIT_CORE, rlim.as_mut_ptr()) };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "getrlimit(RLIMIT_CORE) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: getrlimit returned success, so the value is initialised.
        let rlim = unsafe { rlim.assume_init() };
        if rlim.rlim_cur != 0 {
            return Err(anyhow::anyhow!(
                "Exclusivity Assumption violated: RLIMIT_CORE = {} (must be 0). A core dump \
                 would write the secret key to disk, defeating the erasure guarantee. \
                 Run with: ulimit -c 0",
                rlim.rlim_cur
            ));
        }
        info!(target: "chronos", "Exclusivity Assumption satisfied: RLIMIT_CORE = 0");
    }
    #[cfg(not(unix))]
    warn!(
        target: "chronos",
        "F_OS UNVERIFIED on this platform: cannot confirm core dumps are disabled or that \
         mlock'd pages are excluded from the pagefile. The erasure guarantee is unproven here. \
         Use Linux for any deployment where the guarantee matters."
    );
    Ok(())
}

fn disable_core_dumps() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: both are pure syscalls with no memory-safety implications.
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0usize) };
        let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
    }
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).context("cannot install SIGTERM handler")?;
        tokio::select! {
            _ = sigterm.recv() => info!(target: "chronos", "SIGTERM received"),
            _ = tokio::signal::ctrl_c() => info!(target: "chronos", "Ctrl-C received"),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await.context("cannot listen for Ctrl-C")?;
    Ok(())
}

// ─── Authentication middleware ────────────────────────────────────────────────

/// Require a fresh nonce and a valid request MAC.
///
/// The body must be buffered to authenticate it, which is why the request is
/// decomposed and rebuilt. That is unavoidable: a MAC that did not cover the body
/// would let an attacker swap the payload under a captured header.
async fn auth_middleware(
    State(app): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    let nonce_hex = req
        .headers()
        .get("X-Chronos-Nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_owned();

    // 24 hex chars = 96 bits, wide enough that random nonces do not collide
    // within the cache window.
    if nonce_hex.len() != 24 || hex::decode(&nonce_hex).map(|b| b.len()) != Ok(12) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hex::decode(&nonce_hex).map_err(|_| StatusCode::UNAUTHORIZED)?);

    let mac_hex = req
        .headers()
        .get("X-Chronos-Auth")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 256 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

    if let Some(key) = app.auth_key.as_ref() {
        let presented = mac_hex.ok_or(StatusCode::UNAUTHORIZED)?;
        crypto::verify_request_mac(key, &method, &path, &nonce_hex, &bytes, &presented).map_err(
            |_| {
                warn!(target: "chronos", %path, "request rejected: authentication failed");
                StatusCode::UNAUTHORIZED
            },
        )?;
    }

    // Replay check *after* authentication, so an unauthenticated caller cannot
    // consume nonce-cache slots and evict legitimate entries.
    if !app.nonce_cache.lock().await.check_and_insert(&nonce) {
        warn!(target: "chronos", %path, "request rejected: replayed nonce");
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(Request::from_parts(parts, axum::body::Body::from(bytes))).await)
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct StatusResponse {
    state: AgentState,
    mission_id: String,
    /// Ledger records so far.
    containment_events: u64,
    /// Admitted / denied counts.
    admitted: u64,
    denied: u64,
    /// Hash-chain head over the full containment ledger.
    containment_chain_head: String,
    /// Whether an erasure attestation is available at `/attestation`.
    attested: bool,
}

async fn status_handler(State(app): State<AppState>) -> Json<StatusResponse> {
    let (admitted, denied) = app.sm.counters().await;
    Json(StatusResponse {
        state: app.sm.current().await,
        mission_id: app.mission.mission_id.clone(),
        containment_events: app.sm.ledger_len().await,
        admitted,
        denied,
        containment_chain_head: app.sm.chain_head_hex().await,
        attested: app.attestation.lock().await.is_some(),
    })
}

/// Start the mission.
async fn init_handler(State(app): State<AppState>) -> Response {
    if let Err(e) = app.sm.arm_to_active().await {
        warn!(target: "chronos", error = %e, "init refused");
        return (StatusCode::CONFLICT, Json(e.to_string())).into_response();
    }
    tokio::spawn(run_mission(app));
    (StatusCode::ACCEPTED, Json("mission initialised")).into_response()
}

/// The protocol loop. Any failure erases.
async fn run_mission(app: AppState) {
    if let Err(e) = run_mission_inner(&app).await {
        error!(target: "chronos", error = %e, "mission failed — erasing");
        metrics::error_count().inc();
    }
    app.sm.force_erased().await;
    info!(target: "chronos", "mission complete — agent erased");
}

async fn run_mission_inner(app: &AppState) -> Result<()> {
    let cfg = &app.cfg;
    let mission = &app.mission;

    // ── 1. Inputs ────────────────────────────────────────────────────────────
    let ct = crypto::load_ct_sk(&cfg.paths.ct_sk)
        .await
        .with_context(|| format!("cannot load sealed key '{}'", cfg.paths.ct_sk))?;

    let salt = if cfg.network.fetch_live_beacon {
        let beacon = drand_client::fetch_latest_randomness(
            &cfg.network.drand_url,
            cfg.network.drand_timeout_secs,
        )
        .await
        .context("drand fetch failed")?;
        drand_client::verified_salt(&beacon)
            .context("drand beacon failed verification")?
            .to_vec()
    } else {
        crypto::read_secret_file(&cfg.paths.salt)
            .await
            .with_context(|| format!("cannot load salt '{}'", cfg.paths.salt))?
    };

    let cert = MpcCertificate::load(&cfg.paths.cert_n).context("modulus invalid")?;

    // ── 2. FHE keys ──────────────────────────────────────────────────────────
    let fhe = Arc::clone(&app.fhe);
    tokio::task::spawn_blocking(move || fhe.generate_and_install_keys())
        .await
        .context("FHE key generation panicked")?
        .context("FHE key generation failed")?;
    info!(target: "chronos", "FHE keys generated");

    // ── 3. VDF, interruptible ────────────────────────────────────────────────
    let g = BigUint::from(2u32);
    let n = cert.n.clone();
    let t = mission.t_vdf_steps;
    let abort = app.sm.abort_flag();

    info!(target: "chronos", t, "evaluating VDF");
    let (y, vdf_proof) = {
        let g = g.clone();
        let n = n.clone();
        tokio::task::spawn_blocking(move || {
            WesolowskiVdf::evaluate_interruptible(&g, t, &n, &abort)
        })
        .await
        .context("VDF task panicked")?
        .context("VDF evaluation failed or was aborted")?
    };

    // ── 4. Verify the VDF natively, in O(log T) ──────────────────────────────
    //
    // This is why the circuit does not need 2048-bit modular arithmetic: the
    // Wesolowski equation is checked here, cheaply, and the circuit only binds the
    // `y` that was checked.
    if !WesolowskiVdf.verify(&g, &y, &vdf_proof, t, &n) {
        anyhow::bail!("VDF self-verification failed — refusing to proceed");
    }
    info!(target: "chronos", "VDF complete and self-verified");

    // The circuit fixes `y` at a known width.
    let y_bytes = fixed_width_be(&y, chronos_snark::circuit::Y_BYTES)
        .context("VDF output does not fit the circuit's fixed width")?;

    // ── 5. Open the sealed key into locked memory ────────────────────────────
    let k_enc = ChronosAead::derive_key(&y_bytes, &salt);
    let opened = ChronosAead::decrypt(&k_enc, &ct)
        .context("sealed key failed to open — wrong VDF output, wrong salt, or tampered ct_sk")?;
    let sk_bytes = poseidon::join32(&[opened[0], opened[1]])
        .context("opened plaintext is not a 32-byte key")?;

    // From here the key exists only inside `LockedBytes`: mlock'd against swap and
    // triple-pass wiped on drop. No plain `Vec<u8>` copy is made.
    let sk_locked = LockedBytes::new(sk_bytes.to_vec()).context("cannot mlock the secret key")?;

    // ── 6. Check it against the provisioner's commitment ─────────────────────
    let [_, _, sk_commit, _] = mission.commitments().context("mission artifact malformed")?;
    let observed = poseidon::hash(
        poseidon::Domain::SecretKey,
        &poseidon::split32(&sk_bytes),
    );
    if observed != sk_commit {
        anyhow::bail!(
            "opened key does not match the mission artifact's sk_commit — \
             the artifact and ct_sk.bin are from different provisioning runs"
        );
    }
    info!(target: "chronos", "sealed key opened and matched against sk_commit");

    // ── 7. EAIP, from the same y ─────────────────────────────────────────────
    let mission_digest = mission_id_to_bytes(&mission.mission_id);
    let root = identity_root(&y_bytes, &mission_digest);
    *app.identity_root.lock().await = Some(root);

    app.sm
        .identity
        .lock()
        .await
        .initialize(
            fr_to_bytes32(root),
            mission.mission_id.clone(),
            mission.t_seconds,
        )
        .context("EAIP initialisation failed")?;

    // Prove identity now, while `y` is still available, and cache the proof.
    // After erasure the witness is gone, so the proof cannot be regenerated —
    // which is the intended behaviour, not a limitation.
    {
        let y_for_id = y_bytes.clone();
        let md = mission_digest;
        let (id_prover, id_proof) =
            tokio::task::spawn_blocking(move || -> Result<(IdentityProver, Vec<u8>)> {
                let mut p = IdentityProver::new();
                p.setup_local_development()
                    .map_err(|e| anyhow::anyhow!("identity setup failed: {e}"))?;
                let proof = p
                    .prove_identity(&y_for_id, &md)
                    .map_err(|e| anyhow::anyhow!("identity proving failed: {e}"))?;
                Ok((p, proof))
            })
            .await
            .context("identity task panicked")??;

        // Self-check before publishing: an identity proof that does not verify
        // against its own root is worse than none, because a verifier would read
        // the failure as the agent being an impostor.
        if !id_prover
            .verify_identity(&id_proof, root)
            .unwrap_or(false)
        {
            anyhow::bail!("identity proof failed self-verification — refusing to publish it");
        }

        *app.identity_prover.lock().await = Some(id_prover);
        *app.identity_proof.lock().await = Some(id_proof);
    }
    info!(target: "chronos", "EAIP identity established and self-verified");

    app.sm.active_to_locked().await.context("state transition failed")?;

    // ── 8. Erase, then attest ────────────────────────────────────────────────
    //
    // Ordering: the containment monitor must reach its terminal state *before* the
    // summary is taken, because the circuit enforces that the summary is terminal.
    // The key must still be held when the proof is generated, because the circuit
    // requires it as a witness. So: erase the monitor, snapshot the summary, prove
    // with the still-live key, then drop the key.
    app.sm.force_erased().await;
    let summary = app.sm.containment_summary().await;

    let witness = ErasureWitness {
        y: y_bytes,
        salt,
        ct,
        sk: sk_bytes,
        // The post-wipe state the circuit checks. `LockedBytes` writes exactly this
        // pattern on drop; the constant is shared so the two cannot disagree.
        m_post: vec![WIPE_PATTERN; SK_BYTES],
        mission_digest,
        containment: summary,
    };

    let pk_path = cfg.paths.proving_key.clone();
    let public_inputs = mission
        .to_public_inputs(summary.commitment())
        .context("cannot assemble public inputs")?;

    let (proof, verifying_key) = tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, Vec<u8>)> {
        let prover = load_or_create_prover(&pk_path)?;
        let proof = prover
            .prove_erasure(&witness)
            .map_err(|e| anyhow::anyhow!("erasure proving failed: {e}"))?;
        let vk = prover
            .verifying_key_bytes()
            .map_err(|e| anyhow::anyhow!("verifying key export failed: {e}"))?;
        Ok((proof, vk))
    })
    .await
    .context("proving task panicked")??;

    info!(target: "chronos", proof_bytes = proof.len(), "erasure proof generated");

    *app.attestation.lock().await = Some(Attestation {
        proof,
        public_inputs,
        verifying_key,
    });

    // Explicit drop so the wipe is visibly part of the protocol rather than an
    // accident of scope. `LockedBytes::drop` performs the triple-pass volatile
    // overwrite and then munlocks.
    drop(sk_locked);
    info!(target: "chronos", "secret key wiped");

    Ok(())
}

/// Load the persisted proving key, or run setup once and persist it.
///
/// Persistence is what makes third-party verification possible. It also means the
/// single-party setup limitation is a *deployment* property, recorded in one file,
/// rather than something regenerated invisibly per mission.
fn load_or_create_prover(path: &str) -> Result<Groth16Prover> {
    if std::path::Path::new(path).exists() {
        let p = Groth16Prover::load(path)
            .map_err(|e| anyhow::anyhow!("cannot load proving key '{path}': {e}"))?;
        info!(target: "chronos", %path, "proving key loaded");
        return Ok(p);
    }

    warn!(
        target: "chronos",
        %path,
        "no proving key found — running a SINGLE-PARTY trusted setup. Whoever runs this holds \
         the trapdoor and can forge proofs under the resulting key. Replace with a real \
         multi-party ceremony before any deployment where the verifier does not trust this host."
    );
    let mut transcript = SetupTranscript::new();
    transcript.contribute(&SetupContribution::generate("agent-local-setup"));
    let mut p = Groth16Prover::new();
    p.setup_with_transcript(&transcript)
        .map_err(|e| anyhow::anyhow!("trusted setup failed: {e}"))?;
    p.save(path)
        .map_err(|e| anyhow::anyhow!("cannot persist proving key '{path}': {e}"))?;
    info!(target: "chronos", %path, "proving key generated and persisted");
    Ok(p)
}

/// Encode a field element as exactly 32 big-endian bytes.
///
/// `IdentityManager` stores the root in an mlock'd 32-byte page, so the
/// full-width field element is narrowed here rather than at the call site.
fn fr_to_bytes32(f: Fr) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    let be = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(be.len());
    out[start..].copy_from_slice(&be[be.len().saturating_sub(32)..]);
    out
}

/// Left-pad a big-endian integer to a fixed width.
fn fixed_width_be(v: &BigUint, len: usize) -> Result<Vec<u8>> {
    let be = v.to_bytes_be();
    if be.len() > len {
        anyhow::bail!("value is {} bytes, exceeding fixed width {len}", be.len());
    }
    let mut out = vec![0u8; len];
    out[len - be.len()..].copy_from_slice(&be);
    Ok(out)
}

/// FHE inference, gated by the containment monitor.
async fn infer_handler(State(app): State<AppState>, body: Bytes) -> Response {
    // Admission control first. A denial is recorded in the ledger, so probing is
    // visible in the attestation rather than merely rejected.
    let decision = app
        .sm
        .admit(Event::Infer {
            declared_secs: 1,
            // One 64-bit output element.
            disclosure_bits: 64,
        })
        .await;
    if let chronos_core::containment::Decision::Deny(reason) = decision {
        warn!(target: "chronos", %reason, "inference denied by containment monitor");
        return (StatusCode::FORBIDDEN, Json(reason.to_string())).into_response();
    }

    let timer = metrics::fhe_inference_latency().start_timer();
    let result = app.fhe.evaluate_ciphertext(&body);
    timer.observe_duration();

    match result {
        Ok(out) => (StatusCode::OK, out).into_response(),
        Err(e) => {
            error!(target: "chronos", error = %e, "inference failed");
            metrics::error_count().inc();
            (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string())).into_response()
        }
    }
}

/// Verify a submitted erasure proof against this mission's public inputs.
async fn verify_handler(State(app): State<AppState>, body: Bytes) -> Response {
    const MAX_FAILURES: u32 = 5;

    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, Json("empty proof")).into_response();
    }
    if *app.verify_failures.lock().await >= MAX_FAILURES {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json("verify locked after repeated failures"),
        )
            .into_response();
    }

    let guard = app.attestation.lock().await;
    let Some(att) = guard.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json("no attestation yet — mission has not completed"),
        )
            .into_response();
    };

    let prover = match Groth16Prover::load(&app.cfg.paths.proving_key) {
        Ok(p) => p,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string())).into_response()
        }
    };

    match prover.verify_erasure(&body, &att.public_inputs) {
        Ok(true) => {
            *app.verify_failures.lock().await = 0;
            (StatusCode::OK, Json("proof verified")).into_response()
        }
        Ok(false) => {
            *app.verify_failures.lock().await += 1;
            (StatusCode::UNPROCESSABLE_ENTITY, Json("proof invalid")).into_response()
        }
        Err(e) => {
            *app.verify_failures.lock().await += 1;
            (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string())).into_response()
        }
    }
}

#[derive(Serialize)]
struct AttestationResponse {
    mission_id: String,
    /// Compressed Groth16 proof, hex.
    proof: String,
    /// Public inputs in ABI order, as 32-byte hex words.
    public_inputs: Vec<String>,
    /// arkworks-encoded verifying key, hex.
    verifying_key: String,
    /// EVM calldata for `ChronosRegistry.attestErasure`.
    evm_proof: String,
    evm_public_inputs: Vec<String>,
    /// Restated on every response, because this is where a reader is most likely
    /// to over-interpret an accepted proof.
    trust_note: String,
}

/// Serve the completed erasure attestation.
async fn attestation_handler(State(app): State<AppState>) -> Response {
    let guard = app.attestation.lock().await;
    let Some(att) = guard.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json("no attestation yet — mission has not completed"),
        )
            .into_response();
    };

    let evm_inputs = erasure_public_inputs(&att.public_inputs).to_vec();

    // Failure here means the stored proof is corrupt, which is a server fault.
    let evm_proof = match export_proof_bytes(&att.proof) {
        Ok(p) => p.to_calldata_args(),
        Err(e) => {
            error!(target: "chronos", error = %e, "EVM proof export failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string())).into_response();
        }
    };

    (
        StatusCode::OK,
        Json(AttestationResponse {
            mission_id: app.mission.mission_id.clone(),
            proof: hex::encode(&att.proof),
            public_inputs: att.public_inputs.to_vec().into_iter().map(fr_to_hex).collect(),
            verifying_key: hex::encode(&att.verifying_key),
            evm_proof,
            evm_public_inputs: evm_inputs,
            trust_note:
                "An accepted proof shows the prover knew the key that opens the committed \
                 ciphertext under a key derived from the committed VDF output, and that the \
                 containment monitor terminated erased with all capabilities revoked. It does \
                 NOT show no copy of the key survives — that rests on the F_OS assumption. The \
                 trusted setup is single-party, so the setup operator can forge proofs."
                    .into(),
        }),
    )
        .into_response()
}

#[derive(Serialize)]
struct IdentityResponse {
    mission_id: String,
    /// Full-width identity root, hex.
    identity_root: String,
    /// Zero-knowledge proof of knowledge of the VDF output behind the root.
    zk_proof: String,
    /// ML-DSA (Dilithium3) public key, hex.
    pq_public_key: String,
    /// ML-DSA signature over the identity root and mission ID.
    pq_signature: String,
}

/// Serve the EAIP identity proof.
async fn identity_proof_handler(State(app): State<AppState>) -> Response {
    let decision = app.sm.admit(Event::IdentityAttest).await;
    if let chronos_core::containment::Decision::Deny(reason) = decision {
        return (StatusCode::GONE, Json(reason.to_string())).into_response();
    }

    let root = match *app.identity_root.lock().await {
        Some(r) => r,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json("identity not established — mission has not reached the VDF output"),
            )
                .into_response()
        }
    };

    let zk = match app.identity_proof.lock().await.clone() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json("identity proof unavailable"),
            )
                .into_response()
        }
    };

    let sm_id = app.sm.identity.lock().await;
    let pq_sig = match sm_id.sign_identity() {
        Ok(s) => s,
        Err(e) => return (StatusCode::GONE, Json(e.to_string())).into_response(),
    };
    let pq_pk = sm_id.public_key_bytes().unwrap_or(&[]).to_vec();

    (
        StatusCode::OK,
        Json(IdentityResponse {
            mission_id: app.mission.mission_id.clone(),
            identity_root: fr_to_hex(root),
            zk_proof: hex::encode(&zk),
            pq_public_key: hex::encode(&pq_pk),
            pq_signature: hex::encode(&pq_sig),
        }),
    )
        .into_response()
}

// ─── Metrics ──────────────────────────────────────────────────────────────────

async fn serve_metrics(addr: &str) {
    let app = Router::new().route("/metrics", get(metrics_endpoint));
    match TcpListener::bind(addr).await {
        Ok(l) => {
            info!(target: "chronos", metrics_addr = %addr, "metrics listening");
            axum::serve(l, app).await.ok();
        }
        Err(e) => error!(target: "chronos", error = %e, "metrics server failed to start"),
    }
}

async fn metrics_endpoint() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        render_metrics(),
    )
}
