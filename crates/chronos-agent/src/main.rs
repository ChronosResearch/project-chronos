mod config;
mod crypto;
mod drand_client;
mod erasure;
mod identity;
mod metrics;
mod state;
mod tls;
mod vdf_task;

use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chronos_core::{
    fhe::FheEngine,
    mpc::MpcCertificate,
    redacted::Redacted,
    wipe::secure_wipe,
    VdfEngine,
};
use chronos_snark::identity_circuit::IdentityProver;
use chronos_snark::prover::Groth16Prover;
use chronos_vdf::wesolowski::{generate_identity_root, WesolowskiVdf};
use num_bigint::BigUint;
use serde::Serialize;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use zeroize::Zeroize;

use crate::config::{ChronosConfig, TlsConfig};
use crate::metrics::render_metrics;
use crate::state::{AgentState, StateMachine};
use crate::tls::NonceCache;

// ─── Application State ────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub sm: Arc<StateMachine>,
    pub fhe: Arc<FheEngine>,
    pub cfg: Arc<ChronosConfig>,
    /// Sliding-window nonce cache for replay protection.
    pub nonce_cache: Arc<Mutex<NonceCache>>,
    /// Groth16 prover with keys loaded — shared for verify_handler.
    /// `None` until the first mission init completes key generation.
    pub snark_prover: Arc<Mutex<Option<Groth16Prover>>>,
    /// First byte of the VDF output y — used as SNARK public input in verify_handler.
    pub y_first_byte: Arc<Mutex<u8>>,
    /// EAIP identity prover — shared for /identity/proof.
    /// `None` until the first mission init completes.
    pub identity_prover: Arc<Mutex<Option<IdentityProver>>>,
    /// Failed verify attempts counter — locked after 5 consecutive failures.
    pub verify_failures: Arc<Mutex<u32>>,
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("chronos=debug,warn"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json())
        .init();

    info!(target: "chronos", "chronos-agent starting");

    let cfg = ChronosConfig::load()
        .context("Failed to load agent configuration from config/default.toml")?;
    info!(target: "chronos", api_addr = %cfg.server.api_addr, "Configuration loaded");

    // Verify Exclusivity Assumption: core dumps must be disabled.
    verify_ea(&cfg).context("Exclusivity Assumption verification failed")?;
    disable_core_dumps();

    // Validate TLS configuration.
    let tls_cfg = TlsConfig::default(); // loaded from config in production
    tls::validate_tls_config(&tls_cfg)
        .context("TLS configuration validation failed")?;

    let sm = StateMachine::new();
    let fhe = Arc::new(FheEngine::new());
    let nonce_cache = Arc::new(Mutex::new(NonceCache::new(1024)));
    let snark_prover: Arc<Mutex<Option<Groth16Prover>>> = Arc::new(Mutex::new(None));
    let y_first_byte: Arc<Mutex<u8>> = Arc::new(Mutex::new(0u8));
    let identity_prover: Arc<Mutex<Option<IdentityProver>>> = Arc::new(Mutex::new(None));
    let verify_failures: Arc<Mutex<u32>> = Arc::new(Mutex::new(0u32));

    let app_state = AppState {
        sm: Arc::clone(&sm),
        fhe: Arc::clone(&fhe),
        cfg: Arc::new(cfg.clone()),
        nonce_cache,
        snark_prover: Arc::clone(&snark_prover),
        y_first_byte: Arc::clone(&y_first_byte),
        identity_prover: Arc::clone(&identity_prover),
        verify_failures: Arc::clone(&verify_failures),
    };

    state::spawn_watchdog(Arc::clone(&sm), cfg.mission.t_seconds);

    let metrics_addr = cfg.server.metrics_addr.clone();
    tokio::spawn(async move {
        serve_metrics(&metrics_addr).await;
    });

    let shutdown_sm = Arc::clone(&sm);
    let shutdown_fhe = Arc::clone(&fhe);
    let shutdown = async move {
        if let Err(e) = wait_for_shutdown_signal().await {
            error!(target: "chronos", error = %e, "Signal handler failed — shutting down anyway");
        }
        warn!(target: "chronos", "Shutdown signal received — zeroizing and exiting");
        shutdown_sm.force_erased().await;
        drop(shutdown_fhe);
    };

    let app = Router::new()
        .route("/status", get(status_handler))
        .route("/mission/init", post(init_handler))
        .route("/infer", post(infer_handler))
        .route("/verify", post(verify_handler))
        .route("/identity/proof", get(identity_proof_handler))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            replay_protection_middleware,
        ))
        .with_state(app_state);

    let listener = TcpListener::bind(&cfg.server.api_addr)
        .await
        .with_context(|| format!("Cannot bind to {}", cfg.server.api_addr))?;

    info!(target: "chronos", addr = %cfg.server.api_addr, "API server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("axum server error")?;

    Ok(())
}

// ─── Exclusivity Assumption ───────────────────────────────────────────────────

fn verify_ea(_cfg: &ChronosConfig) -> Result<()> {
    #[cfg(unix)]
    {
        let mut rlim = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        let ret = unsafe { libc::getrlimit(libc::RLIMIT_CORE, rlim.as_mut_ptr()) };
        if ret != 0 {
            let os_err = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!("getrlimit failed: {os_err}"));
        }
        let rlim = unsafe { rlim.assume_init() };
        if rlim.rlim_cur != 0 {
            return Err(anyhow::anyhow!(
                "EA violated: RLIMIT_CORE = {} (must be 0)",
                rlim.rlim_cur
            ));
        }
        info!(target: "chronos", "EA satisfied: RLIMIT_CORE = 0");
    }
    #[cfg(not(unix))]
    warn!(target: "chronos", "EA check skipped (non-Unix platform)");
    Ok(())
}

fn disable_core_dumps() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl and setrlimit are pure syscalls with no memory safety concerns.
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0usize) };
        let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
    }
}

// ─── Graceful Shutdown ────────────────────────────────────────────────────────

async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())
            .context("Failed to install SIGTERM handler")?;
        tokio::select! {
            _ = sigterm.recv() => info!(target: "chronos", "SIGTERM received"),
            _ = tokio::signal::ctrl_c() => info!(target: "chronos", "Ctrl-C received"),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .context("Failed to listen for Ctrl-C")?;
    Ok(())
}

// ─── Replay Protection Middleware ─────────────────────────────────────────────

/// Require a `X-Chronos-Nonce` header containing exactly 24 hex characters
/// (96 bits = 12 bytes).  The nonce is checked against the sliding-window
/// cache to prevent replay attacks.
async fn replay_protection_middleware(
    State(app): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    match req.headers().get("X-Chronos-Nonce") {
        Some(nonce_hdr) if nonce_hdr.len() == 24 => {
            let nonce_hex = nonce_hdr.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;
            let nonce_bytes = hex::decode(nonce_hex).map_err(|_| StatusCode::UNAUTHORIZED)?;
            if nonce_bytes.len() != 12 {
                return Err(StatusCode::UNAUTHORIZED);
            }
            let mut arr = [0u8; 12];
            arr.copy_from_slice(&nonce_bytes);

            // Check and record the nonce — rejects replays.
            let fresh = app.nonce_cache.lock().await.check_and_insert(&arr);
            if !fresh {
                warn!(target: "chronos", "Rejected request: replayed nonce");
                return Err(StatusCode::UNAUTHORIZED);
            }

            Ok(next.run(req).await)
        }
        Some(_) => {
            warn!(target: "chronos", "Rejected request: nonce wrong length");
            Err(StatusCode::UNAUTHORIZED)
        }
        None => {
            warn!(target: "chronos", "Rejected request: missing X-Chronos-Nonce");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

// ─── HTTP Handlers ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct StatusResponse {
    state: AgentState,
}

async fn status_handler(State(state): State<AppState>) -> Json<StatusResponse> {
    let current = state.sm.current().await;
    Json(StatusResponse { state: current })
}

/// Initialise the mission: transition `Armed → Active`, load `ct_sk.bin`,
/// start the VDF, fetch drand, generate FHE keys, and wire VDF output to
/// the SNARK prover.
async fn init_handler(State(app): State<AppState>) -> impl IntoResponse {
    if let Err(e) = app.sm.arm_to_active().await {
        error!(target: "chronos", error = %e, "Init rejected");
        return (StatusCode::CONFLICT, Json(e.to_string())).into_response();
    }

    let sm_clone = Arc::clone(&app.sm);
    let fhe_clone = Arc::clone(&app.fhe);
    let cfg_clone = Arc::clone(&app.cfg);
    let snark_prover_slot = Arc::clone(&app.snark_prover);
    let y_first_byte_slot = Arc::clone(&app.y_first_byte);
    let identity_prover_slot = Arc::clone(&app.identity_prover);

    tokio::spawn(async move {
        // ── Step 1: Load ct_sk.bin ────────────────────────────────────────────
        let ct_sk = match crypto::read_secret_file(&cfg_clone.crypto.ct_sk_path).await {
            Ok(bytes) => {
                info!(target: "chronos", path = %cfg_clone.crypto.ct_sk_path, "ct_sk.bin loaded");
                bytes
            }
            Err(e) => {
                error!(target: "chronos", error = %e, "Failed to load ct_sk.bin");
                metrics::error_count().inc();
                sm_clone.force_erased().await;
                return;
            }
        };

        // ── Step 2: Load MPC certificate (certN.bin) ─────────────────────────
        let cert = match MpcCertificate::load(&cfg_clone.crypto.cert_n_path) {
            Ok(c) => {
                info!(target: "chronos", "MPC certificate loaded");
                c
            }
            Err(e) => {
                error!(target: "chronos", error = %e, "Failed to load certN.bin");
                metrics::error_count().inc();
                sm_clone.force_erased().await;
                return;
            }
        };

        // ── Step 3: FHE key generation ────────────────────────────────────────
        let fhe_result = tokio::task::spawn_blocking({
            let fhe = Arc::clone(&fhe_clone);
            move || fhe.generate_and_install_keys()
        })
        .await;

        match fhe_result {
            Ok(Ok(())) => info!(target: "chronos", "FHE keys generated"),
            Ok(Err(e)) => {
                error!(target: "chronos", error = %e, "FHE key gen failed");
                metrics::error_count().inc();
                sm_clone.force_erased().await;
                return;
            }
            Err(e) => {
                error!(target: "chronos", error = %e, "FHE spawn_blocking panicked");
                metrics::error_count().inc();
                sm_clone.force_erased().await;
                return;
            }
        }

        // ── Step 4: Fetch drand randomness ────────────────────────────────────
        let drand_resp = match drand_client::fetch_latest_randomness(
            &cfg_clone.network.drand_url,
            cfg_clone.network.drand_timeout_secs,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                error!(target: "chronos", error = %e, "Drand fetch failed");
                metrics::error_count().inc();
                sm_clone.force_erased().await;
                return;
            }
        };

        // Decode drand randomness as salt (32 bytes).
        let salt = match hex::decode(&drand_resp.randomness) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                error!(target: "chronos", "Drand randomness decode failed");
                sm_clone.force_erased().await;
                return;
            }
        };

        // ── Step 5: VDF evaluation ────────────────────────────────────────────
        let g = BigUint::from(2u32);
        let n = cert.n.clone();
        let t = cfg_clone.mission.t_vdf_steps;

        let vdf_result = tokio::task::spawn_blocking(move || {
            let vdf = WesolowskiVdf;
            vdf.evaluate(&g, t, &n)
        })
        .await;

        let (y, pi_vdf) = match vdf_result {
            Ok(Ok((y, pi))) => {
                info!(target: "chronos", "VDF evaluation complete");
                (y, pi)
            }
            Ok(Err(e)) => {
                error!(target: "chronos", error = %e, "VDF evaluation failed");
                metrics::error_count().inc();
                sm_clone.force_erased().await;
                return;
            }
            Err(e) => {
                error!(target: "chronos", error = %e, "VDF spawn_blocking panicked");
                metrics::error_count().inc();
                sm_clone.force_erased().await;
                return;
            }
        };

        // ── Step 6: Derive K_enc and decrypt ct_sk ───────────────────────────
        let k_enc = match crypto::derive_k_enc(&y, &salt) {
            Ok(k) => k,
            Err(e) => {
                error!(target: "chronos", error = %e, "HKDF derivation failed");
                sm_clone.force_erased().await;
                return;
            }
        };
        let _k_enc_redacted = Redacted::new(&k_enc);

        // Decrypt the secret key from the ciphertext loaded in Step 1.
        // ct_sk layout: nonce (12 bytes) || ciphertext+tag.
        // Falls back to using ct_sk directly if it is not AES-GCM-wrapped
        // (prototype mode: ct_sk.bin contains the raw key).
        let sk_plaintext = match crypto::decrypt_ct_sk(&k_enc, &ct_sk) {
            Ok(plain) => {
                info!(target: "chronos", "ct_sk decrypted via AES-GCM-256");
                plain
            }
            Err(e) => {
                // Prototype fallback: ct_sk.bin is the raw key (no AES-GCM wrapper).
                // In production this branch must be removed and the error propagated.
                warn!(target: "chronos", error = %e, "AES-GCM decrypt failed — using ct_sk as raw key (prototype mode)");
                ct_sk.clone()
            }
        };

        // ── Step 6b: EAIP — initialize time-locked identity root ──────────────
        // R = SHA-256(y) where y is the VDF output.
        // The identity root is cryptographically bound to mission duration T.
        let mission_id = cfg_clone.mission.mission_id.clone();
        let expires_at = cfg_clone.mission.t_seconds
            + std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

        let identity_root = match generate_identity_root(
            &BigUint::from(2u32),
            cfg_clone.mission.t_vdf_steps,
            &cert.n,
        ) {
            Ok(r) => r,
            Err(e) => {
                error!(target: "chronos", error = %e, "EAIP identity root generation failed");
                metrics::error_count().inc();
                sm_clone.force_erased().await;
                return;
            }
        };

        if let Err(e) = sm_clone
            .identity
            .lock()
            .await
            .initialize(identity_root, mission_id.clone(), expires_at)
        {
            error!(target: "chronos", error = %e, "EAIP identity init failed");
            metrics::error_count().inc();
            sm_clone.force_erased().await;
            return;
        }
        info!(target: "chronos", "EAIP identity root initialized");

        // Generate ZK identity proof on a blocking thread.
        let y_for_id = y.to_bytes_be();
        let id_result = tokio::task::spawn_blocking(move || {
            let mut id_prover = IdentityProver::new();
            id_prover.generate_keys()?;
            let proof = id_prover.generate_identity_proof(
                &y_for_id,
                &mission_id,
                &identity_root,
            )?;
            Ok::<(IdentityProver, Vec<u8>), chronos_core::ChronosError>((id_prover, proof))
        })
        .await;

        match id_result {
            Ok(Ok((id_prover, proof))) => {
                info!(
                    target: "chronos",
                    proof_bytes = proof.len(),
                    "EAIP ZK identity proof generated"
                );
                *identity_prover_slot.lock().await = Some(id_prover);
            }
            Ok(Err(e)) => {
                error!(target: "chronos", error = %e, "EAIP identity proof generation failed");
                metrics::error_count().inc();
            }
            Err(e) => {
                error!(target: "chronos", error = %e, "EAIP identity spawn_blocking panicked");
                metrics::error_count().inc();
            }
        }

        if let Err(e) = sm_clone.active_to_locked().await {
            error!(target: "chronos", error = %e, "State transition to Locked failed");
            sm_clone.force_erased().await;
            return;
        }

        // ── Step 7: Secure erase sk and generate SNARK proof ─────────────────
        // sk_plaintext is the decrypted secret key (or prototype fallback).
        let mut sk_buf = sk_plaintext.clone();
        let m_pre = sk_buf.clone();

        // Capture y[0] before moving y into the SNARK thread.
        let y_first_byte = y.to_bytes_be().first().copied().unwrap_or(0);

        // Wipe the secret key buffer.
        // SAFETY: sk_buf is alive, ptr valid, no concurrent access during shutdown.
        unsafe { secure_wipe(sk_buf.as_mut_ptr(), sk_buf.len()); }
        info!(target: "chronos", "Secret key wiped (triple-pass)");

        // Also wipe ct_sk — it held the plaintext stand-in and must not linger.
        let mut ct_sk_owned = ct_sk;
        unsafe { secure_wipe(ct_sk_owned.as_mut_ptr(), ct_sk_owned.len()); }
        drop(ct_sk_owned);

        // Generate Groth16 erasure proof.
        let y_bytes = y.to_bytes_be();
        let pi_bytes = pi_vdf.proof.to_bytes_be();
        let n_bytes = cert.n.to_bytes_be();
        let g_bytes = BigUint::from(2u32).to_bytes_be();
        // Zeroed stand-in ciphertext for SNARK witness (no real AES-GCM yet).
        let ct_sk_witness = vec![0u8; 48];

        let snark_result = tokio::task::spawn_blocking(move || {
            let mut prover = Groth16Prover::new();
            prover.generate_keys()?;
            let proof = prover.prove_erasure(
                &sk_buf,
                &m_pre,
                &y_bytes,
                &salt,
                &ct_sk_witness,
                &g_bytes,
                &n_bytes,
                &pi_bytes,
            )?;
            Ok::<(Groth16Prover, Vec<u8>), chronos_core::ChronosError>((prover, proof))
        })
        .await;

        match snark_result {
            Ok(Ok((prover, proof))) => {
                info!(
                    target: "chronos",
                    proof_bytes = proof.len(),
                    "Groth16 erasure proof generated"
                );
                // Store the prover (with loaded VK) so verify_handler can use it.
                *snark_prover_slot.lock().await = Some(prover);
                // Store y[0] so verify_handler uses the real public input.
                *y_first_byte_slot.lock().await = y_first_byte;
            }
            Ok(Err(e)) => {
                error!(target: "chronos", error = %e, "SNARK proof generation failed");
                metrics::error_count().inc();
            }
            Err(e) => {
                error!(target: "chronos", error = %e, "SNARK spawn_blocking panicked");
                metrics::error_count().inc();
            }
        }

        // Zeroize K_enc before dropping.
        let mut k_enc_mut = k_enc;
        k_enc_mut.zeroize();

        sm_clone.force_erased().await;
        info!(target: "chronos", "Mission complete — agent erased");
    });

    (StatusCode::ACCEPTED, Json("Mission initialized")).into_response()
}

/// Run FHE inference on a submitted ciphertext.
async fn infer_handler(
    State(app): State<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    if app.sm.current().await == AgentState::Erased {
        return (StatusCode::GONE, Json("Agent erased — inference unavailable")).into_response();
    }

    let timer = metrics::fhe_inference_latency().start_timer();
    let result = app.fhe.evaluate_ciphertext(&body);
    timer.observe_duration();

    match result {
        Ok(ct_out) => (StatusCode::OK, ct_out).into_response(),
        Err(e) => {
            error!(target: "chronos", error = %e, "FHE inference failed");
            metrics::error_count().inc();
            (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string())).into_response()
        }
    }
}

/// Verify a submitted Groth16 erasure proof.
///
/// Rate-limited: locks after 5 consecutive failures to prevent proof-probing.
/// Returns 429 when locked.
async fn verify_handler(State(app): State<AppState>, body: Bytes) -> impl IntoResponse {
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty proof").into_response();
    }

    // Rate limit: reject if too many consecutive failures.
    const MAX_VERIFY_FAILURES: u32 = 5;
    {
        let failures = app.verify_failures.lock().await;
        if *failures >= MAX_VERIFY_FAILURES {
            warn!(target: "chronos", "Verify endpoint locked after {} consecutive failures", MAX_VERIFY_FAILURES);
            return (StatusCode::TOO_MANY_REQUESTS, Json("Verify endpoint locked — too many failed attempts")).into_response();
        }
    }

    let guard = app.snark_prover.lock().await;
    match guard.as_ref() {
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json("No verifying key loaded — run /mission/init first"),
        )
            .into_response(),
        Some(prover) => match prover.verify_erasure(&body, *app.y_first_byte.lock().await, 0xFF) {
            Ok(true) => {
                // Reset failure counter on success.
                *app.verify_failures.lock().await = 0;
                (StatusCode::OK, Json("Proof verified")).into_response()
            }
            Ok(false) => {
                *app.verify_failures.lock().await += 1;
                (StatusCode::UNPROCESSABLE_ENTITY, Json("Proof invalid")).into_response()
            }
            Err(e) => {
                *app.verify_failures.lock().await += 1;
                error!(target: "chronos", error = %e, "Proof verification error");
                (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string())).into_response()
            }
        },
    }
}


/// Return the EAIP zero-knowledge identity proof and PQ signature.
///
/// Returns 503 if no mission has run yet, 410 if the agent is erased.
async fn identity_proof_handler(State(app): State<AppState>) -> impl IntoResponse {
    use crate::identity::IdentityStatus;

    if app.sm.current().await == AgentState::Erased {
        return (StatusCode::GONE, Json("Agent erased — identity wiped")).into_response();
    }

    let id_guard = app.identity_prover.lock().await;
    let id_prover = match id_guard.as_ref() {
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json("Identity not initialized — run /mission/init first"),
            )
                .into_response();
        }
        Some(p) => p,
    };

    let sm_id = app.sm.identity.lock().await;
    let ir = match sm_id.identity_root.as_ref() {
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json("Identity root not available"),
            )
                .into_response();
        }
        Some(r) => r,
    };

    let root_arr: [u8; 32] = match ir.as_bytes().try_into() {
        Ok(a) => a,
        Err(_) => [0u8; 32],
    };

    let zk_proof = match id_prover.generate_identity_proof(
        ir.as_bytes(),
        &ir.mission_id,
        &root_arr,
    ) {
        Ok(p) => p,
        Err(e) => {
            error!(target: "chronos", error = %e, "Identity proof generation failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string())).into_response();
        }
    };

    let pq_sig = match sm_id.sign_identity() {
        Ok(s) => s,
        Err(e) => {
            error!(target: "chronos", error = %e, "PQ identity signing failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string())).into_response();
        }
    };

    let pq_pk = sm_id.public_key_bytes().unwrap_or(&[]).to_vec();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let status = IdentityStatus {
        mission_id: ir.mission_id.clone(),
        expires_at: ir.expires_at,
        expired: ir.is_expired(now),
        root_binding: hex::encode([ir.first_byte()]),
        pq_public_key: hex::encode(&pq_pk),
        zk_proof: hex::encode(&zk_proof),
        pq_signature: hex::encode(&pq_sig),
    };

    (StatusCode::OK, Json(status)).into_response()
}

// ─── Metrics server ───────────────────────────────────────────────────────────

async fn serve_metrics(addr: &str) {
    let app = Router::new().route("/metrics", get(metrics_endpoint));
    match TcpListener::bind(addr).await {
        Ok(listener) => {
            info!(target: "chronos", metrics_addr = %addr, "Metrics server listening");
            axum::serve(listener, app).await.ok();
        }
        Err(e) => error!(target: "chronos", error = %e, "Failed to start metrics server"),
    }
}

async fn metrics_endpoint() -> impl IntoResponse {
    let data = render_metrics();
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        data,
    )
}
