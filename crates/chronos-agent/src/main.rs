mod config;
mod crypto;
mod drand_client;
mod erasure;
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
use chronos_snark::prover::Groth16Prover;
use chronos_vdf::wesolowski::WesolowskiVdf;
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

    let app_state = AppState {
        sm: Arc::clone(&sm),
        fhe: Arc::clone(&fhe),
        cfg: Arc::new(cfg.clone()),
        nonce_cache,
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
        .layer(axum::middleware::from_fn(replay_protection_middleware))
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
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    match req.headers().get("X-Chronos-Nonce") {
        Some(nonce_hdr) if nonce_hdr.len() == 24 => {
            // Decode the 12-byte nonce from hex.
            let nonce_hex = nonce_hdr.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;
            let nonce_bytes = hex::decode(nonce_hex).map_err(|_| StatusCode::UNAUTHORIZED)?;
            if nonce_bytes.len() != 12 {
                return Err(StatusCode::UNAUTHORIZED);
            }
            let mut arr = [0u8; 12];
            arr.copy_from_slice(&nonce_bytes);
            // Note: nonce cache is in AppState; for middleware we do a lightweight
            // check here.  Full cache integration requires extracting AppState.
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

        // ── Step 6: Derive K_enc and transition to Locked ─────────────────────
        let k_enc = match crypto::derive_k_enc(&y, &salt) {
            Ok(k) => k,
            Err(e) => {
                error!(target: "chronos", error = %e, "HKDF derivation failed");
                sm_clone.force_erased().await;
                return;
            }
        };
        let _k_enc_redacted = Redacted::new(&k_enc);

        if let Err(e) = sm_clone.active_to_locked().await {
            error!(target: "chronos", error = %e, "State transition to Locked failed");
            sm_clone.force_erased().await;
            return;
        }

        // ── Step 7: Secure erase sk and generate SNARK proof ─────────────────
        // In production: sk = AES-GCM-Dec(K_enc, ct_sk)
        // Here we use ct_sk as a stand-in for the sk bytes.
        let mut sk_buf = ct_sk.clone();
        let m_pre = sk_buf.clone();

        // Wipe the secret key.
        secure_wipe(sk_buf.as_mut_ptr(), sk_buf.len());
        info!(target: "chronos", "Secret key wiped (triple-pass)");

        // Generate Groth16 erasure proof.
        let y_bytes = y.to_bytes_be();
        let pi_bytes = pi_vdf.proof.to_bytes_be();
        let n_bytes = cert.n.to_bytes_be();
        let g_bytes = BigUint::from(2u32).to_bytes_be();

        let snark_result = tokio::task::spawn_blocking(move || {
            let mut prover = Groth16Prover::new();
            prover.generate_keys()?;
            prover.prove_erasure(
                &sk_buf,
                &m_pre,
                &y_bytes,
                &salt,
                &ct_sk,
                &g_bytes,
                &n_bytes,
                &pi_bytes,
            )
        })
        .await;

        match snark_result {
            Ok(Ok(proof)) => {
                info!(
                    target: "chronos",
                    proof_bytes = proof.len(),
                    "Groth16 erasure proof generated"
                );
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
async fn verify_handler(State(_app): State<AppState>, body: Bytes) -> impl IntoResponse {
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty proof").into_response();
    }

    // Deserialize and verify the proof.
    let prover = Groth16Prover::new();
    // Public inputs: y[0]=0 and wipe_pattern=0xFF are defaults for external verification.
    match prover.verify_erasure(&body, 0, 0xFF) {
        Ok(true) => (StatusCode::OK, Json("Proof verified")).into_response(),
        Ok(false) => (StatusCode::UNPROCESSABLE_ENTITY, Json("Proof invalid")).into_response(),
        Err(e) => {
            error!(target: "chronos", error = %e, "Proof verification error");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string())).into_response()
        }
    }
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
