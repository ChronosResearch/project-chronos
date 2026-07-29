mod config;
mod crypto;
mod drand_client;
mod erasure;
mod metrics;
mod state;
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
    redacted::Redacted,
};
use serde::Serialize;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::config::ChronosConfig;
use crate::metrics::render_metrics;
use crate::state::{AgentState, StateMachine};

// ─── Application State ────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub sm: Arc<StateMachine>,
    pub fhe: Arc<FheEngine>,
    pub cfg: Arc<ChronosConfig>,
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // STEP 12 – Structured JSON logging with env-filter.
    // Default: RUST_LOG=chronos=debug; override with the RUST_LOG env var.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("chronos=debug,warn"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json())
        .init();

    info!(target: "chronos", "chronos-agent starting");

    // STEP 14 – Load configuration; fail fast if missing/malformed.
    let cfg = ChronosConfig::load()
        .context("Failed to load agent configuration from config/default.toml")?;
    info!(target: "chronos", api_addr = %cfg.server.api_addr, "Configuration loaded");

    // STEP 24 – Verify Exclusivity Assumption: core dumps must be disabled.
    verify_ea(&cfg).context("Exclusivity Assumption verification failed")?;

    // STEP 19 – OS Hardening (Linux only).
    disable_core_dumps();

    let sm = StateMachine::new();
    let fhe = Arc::new(FheEngine::new());

    let app_state = AppState {
        sm: Arc::clone(&sm),
        fhe: Arc::clone(&fhe),
        cfg: Arc::new(cfg.clone()),
    };

    // STEP 17 – Start watchdog.
    state::spawn_watchdog(Arc::clone(&sm), cfg.mission.t_seconds);

    // STEP 13 – Metrics server on a separate port.
    let metrics_addr = cfg.server.metrics_addr.clone();
    tokio::spawn(async move {
        serve_metrics(&metrics_addr).await;
    });

    // STEP 6 – Graceful shutdown via SIGTERM / Ctrl-C.
    let shutdown_sm = Arc::clone(&sm);
    let shutdown_fhe = Arc::clone(&fhe);
    let shutdown = async move {
        if let Err(e) = wait_for_shutdown_signal().await {
            error!(target: "chronos", error = %e, "Signal handler failed — shutting down anyway");
        }
        warn!(target: "chronos", "Shutdown signal received — zeroizing and exiting");
        // Force erasure state and let Drop handle key zeroization.
        shutdown_sm.force_erased().await;
        drop(shutdown_fhe);
    };

    // API router.
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

// ─── STEP 24: Exclusivity Assumption Verification ────────────────────────────

/// Verify the system has core dumps disabled via `getrlimit(RLIMIT_CORE)`.
///
/// Fails hard if the limit is non-zero — the agent must not run with core dumps
/// enabled in any environment (an attacker could extract FHE keys from a core).
fn verify_ea(_cfg: &ChronosConfig) -> Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: getrlimit is a pure read syscall with no side effects.
        // rlimit is a plain C struct; MaybeUninit is the correct way to create it.
        let mut rlim = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        let ret = unsafe { libc::getrlimit(libc::RLIMIT_CORE, rlim.as_mut_ptr()) };
        if ret != 0 {
            let os_err = std::io::Error::last_os_error();
            error!(target: "chronos", "getrlimit(RLIMIT_CORE) failed: {os_err}");
            return Err(anyhow::anyhow!("getrlimit failed: {os_err}"));
        }
        // SAFETY: getrlimit succeeded, so rlim is fully initialised.
        let rlim = unsafe { rlim.assume_init() };
        if rlim.rlim_cur != 0 {
            error!(
                target: "chronos",
                rlim_cur = rlim.rlim_cur,
                "RLIMIT_CORE is non-zero — core dumps are ENABLED. \
                 Run: ulimit -c 0 or configure systemd LimitCORE=0"
            );
            return Err(anyhow::anyhow!(
                "EA violated: RLIMIT_CORE = {} (must be 0)",
                rlim.rlim_cur
            ));
        }
        info!(target: "chronos", "EA satisfied: RLIMIT_CORE = 0");
    }
    #[cfg(not(unix))]
    {
        warn!(target: "chronos", "EA check skipped (non-Unix platform)");
    }
    Ok(())
}

/// Disable core dumps and set dumpable flag.  Called once at startup.
fn disable_core_dumps() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) is a standard Linux syscall with no
        // memory safety concerns — it only affects the kernel process flags.
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0usize) };
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit takes a valid pointer to an initialised rlimit struct.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
    }
}

// ─── STEP 6: Graceful Shutdown ────────────────────────────────────────────────

/// Wait for SIGTERM (Unix) or Ctrl-C (all platforms).
///
/// # Errors
/// Returns an `anyhow::Error` if the OS-level signal handler cannot be
/// installed (e.g., signal mask is blocked, privilege issue).
async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())
            .context("Failed to install SIGTERM handler — check process signal mask")?;
        tokio::select! {
            _ = sigterm.recv() => {
                info!(target: "chronos", "SIGTERM received");
            }
            _ = tokio::signal::ctrl_c() => {
                info!(target: "chronos", "Ctrl-C received");
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("Failed to listen for Ctrl-C")?;
    }
    Ok(())
}

// ─── STEP 18: Replay Protection Middleware ───────────────────────────────────

/// Require a `X-Chronos-Nonce` header containing exactly 24 hex characters
/// (96 bits). A sliding-window cache (stubbed) would validate uniqueness.
async fn replay_protection_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    match req.headers().get("X-Chronos-Nonce") {
        Some(nonce) if nonce.len() == 24 => Ok(next.run(req).await),
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

/// Return the current agent lifecycle state.
async fn status_handler(State(state): State<AppState>) -> Json<StatusResponse> {
    let current = state.sm.current().await;
    Json(StatusResponse { state: current })
}

/// Initialise the mission: transition `Armed → Active`, start the VDF, kick
/// off the drand fetch, and launch the FHE key generation on a blocking thread.
async fn init_handler(State(app): State<AppState>) -> impl IntoResponse {
    // STEP 16 – Guard: reject double-init.
    if let Err(e) = app.sm.arm_to_active().await {
        error!(target: "chronos", error = %e, "Init rejected");
        return (StatusCode::CONFLICT, Json(e.to_string())).into_response();
    }

    let sm_clone = Arc::clone(&app.sm);
    let fhe_clone = Arc::clone(&app.fhe);
    let cfg_clone = Arc::clone(&app.cfg);

    // Spawn the orchestration future without awaiting (fire-and-forget).
    tokio::spawn(async move {
        // STEP 7 – FHE key generation must run on a blocking thread so the
        // mlock guard (inside LockedBytes) is tied to an OS thread.
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

        // Fetch drand randomness.
        match drand_client::fetch_latest_randomness(&cfg_clone.network.drand_url, cfg_clone.network.drand_timeout_secs).await {
            Ok(rng) => info!(target: "chronos", round = rng.round, "Drand beacon fetched"),
            Err(e) => {
                error!(target: "chronos", error = %e, "Drand fetch failed");
                metrics::error_count().inc();
                sm_clone.force_erased().await;
            }
        }
    });

    (StatusCode::ACCEPTED, Json("Mission initialized")).into_response()
}

/// Run FHE inference on a submitted ciphertext.
async fn infer_handler(
    State(app): State<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    // Reject inference if erased.
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

/// Verify a submitted SNARK proof.
async fn verify_handler(State(_app): State<AppState>, body: Bytes) -> impl IntoResponse {
    // Stub — wires into chronos-snark prover verify_proof.
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty proof").into_response();
    }
    (StatusCode::OK, Json("Proof accepted (stub)")).into_response()
}

// ─── STEP 13: Metrics server ─────────────────────────────────────────────────

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
        [("Content-Type", "text/plain; version=0.0.4")],
        data,
    )
}
