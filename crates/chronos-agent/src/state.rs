use chronos_core::{ChronosError, ChronosResult};
use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, Notify};
use tracing::{info, warn};

/// Current lifecycle state of the CHRONOS agent.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum AgentState {
    /// Agent is armed and waiting for mission init.
    Armed,
    /// VDF is running; FHE inference is available.
    Active,
    /// VDF completed; decrypting the secret key.
    Locked,
    /// Secret key has been erased; SNARK proof generated.
    Erased,
}

/// Thread-safe state machine wrapper.
///
/// All state transitions are serialised through the inner `Mutex`.
/// The `erased_notify` notifier is signalled when the agent transitions to
/// `Erased`, so the watchdog and inference handlers can wake immediately.
pub struct StateMachine {
    state: Mutex<AgentState>,
    /// Notified when any transition occurs (wake waiting tasks).
    pub erased_notify: Arc<Notify>,
    /// Mission start time — set on first `Armed -> Active` transition.
    start_time: Mutex<Option<Instant>>,
}

impl StateMachine {
    /// Create a new state machine in the `Armed` state.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(AgentState::Armed),
            erased_notify: Arc::new(Notify::new()),
            start_time: Mutex::new(None),
        })
    }

    /// Return the current state without blocking long.
    pub async fn current(&self) -> AgentState {
        *self.state.lock().await
    }

    /// Transition `Armed → Active`.
    ///
    /// # Errors
    /// Returns [`ChronosError::StateMachine`] if the current state is not `Armed`
    /// (prevents double-initialisation — STEP 16).
    pub async fn arm_to_active(&self) -> ChronosResult<()> {
        let mut guard = self.state.lock().await;
        if *guard != AgentState::Armed {
            return Err(ChronosError::StateMachine(format!(
                "Cannot transition to Active from {guard:?} — already initialised"
            )));
        }
        *guard = AgentState::Active;
        *self.start_time.lock().await = Some(Instant::now());
        info!(target: "chronos", "State → Active");
        Ok(())
    }

    /// Transition `Active → Locked`.
    pub async fn active_to_locked(&self) -> ChronosResult<()> {
        let mut guard = self.state.lock().await;
        if *guard != AgentState::Active {
            return Err(ChronosError::StateMachine(format!(
                "Cannot lock from {guard:?}"
            )));
        }
        *guard = AgentState::Locked;
        info!(target: "chronos", "State → Locked");
        Ok(())
    }

    /// Transition `Locked → Erased` (or force from any state).
    ///
    /// Also notifies all waiters so they can observe the state change.
    pub async fn force_erased(&self) {
        let mut guard = self.state.lock().await;
        *guard = AgentState::Erased;
        info!(target: "chronos", "State → Erased");
        self.erased_notify.notify_waiters();
    }

    /// Return elapsed time since `Active` was entered, or `None` if not yet started.
    pub async fn elapsed_secs(&self) -> Option<u64> {
        self.start_time
            .lock()
            .await
            .map(|t| t.elapsed().as_secs())
    }
}

// ─── STEP 17: Watchdog ───────────────────────────────────────────────────────

/// Spawn a watchdog task that forces `Erased` state if the mission timeout
/// expires before the VDF completes.
///
/// The watchdog polls every second.  If `t_seconds` elapses, it calls
/// [`StateMachine::force_erased`] and signals the erasure path.
pub fn spawn_watchdog(sm: Arc<StateMachine>, t_seconds: u64) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            let state = sm.current().await;
            if state == AgentState::Erased {
                return; // Watchdog done — mission complete.
            }
            if state == AgentState::Armed {
                continue; // Not started yet.
            }

            if let Some(elapsed) = sm.elapsed_secs().await {
                if elapsed >= t_seconds {
                    warn!(
                        target: "chronos",
                        elapsed_secs = elapsed,
                        limit_secs = t_seconds,
                        "Watchdog timeout — forcing Erased state"
                    );
                    sm.force_erased().await;
                    return;
                }
            }
        }
    });
}
