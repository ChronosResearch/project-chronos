use chronos_core::{ChronosError, ChronosResult, VdfEngine, VdfProof};
use chronos_vdf::wesolowski::WesolowskiVdf;
use num_bigint::BigUint;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Progress messages from the VDF background task.
#[derive(Debug)]
pub enum VdfProgress {
    /// VDF computation has started.
    Started,
    /// VDF computation finished (success or failure).
    Finished(ChronosResult<(BigUint, VdfProof)>),
}

/// Spawn a VDF computation task.
///
/// # STEP 21 – Concurrency safety
/// [`WesolowskiVdf::evaluate`] creates its own [`GmpBigInt`] locals on each
/// call.  There is no shared mutable GMP state — each task gets an independent
/// `WesolowskiVdf` instance, so 10 tasks running simultaneously is safe.
///
/// # STEP 5 – The blocking computation runs inside `tokio::task::spawn_blocking`
/// so the async executor is never starved.
///
/// # STEP 6 – `abort_signal` is checked once before starting; the PoSW engine
/// checks it every 1000 iterations.  Callers set it to `true` on SIGTERM or
/// watchdog timeout.
pub async fn spawn_vdf_task(
    g: BigUint,
    t: u64,
    n: BigUint,
    abort_signal: Arc<AtomicBool>,
) -> mpsc::Receiver<VdfProgress> {
    let (tx, rx) = mpsc::channel(10);

    tokio::spawn(async move {
        // Notify caller the task has started.
        if tx.send(VdfProgress::Started).await.is_err() {
            return; // Receiver dropped — caller cancelled.
        }

        // STEP 5 – CPU-bound: must run on a blocking OS thread.
        // STEP 21 – WesolowskiVdf is a zero-sized struct; each closure gets its own instance.
        let result = tokio::task::spawn_blocking(move || {
            if abort_signal.load(Ordering::Relaxed) {
                return Err(ChronosError::Vdf("Aborted before start".into()));
            }
            let engine = WesolowskiVdf; // STEP 21: fresh per-closure instance
            engine.evaluate(&g, t, &n)
        })
        .await
        .map_err(|join_err| {
            ChronosError::Vdf(format!("spawn_blocking panicked: {join_err}"))
        })
        .and_then(|inner| inner); // flatten Result<Result<_,_>,_>

        let _ = tx.send(VdfProgress::Finished(result)).await;
    });

    rx
}
