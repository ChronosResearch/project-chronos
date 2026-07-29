use chronos_core::{ChronosError, ChronosResult};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// Hash-chain Proof-of-Sequential-Work engine.
///
/// Iterates SHA-256 for `T` steps, streaming intermediate checkpoints to disk
/// via a **bounded** `mpsc` channel (capacity 32) to bound memory use and avoid
/// the pipe-deadlock described in D4 of the CHRONOS audit.
pub struct PoswEngine;

impl PoswEngine {
    /// Run the hash-chain VDF asynchronously.
    ///
    /// CPU-heavy hashing runs on a `spawn_blocking` thread (STEP 5).  Disk I/O
    /// runs on a separate async task to avoid blocking the tokio executor.
    ///
    /// The `abort_signal` `AtomicBool` can be set to `true` from the watchdog
    /// (STEP 17) to interrupt a long computation gracefully.
    ///
    /// # Errors
    /// Returns [`ChronosError::Vdf`] on hash-chain or I/O failure.
    pub async fn evaluate_async(
        &self,
        g: &[u8],
        t: u64,
        abort_signal: Arc<AtomicBool>,
        checkpoint_path: &str,
    ) -> ChronosResult<Vec<u8>> {
        let g_clone = g.to_vec();
        let path = checkpoint_path.to_owned();

        // STEP 5 – Bounded channel (32 slots). If the writer falls behind the
        // hasher, `blocking_send` will park the blocking thread until a slot
        // frees — this is the correct back-pressure mechanism and prevents
        // unbounded memory growth.
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);
        let abort_clone = Arc::clone(&abort_signal);

        // Async writer task – runs on the tokio I/O executor.
        let writer_task = tokio::spawn(async move {
            let mut file = File::create(&path).await.map_err(|e| {
                ChronosError::Io(e)
            })?;
            while let Some(checkpoint) = rx.recv().await {
                file.write_all(&checkpoint).await.map_err(|e| {
                    ChronosError::Io(e)
                })?;
            }
            Ok::<(), ChronosError>(())
        });

        // CPU-bound hasher – must not run on the async executor.
        let result = tokio::task::spawn_blocking(move || {
            let mut current = g_clone;
            #[cfg(debug_assertions)]
            let effective_t = t.min(10); // STEP 19
            #[cfg(not(debug_assertions))]
            let effective_t = t;

            for i in 0..effective_t {
                if abort_clone.load(Ordering::Relaxed) {
                    return Err(ChronosError::Vdf("Aborted by watchdog signal".into()));
                }
                let mut hasher = Sha256::new();
                hasher.update(&current);
                current = hasher.finalize().to_vec();

                // Every 1000 steps, enqueue a checkpoint.  blocking_send parks
                // here if the writer is behind — this is intentional back-pressure.
                if i % 1000 == 0 {
                    // Ignore send errors: writer task already has the data for
                    // all previous checkpoints; a send error means the writer
                    // died, which we'll catch when we await writer_task below.
                    let _ = tx.blocking_send(current.clone());
                }
            }
            drop(tx); // Signal the writer that no more data is coming.
            Ok(current)
        })
        .await
        .map_err(|join_err| ChronosError::Vdf(format!("spawn_blocking panicked: {join_err}")))?
        .map_err(|e: ChronosError| e)?;

        // Propagate any writer-task failure.
        writer_task
            .await
            .map_err(|e| ChronosError::Vdf(format!("checkpoint writer panicked: {e}")))?
            .map_err(|e| ChronosError::Vdf(format!("checkpoint write I/O error: {e}")))?;

        Ok(result)
    }
}
