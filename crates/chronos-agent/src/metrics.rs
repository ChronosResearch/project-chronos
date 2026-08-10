use once_cell::sync::OnceCell;
use prometheus::{
    register_counter, register_gauge, register_histogram, Counter, Encoder, Gauge, Histogram,
    HistogramOpts, TextEncoder,
};
use tracing::error;

/// Create a Prometheus histogram, logging but not panicking on registration failure.
fn make_histogram(name: &'static str, help: &'static str) -> Histogram {
    match register_histogram!(name, help) {
        Ok(h) => h,
        Err(e) => {
            error!(target: "chronos", error = %e, metric = name, "Histogram registration failed — using unregistered fallback");
            Histogram::with_opts(HistogramOpts::new(name, help))
                .unwrap_or_else(|_| panic!("Prometheus histogram opts rejected for '{name}'"))
        }
    }
}

/// Create a Prometheus gauge, logging but not panicking on registration failure.
#[allow(dead_code)] // Used by vdf_squarings_per_sec; kept for future metrics.
fn make_gauge(name: &'static str, help: &'static str) -> Gauge {
    register_gauge!(name, help).unwrap_or_else(|e| {
        error!(target: "chronos", error = %e, metric = name, "Gauge registration failed — using unregistered fallback");
        Gauge::with_opts(prometheus::Opts::new(name, help))
            .unwrap_or_else(|_| panic!("Prometheus gauge opts rejected for '{name}'"))
    })
}

/// Create a Prometheus counter, logging but not panicking on registration failure.
fn make_counter(name: &'static str, help: &'static str) -> Counter {
    register_counter!(name, help).unwrap_or_else(|e| {
        error!(target: "chronos", error = %e, metric = name, "Counter registration failed — using unregistered fallback");
        Counter::new(name, help)
            .unwrap_or_else(|_| panic!("Prometheus counter opts rejected for '{name}'"))
    })
}

/// Prometheus histogram for FHE inference latency (seconds per request).
pub fn fhe_inference_latency() -> &'static Histogram {
    static METRIC: OnceCell<Histogram> = OnceCell::new();
    METRIC.get_or_init(|| {
        make_histogram(
            "chronos_fhe_inference_latency_seconds",
            "Latency of FHE ciphertext evaluation in seconds",
        )
    })
}

/// Prometheus gauge for VDF modular squaring rate.
#[allow(dead_code)] // Populated by spawn_vdf_task when wired into the orchestrator.
pub fn vdf_squarings_per_sec() -> &'static Gauge {
    static METRIC: OnceCell<Gauge> = OnceCell::new();
    METRIC.get_or_init(|| {
        make_gauge(
            "chronos_vdf_squarings_per_second",
            "Current VDF modular squaring rate",
        )
    })
}

/// Prometheus counter for total agent errors.
pub fn error_count() -> &'static Counter {
    static METRIC: OnceCell<Counter> = OnceCell::new();
    METRIC.get_or_init(|| {
        make_counter(
            "chronos_error_total",
            "Total number of errors encountered by the agent",
        )
    })
}

/// Render all collected metrics in Prometheus text exposition format.
///
/// Returns an empty buffer on encoder failure (should never occur for `TextEncoder`).
pub fn render_metrics() -> Vec<u8> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buf = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buf) {
        error!(target: "chronos", error = %e, "Prometheus encoder failed");
    }
    buf
}
