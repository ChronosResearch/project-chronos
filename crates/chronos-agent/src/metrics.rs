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
            // Registration failures happen only in tests when metrics are
            // registered multiple times.  Fall back to an unregistered instance.
            error!(target: "chronos", error = %e, metric = name, "Histogram registration failed — using fallback");
            Histogram::with_opts(HistogramOpts::new(name, help))
                .unwrap_or_else(|_| Histogram::with_opts(HistogramOpts::new("chronos_fallback_histogram", "fallback")).unwrap_or_else(|_| panic!("Prometheus API broken")))
        }
    }
}

/// Create a Prometheus gauge, logging but not panicking on registration failure.
fn make_gauge(name: &'static str, help: &'static str) -> Gauge {
    register_gauge!(name, help).unwrap_or_else(|e| {
        error!(target: "chronos", error = %e, metric = name, "Gauge registration failed — using fallback");
        Gauge::with_opts(prometheus::Opts::new(name, help))
            .unwrap_or_else(|_| Gauge::new("chronos_fallback_gauge", "fallback").unwrap_or_else(|_| panic!("Prometheus API broken")))
    })
}

/// Create a Prometheus counter, logging but not panicking on registration failure.
fn make_counter(name: &'static str, help: &'static str) -> Counter {
    register_counter!(name, help).unwrap_or_else(|e| {
        error!(target: "chronos", error = %e, metric = name, "Counter registration failed — using fallback");
        Counter::new("chronos_fallback_counter", "fallback").unwrap_or_else(|_| panic!("Prometheus API broken"))
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
