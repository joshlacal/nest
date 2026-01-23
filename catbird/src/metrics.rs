//! Prometheus Metrics for Catbird Gateway
//!
//! Provides HTTP request, proxy, auth, and rate limit metrics.

use lazy_static::lazy_static;
use prometheus::{
    self, CounterVec, Gauge, HistogramOpts, HistogramVec, Opts, Registry,
    TextEncoder,
};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    // HTTP Request Metrics
    pub static ref HTTP_REQUESTS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("catbird_http_requests_total", "Total HTTP requests"),
        &["method", "path", "status"]
    ).unwrap();

    pub static ref HTTP_REQUEST_DURATION: HistogramVec = HistogramVec::new(
        HistogramOpts::new(
            "catbird_http_request_duration_seconds",
            "HTTP request duration in seconds"
        ).buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        &["method", "path"]
    ).unwrap();

    // Proxy Metrics
    pub static ref PROXY_REQUESTS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("catbird_proxy_requests_total", "Total XRPC proxy requests"),
        &["lexicon", "status"]
    ).unwrap();

    pub static ref PROXY_DURATION: HistogramVec = HistogramVec::new(
        HistogramOpts::new(
            "catbird_proxy_duration_seconds",
            "XRPC proxy request duration in seconds"
        ).buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        &["lexicon"]
    ).unwrap();

    // Auth Metrics
    pub static ref OAUTH_LOGINS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("catbird_oauth_logins_total", "Total OAuth login attempts"),
        &["status"]
    ).unwrap();

    pub static ref TOKEN_REFRESHES_TOTAL: CounterVec = CounterVec::new(
        Opts::new("catbird_token_refreshes_total", "Total token refresh attempts"),
        &["status"]
    ).unwrap();

    pub static ref ACTIVE_SESSIONS: Gauge = Gauge::new(
        "catbird_active_sessions",
        "Number of active sessions in Redis"
    ).unwrap();

    // Rate Limit Metrics
    pub static ref RATE_LIMIT_EXCEEDED_TOTAL: CounterVec = CounterVec::new(
        Opts::new("catbird_rate_limit_exceeded_total", "Total rate limit exceeded events"),
        &["endpoint"]
    ).unwrap();
}

/// Register all metrics with the registry
pub fn register_metrics() {
    REGISTRY
        .register(Box::new(HTTP_REQUESTS_TOTAL.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(HTTP_REQUEST_DURATION.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(PROXY_REQUESTS_TOTAL.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(PROXY_DURATION.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(OAUTH_LOGINS_TOTAL.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(TOKEN_REFRESHES_TOTAL.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(ACTIVE_SESSIONS.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(RATE_LIMIT_EXCEEDED_TOTAL.clone()))
        .unwrap();
}

/// Handler for /metrics endpoint - returns Prometheus text format
pub async fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    encoder.encode_to_string(&metric_families).unwrap_or_default()
}

/// Record an HTTP request metric
pub fn record_http_request(method: &str, path: &str, status: u16, duration_secs: f64) {
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, path, &status.to_string()])
        .inc();
    HTTP_REQUEST_DURATION
        .with_label_values(&[method, path])
        .observe(duration_secs);
}

/// Record a proxy request metric
pub fn record_proxy_request(lexicon: &str, status: u16, duration_secs: f64) {
    PROXY_REQUESTS_TOTAL
        .with_label_values(&[lexicon, &status.to_string()])
        .inc();
    PROXY_DURATION
        .with_label_values(&[lexicon])
        .observe(duration_secs);
}

/// Record an OAuth login attempt
pub fn record_oauth_login(success: bool) {
    let status = if success { "success" } else { "failure" };
    OAUTH_LOGINS_TOTAL.with_label_values(&[status]).inc();
}

/// Record a token refresh attempt
pub fn record_token_refresh(success: bool) {
    let status = if success { "success" } else { "failure" };
    TOKEN_REFRESHES_TOTAL.with_label_values(&[status]).inc();
}

/// Update active sessions count
pub fn set_active_sessions(count: f64) {
    ACTIVE_SESSIONS.set(count);
}

/// Record rate limit exceeded event
pub fn record_rate_limit_exceeded(endpoint: &str) {
    RATE_LIMIT_EXCEEDED_TOTAL.with_label_values(&[endpoint]).inc();
}
