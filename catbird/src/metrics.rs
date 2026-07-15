//! Prometheus Metrics for Catbird Gateway
//!
//! Provides HTTP request, proxy, auth, and rate limit metrics.

use jacquard_common::types::string::Nsid;
use lazy_static::lazy_static;
use prometheus::{
    self, CounterVec, Gauge, HistogramOpts, HistogramVec, Opts, Registry, TextEncoder,
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

    pub static ref OAUTH_EXCHANGES_TOTAL: CounterVec = CounterVec::new(
        Opts::new("catbird_oauth_exchanges_total", "OAuth callback exchange outcomes"),
        &["outcome"]
    ).unwrap();

    pub static ref TOKEN_REFRESHES_TOTAL: CounterVec = CounterVec::new(
        Opts::new("catbird_token_refreshes_total", "Total token refresh attempts"),
        &["status"]
    ).unwrap();

    pub static ref ACTIVE_SESSIONS: Gauge = Gauge::new(
        "catbird_active_sessions",
        "Number of active sessions in Redis"
    ).unwrap();

    pub static ref MLS_DEVICE_BINDING_TOTAL: CounterVec = CounterVec::new(
        Opts::new(
            "catbird_mls_device_binding_total",
            "MLS session-to-device binding outcomes"
        ),
        &["outcome"]
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
    REGISTRY.register(Box::new(PROXY_DURATION.clone())).unwrap();
    REGISTRY
        .register(Box::new(OAUTH_LOGINS_TOTAL.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(OAUTH_EXCHANGES_TOTAL.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(TOKEN_REFRESHES_TOTAL.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(ACTIVE_SESSIONS.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(MLS_DEVICE_BINDING_TOTAL.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(RATE_LIMIT_EXCEEDED_TOTAL.clone()))
        .unwrap();
}

/// Handler for /metrics endpoint - returns Prometheus text format
pub async fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    encoder
        .encode_to_string(&metric_families)
        .unwrap_or_default()
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
    record_proxy_request_metrics(
        &PROXY_REQUESTS_TOTAL,
        &PROXY_DURATION,
        lexicon,
        status,
        duration_secs,
    );
}

fn record_proxy_request_metrics(
    requests: &CounterVec,
    duration: &HistogramVec,
    lexicon: &str,
    status: u16,
    duration_secs: f64,
) {
    let family = proxy_metric_lexicon_label(lexicon);
    requests
        .with_label_values(&[family, &status.to_string()])
        .inc();
    duration.with_label_values(&[family]).observe(duration_secs);
}

fn proxy_metric_lexicon_label(lexicon: &str) -> &'static str {
    let Ok(nsid) = Nsid::new(lexicon) else {
        return "invalid";
    };
    let nsid = nsid.as_str();
    if nsid.starts_with("com.atproto.") {
        "com.atproto"
    } else if nsid.starts_with("app.bsky.") {
        "app.bsky"
    } else if nsid.starts_with("chat.bsky.") {
        "chat.bsky"
    } else if nsid.starts_with("blue.catbird.") {
        "blue.catbird"
    } else {
        "other"
    }
}

/// Record an OAuth login attempt
pub fn record_oauth_login(success: bool) {
    let status = if success { "success" } else { "failure" };
    OAUTH_LOGINS_TOTAL.with_label_values(&[status]).inc();
}

pub fn record_oauth_exchange(outcome: &str) {
    OAUTH_EXCHANGES_TOTAL.with_label_values(&[outcome]).inc();
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
    RATE_LIMIT_EXCEEDED_TOTAL
        .with_label_values(&[endpoint])
        .inc();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MlsDeviceBindingOutcome {
    BoundFound,
    BoundMissing,
    BeginPersisted,
    CompletePromoted,
    Denied,
    StoreFailure,
}

impl MlsDeviceBindingOutcome {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::BoundFound => "bound_found",
            Self::BoundMissing => "bound_missing",
            Self::BeginPersisted => "begin_persisted",
            Self::CompletePromoted => "complete_promoted",
            Self::Denied => "denied",
            Self::StoreFailure => "store_failure",
        }
    }
}

pub(crate) fn record_mls_device_binding(outcome: MlsDeviceBindingOutcome) {
    MLS_DEVICE_BINDING_TOTAL
        .with_label_values(&[outcome.label()])
        .inc();
}

#[cfg(test)]
mod mls_binding_tests {
    use super::*;

    #[test]
    fn mls_device_binding_metric_labels_are_closed_and_redacted() {
        let outcomes = [
            MlsDeviceBindingOutcome::BoundFound,
            MlsDeviceBindingOutcome::BoundMissing,
            MlsDeviceBindingOutcome::BeginPersisted,
            MlsDeviceBindingOutcome::CompletePromoted,
            MlsDeviceBindingOutcome::Denied,
            MlsDeviceBindingOutcome::StoreFailure,
        ];
        assert_eq!(
            outcomes.map(MlsDeviceBindingOutcome::label),
            [
                "bound_found",
                "bound_missing",
                "begin_persisted",
                "complete_promoted",
                "denied",
                "store_failure",
            ]
        );
        for outcome in outcomes {
            record_mls_device_binding(outcome);
        }
        let encoded = TextEncoder::new()
            .encode_to_string(&REGISTRY.gather())
            .unwrap();
        assert!(!encoded.contains("did:plc"));
        assert!(!encoded.contains("device_id"));
        assert!(!encoded.contains("secret-session-bearer"));
    }
}

#[cfg(test)]
mod proxy_metric_tests {
    use super::*;
    use std::collections::BTreeSet;

    const ALLOWED_LABELS: [&str; 6] = [
        "app.bsky",
        "blue.catbird",
        "chat.bsky",
        "com.atproto",
        "invalid",
        "other",
    ];

    fn fresh_proxy_metrics() -> (Registry, CounterVec, HistogramVec) {
        let registry = Registry::new();
        let requests = CounterVec::new(
            Opts::new("test_proxy_requests_total", "Test proxy requests"),
            &["lexicon", "status"],
        )
        .unwrap();
        let duration = HistogramVec::new(
            HistogramOpts::new("test_proxy_duration_seconds", "Test proxy duration"),
            &["lexicon"],
        )
        .unwrap();
        registry.register(Box::new(requests.clone())).unwrap();
        registry.register(Box::new(duration.clone())).unwrap();
        (registry, requests, duration)
    }

    #[test]
    fn proxy_metrics_do_not_retain_raw_third_party_nsid_labels() {
        const ATTACKER_NSID: &str = "evil.example.attackerMethod";
        let (registry, requests, duration) = fresh_proxy_metrics();

        record_proxy_request_metrics(&requests, &duration, ATTACKER_NSID, 200, 0.01);

        let retained_labels = registry
            .gather()
            .into_iter()
            .flat_map(|family| family.get_metric().to_vec())
            .flat_map(|metric| metric.get_label().to_vec())
            .filter(|label| label.get_name() == "lexicon")
            .map(|label| label.get_value().to_string())
            .collect::<Vec<_>>();
        assert!(
            !retained_labels.iter().any(|label| label == ATTACKER_NSID),
            "attacker-controlled NSID leaked into the Prometheus label set: {retained_labels:?}"
        );
    }

    #[test]
    fn valid_nsids_map_to_closed_protocol_family_labels() {
        for (nsid, expected) in [
            ("com.atproto.repo.createRecord", "com.atproto"),
            ("app.bsky.feed.getTimeline", "app.bsky"),
            ("chat.bsky.convo.getConvo", "chat.bsky"),
            ("blue.catbird.mlsChat.sendMessage", "blue.catbird"),
            ("org.example.customMethod", "other"),
            ("com.atprotox.customMethod", "other"),
        ] {
            assert_eq!(proxy_metric_lexicon_label(nsid), expected, "{nsid}");
        }
    }

    #[test]
    fn malformed_nsids_map_to_invalid() {
        let oversized = format!("com.example.{}", "a".repeat(306));
        let malformed = [
            "",
            "com.atproto",
            "com..atproto.method",
            "com.atproto.1method",
            "com.atproto.method/extra",
            "com.atproto.method\nextra",
            "app.bsky.méthod",
            oversized.as_str(),
        ];

        for nsid in malformed {
            assert_eq!(proxy_metric_lexicon_label(nsid), "invalid", "{nsid:?}");
        }
    }

    #[test]
    fn attacker_cardinality_is_bounded_in_a_fresh_registry() {
        let (registry, requests, duration) = fresh_proxy_metrics();

        for index in 0..5_000 {
            record_proxy_request_metrics(
                &requests,
                &duration,
                &format!("org.attacker{index}.method"),
                200,
                0.001,
            );
        }
        for nsid in [
            "com.atproto.repo.getRecord",
            "app.bsky.feed.getTimeline",
            "chat.bsky.convo.getConvo",
            "blue.catbird.mlsChat.getConvos",
            "not an nsid",
        ] {
            record_proxy_request_metrics(&requests, &duration, nsid, 200, 0.001);
        }

        let labels = registry
            .gather()
            .into_iter()
            .flat_map(|family| family.get_metric().to_vec())
            .flat_map(|metric| metric.get_label().to_vec())
            .filter(|label| label.get_name() == "lexicon")
            .map(|label| label.get_value().to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            labels,
            ALLOWED_LABELS
                .into_iter()
                .map(str::to_string)
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn proxy_counter_status_and_histogram_observations_are_preserved() {
        let (_registry, requests, duration) = fresh_proxy_metrics();

        record_proxy_request_metrics(
            &requests,
            &duration,
            "com.atproto.repo.getRecord",
            201,
            0.25,
        );
        record_proxy_request_metrics(
            &requests,
            &duration,
            "com.atproto.repo.putRecord",
            201,
            0.75,
        );

        assert_eq!(
            requests.with_label_values(&["com.atproto", "201"]).get(),
            2.0
        );
        let family_duration = duration.with_label_values(&["com.atproto"]);
        assert_eq!(family_duration.get_sample_count(), 2);
        assert_eq!(family_duration.get_sample_sum(), 1.0);
    }
}
