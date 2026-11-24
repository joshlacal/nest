//! Operator account moderation, driven by the Catbird Ozone instance.
//!
//! Reports never reach this server. Users report through their PDS straight
//! to Ozone, carrying only DIDs and ids, never post content or keys. When the
//! operator takes an account down in Ozone, Ozone emits a `!takedown` (or
//! timed `!suspend`) label on the account DID. A background poller re-reads
//! those labels from `com.atproto.label.queryLabels` into
//! `moderation_account_labels`. A restricted account is refused at every
//! authenticated route, its writes are not ingested, and its posts, likes,
//! notifications and owned Circles drop out of every view through the
//! `circle_inactive_dids` view.
//!
//! This file mirrors `mls-ds/server/src/moderation/mod.rs`; `labels.rs` is
//! byte-identical to its mls-ds copy.
//!
//! Ozone must run with `OZONE_LABEL_QUERY_WILDCARDS_ENABLED=true`, since the
//! poller asks for labels by DID prefix.
//!
//! When `MODERATION_LABELER_DID` / `MODERATION_LABELER_URL` are unset the
//! poller does not run, startup clears stored labels, and nothing is
//! restricted.

pub mod labels;

use std::time::Duration;

use chrono::Utc;
use sqlx::PgPool as DbPool;

use labels::{
    account_label_event, parse_enforced_labels, AccountLabelEvent, LabelBucket, QueryLabelsOutput,
};

/// Largest `queryLabels` page body we will read.
const MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;
/// Page size requested from Ozone (the lexicon maximum is 250).
const PAGE_LIMIT: usize = 250;
/// Upper bound on `queryLabels` requests in one reconcile pass.
const MAX_REQUESTS_PER_RECONCILE: usize = 2_000;

/// Configuration for following the operator's Ozone labels.
#[derive(Debug, Clone)]
pub struct ModerationLabelConfig {
    /// DID of the Ozone service account (labels are only trusted from it).
    pub labeler_did: String,
    /// Base URL of the Ozone service, e.g. `https://ozone.catbird.blue`.
    pub labeler_url: String,
    /// Label values that lock an account out.
    pub enforced_labels: Vec<String>,
    /// How often to re-read the labeler's full account-label set.
    pub poll_interval: Duration,
}

impl ModerationLabelConfig {
    /// `None` when moderation is not configured.
    pub fn from_env() -> Option<Self> {
        let labeler_did = std::env::var("MODERATION_LABELER_DID")
            .ok()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())?;
        let labeler_url = std::env::var("MODERATION_LABELER_URL")
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_owned())
            .filter(|v| !v.is_empty())?;
        if !labels::is_account_did(&labeler_did) {
            tracing::error!(
                "MODERATION_LABELER_DID is not a did:plc or did:web; moderation disabled"
            );
            return None;
        }
        if !labeler_url.starts_with("https://") && !labeler_url.starts_with("http://127.0.0.1") {
            tracing::error!("MODERATION_LABELER_URL must be https; moderation disabled");
            return None;
        }
        let secs = |name: &str, default: u64| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(default)
        };
        Some(Self {
            labeler_did,
            labeler_url,
            enforced_labels: parse_enforced_labels(
                std::env::var("MODERATION_ENFORCED_LABELS").ok().as_deref(),
            ),
            poll_interval: Duration::from_secs(secs("MODERATION_LABEL_POLL_SECS", 30)),
        })
    }
}

/// Drop stored labels the current configuration no longer trusts or
/// enforces: rows from another labeler, or values outside
/// `MODERATION_ENFORCED_LABELS`. With moderation unconfigured every row goes,
/// so removing the configuration lifts enforcement (and with it the
/// `circle_inactive_dids` view's operator rows). Run once at startup, before
/// the poller; the next reconcile restores anything still in force.
pub async fn prune_to_config(
    pool: &DbPool,
    cfg: Option<&ModerationLabelConfig>,
) -> Result<u64, sqlx::Error> {
    let result = match cfg {
        Some(cfg) => {
            sqlx::query(
                "DELETE FROM moderation_account_labels \
                  WHERE src <> $1 OR NOT (val = ANY($2))",
            )
            .bind(&cfg.labeler_did)
            .bind(&cfg.enforced_labels)
            .execute(pool)
            .await?
        }
        None => {
            sqlx::query("DELETE FROM moderation_account_labels")
                .execute(pool)
                .await?
        }
    };
    Ok(result.rows_affected())
}

/// Whether `did` is currently locked out by the operator.
pub async fn is_account_restricted(pool: &DbPool, did: &str) -> Result<bool, sqlx::Error> {
    let now = Utc::now();
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM moderation_account_labels \
          WHERE did = $1 AND NOT neg AND (exp IS NULL OR exp > $2))",
    )
    .bind(did)
    .bind(now)
    .fetch_one(pool)
    .await
}

/// Whether any of `dids` is currently locked out by the operator. Takes any
/// executor so ingestion can check inside its projection transaction.
pub async fn any_restricted<'e, E>(executor: E, dids: &[String]) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let now = Utc::now();
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM moderation_account_labels \
          WHERE did = ANY($1) AND NOT neg AND (exp IS NULL OR exp > $2))",
    )
    .bind(dids)
    .bind(now)
    .fetch_one(executor)
    .await
}

/// Store one label event if it is at least as new as what we hold.
pub async fn apply_label_event(pool: &DbPool, ev: &AccountLabelEvent) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO moderation_account_labels (src, did, val, cts, exp, neg, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (src, did, val) DO UPDATE \
            SET cts = EXCLUDED.cts, exp = EXCLUDED.exp, neg = EXCLUDED.neg, \
                updated_at = EXCLUDED.updated_at \
          WHERE moderation_account_labels.cts <= EXCLUDED.cts",
    )
    .bind(&ev.src)
    .bind(&ev.did)
    .bind(&ev.val)
    .bind(ev.cts)
    .bind(ev.exp)
    .bind(ev.neg)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Why a reconcile pass stopped early. Already-applied labels are kept.
#[derive(Debug)]
enum ReconcileError {
    /// Ozone refuses wildcard `queryLabels` patterns.
    WildcardsDisabled,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for ReconcileError {
    fn from(error: anyhow::Error) -> Self {
        Self::Other(error)
    }
}

impl From<sqlx::Error> for ReconcileError {
    fn from(error: sqlx::Error) -> Self {
        Self::Other(error.into())
    }
}

/// Fetch every label from the trusted labeler in `bucket`, in one request.
/// `None` means the page came back full, so the bucket may hold more than
/// one page and must be split.
async fn query_bucket(
    http: &reqwest::Client,
    cfg: &ModerationLabelConfig,
    bucket: &LabelBucket,
) -> Result<Option<Vec<labels::WireLabel>>, ReconcileError> {
    let pattern = bucket.pattern();
    let limit = PAGE_LIMIT.to_string();
    let response = http
        .get(format!(
            "{}/xrpc/com.atproto.label.queryLabels",
            cfg.labeler_url
        ))
        .query(&[
            ("uriPatterns", pattern.as_str()),
            ("sources", cfg.labeler_did.as_str()),
            ("limit", limit.as_str()),
        ])
        .send()
        .await
        .map_err(anyhow::Error::from)?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::BAD_REQUEST && body.contains("wildcard") {
            return Err(ReconcileError::WildcardsDisabled);
        }
        return Err(anyhow::anyhow!("queryLabels returned HTTP {status}").into());
    }
    if response
        .content_length()
        .is_some_and(|len| len as usize > MAX_PAGE_BYTES)
    {
        return Err(anyhow::anyhow!("queryLabels page too large").into());
    }
    let body = response.bytes().await.map_err(anyhow::Error::from)?;
    if body.len() > MAX_PAGE_BYTES {
        return Err(anyhow::anyhow!("queryLabels page too large").into());
    }
    let page: QueryLabelsOutput = serde_json::from_slice(&body).map_err(anyhow::Error::from)?;
    if page.labels.len() >= PAGE_LIMIT {
        return Ok(None);
    }
    Ok(Some(page.labels))
}

/// Read the labeler's whole account-label set and apply it.
///
/// Ozone's `queryLabels` pages without an `ORDER BY`, so a cursor walk can
/// skip rows. Instead each request asks for one subject prefix (see
/// [`LabelBucket`]); a page that comes back short holds every matching row,
/// and a full page is split into longer prefixes until every bucket fits.
/// A small labeler costs one request per pass. Returns how many labels were
/// applied.
async fn reconcile(
    pool: &DbPool,
    http: &reqwest::Client,
    cfg: &ModerationLabelConfig,
) -> Result<usize, ReconcileError> {
    let mut pending = vec![LabelBucket::Prefix(labels::RECONCILE_ROOT.to_owned())];
    let mut requests = 0usize;
    let mut applied = 0usize;
    while let Some(bucket) = pending.pop() {
        if requests >= MAX_REQUESTS_PER_RECONCILE {
            return Err(anyhow::anyhow!(
                "reconcile stopped after {requests} requests; {} prefixes left",
                pending.len() + 1
            )
            .into());
        }
        requests += 1;
        let Some(rows) = query_bucket(http, cfg, &bucket).await? else {
            match bucket.split() {
                Some(children) => pending.extend(children),
                None => tracing::error!(
                    "moderation labels under one subject exceed a page; some may be missed"
                ),
            }
            continue;
        };
        for label in &rows {
            match account_label_event(label, &cfg.labeler_did, &cfg.enforced_labels) {
                Ok(ev) => {
                    apply_label_event(pool, &ev).await?;
                    applied += 1;
                }
                Err(skip) => tracing::debug!(?skip, "moderation label skipped"),
            }
        }
    }
    Ok(applied)
}

/// Background worker: re-read the labeler's labels every poll interval until
/// `shutdown` flips to `true`.
pub async fn run_label_poller(
    pool: DbPool,
    http: reqwest::Client,
    cfg: ModerationLabelConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tracing::info!(
        labeler = %cfg.labeler_did,
        labels = ?cfg.enforced_labels,
        "moderation label poller started"
    );
    loop {
        match reconcile(&pool, &http, &cfg).await {
            Ok(applied) => tracing::debug!(applied, "moderation labels reconciled"),
            Err(ReconcileError::WildcardsDisabled) => tracing::error!(
                "Ozone refuses wildcard label queries, so takedowns are NOT enforced; \
                 set OZONE_LABEL_QUERY_WILDCARDS_ENABLED=true on the Ozone service"
            ),
            // Keep the last known state: an unreachable Ozone never lifts a
            // ban and never adds one.
            Err(ReconcileError::Other(error)) => {
                tracing::warn!(%error, "moderation label reconcile failed")
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(cfg.poll_interval) => {}
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    tracing::info!("moderation label poller stopped");
                    return;
                }
            }
        }
    }
}

/// Drop labels the configuration no longer enforces, then start the poller
/// when configured. Returns its handle and shutdown sender.
pub async fn spawn_label_poller(
    pool: DbPool,
    http: reqwest::Client,
) -> Option<(
    tokio::task::JoinHandle<()>,
    tokio::sync::watch::Sender<bool>,
)> {
    let cfg = ModerationLabelConfig::from_env();
    match prune_to_config(&pool, cfg.as_ref()).await {
        Ok(0) => {}
        Ok(rows) => tracing::info!(rows, "dropped moderation labels no longer enforced"),
        Err(error) => tracing::error!(%error, "pruning moderation labels failed"),
    }
    let Some(cfg) = cfg else {
        tracing::warn!("MODERATION_LABELER_DID/URL unset: Ozone takedowns are NOT enforced");
        return None;
    };
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(run_label_poller(pool, http, cfg, rx));
    Some((handle, tx))
}
