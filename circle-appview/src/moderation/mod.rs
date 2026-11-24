//! Operator account moderation, driven by the Catbird Ozone instance.
//!
//! Reports never reach this server. Users report through their PDS straight
//! to Ozone, carrying only DIDs and ids, never post content or keys. When the
//! operator takes an account down in Ozone, Ozone emits a `!takedown` (or
//! timed `!suspend`) label on the account DID. A background poller copies
//! those labels from `com.atproto.label.queryLabels` into
//! `moderation_account_labels`. A restricted account is refused at every
//! authenticated route, its writes are not ingested, and its posts, likes,
//! notifications and owned Circles drop out of every view through the
//! `circle_inactive_dids` view.
//!
//! This file mirrors `mls-ds/server/src/moderation/mod.rs`; `labels.rs` is
//! byte-identical to its mls-ds copy.
//!
//! When `MODERATION_LABELER_DID` / `MODERATION_LABELER_URL` are unset the
//! poller does not run and nothing is ever restricted.

pub mod labels;

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool as DbPool;

use labels::{account_label_event, parse_enforced_labels, AccountLabelEvent, QueryLabelsOutput};

/// Largest `queryLabels` page body we will read.
const MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;
/// Page size requested from Ozone (the lexicon maximum is 250).
const PAGE_LIMIT: u32 = 250;
/// Pages drained back-to-back in one tick before sleeping again.
const MAX_PAGES_PER_TICK: usize = 40;

/// Configuration for following the operator's Ozone labels.
#[derive(Debug, Clone)]
pub struct ModerationLabelConfig {
    /// DID of the Ozone service account (labels are only trusted from it).
    pub labeler_did: String,
    /// Base URL of the Ozone service, e.g. `https://ozone.catbird.blue`.
    pub labeler_url: String,
    /// Label values that lock an account out.
    pub enforced_labels: Vec<String>,
    pub poll_interval: Duration,
    /// How often to re-read every label from the start, to self-heal a
    /// missed page or a cursor reset on the Ozone side.
    pub resync_interval: Duration,
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
            resync_interval: Duration::from_secs(secs("MODERATION_LABEL_RESYNC_SECS", 6 * 3600)),
        })
    }
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

async fn load_cursor(pool: &DbPool, src: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT cursor FROM moderation_label_cursors WHERE src = $1",
    )
    .bind(src)
    .fetch_optional(pool)
    .await
    .map(Option::flatten)
}

async fn store_cursor(pool: &DbPool, src: &str, cursor: Option<&str>) -> Result<(), sqlx::Error> {
    let now: DateTime<Utc> = Utc::now();
    sqlx::query(
        "INSERT INTO moderation_label_cursors (src, cursor, updated_at) VALUES ($1, $2, $3) \
         ON CONFLICT (src) DO UPDATE SET cursor = EXCLUDED.cursor, updated_at = EXCLUDED.updated_at",
    )
    .bind(src)
    .bind(cursor)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch and apply one page. Returns how many labels the page held.
async fn poll_page(
    pool: &DbPool,
    http: &reqwest::Client,
    cfg: &ModerationLabelConfig,
) -> anyhow::Result<usize> {
    let cursor = load_cursor(pool, &cfg.labeler_did).await?;
    let limit = PAGE_LIMIT.to_string();
    let mut query: Vec<(&str, &str)> = vec![
        ("uriPatterns", "did:*"),
        ("sources", cfg.labeler_did.as_str()),
        ("limit", limit.as_str()),
    ];
    if let Some(cursor) = cursor.as_deref() {
        query.push(("cursor", cursor));
    }
    let response = http
        .get(format!(
            "{}/xrpc/com.atproto.label.queryLabels",
            cfg.labeler_url
        ))
        .query(&query)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("queryLabels returned HTTP {status}");
    }
    if response
        .content_length()
        .is_some_and(|len| len as usize > MAX_PAGE_BYTES)
    {
        anyhow::bail!("queryLabels page too large");
    }
    let body = response.bytes().await?;
    if body.len() > MAX_PAGE_BYTES {
        anyhow::bail!("queryLabels page too large");
    }
    let page: QueryLabelsOutput = serde_json::from_slice(&body)?;
    let count = page.labels.len();
    for label in &page.labels {
        match account_label_event(label, &cfg.labeler_did, &cfg.enforced_labels) {
            Ok(ev) => {
                apply_label_event(pool, &ev).await?;
                tracing::info!(
                    did = %ev.did,
                    val = %ev.val,
                    neg = ev.neg,
                    "moderation label applied"
                );
            }
            Err(skip) => tracing::debug!(?skip, "moderation label skipped"),
        }
    }
    if let Some(next) = page.cursor.as_deref().filter(|c| !c.is_empty()) {
        if cursor.as_deref() != Some(next) {
            store_cursor(pool, &cfg.labeler_did, Some(next)).await?;
        }
    }
    Ok(count)
}

/// Background worker: follow the labeler until `shutdown` flips to `true`.
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
    let mut last_resync = tokio::time::Instant::now();
    loop {
        if last_resync.elapsed() >= cfg.resync_interval {
            if let Err(error) = store_cursor(&pool, &cfg.labeler_did, None).await {
                tracing::warn!(%error, "moderation label resync reset failed");
            } else {
                tracing::info!("moderation label full resync started");
            }
            last_resync = tokio::time::Instant::now();
        }
        for _ in 0..MAX_PAGES_PER_TICK {
            match poll_page(&pool, &http, &cfg).await {
                Ok(n) if n as u32 >= PAGE_LIMIT => continue,
                Ok(_) => break,
                Err(error) => {
                    // Keep the last known state: an unreachable Ozone never
                    // lifts a ban and never adds one.
                    tracing::warn!(%error, "moderation label poll failed");
                    break;
                }
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

/// Start the poller when configured. Returns its handle and shutdown sender.
pub fn spawn_label_poller(
    pool: DbPool,
    http: reqwest::Client,
) -> Option<(
    tokio::task::JoinHandle<()>,
    tokio::sync::watch::Sender<bool>,
)> {
    let cfg = match ModerationLabelConfig::from_env() {
        Some(cfg) => cfg,
        None => {
            tracing::warn!("MODERATION_LABELER_DID/URL unset: Ozone takedowns are NOT enforced");
            return None;
        }
    };
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(run_label_poller(pool, http, cfg, rx));
    Some((handle, tx))
}
