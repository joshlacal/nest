//! Public relay events are refresh hints, not proofs of account deletion.
//!
//! A configured TLS relay supplies bounded, resumable subscribeRepos messages.
//! Account effects require an HTTPS response from the current DID-resolved PDS.
//! Suspension gates serving without changing membership or deleting projections.
//! Confirmed deletion persists the gate before the idempotent purge, then advances
//! the cursor only after purge succeeds. A crash therefore replays unfinished work.
//! A PDS that does not confirm a status denies only that account; the event is
//! still checkpointed and the account is re-checked later.
use crate::{auth, AppError, AppState};
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sqlx::{Connection, PgPool};
use std::{io::Cursor, time::Duration};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig, Message};

const MAX_FRAME_BYTES: usize = 3 * 1024 * 1024;
const MAX_REPLAY_EVENTS: usize = 100_000;
const MAX_CONNECTION_SECS: u64 = 300;
const CURSOR_FLUSH_EVENTS: usize = 256;
const HEALTH_SECS: i64 = 60;
const CONSUMER_LOCK: i64 = 0x434952434c454944;
/// Bounds one current-PDS confirmation (DID resolution plus getRepoStatus) so a
/// slow host cannot hold the sequential consumer.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(10);
/// Inactive, non-terminal ledger states for an account whose current PDS did not
/// confirm a status. They deny serving that account only and are re-checked.
const UNCONFIRMED: &str = "unconfirmed";
/// As UNCONFIRMED, after the relay reported the account deleted. A later
/// RepoNotFound from the current PDS then completes the deletion.
const DELETION_UNCONFIRMED: &str = "deletion_unconfirmed";
const RECHECK_TICK_SECS: u64 = 60;
const RECHECK_AFTER_SECS: f64 = 300.0;
const RECHECK_BATCH: i64 = 50;
const RECHECK_BUDGET: Duration = Duration::from_secs(15);

pub fn validate_relay_url(raw: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(raw)?;
    anyhow::ensure!(
        url.scheme() == "wss",
        "CIRCLE_IDENTITY_RELAY_URL must use wss"
    );
    anyhow::ensure!(
        url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && matches!(url.path(), "" | "/"),
        "CIRCLE_IDENTITY_RELAY_URL must be an origin without credentials, path, query, or fragment"
    );
    let host = url.host_str().unwrap();
    anyhow::ensure!(
        !auth::is_localhost_hostname(host)
            && !host
                .trim_matches(['[', ']'])
                .parse()
                .is_ok_and(|ip| auth::is_private_ip(&ip)),
        "Relay must have a public address"
    );
    Ok(url)
}

/// A recent source event must establish catch-up after each connection. Once
/// caught up, valid WebSocket ping/pong traffic maintains idle-stream liveness.
/// Replaying old data or a durable history gap cannot become healthy via ping.
pub async fn is_healthy(pool: &PgPool, relay_url: &str) -> Result<bool, AppError> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT COALESCE(blocked_reason IS NULL AND reconciled_at IS NOT NULL AND caught_up AND NOT replay_invalid \
         AND last_received_at > now() - make_interval(secs => $2), false) \
         FROM circle_identity_cursor WHERE relay_url = $1")
        .bind(relay_url).bind(HEALTH_SECS as f64).fetch_optional(pool).await?.unwrap_or(false))
}

pub async fn require_active_account(pool: &PgPool, did: &str) -> Result<(), AppError> {
    let row: Option<(bool, Option<String>)> =
        sqlx::query_as("SELECT active, status FROM circle_account_status WHERE did = $1")
            .bind(did)
            .fetch_optional(pool)
            .await?;
    match row {
        Some((false, Some(status))) if status == "deleted" => {
            Err(AppError::AccessRemoved("Account deleted".into()))
        }
        Some((false, _)) => Err(AppError::Forbidden(
            "Account temporarily unavailable".into(),
        )),
        _ => Ok(()),
    }
}

#[derive(Debug, Deserialize)]
struct Header {
    op: i64,
    t: Option<String>,
}
#[derive(Debug, Deserialize)]
struct Body {
    seq: Option<i64>,
    did: Option<String>,
    time: Option<DateTime<Utc>>,
    active: Option<bool>,
    status: Option<String>,
    name: Option<String>,
    error: Option<String>,
}
#[derive(Debug)]
struct Event {
    seq: i64,
    time: DateTime<Utc>,
    did: Option<String>,
    identity: bool,
    account: bool,
    /// The relay reported `#account active=false status=deleted`. This is only a
    /// hint: deletion also needs RepoNotFound from the DID's current PDS.
    deletion_hint: bool,
}

fn decode_frame(bytes: &[u8]) -> anyhow::Result<Option<Event>> {
    anyhow::ensure!(bytes.len() <= MAX_FRAME_BYTES, "Relay frame exceeds limit");
    let mut reader = Cursor::new(bytes);
    let header: Header = ciborium::from_reader(&mut reader)?;
    let body: Body = ciborium::from_reader(&mut reader)?;
    anyhow::ensure!(
        reader.position() == bytes.len() as u64,
        "Trailing relay frame data"
    );
    if header.op == -1 {
        let reason = match body.error.as_deref() {
            Some("FutureCursor") => "FutureCursor",
            Some("ConsumerTooSlow") => "ConsumerTooSlow",
            _ => "unspecified",
        };
        anyhow::bail!("Relay stream error: {reason}");
    }
    anyhow::ensure!(header.op == 1, "Unknown relay frame operation");
    let kind = header
        .t
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Missing relay frame type"))?;
    if kind == "#info" {
        anyhow::ensure!(
            body.name.as_deref() != Some("OutdatedCursor"),
            "OutdatedCursor requires operator reconciliation; cursor retained"
        );
        return Ok(None);
    }
    anyhow::ensure!(
        matches!(kind, "#commit" | "#sync" | "#identity" | "#account"),
        "Unknown relay event type"
    );
    let seq = body
        .seq
        .ok_or_else(|| anyhow::anyhow!("Missing sequence"))?;
    anyhow::ensure!(seq >= 0, "Negative relay sequence");
    let time = body
        .time
        .ok_or_else(|| anyhow::anyhow!("Missing event time"))?;
    anyhow::ensure!(
        time <= Utc::now() + chrono::Duration::seconds(30),
        "Relay event from the future"
    );
    if kind == "#account" {
        anyhow::ensure!(body.active.is_some(), "Missing account active field");
    }
    if matches!(kind, "#identity" | "#account") {
        let did = body
            .did
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Missing account DID"))?;
        anyhow::ensure!(
            did.len() <= 2048
                && (did.starts_with("did:plc:") || did.starts_with("did:web:"))
                && !did.contains(['/', '?', '#', ' ', '\n']),
            "Invalid account DID"
        );
    }
    Ok(Some(Event {
        seq,
        time,
        did: body.did,
        identity: kind == "#identity",
        account: kind == "#account",
        deletion_hint: kind == "#account"
            && body.active == Some(false)
            && body.status.as_deref() == Some("deleted"),
    }))
}

#[derive(Debug, Deserialize)]
struct RepoStatus {
    did: String,
    active: bool,
    status: Option<String>,
}
#[derive(Debug)]
struct ConfirmedStatus {
    active: bool,
    status: Option<String>,
    pds_url: String,
}

#[derive(Debug, Deserialize)]
struct XrpcError {
    error: Option<String>,
}
#[derive(Debug)]
enum Confirmation {
    /// The current PDS answered getRepoStatus for exactly this DID.
    Status(ConfirmedStatus),
    /// The current PDS answered `RepoNotFound`: it no longer hosts this DID.
    RepoNotFound { pds_url: String },
}
/// The current PDS did not confirm a status. Nothing was written yet.
struct Unconfirmed {
    reason: anyhow::Error,
    pds_url: Option<String>,
    deletion_hint: bool,
}

/// Called for newly encountered accounts too, so enrolling after bootstrap cannot
/// evade account lifecycle gating. A failed confirmation does not change grants
/// or the ledger; it is returned so the caller can deny the request.
pub async fn refresh_account(
    state: &AppState,
    did: &str,
    relay: &str,
    seq: i64,
) -> anyhow::Result<()> {
    let transport = crate::space_client::DefaultSpaceHostTransport::new();
    match refresh(state, did, relay, seq, false, &transport).await? {
        None => Ok(()),
        Some(unconfirmed) => Err(unconfirmed.reason),
    }
}

/// Confirms `did` at its current PDS and applies a confirmed outcome. Returns
/// `Err` only for local (database) failures, and `Some` when the PDS did not
/// confirm a status. Deletion needs the PDS: either an explicit `deleted`
/// status, or RepoNotFound after the relay reported this account deleted (the
/// reference PDS removes the account before sequencing that event). A relay
/// hint alone, or RepoNotFound alone, never purges.
async fn refresh(
    state: &AppState,
    did: &str,
    relay: &str,
    seq: i64,
    deletion_hint: bool,
    transport: &crate::space_client::DefaultSpaceHostTransport,
) -> anyhow::Result<Option<Unconfirmed>> {
    let previous: Option<(Option<String>, String)> =
        sqlx::query_as("SELECT status, pds_url FROM circle_account_status WHERE did=$1")
            .bind(did)
            .fetch_optional(&state.db)
            .await?;
    let previous_status = previous.as_ref().and_then(|(status, _)| status.as_deref());
    if let Some((Some(status), pds_url)) = &previous {
        if status == "deleted" {
            // Resume a terminal deletion without requiring the DID to resolve.
            let confirmed = ConfirmedStatus {
                active: false,
                status: Some("deleted".into()),
                pds_url: pds_url.clone(),
            };
            apply_confirmed_status(state, did, relay, seq, confirmed).await?;
            return Ok(None);
        }
    }
    let deletion_hint = deletion_hint || previous_status == Some(DELETION_UNCONFIRMED);
    let already_gated = matches!(previous_status, Some(UNCONFIRMED | DELETION_UNCONFIRMED));
    let confirmed = match confirm_status(state, did, transport).await {
        Ok(Confirmation::Status(status)) => status,
        Ok(Confirmation::RepoNotFound { pds_url }) if deletion_hint => ConfirmedStatus {
            active: false,
            status: Some("deleted".into()),
            pds_url,
        },
        Ok(Confirmation::RepoNotFound { pds_url }) => {
            return Ok(Some(Unconfirmed {
                reason: anyhow::anyhow!(
                    "PDS answered RepoNotFound without an account deletion event"
                ),
                pds_url: Some(pds_url),
                deletion_hint,
            }))
        }
        Err(reason) => {
            return Ok(Some(Unconfirmed {
                reason,
                pds_url: None,
                deletion_hint,
            }))
        }
    };
    if already_gated && confirmed.status.as_deref() == Some("deleted") {
        // Reads are already denied, so purge before the terminal write. If the
        // purge fails, the row stays unconfirmed and a re-check resumes it.
        // apply_confirmed_status purges again once 'deleted' is accepted;
        // purge_account is idempotent, so that pass only re-checks done work.
        purge_account(state, did).await?;
    }
    apply_confirmed_status(state, did, relay, seq, confirmed).await?;
    Ok(None)
}

/// Consumer path: a confirmation failure denies only that account. It records
/// the account as unconfirmed (inactive) and never holds the cursor or blocks
/// readiness for anyone else. The next lifecycle event for the DID or
/// `recheck_unconfirmed` confirms it again.
async fn refresh_or_gate(
    state: &AppState,
    did: &str,
    relay: &str,
    seq: i64,
    deletion_hint: bool,
    transport: &crate::space_client::DefaultSpaceHostTransport,
) -> anyhow::Result<()> {
    let Some(unconfirmed) = refresh(state, did, relay, seq, deletion_hint, transport).await? else {
        return Ok(());
    };
    tracing::warn!(
        error = %unconfirmed.reason,
        "Current PDS did not confirm an account status; denying that account until it is re-checked"
    );
    let status = if unconfirmed.deletion_hint {
        DELETION_UNCONFIRMED
    } else {
        UNCONFIRMED
    };
    // Same terminal and ordering guards as apply_confirmed_status. confirmed_at
    // records this attempt and orders re-checks.
    sqlx::query(
        "INSERT INTO circle_account_status(did,active,status,pds_url,source_seq,relay_url) VALUES($1,false,$2,COALESCE($3,''),$4,$5) \
         ON CONFLICT(did) DO UPDATE SET active=false,status=EXCLUDED.status,pds_url=COALESCE($3,circle_account_status.pds_url),\
         source_seq=EXCLUDED.source_seq,relay_url=EXCLUDED.relay_url,confirmed_at=now() \
         WHERE circle_account_status.status IS DISTINCT FROM 'deleted' \
         AND (circle_account_status.relay_url != EXCLUDED.relay_url OR circle_account_status.source_seq <= EXCLUDED.source_seq)")
        .bind(did).bind(status).bind(unconfirmed.pds_url).bind(seq).bind(relay)
        .execute(&state.db).await?;
    Ok(())
}

/// Confirms unconfirmed accounts again, oldest attempt first. Bounded in count
/// and time so the sequential consumer keeps up with the stream; each account
/// is retried no sooner than RECHECK_AFTER_SECS after its last attempt.
async fn recheck_unconfirmed(
    state: &AppState,
    relay: &str,
    seq: i64,
    transport: &crate::space_client::DefaultSpaceHostTransport,
) -> anyhow::Result<()> {
    let started = tokio::time::Instant::now();
    let due: Vec<(String, i64)> = sqlx::query_as(
        "SELECT did, source_seq FROM circle_account_status WHERE NOT active AND status IN ($1,$2) \
         AND confirmed_at < now() - make_interval(secs => $3) ORDER BY confirmed_at, did LIMIT $4",
    )
    .bind(UNCONFIRMED)
    .bind(DELETION_UNCONFIRMED)
    .bind(RECHECK_AFTER_SECS)
    .bind(RECHECK_BATCH)
    .fetch_all(&state.db)
    .await?;
    for (did, source_seq) in due {
        if started.elapsed() >= RECHECK_BUDGET {
            break;
        }
        // A re-check is at least as fresh as the event that left the account
        // unconfirmed, so it is applied at no lower a sequence.
        refresh_or_gate(state, &did, relay, seq.max(source_seq), false, transport).await?;
    }
    Ok(())
}

async fn confirm_status(
    state: &AppState,
    did: &str,
    transport: &crate::space_client::DefaultSpaceHostTransport,
) -> anyhow::Result<Confirmation> {
    tokio::time::timeout(
        CONFIRM_TIMEOUT,
        confirm_status_with_transport(state, did, transport),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Account status confirmation timed out"))?
}

async fn confirm_status_with_transport(
    state: &AppState,
    did: &str,
    transport: &crate::space_client::DefaultSpaceHostTransport,
) -> anyhow::Result<Confirmation> {
    // KEM keys are read from this same DID-document cache; invalidating it also
    // prevents reuse of an old KEM key on the next Space response-MAC request.
    state.did_resolver.invalidate_cached(did);
    let doc = state
        .did_resolver
        .resolve_identity_event(did)
        .await
        .map_err(|_| anyhow::anyhow!("Cannot confirm current account PDS"))?;
    let (endpoint, _) = crate::access::resolve_pds_endpoint(&doc, did)?;
    let mut target = url::Url::parse(&endpoint)?;
    anyhow::ensure!(
        target.scheme() == "https"
            && target.username().is_empty()
            && target.password().is_none()
            && target.query().is_none()
            && target.fragment().is_none(),
        "Invalid PDS endpoint"
    );
    target.set_path("/xrpc/com.atproto.sync.getRepoStatus");
    target.query_pairs_mut().append_pair("did", did);
    let client = transport.build_pinned_client(&target).await?;
    let response = client.get(target).send().await?;
    if matches!(response.status().as_u16(), 400 | 404) {
        // The reference PDS answers 400 RepoNotFound once it no longer hosts the
        // DID. Reported as such; it is not by itself a deletion (see refresh).
        let bytes = auth::read_bounded_public_response_bytes(response, 16 * 1024).await?;
        let error: XrpcError = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            error.error.as_deref() == Some("RepoNotFound"),
            "PDS did not confirm account status"
        );
        return Ok(Confirmation::RepoNotFound { pds_url: endpoint });
    }
    // An HTTP error, network loss, or an unresolvable DID confirms nothing.
    anyhow::ensure!(
        response.status().is_success(),
        "PDS did not confirm account status"
    );
    let bytes = auth::read_bounded_public_response_bytes(response, 16 * 1024).await?;
    let status: RepoStatus = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(status.did == did, "PDS account identity mismatch");
    anyhow::ensure!(
        status.status.as_ref().is_none_or(|s| s.len() <= 128),
        "Account status exceeds limit"
    );
    Ok(Confirmation::Status(ConfirmedStatus {
        active: status.active,
        status: if status.active { None } else { status.status },
        pds_url: endpoint,
    }))
}

async fn relevant_account(pool: &PgPool, did: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM circle_account_status WHERE did=$1) \
        OR EXISTS(SELECT 1 FROM circles WHERE authority_did=$1) \
        OR EXISTS(SELECT 1 FROM circle_member_cache WHERE member_did=$1) \
        OR EXISTS(SELECT 1 FROM circle_former_members WHERE member_did=$1) \
        OR EXISTS(SELECT 1 FROM circle_records WHERE author_did=$1) \
        OR EXISTS(SELECT 1 FROM circle_repo_sync_state WHERE author_did=$1)",
    )
    .bind(did)
    .fetch_one(pool)
    .await
}

async fn apply_confirmed_status(
    state: &AppState,
    did: &str,
    relay: &str,
    seq: i64,
    status: ConfirmedStatus,
) -> anyhow::Result<()> {
    // A deleted lifecycle is terminal. A later "active" hint cannot resurrect
    // previously purged author content or authority Circles.
    let mut tx = state.db.begin().await?;
    let accepted: Option<(bool, Option<String>)> = sqlx::query_as(
        "INSERT INTO circle_account_status(did,active,status,pds_url,source_seq,relay_url) VALUES($1,$2,$3,$4,$5,$6) \
         ON CONFLICT(did) DO UPDATE SET active=EXCLUDED.active,status=EXCLUDED.status,pds_url=EXCLUDED.pds_url,\
         source_seq=EXCLUDED.source_seq,relay_url=EXCLUDED.relay_url,confirmed_at=now() \
         WHERE circle_account_status.status IS DISTINCT FROM 'deleted' \
         AND (circle_account_status.relay_url != EXCLUDED.relay_url OR circle_account_status.source_seq <= EXCLUDED.source_seq) \
         RETURNING active,status")
        .bind(did).bind(status.active).bind(&status.status).bind(status.pds_url).bind(seq).bind(relay)
        .fetch_optional(&mut *tx).await?;
    tx.commit().await?;
    let deleted = accepted
        .as_ref()
        .is_some_and(|(_, status)| status.as_deref() == Some("deleted"))
        || sqlx::query_scalar::<_, bool>(
            "SELECT COALESCE(status='deleted',false) FROM circle_account_status WHERE did=$1",
        )
        .bind(did)
        .fetch_optional(&state.db)
        .await?
        .unwrap_or(false);
    if deleted {
        // Cursor has not advanced. Any failure below is retried, including after
        // process restart, while the durable inactive gate already denies reads.
        purge_account(state, did).await?;
    }
    Ok(())
}

/// Deletes every Space the account is the authority of, then its author
/// payloads. Idempotent, so a repeated or resumed purge is safe.
async fn purge_account(state: &AppState, did: &str) -> anyhow::Result<()> {
    let mut after = String::new();
    loop {
        let spaces: Vec<String> = sqlx::query_scalar(
            "SELECT space_uri FROM circles WHERE authority_did=$1 AND space_uri>$2 ORDER BY space_uri LIMIT 100")
            .bind(did).bind(&after).fetch_all(&state.db).await?;
        if spaces.is_empty() {
            break;
        }
        for space in spaces {
            crate::purge::delete_space(&state.db, &state.credential_store, &space).await?;
            after = space;
        }
    }
    crate::purge::purge_deleted_author(&state.db, did).await?;
    Ok(())
}

/// Applies one `#identity`/`#account` event, then checkpoints it.
async fn process_lifecycle_event(
    state: &AppState,
    relay: &str,
    event: &Event,
    transport: &crate::space_client::DefaultSpaceHostTransport,
) -> anyhow::Result<()> {
    let did = event
        .did
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Missing account DID"))?;
    state.did_resolver.invalidate_cached(did);
    if relevant_account(&state.db, did).await? {
        refresh_or_gate(state, did, relay, event.seq, event.deletion_hint, transport).await?;
    }
    checkpoint(&state.db, relay, event).await
}

async fn checkpoint(pool: &PgPool, relay: &str, event: &Event) -> anyhow::Result<()> {
    sqlx::query("UPDATE circle_identity_cursor SET cursor=$2,last_event_at=$3,last_received_at=now(),blocked_reason=NULL, \
        caught_up=($3 BETWEEN now() - interval '60 seconds' AND now() + interval '30 seconds') \
        WHERE relay_url=$1 AND cursor <= $2")
        .bind(relay).bind(event.seq).bind(event.time).execute(pool).await?;
    Ok(())
}

async fn reconcile_known_accounts(
    state: &AppState,
    relay: &str,
    seq: i64,
    transport: &crate::space_client::DefaultSpaceHostTransport,
) -> anyhow::Result<()> {
    let mut after: String =
        sqlx::query_scalar("SELECT reconcile_after FROM circle_identity_cursor WHERE relay_url=$1")
            .bind(relay)
            .fetch_one(&state.db)
            .await?;
    loop {
        let dids: Vec<String> = sqlx::query_scalar(
            "SELECT did FROM (SELECT authority_did AS did FROM circles WHERE deleted_at IS NULL \
             UNION SELECT member_did FROM circle_member_cache UNION SELECT author_did FROM circle_records \
             UNION SELECT author_did FROM circle_repo_sync_state UNION SELECT did FROM circle_account_status) accounts \
             WHERE did > $1 ORDER BY did LIMIT 100")
            .bind(&after).fetch_all(&state.db).await?;
        if dids.is_empty() {
            break;
        }
        for did in dids {
            refresh_or_gate(state, &did, relay, seq, false, transport).await?;
            after = did;
            sqlx::query("UPDATE circle_identity_cursor SET reconcile_after=$2 WHERE relay_url=$1")
                .bind(relay)
                .bind(&after)
                .execute(&state.db)
                .await?;
        }
    }
    sqlx::query("UPDATE circle_identity_cursor SET reconciled_at=now() WHERE relay_url=$1")
        .bind(relay)
        .execute(&state.db)
        .await?;
    Ok(())
}

async fn consume_connection(state: &AppState, relay: &url::Url) -> anyhow::Result<()> {
    let invalid: bool = sqlx::query_scalar("SELECT COALESCE(bool_or(replay_invalid),false) FROM circle_identity_cursor WHERE relay_url=$1")
        .bind(relay.as_str()).fetch_one(&state.db).await?;
    anyhow::ensure!(
        !invalid,
        "Relay cursor requires operator reconciliation; cursor retained"
    );
    let saved: Option<(i64, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT cursor,reconciled_at FROM circle_identity_cursor WHERE relay_url=$1",
    )
    .bind(relay.as_str())
    .fetch_optional(&state.db)
    .await?;
    let transport = crate::space_client::DefaultSpaceHostTransport::new();
    let mut url = relay.clone();
    url.set_path("/xrpc/com.atproto.sync.subscribeRepos");
    if let Some((cursor, _)) = saved {
        url.query_pairs_mut()
            .append_pair("cursor", &cursor.to_string());
    }
    let host = url.host_str().unwrap();
    let addrs: Vec<_> = tokio::net::lookup_host((host, url.port().unwrap_or(443)))
        .await?
        .collect();
    anyhow::ensure!(
        !addrs.is_empty() && addrs.iter().all(|a| !auth::is_private_ip(&a.ip())),
        "Relay DNS resolved to a nonpublic address"
    );
    let stream = tokio::net::TcpStream::connect(addrs[0]).await?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES));
    let (mut socket, _) =
        tokio_tungstenite::client_async_tls_with_config(url.as_str(), stream, Some(config), None)
            .await?;
    sqlx::query("UPDATE circle_identity_cursor SET last_connected_at=now(),caught_up=false WHERE relay_url=$1")
        .bind(relay.as_str())
        .execute(&state.db)
        .await?;
    let mut last_seq = saved.map(|(seq, _)| seq);
    let needs_reconcile = saved.is_none_or(|(_, at)| at.is_none());
    let mut reconciled = !needs_reconcile;
    let mut pending = None;
    let mut processed = 0;
    let mut caught_up = false;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    let mut ping_nonce = Vec::new();
    let mut flush = tokio::time::interval(Duration::from_secs(1));
    // Starts one tick after connecting so it never delays the first fresh event.
    let mut recheck = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(RECHECK_TICK_SECS),
        Duration::from_secs(RECHECK_TICK_SECS),
    );
    recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(MAX_CONNECTION_SECS);
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = heartbeat.tick() => {
                ping_nonce = rand::random::<[u8;16]>().to_vec();
                socket.send(Message::Ping(ping_nonce.clone().into())).await?;
            },
            _ = flush.tick() => if let Some(event) = pending.take() { checkpoint(&state.db,relay.as_str(),&event).await?; },
            _ = recheck.tick() => if let (true, Some(seq)) = (reconciled, last_seq) {
                recheck_unconfirmed(state,relay.as_str(),seq,&transport).await?;
            },
            message = socket.next() => {
                let message = message.ok_or_else(|| anyhow::anyhow!("Relay disconnected"))??;
                match message {
                    Message::Binary(bytes) => {
                        let Some(event) = decode_frame(&bytes)? else { continue; };
                        if last_seq.is_some_and(|seq| event.seq <= seq) { continue; }
                        let fresh = event.time >= Utc::now() - chrono::Duration::seconds(HEALTH_SECS);
                        if caught_up && !fresh {
                            sqlx::query("UPDATE circle_identity_cursor SET caught_up=false WHERE relay_url=$1")
                                .bind(relay.as_str()).execute(&state.db).await?;
                        }
                        caught_up = fresh;
                        if !reconciled {
                            // Pin a durable replay point before baseline confirmation.
                            // Buffered/new events remain replayable if startup is interrupted.
                            sqlx::query("INSERT INTO circle_identity_cursor(relay_url,cursor,blocked_reason,last_connected_at) \
                                VALUES($1,$2,'Initial account reconciliation',now()) ON CONFLICT(relay_url) DO NOTHING")
                                .bind(relay.as_str()).bind(event.seq.saturating_sub(1)).execute(&state.db).await?;
                            reconcile_known_accounts(state,relay.as_str(),event.seq.saturating_sub(1),&transport).await?;
                            reconciled = true;
                        }
                        if event.identity || event.account {
                            process_lifecycle_event(state,relay.as_str(),&event,&transport).await?;
                        }
                        last_seq = Some(event.seq);
                        pending = Some(event);
                        processed += 1;
                        if processed % CURSOR_FLUSH_EVENTS == 0 {
                            if let Some(event) = pending.take() { checkpoint(&state.db,relay.as_str(),&event).await?; }
                        }
                        if processed >= MAX_REPLAY_EVENTS { break; }
                    },
                    Message::Ping(data) => {
                        socket.send(Message::Pong(data)).await?;
                        if caught_up { record_heartbeat(&state.db,relay.as_str()).await?; }
                    },
                    Message::Pong(data) => {
                        if caught_up && data.as_ref() == ping_nonce.as_slice() {
                            record_heartbeat(&state.db,relay.as_str()).await?;
                        }
                    },
                    Message::Close(_) => anyhow::bail!("Relay closed stream"),
                    _ => anyhow::bail!("Nonbinary relay event"),
                }
            }
        }
    }
    if let Some(event) = pending {
        checkpoint(&state.db, relay.as_str(), &event).await?;
    }
    socket.close(None).await?;
    Ok(())
}

async fn record_heartbeat(pool: &PgPool, relay: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE circle_identity_cursor SET last_received_at=now() WHERE relay_url=$1 AND caught_up AND NOT replay_invalid AND blocked_reason IS NULL")
        .bind(relay).execute(pool).await?;
    Ok(())
}

pub fn spawn(state: AppState) -> Option<(tokio::task::JoinHandle<()>, watch::Sender<bool>)> {
    let relay = state.config.identity_relay_url.clone()?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        let mut delay = 1u64;
        loop {
            if *shutdown_rx.borrow() {
                break;
            }
            // A dedicated connection owns the advisory lock. Dropping it closes
            // the session and releases leadership even on cancellation/panic.
            let attempt = async {
                let mut lease =
                    sqlx::PgConnection::connect_with(&state.db.connect_options()).await?;
                let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                    .bind(CONSUMER_LOCK)
                    .fetch_one(&mut lease)
                    .await?;
                if !acquired {
                    // Standby workers must not mark the active leader unhealthy.
                    lease.close().await?;
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    return Ok::<(), anyhow::Error>(());
                }
                let result = tokio::time::timeout(
                    Duration::from_secs(MAX_CONNECTION_SECS + 60),
                    consume_connection(&state, &relay),
                )
                .await;
                let _ = lease.close().await;
                result?
            };
            tokio::select! {
                changed = shutdown_rx.changed() => { if changed.is_err() || *shutdown_rx.borrow() { break; } },
                result = attempt => {
                    match result {
                        Ok(()) => { delay = 1; continue; },
                        Err(error) => {
                            tracing::warn!(error=%error,"Circle identity consumer paused; durable cursor retained");
                            // Store only a bounded operational reason, never event content.
                            let reason: String = error.to_string().chars().take(256).collect();
                            if reason.contains("OutdatedCursor") || reason.contains("FutureCursor") {
                                // Even a gap reported before the first data event
                                // must latch durably; there may not be a cursor row yet.
                                let _ = sqlx::query("INSERT INTO circle_identity_cursor(relay_url,cursor,blocked_reason,replay_invalid) VALUES($1,0,$2,true) \
                                    ON CONFLICT(relay_url) DO UPDATE SET blocked_reason=EXCLUDED.blocked_reason,replay_invalid=true")
                                    .bind(relay.as_str()).bind(&reason).execute(&state.db).await;
                            } else {
                                let _ = sqlx::query("UPDATE circle_identity_cursor SET blocked_reason=$2 WHERE relay_url=$1")
                                    .bind(relay.as_str()).bind(&reason).execute(&state.db).await;
                            }
                        }
                    }
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(delay)) => {},
                _ = shutdown_rx.changed() => break,
            }
            delay = (delay * 2).min(30);
        }
    });
    Some((handle, shutdown_tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RELAY: &str = "wss://relay.example.com/";
    const OWNER: &str = "did:plc:lifecycleowner";
    const AUTHOR: &str = "did:plc:lifecycleauthor";
    const SPACE: &str = "at://did:plc:lifecycleowner/space/blue.catbird.circle/test";

    fn frame(kind: &str, body: serde_json::Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(&json!({"op":1,"t":kind}), &mut bytes).unwrap();
        ciborium::into_writer(&body, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn relay_origin_rejects_plaintext_private_and_credential_urls() {
        for url in [
            "ws://relay.example",
            "wss://localhost",
            "wss://127.0.0.1",
            "wss://[::1]",
            "wss://10.0.0.1",
            "wss://user@relay.example",
            "wss://relay.example.com/path",
            "wss://relay.example.com/?cursor=1",
        ] {
            assert!(validate_relay_url(url).is_err(), "accepted {url}");
        }
        assert!(validate_relay_url(RELAY).is_ok());
    }

    #[test]
    fn relay_deleted_hint_decodes_as_hint_and_outdated_cursor_stops_replay() {
        let bytes = frame(
            "#account",
            json!({"seq":10,"did":AUTHOR,"active":false,"status":"deleted","time":Utc::now()}),
        );
        let event = decode_frame(&bytes).unwrap().unwrap();
        assert!(event.account);
        assert_eq!(event.did.as_deref(), Some(AUTHOR));
        // Only a deletion hint survives in Event. Only PDS confirmation can
        // construct the ConfirmedStatus consumed by the state mutation path.
        assert!(event.deletion_hint);
        assert!(
            !decode_frame(&frame(
                "#account",
                json!({"seq":12,"did":AUTHOR,"active":false,"status":"suspended","time":Utc::now()})
            ))
            .unwrap()
            .unwrap()
            .deletion_hint
        );
        assert!(decode_frame(&frame("#info", json!({"name":"OutdatedCursor"}))).is_err());
        let mut extra = bytes;
        extra.push(0);
        assert!(decode_frame(&extra).is_err());
        assert!(decode_frame(&vec![0; MAX_FRAME_BYTES + 1]).is_err());
        assert!(decode_frame(&frame(
            "#account",
            json!({"seq":11,"did":AUTHOR,"time":Utc::now()})
        ))
        .is_err());
    }

    fn state(pool: PgPool) -> AppState {
        std::env::set_var(
            "SESSION_ENCRYPTION_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        AppState::new(
            crate::Config {
                host: "127.0.0.1".into(),
                port: 0,
                database_url: "postgres://localhost/postgres".into(),
                service_did: "did:web:circles.example".into(),
                plc_directory_url: "https://plc.directory".into(),
                identity_relay_url: None,
                public_appview_url: "https://public.api.bsky.app".into(),
                circle_media_base_url: url::Url::parse("https://media.example").unwrap(),
                appview_base_url: "http://127.0.0.1:3002".into(),
                oauth_key_id: None,
                oauth_signing_key_path: None,
                oauth_signing_key_hex: None,
                push_key_id: "did:web:circles.example#atproto_circles".into(),
                push_signing_key_path: None,
                push_signing_key_hex: None,
            },
            pool,
        )
    }

    async fn seed(pool: &PgPool) {
        sqlx::query("INSERT INTO circles(space_uri,circle_id,authority_did,display_name,created_at) VALUES($1,'test',$2,'Private circle',now())")
            .bind(SPACE).bind(OWNER).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO circle_member_cache(space_uri,member_did,can_read,can_write) VALUES($1,$2,true,false)")
            .bind(SPACE).bind(AUTHOR).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO circle_records(uri,cid,space_uri,author_did,collection,rkey,record_json,created_at) VALUES($1,'cid',$2,$3,'app.bsky.feed.post','post',$4,now())")
            .bind(format!("{SPACE}/{AUTHOR}/app.bsky.feed.post/post")).bind(SPACE).bind(AUTHOR)
            .bind(json!({"text":"private author content"})).execute(pool).await.unwrap();
        sqlx::query(
            "INSERT INTO circle_identity_cursor(relay_url,cursor,reconciled_at) VALUES($1,9,now())",
        )
        .bind(RELAY)
        .execute(pool)
        .await
        .unwrap();
    }

    fn confirmation(active: bool, status: Option<&str>) -> ConfirmedStatus {
        ConfirmedStatus {
            active,
            status: status.map(String::from),
            pds_url: "https://pds.example".into(),
        }
    }

    /// A pinned-TLS stand-in for each DID's current PDS plus a PLC directory that
    /// points every listed DID at it. `getRepoStatus` answers come from
    /// `responses` by DID; an unlisted DID gets a 500.
    struct PdsFixture {
        transport: crate::space_client::DefaultSpaceHostTransport,
        responses: std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<String, (u16, serde_json::Value)>>,
        >,
        _plc: wiremock::MockServer,
        server: tokio::task::JoinHandle<()>,
    }

    impl PdsFixture {
        async fn start(app: &mut AppState, dids: &[&str]) -> Self {
            use crate::space_client::{DefaultSpaceHostTransport, SpaceHostDnsResolver};
            use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _ = rustls::crypto::ring::default_provider().install_default();
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(vec!["pds.lifecycle.example".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            let certificate = reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap();
            let server_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
                )
                .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let responses: Arc<
                std::sync::Mutex<std::collections::HashMap<String, (u16, serde_json::Value)>>,
            > = Default::default();
            let answers = responses.clone();
            let server = tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut stream = acceptor.accept(stream).await.unwrap();
                    let mut request = [0; 8192];
                    let n = stream.read(&mut request).await.unwrap();
                    let request = String::from_utf8_lossy(&request[..n]).to_string();
                    let path = request.split_whitespace().nth(1).unwrap_or_default();
                    assert!(path.starts_with("/xrpc/com.atproto.sync.getRepoStatus?did="));
                    let did = url::Url::parse(&format!("https://fixture{path}"))
                        .unwrap()
                        .query_pairs()
                        .find(|(k, _)| k == "did")
                        .map(|(_, v)| v.into_owned())
                        .unwrap_or_default();
                    let (code, body) = answers
                        .lock()
                        .unwrap()
                        .get(&did)
                        .cloned()
                        .unwrap_or((500, json!({"error":"InternalServerError"})));
                    let body = body.to_string();
                    stream.write_all(format!("HTTP/1.1 {code} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            });
            struct FixtureDns(SocketAddr);
            impl SpaceHostDnsResolver for FixtureDns {
                fn resolve_dns<'a>(
                    &'a self,
                    _host: &'a str,
                    _port: u16,
                ) -> Pin<
                    Box<
                        dyn Future<Output = Result<Vec<SocketAddr>, crate::error::AuthReason>>
                            + Send
                            + 'a,
                    >,
                > {
                    Box::pin(async move { Ok(vec![self.0]) })
                }
            }
            let plc = wiremock::MockServer::start().await;
            for did in dids {
                let doc = json!({"id":did,"verificationMethod":[],
                    "service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":format!("https://pds.lifecycle.example:{}",addr.port())}]});
                wiremock::Mock::given(wiremock::matchers::method("GET"))
                    .and(wiremock::matchers::path(format!("/{did}")))
                    .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&doc))
                    .mount(&plc)
                    .await;
            }
            app.did_resolver = Arc::new(crate::DidResolver::new(
                plc.uri(),
                reqwest::Client::builder().no_proxy().build().unwrap(),
            ));
            Self {
                transport: DefaultSpaceHostTransport::with_test_fixture(
                    Arc::new(FixtureDns(addr)),
                    Some(certificate),
                    true,
                ),
                responses,
                _plc: plc,
                server,
            }
        }

        fn answer(&self, did: &str, code: u16, body: serde_json::Value) {
            self.responses
                .lock()
                .unwrap()
                .insert(did.into(), (code, body));
        }
    }

    impl Drop for PdsFixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    fn lifecycle_event(kind: &str, body: serde_json::Value) -> Event {
        decode_frame(&frame(kind, body)).unwrap().unwrap()
    }

    async fn cursor(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT cursor FROM circle_identity_cursor WHERE relay_url=$1")
            .bind(RELAY)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn record_count(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM circle_records")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// F1: the reference PDS deletes the account row before it sequences
    /// `#account deleted`, so getRepoStatus answers 400 RepoNotFound. That pair
    /// is a confirmed deletion: purge, checkpoint, and stay ready for everyone.
    #[sqlx::test(migrations = "./migrations")]
    async fn reference_account_deletion_purges_and_keeps_readiness(pool: PgPool) {
        seed(&pool).await;
        let mut app = state(pool.clone());
        let pds = PdsFixture::start(&mut app, &[AUTHOR, OWNER]).await;
        pds.answer(
            AUTHOR,
            400,
            json!({"error":"RepoNotFound","message":"Could not find repo for DID"}),
        );
        let deleted = lifecycle_event(
            "#account",
            json!({"seq":10,"did":AUTHOR,"active":false,"status":"deleted","time":Utc::now()}),
        );
        process_lifecycle_event(&app, RELAY, &deleted, &pds.transport)
            .await
            .unwrap();
        assert!(matches!(
            require_active_account(&pool, AUTHOR).await,
            Err(AppError::AccessRemoved(_))
        ));
        assert_eq!(
            record_count(&pool).await,
            0,
            "deleted author payload purged"
        );
        assert_eq!(cursor(&pool).await, 10, "event checkpointed");
        assert!(
            is_healthy(&pool, RELAY).await.unwrap(),
            "readiness unaffected"
        );
        require_active_account(&pool, OWNER).await.unwrap();
        // A later active hint and an active PDS answer cannot resurrect it.
        pds.answer(AUTHOR, 200, json!({"did":AUTHOR,"active":true}));
        let active = lifecycle_event(
            "#account",
            json!({"seq":11,"did":AUTHOR,"active":true,"time":Utc::now()}),
        );
        process_lifecycle_event(&app, RELAY, &active, &pds.transport)
            .await
            .unwrap();
        assert!(matches!(
            require_active_account(&pool, AUTHOR).await,
            Err(AppError::AccessRemoved(_))
        ));
    }

    async fn ledger_status(pool: &PgPool, did: &str) -> Option<(bool, Option<String>)> {
        sqlx::query_as("SELECT active, status FROM circle_account_status WHERE did=$1")
            .bind(did)
            .fetch_optional(pool)
            .await
            .unwrap()
    }

    /// F1: a PDS that does not confirm a status (5xx, or a deletion hint it
    /// cannot back up) denies only that account. The event is checkpointed,
    /// readiness stays healthy, nothing is purged, and a later re-check settles it.
    #[sqlx::test(migrations = "./migrations")]
    async fn unconfirmed_account_is_denied_alone_and_rechecked_later(pool: PgPool) {
        seed(&pool).await;
        let mut app = state(pool.clone());
        let pds = PdsFixture::start(&mut app, &[AUTHOR, OWNER]).await;
        pds.answer(OWNER, 500, json!({"error":"InternalServerError"}));
        let identity =
            lifecycle_event("#identity", json!({"seq":10,"did":OWNER,"time":Utc::now()}));
        process_lifecycle_event(&app, RELAY, &identity, &pds.transport)
            .await
            .unwrap();
        assert_eq!(
            ledger_status(&pool, OWNER).await,
            Some((false, Some(UNCONFIRMED.into())))
        );
        assert!(matches!(
            require_active_account(&pool, OWNER).await,
            Err(AppError::Forbidden(_))
        ));
        require_active_account(&pool, AUTHOR).await.unwrap();
        assert_eq!(cursor(&pool).await, 10);
        assert!(is_healthy(&pool, RELAY).await.unwrap());

        // A relay deletion hint the PDS cannot back up never purges.
        pds.answer(AUTHOR, 503, json!({"error":"Unavailable"}));
        let hint = lifecycle_event(
            "#account",
            json!({"seq":11,"did":AUTHOR,"active":false,"status":"deleted","time":Utc::now()}),
        );
        process_lifecycle_event(&app, RELAY, &hint, &pds.transport)
            .await
            .unwrap();
        assert_eq!(
            ledger_status(&pool, AUTHOR).await,
            Some((false, Some(DELETION_UNCONFIRMED.into())))
        );
        assert_eq!(record_count(&pool).await, 1, "hint alone never purges");
        let circle_alive: bool =
            sqlx::query_scalar("SELECT deleted_at IS NULL FROM circles WHERE space_uri=$1")
                .bind(SPACE)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(circle_alive, "an unconfirmed authority keeps its Circles");
        assert_eq!(cursor(&pool).await, 11);
        assert!(is_healthy(&pool, RELAY).await.unwrap());

        // The PDSes recover. A re-check waits RECHECK_AFTER_SECS after the
        // last attempt, then confirms both accounts.
        pds.answer(OWNER, 200, json!({"did":OWNER,"active":true}));
        pds.answer(
            AUTHOR,
            400,
            json!({"error":"RepoNotFound","message":"Could not find repo for DID"}),
        );
        recheck_unconfirmed(&app, RELAY, 11, &pds.transport)
            .await
            .unwrap();
        assert_eq!(
            ledger_status(&pool, OWNER).await,
            Some((false, Some(UNCONFIRMED.into()))),
            "not re-checked before its retry interval"
        );
        sqlx::query("UPDATE circle_account_status SET confirmed_at=now()-interval '10 minutes'")
            .execute(&pool)
            .await
            .unwrap();
        recheck_unconfirmed(&app, RELAY, 11, &pds.transport)
            .await
            .unwrap();
        require_active_account(&pool, OWNER).await.unwrap();
        assert!(matches!(
            require_active_account(&pool, AUTHOR).await,
            Err(AppError::AccessRemoved(_))
        ));
        assert_eq!(
            record_count(&pool).await,
            0,
            "persisted deletion hint plus RepoNotFound completes the deletion"
        );
        assert!(is_healthy(&pool, RELAY).await.unwrap());
    }

    /// F1: initial reconciliation completes even when a known account cannot be
    /// confirmed. RepoNotFound without a relay deletion event is not a deletion.
    #[sqlx::test(migrations = "./migrations")]
    async fn reconcile_completes_when_a_known_account_cannot_be_confirmed(pool: PgPool) {
        seed(&pool).await;
        sqlx::query("UPDATE circle_identity_cursor SET reconciled_at=NULL")
            .execute(&pool)
            .await
            .unwrap();
        let mut app = state(pool.clone());
        let pds = PdsFixture::start(&mut app, &[AUTHOR, OWNER]).await;
        pds.answer(OWNER, 200, json!({"did":OWNER,"active":true}));
        pds.answer(
            AUTHOR,
            400,
            json!({"error":"RepoNotFound","message":"Could not find repo for DID"}),
        );
        reconcile_known_accounts(&app, RELAY, 9, &pds.transport)
            .await
            .unwrap();
        let reconciled: bool = sqlx::query_scalar(
            "SELECT reconciled_at IS NOT NULL FROM circle_identity_cursor WHERE relay_url=$1",
        )
        .bind(RELAY)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(reconciled);
        require_active_account(&pool, OWNER).await.unwrap();
        assert_eq!(
            ledger_status(&pool, AUTHOR).await,
            Some((false, Some(UNCONFIRMED.into())))
        );
        assert_eq!(
            record_count(&pool).await,
            1,
            "RepoNotFound alone never purges"
        );
        // The on-request path for a first-seen account still refuses, and writes
        // nothing, when the PDS does not confirm a status.
        assert!(refresh_account(&app, "did:plc:lifecyclestranger", RELAY, 0)
            .await
            .is_err());
        assert_eq!(
            ledger_status(&pool, "did:plc:lifecyclestranger").await,
            None
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn suspension_preserves_grants_and_reactivation_is_reversible(pool: PgPool) {
        seed(&pool).await;
        let app = state(pool.clone());
        apply_confirmed_status(
            &app,
            AUTHOR,
            RELAY,
            10,
            confirmation(false, Some("suspended")),
        )
        .await
        .unwrap();
        assert!(matches!(
            require_active_account(&pool, AUTHOR).await,
            Err(AppError::Forbidden(_))
        ));
        let grants: (bool, bool) = sqlx::query_as(
            "SELECT can_read,can_write FROM circle_member_cache WHERE member_did=$1",
        )
        .bind(AUTHOR)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(grants, (true, false));
        let records: i64 = sqlx::query_scalar("SELECT count(*) FROM circle_records")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(records, 1);
        apply_confirmed_status(&app, AUTHOR, RELAY, 11, confirmation(true, None))
            .await
            .unwrap();
        require_active_account(&pool, AUTHOR).await.unwrap();
        // Older events cannot roll the confirmed account state backwards.
        apply_confirmed_status(
            &app,
            AUTHOR,
            RELAY,
            10,
            confirmation(false, Some("suspended")),
        )
        .await
        .unwrap();
        require_active_account(&pool, AUTHOR).await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn deleted_author_purges_payload_and_cannot_be_resurrected(pool: PgPool) {
        seed(&pool).await;
        let app = state(pool.clone());
        apply_confirmed_status(
            &app,
            AUTHOR,
            RELAY,
            10,
            confirmation(false, Some("deleted")),
        )
        .await
        .unwrap();
        assert!(matches!(
            require_active_account(&pool, AUTHOR).await,
            Err(AppError::AccessRemoved(_))
        ));
        let records: i64 = sqlx::query_scalar("SELECT count(*) FROM circle_records")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(records, 0);
        apply_confirmed_status(&app, AUTHOR, RELAY, 11, confirmation(true, None))
            .await
            .unwrap();
        assert!(matches!(
            require_active_account(&pool, AUTHOR).await,
            Err(AppError::AccessRemoved(_))
        ));
        let owner_alive: bool =
            sqlx::query_scalar("SELECT deleted_at IS NULL FROM circles WHERE space_uri=$1")
                .bind(SPACE)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(owner_alive);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn deleted_authority_restarts_partial_purge_before_cursor_ack(pool: PgPool) {
        seed(&pool).await;
        // Simulate interruption after committing the inactive ledger but before
        // purge/cursor acknowledgment. Fresh process must resume from the ledger
        // even if the deleted DID can no longer resolve over the network.
        sqlx::query("INSERT INTO circle_account_status(did,active,status,pds_url,source_seq,relay_url) VALUES($1,false,'deleted','https://unresolvable.invalid',10,$2)")
            .bind(OWNER).bind(RELAY).execute(&pool).await.unwrap();
        let restarted = state(pool.clone());
        refresh_account(&restarted, OWNER, RELAY, 10).await.unwrap();
        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM circle_records")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 0);
        let deleted: bool =
            sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM circles WHERE space_uri=$1")
                .bind(SPACE)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(deleted);
        let tombstone: (String, String) =
            sqlx::query_as("SELECT display_name, circle_id FROM circles WHERE space_uri=$1")
                .bind(SPACE)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            tombstone,
            ("Circle".into(), String::new()),
            "authority deletion keeps no private Circle metadata"
        );
        let seq: i64 =
            sqlx::query_scalar("SELECT cursor FROM circle_identity_cursor WHERE relay_url=$1")
                .bind(RELAY)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(seq, 9);
        let event = Event {
            seq: 10,
            time: Utc::now(),
            did: Some(OWNER.into()),
            identity: false,
            account: true,
            deletion_hint: true,
        };
        checkpoint(&pool, RELAY, &event).await.unwrap();
        // Repeat the same event as a second crash/reconnect replay.
        refresh_account(&restarted, OWNER, RELAY, 10).await.unwrap();
        checkpoint(&pool, RELAY, &event).await.unwrap();
        assert!(is_healthy(&pool, RELAY).await.unwrap());
        // A retained older event cannot decrease the durable cursor.
        checkpoint(&pool, RELAY, &Event { seq: 8, ..event })
            .await
            .unwrap();
        let seq: i64 =
            sqlx::query_scalar("SELECT cursor FROM circle_identity_cursor WHERE relay_url=$1")
                .bind(RELAY)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(seq, 10);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn readiness_rejects_lagged_blocked_or_unreconciled_cursor(pool: PgPool) {
        seed(&pool).await;
        assert!(!is_healthy(&pool, RELAY).await.unwrap());
        let event = Event {
            seq: 10,
            time: Utc::now() - chrono::Duration::minutes(2),
            did: None,
            identity: false,
            account: false,
            deletion_hint: false,
        };
        checkpoint(&pool, RELAY, &event).await.unwrap();
        assert!(!is_healthy(&pool, RELAY).await.unwrap());
        checkpoint(
            &pool,
            RELAY,
            &Event {
                time: Utc::now(),
                ..event
            },
        )
        .await
        .unwrap();
        assert!(is_healthy(&pool, RELAY).await.unwrap());
        sqlx::query("UPDATE circle_identity_cursor SET last_event_at=now()-interval '10 minutes',last_received_at=now()-interval '2 minutes'").execute(&pool).await.unwrap();
        assert!(!is_healthy(&pool, RELAY).await.unwrap());
        record_heartbeat(&pool, RELAY).await.unwrap();
        assert!(
            is_healthy(&pool, RELAY).await.unwrap(),
            "idle caught-up stream stays healthy through ping/pong"
        );
        sqlx::query("UPDATE circle_identity_cursor SET blocked_reason='OutdatedCursor'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(!is_healthy(&pool, RELAY).await.unwrap());
        sqlx::query("UPDATE circle_identity_cursor SET blocked_reason=NULL,replay_invalid=true")
            .execute(&pool)
            .await
            .unwrap();
        record_heartbeat(&pool, RELAY).await.unwrap();
        assert!(
            !is_healthy(&pool, RELAY).await.unwrap(),
            "heartbeat must not clear a history gap"
        );
        sqlx::query("UPDATE circle_identity_cursor SET replay_invalid=false,reconciled_at=NULL")
            .execute(&pool)
            .await
            .unwrap();
        assert!(!is_healthy(&pool, RELAY).await.unwrap());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn pinned_pds_confirmation_overrides_relay_hint_and_refreshes_identity(pool: PgPool) {
        use crate::space_client::{DefaultSpaceHostTransport, SpaceHostDnsResolver};
        use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["pds.lifecycle.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certificate = reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(async move {
            for (code, body) in [
                ("200 OK", json!({"did":AUTHOR,"active":true})),
                (
                    "200 OK",
                    json!({"did":"did:plc:other","active":false,"status":"deleted"}),
                ),
                ("404 Not Found", json!({"error":"RepoNotFound"})),
            ] {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                let mut request = [0; 8192];
                let n = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                assert!(request.starts_with("GET /xrpc/com.atproto.sync.getRepoStatus?did="));
                let body = body.to_string();
                stream.write_all(format!("HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        struct FixtureDns(SocketAddr);
        impl SpaceHostDnsResolver for FixtureDns {
            fn resolve_dns<'a>(
                &'a self,
                _host: &'a str,
                _port: u16,
            ) -> Pin<
                Box<
                    dyn Future<Output = Result<Vec<SocketAddr>, crate::error::AuthReason>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(async move { Ok(vec![self.0]) })
            }
        }
        let transport = DefaultSpaceHostTransport::with_test_fixture(
            Arc::new(FixtureDns(addr)),
            Some(certificate),
            true,
        );
        let plc = wiremock::MockServer::start().await;
        let fresh_doc = json!({"id":AUTHOR,"verificationMethod":[{"id":format!("{AUTHOR}#atproto_kem"),"type":"Multikey","controller":AUTHOR,"publicKeyMultibase":"fresh-kem-fixture"}],
            "service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":format!("https://pds.lifecycle.example:{}",addr.port())}]});
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!("/{AUTHOR}")))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&fresh_doc))
            .mount(&plc)
            .await;
        let mut app = state(pool.clone());
        app.did_resolver = Arc::new(crate::DidResolver::new(
            plc.uri(),
            reqwest::Client::builder().no_proxy().build().unwrap(),
        ));
        app.did_resolver.insert_cached(
            AUTHOR.into(),
            crate::DidDocument {
                id: AUTHOR.into(),
                verification_method: vec![],
                service: vec![],
            },
        );
        let hint = decode_frame(&frame(
            "#account",
            json!({"did":AUTHOR,"active":false,"status":"deleted","seq":20,"time":Utc::now()}),
        ))
        .unwrap()
        .unwrap();
        let Confirmation::Status(confirmed) =
            confirm_status_with_transport(&app, AUTHOR, &transport)
                .await
                .unwrap()
        else {
            panic!("an active account answers with a status");
        };
        assert!(hint.deletion_hint);
        assert!(
            confirmed.active,
            "relay deletion hint cannot override active current PDS"
        );
        apply_confirmed_status(&app, AUTHOR, RELAY, hint.seq, confirmed)
            .await
            .unwrap();
        require_active_account(&pool, AUTHOR).await.unwrap();
        let resolved = app.did_resolver.resolve(AUTHOR).await.unwrap();
        assert_eq!(
            resolved.verification_method[0]
                .public_key_multibase
                .as_deref(),
            Some("fresh-kem-fixture")
        );
        assert!(
            confirm_status_with_transport(&app, AUTHOR, &transport)
                .await
                .is_err(),
            "mismatched DID must not confirm deletion"
        );
        // RepoNotFound is reported, not concluded: refresh() purges only when
        // the relay also reported this account deleted.
        assert!(
            matches!(
                confirm_status_with_transport(&app, AUTHOR, &transport).await,
                Ok(Confirmation::RepoNotFound { .. })
            ),
            "RepoNotFound must not be a confirmed status"
        );
        require_active_account(&pool, AUTHOR).await.unwrap();
        serving.await.unwrap();
    }
}
