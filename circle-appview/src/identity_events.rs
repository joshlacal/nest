//! Public relay events are refresh hints, not proofs of account deletion.
//!
//! A configured TLS relay supplies bounded, resumable subscribeRepos messages.
//! Account effects require an HTTPS response from the current DID-resolved PDS.
//! Suspension gates serving without changing membership or deleting projections.
//! Confirmed deletion persists the gate before the idempotent purge, then advances
//! the cursor only after purge succeeds. A crash therefore replays unfinished work.
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

/// Called for newly encountered accounts too, so enrolling after bootstrap cannot
/// evade account lifecycle gating. A failed confirmation does not change grants.
pub async fn refresh_account(
    state: &AppState,
    did: &str,
    relay: &str,
    seq: i64,
) -> anyhow::Result<()> {
    let previous_pds: Option<String> = sqlx::query_scalar(
        "SELECT pds_url FROM circle_account_status WHERE did=$1 AND status='deleted'",
    )
    .bind(did)
    .fetch_optional(&state.db)
    .await?;
    let confirmed = if let Some(pds_url) = previous_pds {
        ConfirmedStatus {
            active: false,
            status: Some("deleted".into()),
            pds_url,
        }
    } else {
        confirm_status(state, did).await?
    };
    apply_confirmed_status(state, did, relay, seq, confirmed).await
}

async fn confirm_status(state: &AppState, did: &str) -> anyhow::Result<ConfirmedStatus> {
    confirm_status_with_transport(
        state,
        did,
        &crate::space_client::DefaultSpaceHostTransport::new(),
    )
    .await
}

async fn confirm_status_with_transport(
    state: &AppState,
    did: &str,
    transport: &crate::space_client::DefaultSpaceHostTransport,
) -> anyhow::Result<ConfirmedStatus> {
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
    // RepoNotFound, an HTTP error, network loss, or an unresolvable DID is NOT a
    // deletion confirmation. Hold the cursor and retry rather than infer deletion.
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
    Ok(ConfirmedStatus {
        active: status.active,
        status: if status.active { None } else { status.status },
        pds_url: endpoint,
    })
}

async fn relevant_account(pool: &PgPool, did: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM circle_account_status WHERE did=$1) \
        OR EXISTS(SELECT 1 FROM circles WHERE authority_did=$1) \
        OR EXISTS(SELECT 1 FROM circle_member_cache WHERE member_did=$1) \
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
    }
    Ok(())
}

async fn checkpoint(pool: &PgPool, relay: &str, event: &Event) -> anyhow::Result<()> {
    sqlx::query("UPDATE circle_identity_cursor SET cursor=$2,last_event_at=$3,last_received_at=now(),blocked_reason=NULL, \
        caught_up=($3 BETWEEN now() - interval '60 seconds' AND now() + interval '30 seconds') \
        WHERE relay_url=$1 AND cursor <= $2")
        .bind(relay).bind(event.seq).bind(event.time).execute(pool).await?;
    Ok(())
}

async fn reconcile_known_accounts(state: &AppState, relay: &str, seq: i64) -> anyhow::Result<()> {
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
            refresh_account(state, &did, relay, seq).await?;
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(MAX_CONNECTION_SECS);
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = heartbeat.tick() => {
                ping_nonce = rand::random::<[u8;16]>().to_vec();
                socket.send(Message::Ping(ping_nonce.clone().into())).await?;
            },
            _ = flush.tick() => if let Some(event) = pending.take() { checkpoint(&state.db,relay.as_str(),&event).await?; },
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
                            reconcile_known_accounts(state,relay.as_str(),event.seq.saturating_sub(1)).await?;
                            reconciled = true;
                        }
                        if event.identity || event.account {
                            let did = event.did.as_deref().unwrap();
                            state.did_resolver.invalidate_cached(did);
                            if relevant_account(&state.db,did).await? {
                                refresh_account(state,did,relay.as_str(),event.seq).await?;
                            }
                            checkpoint(&state.db,relay.as_str(),&event).await?;
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
        // No relay-supplied status survives in Event. Only PDS confirmation can
        // construct the ConfirmedStatus consumed by the state mutation path.
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
        let confirmed = confirm_status_with_transport(&app, AUTHOR, &transport)
            .await
            .unwrap();
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
        assert!(
            confirm_status_with_transport(&app, AUTHOR, &transport)
                .await
                .is_err(),
            "RepoNotFound must not confirm deletion"
        );
        require_active_account(&pool, AUTHOR).await.unwrap();
        serving.await.unwrap();
    }
}
