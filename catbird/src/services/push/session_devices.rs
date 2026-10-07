//! Which session registered which push device, so signing out one session stops only
//! that session's devices.
//!
//! `user_devices` has no session column, and adding one would make the previous
//! release refuse to start (sqlx rejects unknown applied migrations), turning a
//! binary rollback into a production DB write. The link therefore lives in Redis
//! next to the sessions it describes, keyed by the non-replayable SHA-256 session
//! fingerprint and bounded by the session index TTL:
//!
//! - `{prefix}push_device_session:{device_id}` → fingerprint of the registering session
//! - `{prefix}push_session_devices:{fingerprint}` → set of device row IDs
//!
//! The device key is authoritative: a device that a newer session re-registered
//! still sits in the old session's set, but no longer belongs to it.

use std::collections::BTreeSet;

use uuid::Uuid;

use crate::services::push::registry::{normalize_or_hash_session_fingerprint, PushRegistry};
use crate::services::push::types::SignOutPushOutcome;
use crate::services::{RedisAuthStore, SESSION_INDEX_TTL_SECONDS};

fn device_key(prefix: &str, device_id: Uuid) -> String {
    format!("{prefix}push_device_session:{device_id}")
}

fn session_key(prefix: &str, session_fp: &str) -> String {
    format!("{prefix}push_session_devices:{session_fp}")
}

/// Records that the session with `raw_session_id` registered `device_id`.
pub async fn link(
    store: &RedisAuthStore,
    device_id: Uuid,
    raw_session_id: &str,
) -> redis::RedisResult<()> {
    let prefix = store.key_prefix();
    let fp = normalize_or_hash_session_fingerprint(raw_session_id);
    let set_key = session_key(prefix, &fp);
    let mut conn = store.redis_connection();
    redis::pipe()
        .atomic()
        .cmd("SET")
        .arg(device_key(prefix, device_id))
        .arg(&fp)
        .arg("EX")
        .arg(SESSION_INDEX_TTL_SECONDS)
        .ignore()
        .cmd("SADD")
        .arg(&set_key)
        .arg(device_id.to_string())
        .ignore()
        .cmd("EXPIRE")
        .arg(&set_key)
        .arg(SESSION_INDEX_TTL_SECONDS)
        .ignore()
        .query_async(&mut conn)
        .await
}

async fn session_for_device(
    conn: &mut redis::aio::ConnectionManager,
    prefix: &str,
    device_id: Uuid,
) -> Option<String> {
    redis::cmd("GET")
        .arg(device_key(prefix, device_id))
        .query_async::<_, Option<String>>(conn)
        .await
        .ok()
        .flatten()
}

/// Devices whose current link points at this session.
async fn devices_owned_by(
    conn: &mut redis::aio::ConnectionManager,
    prefix: &str,
    session_fp: &str,
) -> Vec<Uuid> {
    let members: Vec<String> = redis::cmd("SMEMBERS")
        .arg(session_key(prefix, session_fp))
        .query_async(conn)
        .await
        .unwrap_or_default();
    let mut owned = Vec::new();
    for id in members.iter().filter_map(|m| Uuid::parse_str(m).ok()) {
        if session_for_device(conn, prefix, id).await.as_deref() == Some(session_fp) {
            owned.push(id);
        }
    }
    owned
}

/// Distinct sessions, other than the one signing out, that registered an active device.
pub fn handover_candidates(links: &[(Uuid, Option<String>)], leaving_fp: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    links
        .iter()
        .filter_map(|(_, fp)| fp.as_deref())
        .filter(|fp| *fp != leaving_fp && seen.insert(fp.to_string()))
        .map(str::to_string)
        .collect()
}

/// Stops notification access for one signed-out session: deactivates the devices it
/// registered and, if it was the account's push session, hands push over to another
/// live session with an active device, or revokes the account's push access when none
/// remains. Preferences, mutes and subscriptions are left untouched.
pub async fn sign_out_session(
    store: Option<&RedisAuthStore>,
    registry: &PushRegistry,
    did: &str,
    raw_session_id: &str,
) -> anyhow::Result<SignOutPushOutcome> {
    let leaving_fp = normalize_or_hash_session_fingerprint(raw_session_id);
    let (own_devices, handover_fp) = match store {
        Some(store) => {
            let prefix = store.key_prefix();
            let mut conn = store.redis_connection();
            let own = devices_owned_by(&mut conn, prefix, &leaving_fp).await;
            let mut links = Vec::new();
            for id in registry.active_device_ids(did).await? {
                if !own.contains(&id) {
                    links.push((id, session_for_device(&mut conn, prefix, id).await));
                }
            }
            let mut handover = None;
            for fp in handover_candidates(&links, &leaving_fp) {
                let live = store
                    .resolve_session_for_did_with_fingerprint(did, &fp)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|s| {
                        normalize_or_hash_session_fingerprint(s.session_id.as_str()) == fp
                    });
                if live {
                    handover = Some(fp);
                    break;
                }
            }
            (own, handover)
        }
        None => (Vec::new(), None),
    };
    let outcome = registry
        .sign_out_session(did, raw_session_id, &own_devices, handover_fp.as_deref())
        .await?;
    if let Some(store) = store {
        let prefix = store.key_prefix();
        let mut conn = store.redis_connection();
        let mut pipe = redis::pipe();
        pipe.cmd("DEL")
            .arg(session_key(prefix, &leaving_fp))
            .ignore();
        for id in &own_devices {
            pipe.cmd("DEL").arg(device_key(prefix, *id)).ignore();
        }
        let _: redis::RedisResult<()> = pipe.query_async(&mut conn).await;
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_use_fingerprints_and_device_ids_only() {
        let id = Uuid::nil();
        assert_eq!(
            device_key("p:", id),
            "p:push_device_session:00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(session_key("p:", "abc"), "p:push_session_devices:abc");
    }

    #[test]
    fn handover_skips_leaving_session_unlinked_devices_and_duplicates() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let d = Uuid::new_v4();
        let links = vec![
            (a, Some("leaving".to_string())),
            (b, None),
            (c, Some("other".to_string())),
            (d, Some("other".to_string())),
        ];
        assert_eq!(
            handover_candidates(&links, "leaving"),
            vec!["other".to_string()]
        );
        assert!(handover_candidates(&[], "leaving").is_empty());
    }
}
