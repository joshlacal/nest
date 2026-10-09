//! Reverse links between a session and its registered notification devices.
//!
//! New registrations also record `user_devices.auth_session_fingerprint` in the
//! SQL registration transaction. That SQL owner is authoritative for lifecycle
//! cleanup; these Redis links support lookup and verified legacy ownership.
//!
//! - `{prefix}push_device_session:{device_id}` → registering session fingerprint
//! - `{prefix}push_session_devices:{fingerprint}` → set of device row IDs
//!
//! A successful OAuth upgrade transfers proven old SQL ownership and repairs
//! these links under the same account lock. Another device's current SQL owner
//! is never inherited just because it supplies the account's push session.

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
    let did: Option<String> = redis::cmd("GET")
        .arg(store.session_index_key(raw_session_id))
        .query_async(&mut conn)
        .await?;
    let Some(did) = did else {
        return Err(redis::RedisError::from((
            redis::ErrorKind::ResponseError,
            "session no longer live",
        )));
    };
    let applied: i32 = redis::Script::new(
        r#"
        if redis.call('EXISTS',KEYS[3]) == 1 or redis.call('EXISTS',KEYS[4]) == 1
          or redis.call('EXISTS',KEYS[5]) == 0 then return 0 end
        redis.call('SET',KEYS[1],ARGV[1],'EX',ARGV[3])
        redis.call('SADD',KEYS[2],ARGV[2]); redis.call('EXPIRE',KEYS[2],ARGV[3]); return 1
    "#,
    )
    .key(device_key(prefix, device_id))
    .key(&set_key)
    .key(store.retired_key(raw_session_id))
    .key(store.account_erasure_key(&did))
    .key(store.session_key(&did, raw_session_id))
    .arg(&fp)
    .arg(device_id.to_string())
    .arg(SESSION_INDEX_TTL_SECONDS)
    .invoke_async(&mut conn)
    .await?;
    if applied == 1 {
        Ok(())
    } else {
        Err(redis::RedisError::from((
            redis::ErrorKind::ResponseError,
            "session no longer live",
        )))
    }
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
