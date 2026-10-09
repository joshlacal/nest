//! Real Redis expiry regressions. Synthetic sessions use a fresh owned prefix;
//! explicit disposable loopback URLs are mandatory. Root owns execution.
use catbird::services::{push::registry::session_fingerprint, RedisAuthStore};
use jacquard_common::types::did::Did;
use jacquard_oauth::authstore::ClientAuthStore;
use uuid::Uuid;

#[path = "support/cleanup_auth.rs"]
mod cleanup_auth;

const DID: &str = "did:plc:expiryfixture";
const SHORT_MS: i64 = 30_000;

async fn install(store: &RedisAuthStore) -> String {
    let bearer = Uuid::new_v4().to_string();
    store
        .upsert_session(cleanup_auth::grant(DID, &bearer, "https://pds.example.com"))
        .await
        .unwrap();
    bearer
}

fn keys(store: &RedisAuthStore, bearer: &str) -> [String; 4] {
    [
        store.session_key(DID, bearer),
        store.session_index_key(bearer),
        store.session_fp_index_key(bearer),
        store.did_index_key(DID),
    ]
}

async fn shorten(store: &RedisAuthStore, keys: &[String]) -> Vec<i64> {
    let mut conn = store.redis_connection();
    for key in keys {
        let changed: i64 = redis::cmd("PEXPIRE")
            .arg(key)
            .arg(SHORT_MS)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(changed, 1, "fixture key must exist before shortening");
    }
    ttls(store, keys).await
}

async fn ttls(store: &RedisAuthStore, keys: &[String]) -> Vec<i64> {
    let mut conn = store.redis_connection();
    let mut result = Vec::new();
    for key in keys {
        result.push(
            redis::cmd("PTTL")
                .arg(key)
                .query_async(&mut conn)
                .await
                .unwrap(),
        );
    }
    result
}

fn assert_not_extended(before: &[i64], after: &[i64]) {
    assert_eq!(before.len(), after.len());
    for (&before, &after) in before.iter().zip(after) {
        assert!(before > 0 && before <= SHORT_MS);
        assert!(
            after > 0 && after <= before,
            "unauthenticated read must not extend TTL: before={before}, after={after}"
        );
    }
}

#[tokio::test]
#[ignore = "root-owned disposable Redis fixture"]
async fn missing_blob_pointer_lookup_does_not_slide_indexes() {
    let store = cleanup_auth::store().await;
    let bearer = install(&store).await;
    let all = keys(&store, &bearer);
    let before = shorten(&store, &all[1..]).await;
    let mut conn = store.redis_connection();
    let _: () = redis::cmd("DEL")
        .arg(&all[0])
        .query_async(&mut conn)
        .await
        .unwrap();
    for _ in 0..3 {
        assert_eq!(store.lookup_did_for_session(&bearer).await.unwrap(), None);
    }
    assert_not_extended(&before, &ttls(&store, &all[1..]).await);
    let exists: bool = redis::cmd("EXISTS")
        .arg(&all[0])
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(!exists, "lookup must not recreate the absent grant");
}

#[tokio::test]
#[ignore = "root-owned disposable Redis fixture"]
async fn corrupt_blob_read_does_not_slide_blob_or_indexes() {
    let store = cleanup_auth::store().await;
    let bearer = install(&store).await;
    let all = keys(&store, &bearer);
    let mut conn = store.redis_connection();
    let _: () = redis::cmd("SET")
        .arg(&all[0])
        .arg("synthetic-invalid-ciphertext")
        .arg("PX")
        .arg(SHORT_MS)
        .query_async(&mut conn)
        .await
        .unwrap();
    let before = shorten(&store, &all).await;
    let did: Did = Did::new_owned(DID.to_string()).unwrap();
    for _ in 0..3 {
        assert!(store.get_session(&did, &bearer).await.is_err());
    }
    assert_not_extended(&before, &ttls(&store, &all).await);
    let value: String = redis::cmd("GET")
        .arg(&all[0])
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(value, "synthetic-invalid-ciphertext");
}

#[tokio::test]
#[ignore = "root-owned disposable Redis fixture"]
async fn only_verified_session_read_slides_expiration() {
    let store = cleanup_auth::store().await;
    let bearer = install(&store).await;
    let all = keys(&store, &bearer);
    let before = shorten(&store, &all).await;
    assert_eq!(
        store
            .lookup_did_for_session(&bearer)
            .await
            .unwrap()
            .as_deref(),
        Some(DID)
    );
    assert!(store
        .read_session_local(DID, &bearer)
        .await
        .unwrap()
        .is_some());
    assert_not_extended(&before, &ttls(&store, &all).await);
    let did: Did = Did::new_owned(DID.to_string()).unwrap();
    let read = store.get_session(&did, &bearer).await.unwrap().unwrap();
    assert_eq!(read.session_id.as_str(), bearer);
    for ttl in ttls(&store, &all).await {
        assert!(
            ttl > 3_000_000,
            "verified read must apply configured sliding TTL, got {ttl}"
        );
    }
}

#[tokio::test]
#[ignore = "root-owned disposable Redis fixture"]
async fn fingerprint_resolver_miss_does_not_slide_orphan_indexes() {
    let store = cleanup_auth::store().await;
    let bearer = install(&store).await;
    let all = keys(&store, &bearer);
    let before = shorten(&store, &all[1..]).await;
    let mut conn = store.redis_connection();
    let _: () = redis::cmd("DEL")
        .arg(&all[0])
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(store
        .resolve_session_for_did_with_fingerprint(DID, &session_fingerprint(&bearer))
        .await
        .unwrap()
        .is_none());
    assert_not_extended(&before, &ttls(&store, &all[1..]).await);
    let exists: bool = redis::cmd("EXISTS")
        .arg(&all[0])
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(!exists);
}
