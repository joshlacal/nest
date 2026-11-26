//! `20261125000001_space_uri_at_space.sql` rewrites stored `at://{did}/space/...` URIs to
//! `at:space/{did}/...` in place, across the foreign keys, and is a no-op on re-run.
use sqlx::PgPool;

const MIGRATION: &str = include_str!("../migrations/20261125000001_space_uri_at_space.sql");
const OLD_SPACE: &str = "at://did:plc:migration-owner/space/blue.catbird.circle/3l7migrate1";
const NEW_SPACE: &str = "at:space/did:plc:migration-owner/blue.catbird.circle/3l7migrate1";
const OWNER: &str = "did:plc:migration-owner";

#[sqlx::test(migrations = "./migrations")]
async fn space_uri_migration_rewrites_old_form_and_is_idempotent(pool: PgPool) {
    let old_post = format!("{OLD_SPACE}/{OWNER}/app.bsky.feed.post/3l7post1");
    let old_like = format!("{OLD_SPACE}/{OWNER}/app.bsky.feed.like/3l7like1");
    let record = serde_json::json!({"$type": "app.bsky.feed.post", "text": "kept", "reply": {"parent": {"uri": old_post}}});

    sqlx::query(
        "INSERT INTO circles (space_uri, circle_id, authority_did, display_name, created_at) \
         VALUES ($1, '3l7migrate1', $2, 'Migration', now())",
    )
    .bind(OLD_SPACE)
    .bind(OWNER)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO circle_member_cache (space_uri, member_did) VALUES ($1, $2)")
        .bind(OLD_SPACE)
        .bind(OWNER)
        .execute(&pool)
        .await
        .unwrap();
    for (uri, collection, rkey, parent) in [
        (&old_post, "app.bsky.feed.post", "3l7post1", None),
        (&old_like, "app.bsky.feed.like", "3l7like1", Some(&old_post)),
    ] {
        sqlx::query(
            "INSERT INTO circle_records (uri, cid, space_uri, author_did, collection, rkey, record_json, created_at, parent_uri, root_uri) \
             VALUES ($1, 'bafyreimigration', $2, $3, $4, $5, $6, now(), $7, $7)",
        )
        .bind(uri)
        .bind(OLD_SPACE)
        .bind(OWNER)
        .bind(collection)
        .bind(rkey)
        .bind(&record)
        .bind(parent)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO circle_likes (uri, space_uri, post_uri, author_did, created_at) VALUES ($1, $2, $3, $4, now())",
    )
    .bind(&old_like)
    .bind(OLD_SPACE)
    .bind(&old_post)
    .bind(OWNER)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::raw_sql(MIGRATION).execute(&pool).await.unwrap();
    sqlx::raw_sql(MIGRATION).execute(&pool).await.unwrap();

    let new_post = format!("{NEW_SPACE}/{OWNER}/app.bsky.feed.post/3l7post1");
    let new_like = format!("{NEW_SPACE}/{OWNER}/app.bsky.feed.like/3l7like1");
    let circle: String = sqlx::query_scalar("SELECT space_uri FROM circles")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(circle, NEW_SPACE);
    let member: String = sqlx::query_scalar("SELECT space_uri FROM circle_member_cache")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(member, NEW_SPACE);
    let (parent, root, stored): (Option<String>, Option<String>, serde_json::Value) =
        sqlx::query_as(
            "SELECT parent_uri, root_uri, record_json FROM circle_records WHERE uri = $1 AND space_uri = $2",
        )
        .bind(&new_like)
        .bind(NEW_SPACE)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(parent.as_deref(), Some(new_post.as_str()));
    assert_eq!(root.as_deref(), Some(new_post.as_str()));
    assert_eq!(
        stored, record,
        "record values are CID-covered and stay as written"
    );
    let (like_uri, like_post): (String, String) =
        sqlx::query_as("SELECT uri, post_uri FROM circle_likes WHERE space_uri = $1")
            .bind(NEW_SPACE)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((like_uri, like_post), (new_like, new_post));

    // Foreign keys were re-created: a dangling child row is still refused.
    let dangling = sqlx::query(
        "INSERT INTO circle_member_cache (space_uri, member_did) VALUES ($1, 'did:plc:x')",
    )
    .bind(OLD_SPACE)
    .execute(&pool)
    .await;
    assert!(dangling.is_err());
}
