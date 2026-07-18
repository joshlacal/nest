const UP_MIGRATION: &str =
    include_str!("../migrations/20260718040000_quarantine_legacy_moderation_backfill.up.sql");
const DOWN_MIGRATION: &str =
    include_str!("../migrations/20260718040000_quarantine_legacy_moderation_backfill.down.sql");

#[test]
fn corrective_migration_quarantines_rows_and_both_freshness_markers() {
    assert!(UP_MIGRATION.contains("DELETE FROM moderation_list_members_by_user"));
    assert!(UP_MIGRATION.contains("UPDATE moderation_list_subscriptions"));
    assert!(UP_MIGRATION.contains("last_synced_at = NULL"));
    assert!(UP_MIGRATION.contains("UPDATE push_accounts"));
    assert!(UP_MIGRATION.contains("last_list_sync_at = NULL"));
    assert!(!UP_MIGRATION.contains("INSERT INTO moderation_list_members_by_user"));
    assert!(!UP_MIGRATION.contains("FROM moderation_list_members AS"));
}

#[test]
fn corrective_down_migration_is_explicitly_non_restorative() {
    assert!(DOWN_MIGRATION.contains("Intentionally non-restorative"));
    assert!(!DOWN_MIGRATION.contains("INSERT"));
    assert!(!DOWN_MIGRATION.contains("UPDATE"));
    assert!(!DOWN_MIGRATION.contains("DELETE"));
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL with migration privileges"]
async fn corrective_migration_is_idempotent_with_populated_or_empty_backfill() {
    use sqlx::{Connection, Executor, PgConnection, Row};

    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL is required for the ignored PostgreSQL test");
    let mut connection = PgConnection::connect(&database_url)
        .await
        .expect("connect to PostgreSQL test database");
    let schema = format!("moderation_quarantine_{}", uuid::Uuid::new_v4().simple());

    connection
        .execute(format!("CREATE SCHEMA {schema}").as_str())
        .await
        .expect("create isolated schema");
    connection
        .execute(format!("SET search_path TO {schema}").as_str())
        .await
        .expect("select isolated schema");
    connection
        .execute(
            r#"
            CREATE TABLE moderation_list_members_by_user (
                user_did TEXT NOT NULL,
                list_uri TEXT NOT NULL,
                subject_did TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (user_did, list_uri, subject_did)
            );
            CREATE TABLE moderation_list_subscriptions (
                user_did TEXT NOT NULL,
                list_uri TEXT NOT NULL,
                last_synced_at TIMESTAMPTZ,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (user_did, list_uri)
            );
            CREATE TABLE push_accounts (
                account_did TEXT PRIMARY KEY,
                last_list_sync_at TIMESTAMPTZ,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            INSERT INTO moderation_list_members_by_user (user_did, list_uri, subject_did)
            VALUES ('did:plc:a', 'at://list/shared', 'did:plc:from-b');
            INSERT INTO moderation_list_subscriptions (
                user_did, list_uri, last_synced_at
            ) VALUES ('did:plc:a', 'at://list/shared', NOW());
            INSERT INTO push_accounts (account_did, last_list_sync_at)
            VALUES ('did:plc:a', NOW());
            "#,
        )
        .await
        .expect("seed ambiguous backfill and fresh markers");

    sqlx::raw_sql(UP_MIGRATION)
        .execute(&mut connection)
        .await
        .expect("apply corrective migration to populated state");
    sqlx::raw_sql(UP_MIGRATION)
        .execute(&mut connection)
        .await
        .expect("reapply corrective migration to empty state");

    let members: i64 = sqlx::query("SELECT COUNT(*) AS count FROM moderation_list_members_by_user")
        .fetch_one(&mut connection)
        .await
        .expect("count quarantined rows")
        .try_get("count")
        .expect("read count");
    let subscription_is_stale: bool =
        sqlx::query("SELECT last_synced_at IS NULL AS stale FROM moderation_list_subscriptions")
            .fetch_one(&mut connection)
            .await
            .expect("read subscription freshness")
            .try_get("stale")
            .expect("read subscription stale flag");
    let account_is_stale: bool =
        sqlx::query("SELECT last_list_sync_at IS NULL AS stale FROM push_accounts")
            .fetch_one(&mut connection)
            .await
            .expect("read account freshness")
            .try_get("stale")
            .expect("read account stale flag");

    assert_eq!(members, 0);
    assert!(subscription_is_stale);
    assert!(account_is_stale);

    connection
        .execute("SET search_path TO public")
        .await
        .expect("restore public schema");
    connection
        .execute(format!("DROP SCHEMA {schema} CASCADE").as_str())
        .await
        .expect("drop isolated schema");
}
