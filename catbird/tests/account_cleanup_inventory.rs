//! Synthetic inventory and isolated-store tests. No ambient DATABASE_URL or
//! REDIS_URL fallback. Real-store cases are ignored until the root owns the
//! fixture lane; they require explicit loopback task7 fixture URLs and create
//! only their own random schema/prefix. They never run migrations/admin CLI.

use std::collections::{BTreeMap, BTreeSet};

use catbird::services::account_cleanup_inventory::*;
use catbird::services::RedisAuthStore;
use sqlx::PgPool;
use uuid::Uuid;

const A: &str = "did:plc:cleanupfixtureaaaa";
const B: &str = "did:plc:cleanupfixturebbbb";
const PREFIX: &str = "test:v2:cleanup:";

fn authorization() -> CleanupAuthorization {
    CleanupAuthorization {
        account_scope: Some(AccountEraseScope::ExplicitAccountEraseAfterLastActiveSessionLogout),
        quiescence: Some(Quiescence::AllAccountWritersAndInflightWorkDrained),
        retry_credentials: Some(RetryCredentialPolicy::Delete),
    }
}

fn catalog() -> SchemaInventory {
    let mut c = SchemaInventory::default();
    for spec in SQL_TABLES {
        c.base_tables
            .entry(spec.table.into())
            .or_default()
            .insert(spec.owner_column.into(), spec.owner_type.into());
    }
    for (table, column, kind) in [
        ("user_devices", "id", "uuid"),
        ("user_devices", "auth_session_fingerprint", "text"),
        ("push_event_receipts", "dedupe_key", "text"),
        ("push_device_deliveries", "device_id", "uuid"),
    ] {
        c.base_tables
            .get_mut(table)
            .unwrap()
            .insert(column.into(), kind.into());
    }
    c
}

fn captured() -> CapturedSqlIdentities {
    CapturedSqlIdentities {
        did: A.into(),
        device_ids: BTreeSet::new(),
        receipt_keys: BTreeSet::new(),
        historical_delivery_device_ids: BTreeSet::new(),
        capture_complete: true,
    }
}

fn discovery() -> RedisDiscovery {
    RedisDiscovery {
        records: Vec::new(),
        sessions: Vec::new(),
        completely_inspected: REDIS_FAMILIES.iter().copied().collect(),
        unresolved_records: 0,
        preserved_preaccount_operational: 0,
        preserved_safety_metadata: 0,
    }
}

fn prepare(
    auth: CleanupAuthorization,
    cap: CapturedSqlIdentities,
    redis: RedisDiscovery,
) -> Result<AccountCleanupPlan, InventoryError> {
    AccountCleanupPlan::prepare(A, "public", PREFIX, auth, &catalog(), cap, redis)
}

#[test]
fn account_authority_quiescence_capture_and_discovery_are_required() {
    let mut auth = authorization();
    auth.account_scope = None;
    assert!(matches!(
        prepare(auth, captured(), discovery()),
        Err(InventoryError::AccountScopeNotAuthorized)
    ));
    let mut auth = authorization();
    auth.quiescence = None;
    assert!(matches!(
        prepare(auth, captured(), discovery()),
        Err(InventoryError::AccountNotQuiescent)
    ));
    let mut auth = authorization();
    auth.retry_credentials = None;
    assert!(matches!(
        prepare(auth, captured(), discovery()),
        Err(InventoryError::RetryCredentialPolicyNotChosen)
    ));
    let mut cap = captured();
    cap.capture_complete = false;
    assert!(matches!(
        prepare(authorization(), cap, discovery()),
        Err(InventoryError::IncompleteSqlCapture)
    ));
    let mut d = discovery();
    d.completely_inspected.remove(&RedisFamily::Exchange);
    assert!(matches!(
        prepare(authorization(), captured(), d),
        Err(InventoryError::IncompleteRedisDiscovery)
    ));
    let mut d = discovery();
    d.unresolved_records = 1;
    assert!(matches!(
        prepare(authorization(), captured(), d),
        Err(InventoryError::IncompleteRedisDiscovery)
    ));
}

#[test]
fn ownership_scope_and_legacy_shape_are_not_guessed() {
    let mut cap = captured();
    cap.did = B.into();
    assert!(matches!(
        prepare(authorization(), cap, discovery()),
        Err(InventoryError::ForeignAccountIdentity)
    ));
    let mut d = discovery();
    d.records.push(VerifiedRedisRecord {
        owner_did: B.into(),
        family: RedisFamily::DidIndex,
        key: format!("{PREFIX}did_index:{B}"),
    });
    assert!(matches!(
        prepare(authorization(), captured(), d),
        Err(InventoryError::ForeignAccountIdentity)
    ));
    let mut c = catalog();
    c.base_tables
        .get_mut("notification_preferences")
        .unwrap()
        .insert("user_id".into(), "text".into());
    assert!(matches!(
        AccountCleanupPlan::prepare(
            A,
            "public",
            PREFIX,
            authorization(),
            &c,
            captured(),
            discovery()
        ),
        Err(InventoryError::MissingOrUnexpectedColumn(
            "notification_preferences",
            "user_id"
        ))
    ));
    let mut c = catalog();
    c.base_tables.remove("notification_preferences");
    c.non_base_tables.insert("notification_preferences".into());
    assert!(matches!(
        AccountCleanupPlan::prepare(
            A,
            "public",
            PREFIX,
            authorization(),
            &c,
            captured(),
            discovery()
        ),
        Err(InventoryError::MissingOrUnexpectedTable(
            "notification_preferences"
        ))
    ));
    assert!(capture_queries("public; DROP SCHEMA public").is_err());
}

#[test]
fn candidate_children_and_all_local_state_are_included_but_shared_state_is_not() {
    let plan =
        prepare(authorization(), captured(), discovery()).unwrap_or_else(|e| panic!("{e:?}"));
    let tables: Vec<_> = plan.sql_operations().iter().map(|o| o.table).collect();
    assert_eq!(tables.len(), 22);
    for table in [
        "push_device_deliveries",
        "push_event_receipts",
        "chat_mute_sync_generations",
        "push_preferences",
        "activity_subscriptions",
        "thread_mutes",
        "chat_muted_convos",
        "chat_notified_watermarks",
        "chat_poll_state",
        "user_devices",
        "notification_preferences",
        "relationship_audit_log",
        "user_blocks_encrypted",
        "user_mutes_hashed",
    ] {
        assert!(tables.contains(&table));
    }
    let position = |name| tables.iter().position(|t| *t == name).unwrap();
    assert!(position("push_device_deliveries") < position("push_event_receipts"));
    assert!(position("notification_preferences") < position("user_devices"));
    for table in [
        "firehose_cursor",
        "did_cache",
        "post_cache",
        "moderation_list_members",
    ] {
        assert!(!tables.contains(&table));
    }
    for operation in plan.sql_operations() {
        assert!(operation.statement.contains("$1"));
        assert!(!operation.statement.contains(A));
        assert!(!operation.statement.contains("WHERE actor_did"));
        assert!(!operation.statement.contains("WHERE subject_did"));
    }
}

#[test]
fn redis_derivation_is_exact_and_tombstones_and_retry_exception_are_explicit() {
    let mut d = discovery();
    d.sessions.push(VerifiedSessionIdentity {
        owner_did: A.into(),
        hmac_fingerprint: "a".repeat(64),
        sha256_fingerprint: "b".repeat(64),
    });
    d.records.push(VerifiedRedisRecord {
        owner_did: A.into(),
        family: RedisFamily::LogoutGrant,
        key: format!("{PREFIX}logout_cleanup_grant:{}", "c".repeat(64)),
    });
    d.preserved_preaccount_operational = 2;
    d.preserved_safety_metadata = 3;
    let mut auth = authorization();
    auth.retry_credentials =
        Some(RetryCredentialPolicy::RetainUntilExistingExpiryForUpstreamRevocation);
    let plan = prepare(auth, captured(), d).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(plan.retained_retry_keys.len(), 3);
    assert_eq!(plan.preserved_preaccount_operational, 2);
    assert_eq!(plan.preserved_safety_metadata, 3);
    assert_eq!(plan.retained_replay_tombstones.len(), 1);
    assert!(!plan.redis_operations().iter().any(|o| matches!(
        o.family,
        RedisFamily::Retired
            | RedisFamily::RevokeJob
            | RedisFamily::RevokeClaim
            | RedisFamily::LogoutGrant
    )));
    assert!(plan.redis_operations().iter().all(|o| !o.key.contains('*')));
    assert!(plan
        .redis_operations()
        .iter()
        .any(|o| o.key == format!("{PREFIX}session:{A}_{}", "a".repeat(64))));
    let mut d = discovery();
    d.records.push(VerifiedRedisRecord {
        owner_did: A.into(),
        family: RedisFamily::LogoutGrant,
        key: format!("{PREFIX}logout_cleanup_grant:{}", "c".repeat(64)),
    });
    let delete_plan = prepare(authorization(), captured(), d).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(delete_plan
        .redis_operations()
        .iter()
        .any(|operation| operation.family == RedisFamily::LogoutGrant));
    assert!(delete_plan.retained_retry_keys.is_empty());
    let mut d = discovery();
    d.records.push(VerifiedRedisRecord {
        owner_did: A.into(),
        family: RedisFamily::Session,
        key: format!("{PREFIX}session:{A}longer_{}", "a".repeat(64)),
    });
    assert!(matches!(
        prepare(authorization(), captured(), d),
        Err(InventoryError::InvalidRedisKey)
    ));
}

#[test]
fn historical_devices_must_be_resolved_before_parent_rows_can_disappear() {
    let mut cap = captured();
    cap.historical_delivery_device_ids
        .insert(Uuid::new_v4().to_string());
    assert!(matches!(
        prepare(authorization(), cap, discovery()),
        Err(InventoryError::IncompleteRedisDiscovery)
    ));
}

#[test]
fn rollback_commit_unknown_and_partial_redis_never_mean_erased() {
    for sql in [
        SqlOutcome::NotStarted,
        SqlOutcome::RolledBack,
        SqlOutcome::RollbackUnknown,
        SqlOutcome::CommitUnknown,
    ] {
        assert_eq!(
            completion(sql, RedisOutcome::Deleted, true, false),
            CleanupCompletion::Pending
        );
    }
    assert_eq!(
        completion(
            SqlOutcome::Committed,
            RedisOutcome::PartialOrUnknown,
            true,
            false
        ),
        CleanupCompletion::Pending
    );
    assert_eq!(
        completion(SqlOutcome::Committed, RedisOutcome::Deleted, false, false),
        CleanupCompletion::Pending
    );
    assert_eq!(
        completion(SqlOutcome::Committed, RedisOutcome::Deleted, true, true),
        CleanupCompletion::ErasedWithExplicitRetryCredentialException
    );
}

struct Fixture {
    pool: PgPool,
    store: RedisAuthStore,
    schema: String,
    nonce: String,
}

impl Fixture {
    async fn new() -> Self {
        let pg_url = std::env::var("TASK7_ACCOUNT_CLEANUP_FIXTURE_DATABASE_URL")
            .expect("explicit fresh task7 fixture URL required");
        let redis_url = std::env::var("TASK7_ACCOUNT_CLEANUP_FIXTURE_REDIS_URL")
            .expect("explicit fresh task7 Redis fixture URL required");
        let pg = url::Url::parse(&pg_url).unwrap();
        let redis = url::Url::parse(&redis_url).unwrap();
        assert_eq!(pg.host_str(), Some("127.0.0.1"));
        assert_eq!(pg.username(), "lite_push_test");
        assert!(pg.path().starts_with("/task7_"));
        assert_eq!(redis.host_str(), Some("127.0.0.1"));
        let schema = format!("cleanup_{}", Uuid::new_v4().simple());
        let prefix = format!("task7:v2:{schema}:");
        let pool = PgPool::connect(&pg_url).await.expect("fixture PostgreSQL");
        let conn = redis::aio::ConnectionManager::new(redis::Client::open(redis_url).unwrap())
            .await
            .expect("fixture Redis");
        let store = RedisAuthStore::from_key(conn, prefix, 3600, [42; 32]).unwrap();
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(&pool)
            .await
            .unwrap();
        let c = catalog();
        for (table, columns) in &c.base_tables {
            let columns = columns
                .iter()
                .map(|(name, kind)| format!("\"{name}\" {kind} NOT NULL"))
                .collect::<Vec<_>>()
                .join(", ");
            sqlx::query(&format!(
                "CREATE TABLE \"{schema}\".\"{table}\" ({columns})"
            ))
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(&format!(
            "ALTER TABLE \"{schema}\".push_event_receipts ADD PRIMARY KEY(dedupe_key)"
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            "ALTER TABLE \"{schema}\".user_devices ADD PRIMARY KEY(id)"
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(&format!("ALTER TABLE \"{schema}\".push_device_deliveries ADD FOREIGN KEY(dedupe_key) REFERENCES \"{schema}\".push_event_receipts(dedupe_key)")).execute(&pool).await.unwrap();
        for table in [
            "did_cache",
            "post_cache",
            "firehose_cursor",
            "moderation_list_members",
        ] {
            sqlx::raw_sql(&format!("CREATE TABLE \"{schema}\".\"{table}\" (sentinel text); INSERT INTO \"{schema}\".\"{table}\" VALUES ('shared')"))
                .execute(&pool).await.unwrap();
        }
        let nonce = Uuid::new_v4().to_string();
        let mut redis = store.redis_connection();
        let _: () = redis::cmd("SET")
            .arg(format!("{}account_erasure:{A}", store.key_prefix()))
            .arg(&nonce)
            .query_async(&mut redis)
            .await
            .unwrap();
        Self {
            pool,
            store,
            schema,
            nonce,
        }
    }

    async fn seed(&self) {
        let a_device = Uuid::new_v4();
        let b_device = Uuid::new_v4();
        let historic = Uuid::new_v4();
        for (did, device, receipt) in [(A, a_device, "event_a"), (B, b_device, "event_b")] {
            for spec in SQL_TABLES {
                let table = format!("\"{}\".\"{}\"", self.schema, spec.table);
                match spec.table {
                    "push_device_deliveries" => (), // parents first below
                    "notification_preferences" => {
                        sqlx::query(&format!("INSERT INTO {table}(user_id) VALUES($1)"))
                            .bind(device)
                            .execute(&self.pool)
                            .await
                            .unwrap();
                    }
                    "user_devices" => {
                        sqlx::query(&format!(
                            "INSERT INTO {table}(id,did,auth_session_fingerprint) VALUES($1,$2,$3)"
                        ))
                        .bind(device)
                        .bind(did)
                        .bind("a".repeat(64))
                        .execute(&self.pool)
                        .await
                        .unwrap();
                    }
                    "push_event_receipts" => {
                        sqlx::query(&format!(
                            "INSERT INTO {table}(dedupe_key,recipient_did) VALUES($1,$2)"
                        ))
                        .bind(receipt)
                        .bind(did)
                        .execute(&self.pool)
                        .await
                        .unwrap();
                    }
                    _ => {
                        sqlx::query(&format!(
                            "INSERT INTO {table}(\"{}\") VALUES($1)",
                            spec.owner_column
                        ))
                        .bind(did)
                        .execute(&self.pool)
                        .await
                        .unwrap();
                    }
                }
            }
            sqlx::query(&format!(
                "INSERT INTO \"{}\".push_device_deliveries(dedupe_key,device_id) VALUES($1,$2)",
                self.schema
            ))
            .bind(receipt)
            .bind(if did == A { historic } else { device })
            .execute(&self.pool)
            .await
            .unwrap();
        }
        sqlx::query(&format!("ALTER TABLE \"{}\".notification_preferences ADD FOREIGN KEY(user_id) REFERENCES \"{}\".user_devices(id)", self.schema, self.schema))
            .execute(&self.pool).await.unwrap();
        for (table, column) in [
            ("activity_subscriptions", "subject_did"),
            ("push_event_queue", "actor_did"),
            ("actor_moderation_verdict", "actor_did"),
        ] {
            sqlx::query(&format!(
                "ALTER TABLE \"{}\".\"{table}\" ADD COLUMN \"{column}\" TEXT",
                self.schema
            ))
            .execute(&self.pool)
            .await
            .unwrap();
            sqlx::query(&format!(
                "UPDATE \"{}\".\"{table}\" SET \"{column}\"=$1",
                self.schema
            ))
            .bind(A)
            .execute(&self.pool)
            .await
            .unwrap();
        }
    }

    async fn locked_plan(&self) -> (LockedSqlInventory, AccountCleanupPlan) {
        let locked =
            LockedSqlInventory::begin(&self.pool, &self.store, A, &self.nonce, &self.schema)
                .await
                .unwrap();
        let mut d = discovery();
        for device in locked
            .captured
            .device_ids
            .union(&locked.captured.historical_delivery_device_ids)
        {
            d.records.push(VerifiedRedisRecord {
                owner_did: A.into(),
                family: RedisFamily::DeviceSession,
                key: format!("{}push_device_session:{device}", self.store.key_prefix()),
            });
        }
        let plan = AccountCleanupPlan::prepare(
            A,
            &self.schema,
            self.store.key_prefix(),
            authorization(),
            &locked.catalog,
            locked.captured.clone(),
            d,
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
        (locked, plan)
    }

    async fn cleanup(self) {
        sqlx::query(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema))
            .execute(&self.pool)
            .await
            .unwrap();
        let mut conn = self.store.redis_connection();
        let _: i64 = redis::cmd("DEL")
            .arg(format!("{}account_erasure:{A}", self.store.key_prefix()))
            .query_async(&mut conn)
            .await
            .unwrap();
        self.pool.close().await;
    }
}

#[tokio::test]
#[ignore = "requires explicitly authorized fresh task7 PostgreSQL/Redis fixture lane"]
async fn real_store_account_isolation_receipt_order_and_fence_are_enforced() {
    let f = Fixture::new().await;
    f.seed().await;
    assert!(LockedSqlInventory::begin(
        &f.pool,
        &f.store,
        A,
        &Uuid::new_v4().to_string(),
        &f.schema
    )
    .await
    .is_err());
    let (locked, plan) = f.locked_plan().await;
    assert_eq!(plan.captured.device_ids.len(), 1);
    assert_eq!(plan.captured.historical_delivery_device_ids.len(), 1);
    let outcome = locked.erase(&f.store, &plan).await;
    assert!(outcome.is_ok());
    let mut remaining = BTreeMap::new();
    for spec in SQL_TABLES {
        let n: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM \"{}\".\"{}\"",
            f.schema, spec.table
        ))
        .fetch_one(&f.pool)
        .await
        .unwrap();
        remaining.insert(spec.table, n);
    }
    assert!(
        remaining.values().all(|n| *n == 1),
        "the other account must remain in every store"
    );
    for table in [
        "did_cache",
        "post_cache",
        "firehose_cursor",
        "moderation_list_members",
    ] {
        let n: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM \"{}\".\"{table}\"",
            f.schema
        ))
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(n, 1);
    }
    let mut conn = f.store.redis_connection();
    let fence: Option<String> = redis::cmd("GET")
        .arg(format!("{}account_erasure:{A}", f.store.key_prefix()))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        fence.as_deref(),
        Some(f.nonce.as_str()),
        "SQL must leave cross-store fence installed"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires explicitly authorized fresh task7 PostgreSQL/Redis fixture lane"]
async fn real_store_error_rolls_back_children_and_keeps_cleanup_pending() {
    let f = Fixture::new().await;
    f.seed().await;
    sqlx::raw_sql(&format!("CREATE FUNCTION \"{}\".reject_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic deletion failure'; END $$; CREATE TRIGGER reject_delete BEFORE DELETE ON \"{}\".push_preferences FOR EACH ROW EXECUTE FUNCTION \"{}\".reject_delete();", f.schema, f.schema, f.schema))
        .execute(&f.pool).await.unwrap();
    let (locked, plan) = f.locked_plan().await;
    let outcome = locked.erase(&f.store, &plan).await;
    let failure = match outcome {
        Err(failure) => failure,
        Ok(_) => panic!("fixture trigger must fail"),
    };
    assert_eq!(failure.outcome, SqlOutcome::RolledBack);
    let children: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM \"{}\".push_device_deliveries",
        f.schema
    ))
    .fetch_one(&f.pool)
    .await
    .unwrap();
    let legacy: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM \"{}\".notification_preferences",
        f.schema
    ))
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!((children, legacy), (2, 2));
    assert_eq!(
        completion(
            failure.outcome,
            RedisOutcome::PartialOrUnknown,
            false,
            false
        ),
        CleanupCompletion::Pending
    );
    f.cleanup().await;
}
