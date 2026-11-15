//! Paired `mls-ds` → Nest direct-request wake harness (test-only).
//!
//! `mls-ds/e2e-tests` (t16, c32) publishes a real direct request through a real
//! DS process, then starts one of these tests as a second process. The harness
//! serves Nest's production D2 Push Gateway (`registerKey`, `deliver`) on
//! loopback with a recording provider transport. The device registers its
//! synthetic native token here over HTTP and receives an opaque `pushKey`,
//! registers that key with its DS through `registerPushGateway`, and the DS
//! worker's authenticated `wakeKind=directRequest` wake must reach the fake
//! provider as Nest's generic envelope. Native tokens only ever arrive over
//! loopback HTTP and never reach an artifact or the log.

mod c32_paired_harness;
mod paired_harness;

use std::{
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::{anyhow, ensure, Result};
use atproto_spaces::{did_resolver::DidDocument, tokens::SpaceVerifyingKey};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Extension, Json, Router,
};
use catbird_atproto::generated::blue_catbird::push::register_key::RegisterKey;
use chrono::Utc;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, Executor as _, PgPool, Row as _};
use uuid::Uuid;

use super::gateway::{
    extract_user_atproto_mls_service_did, DispatchedGatewayPush, GatewayDeliveryOutcome,
    GatewayPlatform, MlsDsIdentityResolver, PushGatewayConfig, PushGatewayService,
    PushGatewayTransport,
};
use crate::{
    handlers::push_gateway::{deliver_with_service, register_key_with_service},
    models::CatbirdSession,
};

/// The gateway URL the DS signs as `htu`; the DS fixture maps it to loopback.
const CANONICAL_GATEWAY_URL: &str =
    "https://nest.paired-push.invalid/xrpc/blue.catbird.push.deliver";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Scenario {
    /// The provider fails the first wake; the DS's durable retry delivers it.
    RetryAfterProviderFailure,
    /// The request was answered before the wake; the DS must not wake at all.
    CanonicalIneligible,
    /// The provider accepts but the gateway's ACK to the DS is lost; the DS
    /// retries with the identical wake.
    ProviderAcceptedAckLost,
    /// The device re-registered with an FCM token; only FCM may be used.
    FcmRouting,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fixture {
    event_id: Uuid,
    conversation_id: Uuid,
    recipient_did: String,
    /// The recipient's DID document; its `#atproto_mls` service is the only DS
    /// allowed to wake the keys it registers.
    recipient_did_document: Value,
    /// The waking DS's DID document; its `#atproto` key verifies wake JWTs.
    ds_did_document: Value,
    scenario: Scenario,
}

/// DID resolution answered from the fixture's documents through Nest's
/// production parsers.
struct FixtureResolver {
    recipient_did: String,
    recipient_document: Vec<u8>,
    ds_document: Vec<u8>,
}

#[async_trait::async_trait]
impl MlsDsIdentityResolver for FixtureResolver {
    async fn resolve_user_mls_service_did(&self, account_did: &str) -> Result<String> {
        ensure!(account_did == self.recipient_did, "unknown account");
        extract_user_atproto_mls_service_did(&self.recipient_document, account_did)
    }

    async fn resolve_ds_atproto_key(
        &self,
        caller_ds_did: &str,
        _force_refresh: bool,
    ) -> Result<SpaceVerifyingKey> {
        DidDocument::parse_json(caller_ds_did, &self.ds_document)
            .map_err(|error| anyhow!("caller DS document: {error}"))?
            .atproto_key
            .ok_or_else(|| anyhow!("caller DS document has no #atproto key"))
    }
}

/// Fake APNs/FCM: records every dispatch, optionally failing the first one.
#[derive(Default)]
struct Provider {
    calls: Mutex<Vec<DispatchedGatewayPush>>,
    fail_first: AtomicBool,
}

#[async_trait::async_trait]
impl PushGatewayTransport for Provider {
    async fn send(&self, push: DispatchedGatewayPush) -> Result<GatewayDeliveryOutcome> {
        self.calls.lock().unwrap().push(push);
        if self.fail_first.swap(false, Ordering::SeqCst) {
            anyhow::bail!("controlled transient provider failure");
        }
        Ok(GatewayDeliveryOutcome::Delivered)
    }
}

/// One harness process: Nest's gateway on loopback plus what it observed.
struct Paired {
    pool: PgPool,
    schema: String,
    provider: Arc<Provider>,
    /// `(platform, native token)` in registration order; process memory only.
    registrations: Arc<Mutex<Vec<(String, String)>>>,
    acks_dropped: Arc<AtomicUsize>,
    deliveries: Arc<AtomicUsize>,
    base_url: String,
    server: tokio::task::JoinHandle<()>,
}

fn session(did: &str) -> CatbirdSession {
    let now = Utc::now();
    CatbirdSession {
        id: Uuid::new_v4(),
        did: did.to_owned(),
        handle: "paired-recipient.test".into(),
        pds_url: "https://pds.paired-push.invalid".into(),
        access_token: String::new(),
        refresh_token: String::new(),
        scopes: Vec::new(),
        access_token_expires_at: now + chrono::Duration::hours(1),
        created_at: now,
        last_used_at: now,
        granted_scopes: Vec::new(),
    }
}

/// An isolated schema holding Nest's real `push_gateway_keys` table.
async fn database(url: &str) -> Result<(PgPool, String)> {
    let schema = format!("push_paired_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new().max_connections(1).connect(url).await?;
    admin
        .execute(format!("CREATE SCHEMA \"{schema}\"").as_str())
        .await?;
    admin.close().await;
    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |conn, _| {
            let search_path = search_path.clone();
            Box::pin(async move {
                conn.execute(format!("SET search_path TO \"{search_path}\"").as_str())
                    .await?;
                Ok(())
            })
        })
        .connect(url)
        .await?;
    pool.execute(include_str!(
        "../../../../migrations/20261031000001_push_gateway_keys.up.sql"
    ))
    .await?;
    pool.execute(include_str!(
        "../../../../migrations/20261111000001_push_gateway_keys_session.up.sql"
    ))
    .await?;
    Ok((pool, schema))
}

impl Paired {
    async fn start(
        database_url: &str,
        recipient_did: &str,
        resolver: FixtureResolver,
        scenario: Scenario,
    ) -> Result<Self> {
        let (pool, schema) = database(database_url).await?;
        let provider = Arc::new(Provider::default());
        provider.fail_first.store(
            scenario == Scenario::RetryAfterProviderFailure,
            Ordering::SeqCst,
        );
        let mut token_key = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token_key);
        let gateway = Arc::new(PushGatewayService::new(
            pool.clone(),
            PushGatewayConfig {
                gateway_url: CANONICAL_GATEWAY_URL.into(),
                token_encryption_key: token_key,
                wake_envelope: crate::services::push::gateway::WakeEnvelopeMode::ClearV1,
                per_key_burst: 10,
                per_key_per_minute: 30,
                per_ds_burst: 200,
                per_ds_per_minute: 600,
            },
            Arc::new(resolver),
            provider.clone(),
        ));
        let registrations = Arc::new(Mutex::new(Vec::new()));
        let acks_dropped = Arc::new(AtomicUsize::new(0));
        let deliveries = Arc::new(AtomicUsize::new(0));
        let register_state = (gateway.clone(), registrations.clone());
        let deliver_state = (gateway, acks_dropped.clone(), deliveries.clone());
        let router = Router::new()
            .route(
                "/xrpc/blue.catbird.push.registerKey",
                post(
                    move |Extension(session): Extension<CatbirdSession>,
                          Json(input): Json<RegisterKey>| {
                        let (gateway, registrations) = register_state.clone();
                        async move {
                            let platform = input.platform.as_str().to_owned();
                            let token = input.native_token.as_str().to_owned();
                            let output = register_key_with_service(
                                State(gateway),
                                Extension(session),
                                Json(input),
                            )
                            .await?;
                            registrations.lock().unwrap().push((platform, token));
                            Ok::<_, crate::error::AppError>(output)
                        }
                    },
                ),
            )
            .route(
                "/xrpc/blue.catbird.push.deliver",
                post(move |headers: HeaderMap, body: Bytes| {
                    let (gateway, acks_dropped, deliveries) = deliver_state.clone();
                    async move {
                        deliveries.fetch_add(1, Ordering::SeqCst);
                        let (status, payload) =
                            deliver_with_service(State(gateway), headers, body).await;
                        // The provider already accepted this wake; losing the
                        // gateway's acknowledgement must make the DS retry.
                        if scenario == Scenario::ProviderAcceptedAckLost
                            && status == StatusCode::ACCEPTED
                            && acks_dropped
                                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok()
                        {
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(json!({"error": "AckLost"})),
                            );
                        }
                        (status, payload)
                    }
                }),
            )
            .layer(Extension(session(recipient_did)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base_url = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Ok(Self {
            pool,
            schema,
            provider,
            registrations,
            acks_dropped,
            deliveries,
            base_url,
            server,
        })
    }

    async fn stop(self) {
        self.server.abort();
        let _ = self
            .pool
            .execute(format!("DROP SCHEMA IF EXISTS \"{}\" CASCADE", self.schema).as_str())
            .await;
        self.pool.close().await;
    }

    fn calls(&self) -> Vec<DispatchedGatewayPush> {
        self.provider.calls.lock().unwrap().clone()
    }

    fn calls_on(&self, platforms: &[GatewayPlatform]) -> usize {
        self.calls()
            .iter()
            .filter(|call| platforms.contains(&call.platform))
            .count()
    }

    /// Every stored key is opaque: the push key only as SHA-256 and the native
    /// token only as AES-GCM ciphertext bound to it. Returns the row count.
    async fn verify_keys_at_rest(&self) -> Result<i64> {
        let rows = sqlx::query(
            "SELECT push_key_sha256,encrypted_native_token,row_to_json(k)::text AS row_text \
               FROM push_gateway_keys k",
        )
        .fetch_all(&self.pool)
        .await?;
        let tokens: Vec<String> = self
            .registrations
            .lock()
            .unwrap()
            .iter()
            .map(|(_, token)| token.clone())
            .collect();
        for row in &rows {
            let key_hash: Vec<u8> = row.get("push_key_sha256");
            let sealed: Vec<u8> = row.get("encrypted_native_token");
            let text: String = row.get("row_text");
            ensure!(key_hash.len() == 32, "push key is stored only as SHA-256");
            for token in &tokens {
                ensure!(
                    !text.contains(token.as_str())
                        && !sealed
                            .windows(token.len())
                            .any(|window| window == token.as_bytes()),
                    "native token retained in plaintext"
                );
            }
        }
        Ok(rows.len() as i64)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Nest's generic, metadata-only envelope for exactly this request's wake:
/// a fixed alert, no sender, no plaintext, no ciphertext.
fn verify_generic_envelope(call: &DispatchedGatewayPush, fixture: &Fixture) -> Result<()> {
    let catbird = if matches!(call.platform, GatewayPlatform::Fcm) {
        let message = &call.fcm_envelope["message"];
        ensure!(
            message.as_object().map(|object| object.len()) == Some(3)
                && message["token"] == call.native_token
                && message["android"]
                    == json!({"priority": "high", "collapse_key": call.collapse_id})
                && message["data"].as_object().map(|object| object.len()) == Some(1),
            "FCM envelope is not the generic data-only shape"
        );
        serde_json::from_str::<Value>(message["data"]["catbird"].as_str().unwrap_or_default())?
    } else {
        ensure!(
            call.apns_envelope.as_object().map(|object| object.len()) == Some(2)
                && call.apns_envelope["aps"]
                    == json!({"alert": {"body": "New message"}, "mutable-content": 1}),
            "APNs envelope is not the generic alert"
        );
        call.apns_envelope["catbird"].clone()
    };
    let object = catbird
        .as_object()
        .ok_or_else(|| anyhow!("catbird payload is not an object"))?;
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    ensure!(
        keys == [
            "conversationId",
            "epoch",
            "fetchRequired",
            "generation",
            "recipientAccountHash",
            "seq",
            "wakeKind"
        ],
        "unexpected wake payload fields {keys:?}"
    );
    ensure!(
        catbird["wakeKind"] == "directRequest"
            && catbird["conversationId"] == fixture.conversation_id.to_string()
            && catbird["fetchRequired"] == true
            && catbird["recipientAccountHash"]
                == hex(&Sha256::digest(fixture.recipient_did.as_bytes()))
            && ["generation", "seq", "epoch"]
                .iter()
                .all(|field| catbird[*field].as_i64().is_some_and(|value| value >= 0)),
        "wake payload does not describe this request"
    );
    Ok(())
}

fn create(path: &Path, value: &Value) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    Ok(())
}

async fn wait_json(path: &Path) -> Result<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            return Ok(serde_json::from_slice(&bytes)?);
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The guarded paired directory named by the e2e test.
fn paired_directory(prefix: &str) -> Result<PathBuf> {
    let directory =
        PathBuf::from(std::env::var("CATBIRD_REQUEST_PUSH_PAIRED_DIR")?).canonicalize()?;
    ensure!(
        (directory.starts_with("/private/tmp") || directory.starts_with("/tmp"))
            && directory
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix)),
        "paired directory must be a /tmp {prefix}* directory"
    );
    Ok(directory)
}

/// Run one paired scenario to completion and write `nest-result.json`.
async fn run_paired(prefix: &str, allowed: &[Scenario]) -> Result<()> {
    let directory = paired_directory(prefix)?;
    let mut raw = Vec::new();
    std::io::stdin().take(65_537).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 65_536, "paired fixture exceeds 64 KiB");
    let fixture: Fixture = serde_json::from_slice(&raw)?;
    ensure!(
        allowed.contains(&fixture.scenario),
        "scenario {:?} not served by this harness",
        fixture.scenario
    );
    let database_url = std::env::var("CATBIRD_REQUEST_PUSH_TEST_DB")?;
    let paired = Paired::start(
        &database_url,
        &fixture.recipient_did,
        FixtureResolver {
            recipient_did: fixture.recipient_did.clone(),
            recipient_document: serde_json::to_vec(&fixture.recipient_did_document)?,
            ds_document: serde_json::to_vec(&fixture.ds_did_document)?,
        },
        fixture.scenario,
    )
    .await?;
    let outcome = observe(&paired, &directory, &fixture).await;
    paired.stop().await;
    let result = outcome?;
    create(&directory.join("nest-result.json"), &result)
}

async fn observe(paired: &Paired, directory: &Path, fixture: &Fixture) -> Result<Value> {
    create(
        &directory.join("nest-ready.json"),
        &json!({
            "eventId": fixture.event_id,
            "gatewayUrl": CANONICAL_GATEWAY_URL,
            "ingressUrl": format!("{}/xrpc/blue.catbird.push.deliver", paired.base_url),
            "registerUrl": format!("{}/xrpc/blue.catbird.push.registerKey", paired.base_url),
        }),
    )?;
    // The DS fixture writes its result only after its targeted worker run,
    // including every retry, has finished: no wake can still be in flight.
    let ds = wait_json(&directory.join("ds-result.json")).await?;
    ensure!(
        ds["ok"] == true && ds["claimed"] == 1 && ds["eventId"] == fixture.event_id.to_string(),
        "DS worker did not complete exactly this event: {ds}"
    );
    let calls = paired.calls();
    let apns_calls = paired.calls_on(&[GatewayPlatform::Apns, GatewayPlatform::ApnsSandbox]);
    let fcm_calls = paired.calls_on(&[GatewayPlatform::Fcm]);
    let registrations = paired.registrations.lock().unwrap().clone();
    let stored_keys = paired.verify_keys_at_rest().await?;
    let latest = registrations
        .last()
        .ok_or_else(|| anyhow!("the device never registered a native token"))?
        .clone();
    let suppressed = ds["suppressed"] == true;
    let (status, result) = if fixture.scenario == Scenario::CanonicalIneligible {
        ensure!(
            suppressed,
            "the DS woke a request that was no longer pending"
        );
        ensure!(
            calls.is_empty() && paired.deliveries.load(Ordering::SeqCst) == 0,
            "an ineligible request reached the gateway or a provider"
        );
        ("suppressed", "canonical_ineligible")
    } else {
        ensure!(
            !suppressed && !calls.is_empty(),
            "the DS never woke the device"
        );
        for call in &calls {
            ensure!(
                call.native_token == latest.1,
                "a provider call did not use the device's current token"
            );
            ensure!(
                call.app_id == "blue.catbird",
                "a provider call used the wrong app"
            );
            verify_generic_envelope(call, fixture)?;
        }
        ("delivered", "provider_accepted")
    };
    let stable_identity = calls.windows(2).all(|pair| {
        pair[0].collapse_id == pair[1].collapse_id && pair[0].apns_envelope == pair[1].apns_envelope
    });
    ensure!(stable_identity, "retries changed the wake identity");
    let ack_lost_retry =
        paired.acks_dropped.load(Ordering::SeqCst) == 1 && calls.len() == 2 && ds["attempts"] == 2;
    if fixture.scenario == Scenario::ProviderAcceptedAckLost {
        ensure!(ack_lost_retry, "the lost ACK was not retried exactly once");
    }
    if fixture.scenario == Scenario::RetryAfterProviderFailure {
        ensure!(
            calls.len() == 2 && ds["attempts"] == 2,
            "the provider failure was not retried exactly once"
        );
    }
    if fixture.scenario == Scenario::FcmRouting {
        ensure!(
            latest.0 == "fcm",
            "the device's current registration is not FCM"
        );
    }
    Ok(json!({
        "eventId": fixture.event_id,
        "status": status,
        "result": result,
        "apnsCalls": apns_calls,
        "fcmCalls": fcm_calls,
        // Registrations of this device's native token at the gateway; each
        // replaces the previous key for (account, device, app).
        "tokenGeneration": registrations.len(),
        "exactClaimCount": stored_keys,
        "exactGenericPayloadVerified": status == "delivered",
        "stableIdentityVerified": stable_identity,
        "ackLostRetryVerified": ack_lost_retry,
        "tokenPrivacyVerified": true,
        "scenario": fixture.scenario,
        "scope": "real DS worker and registerPushGateway binding; production Nest D2 registerKey/deliver; fake provider",
    }))
}

#[cfg(test)]
mod tests {
    //! The harness's gateway pieces without a paired DS: a DS-signed
    //! `directRequest` wake for an opaque key reaches the provider as the
    //! generic envelope, a lost ACK is replayable with identical identity, and
    //! the native token is never stored in plaintext.
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};

    const DS_DID: &str = "did:web:ds.paired-push.invalid";
    const RECIPIENT: &str = "did:web:recipient.paired-push.invalid";

    fn ds_key() -> SigningKey {
        SigningKey::from_bytes((&[0x61_u8; 32]).into()).unwrap()
    }

    fn wake_jwt(body: &[u8]) -> String {
        let now = Utc::now().timestamp();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"atproto-push-wake+jwt"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": DS_DID,
                "htm": "POST",
                "htu": CANONICAL_GATEWAY_URL,
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
                "body_sha256": hex(&Sha256::digest(body)),
            }))
            .unwrap(),
        );
        let input = format!("{header}.{claims}");
        let signature: Signature = ds_key().sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    fn resolver() -> FixtureResolver {
        let mut multikey = vec![0x80, 0x24];
        multikey.extend_from_slice(ds_key().verifying_key().to_encoded_point(true).as_bytes());
        FixtureResolver {
            recipient_did: RECIPIENT.into(),
            recipient_document: serde_json::to_vec(&json!({
                "id": RECIPIENT,
                "service": [{"id": "#atproto_mls", "type": "AtprotoMLSDeliveryService",
                             "serviceEndpoint": DS_DID}],
            }))
            .unwrap(),
            ds_document: serde_json::to_vec(&json!({
                "id": DS_DID,
                "verificationMethod": [{"id": format!("{DS_DID}#atproto"), "type": "Multikey",
                    "controller": DS_DID,
                    "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, multikey)}],
            }))
            .unwrap(),
        }
    }

    #[tokio::test]
    async fn direct_request_wake_maps_opaque_key_without_retaining_token() {
        let user = std::env::var("USER").unwrap_or_else(|_| "postgres".into());
        let url = std::env::var("CATBIRD_REQUEST_PUSH_TEST_DB")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| format!("postgres://{user}@localhost:5432/postgres"));
        let paired = Paired::start(
            &url,
            RECIPIENT,
            resolver(),
            Scenario::ProviderAcceptedAckLost,
        )
        .await
        .unwrap();
        let http = reqwest::Client::new();
        let device = Uuid::new_v4();
        let token = format!("synthetic-apns-token-{}", Uuid::new_v4().simple());
        let registered: Value = http
            .post(format!(
                "{}/xrpc/blue.catbird.push.registerKey",
                paired.base_url
            ))
            .json(
                &json!({"deviceId": device, "appId": "blue.catbird", "platform": "apns",
                          "nativeToken": token}),
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(registered["gatewayUrl"], CANONICAL_GATEWAY_URL);
        let push_key = registered["pushKey"].as_str().unwrap().to_owned();
        assert_ne!(push_key, token);

        let conversation = Uuid::new_v4();
        let body = serde_json::to_vec(&json!({
            "appId": "blue.catbird",
            "pushKey": push_key,
            "payload": {"wakeKind": "directRequest", "conversationId": conversation,
                        "generation": 0, "seq": 1, "epoch": 1},
        }))
        .unwrap();
        let mut statuses = Vec::new();
        for _ in 0..2 {
            statuses.push(
                http.post(format!(
                    "{}/xrpc/blue.catbird.push.deliver",
                    paired.base_url
                ))
                .header("authorization", format!("Bearer {}", wake_jwt(&body)))
                .header("content-type", "application/json")
                .body(body.clone())
                .send()
                .await
                .unwrap()
                .status(),
            );
        }
        assert_eq!(
            statuses,
            [StatusCode::SERVICE_UNAVAILABLE, StatusCode::ACCEPTED],
            "first ACK lost after provider acceptance, replay accepted"
        );
        assert_eq!(paired.acks_dropped.load(Ordering::SeqCst), 1);
        let calls = paired.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].collapse_id, calls[1].collapse_id);
        assert_eq!(calls[0].apns_envelope, calls[1].apns_envelope);
        let fixture = Fixture {
            event_id: Uuid::new_v4(),
            conversation_id: conversation,
            recipient_did: RECIPIENT.into(),
            recipient_did_document: Value::Null,
            ds_did_document: Value::Null,
            scenario: Scenario::ProviderAcceptedAckLost,
        };
        for call in &calls {
            assert_eq!(call.native_token, token);
            verify_generic_envelope(call, &fixture).unwrap();
        }
        assert_eq!(paired.verify_keys_at_rest().await.unwrap(), 1);

        // A wake from a DS the recipient never named is accepted blindly and
        // never reaches a provider (D2 zero-oracle rule).
        let mut spoofed = resolver();
        spoofed.recipient_document = serde_json::to_vec(&json!({
            "id": RECIPIENT,
            "service": [{"id": "#atproto_mls", "type": "AtprotoMLSDeliveryService",
                         "serviceEndpoint": "did:web:other-ds.paired-push.invalid"}],
        }))
        .unwrap();
        let other = Paired::start(&url, RECIPIENT, spoofed, Scenario::FcmRouting)
            .await
            .unwrap();
        let registered: Value = http
            .post(format!(
                "{}/xrpc/blue.catbird.push.registerKey",
                other.base_url
            ))
            .json(
                &json!({"deviceId": device, "appId": "blue.catbird", "platform": "fcm",
                          "nativeToken": token}),
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let body = serde_json::to_vec(&json!({
            "appId": "blue.catbird",
            "pushKey": registered["pushKey"],
            "payload": {"wakeKind": "directRequest", "conversationId": conversation,
                        "generation": 0, "seq": 1, "epoch": 1},
        }))
        .unwrap();
        let status = http
            .post(format!("{}/xrpc/blue.catbird.push.deliver", other.base_url))
            .header("authorization", format!("Bearer {}", wake_jwt(&body)))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(other.calls().is_empty());
        other.stop().await;
        paired.stop().await;
    }
}
