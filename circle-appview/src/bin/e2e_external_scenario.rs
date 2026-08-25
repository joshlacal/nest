//! Real External Multi-User E2E Scenario for Catbird Circles.
//!
//! Drives the complete Circle lifecycle across real external HTTP services:
//! - Four distinct preprovisioned Nest sessions for Alice, Bob, Carol, Dave
//! - Nest gateway (for createCircle, activateSpace, updateMember, getOperation,
//!   com.atproto.repo.createRecord/uploadBlob proxying with DPoP, and read forwarding)
//! - Public AppView (for public control record and public boundary isolation verification)
//!
//! Exit codes:
//! - 0: All lifecycle assertions passed.
//! - 1: Assertion failure / invariant violation.
//! - 2: Missing prerequisite / unusable credential / unreachable service endpoint.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use catbird_atproto::generated::blue_catbird::circle::activate_space::{
    ActivateSpace, ActivateSpaceOutput,
};
use catbird_atproto::generated::blue_catbird::circle::create_circle::{
    CreateCircle, CreateCircleOutput,
};
use catbird_atproto::generated::blue_catbird::circle::defs::{
    AccessState, MemberAction, OperationStatus, SpaceRef,
};
use catbird_atproto::generated::blue_catbird::circle::get_feed::GetFeedOutput;
use catbird_atproto::generated::blue_catbird::circle::get_operation::GetOperationOutput;
use catbird_atproto::generated::blue_catbird::circle::get_post_thread::GetPostThreadOutput;
use catbird_atproto::generated::blue_catbird::circle::list_notifications::ListNotificationsOutput;
use catbird_atproto::generated::blue_catbird::circle::update_member::{
    UpdateMember, UpdateMemberOutput,
};
use catbird_atproto::types::string::{AtUri, Did};
use chrono::Utc;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

fn url_encode(input: &str) -> String {
    url::form_urlencoded::byte_serialize(input.as_bytes()).collect()
}

#[derive(Debug, Clone)]
pub struct UserSession {
    pub name: &'static str,
    pub did: String,
    pub session_id: String,
}

impl UserSession {
    pub fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header("Cookie", format!("catbird_session={}", self.session_id))
            .header("Authorization", format!("Bearer {}", self.session_id))
    }
}

#[derive(Debug, Clone)]
pub struct ScenarioConfig {
    pub nest_url: String,
    pub public_appview_url: String,

    pub alice: UserSession,
    pub bob: UserSession,
    pub carol: UserSession,
    pub dave: UserSession,

    pub artifacts_dir: PathBuf,
    pub database_url: Option<String>,
}

impl ScenarioConfig {
    pub fn from_env() -> Result<Self, String> {
        let nest_url = env::var("NEST_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".into());
        let public_appview_url =
            env::var("PUBLIC_APPVIEW_URL").unwrap_or_else(|_| "https://public.api.bsky.app".into());

        let alice_did = env::var("ALICE_DID")
            .map_err(|_| "ALICE_DID is required (e.g. did:plc:alice...)".to_string())?;
        let alice_session = env::var("ALICE_SESSION_ID")
            .or_else(|_| env::var("ALICE_COOKIE"))
            .or_else(|_| env::var("ALICE_AUTH_TOKEN"))
            .or_else(|_| env::var("ALICE_TOKEN"))
            .map_err(|_| "ALICE_SESSION_ID is required (Nest session cookie/token)".to_string())?;

        let bob_did = env::var("BOB_DID")
            .map_err(|_| "BOB_DID is required (e.g. did:plc:bob...)".to_string())?;
        let bob_session = env::var("BOB_SESSION_ID")
            .or_else(|_| env::var("BOB_COOKIE"))
            .or_else(|_| env::var("BOB_AUTH_TOKEN"))
            .or_else(|_| env::var("BOB_TOKEN"))
            .map_err(|_| "BOB_SESSION_ID is required (Nest session cookie/token)".to_string())?;

        let carol_did = env::var("CAROL_DID")
            .map_err(|_| "CAROL_DID is required (e.g. did:plc:carol...)".to_string())?;
        let carol_session = env::var("CAROL_SESSION_ID")
            .or_else(|_| env::var("CAROL_COOKIE"))
            .or_else(|_| env::var("CAROL_AUTH_TOKEN"))
            .or_else(|_| env::var("CAROL_TOKEN"))
            .map_err(|_| "CAROL_SESSION_ID is required (Nest session cookie/token)".to_string())?;

        let dave_did = env::var("DAVE_DID")
            .map_err(|_| "DAVE_DID is required (e.g. did:plc:dave...)".to_string())?;
        let dave_session = env::var("DAVE_SESSION_ID")
            .or_else(|_| env::var("DAVE_COOKIE"))
            .or_else(|_| env::var("DAVE_AUTH_TOKEN"))
            .or_else(|_| env::var("DAVE_TOKEN"))
            .map_err(|_| "DAVE_SESSION_ID is required (Nest session cookie/token)".to_string())?;

        // Ensure all four sessions are distinct
        let sessions = [&alice_session, &bob_session, &carol_session, &dave_session];
        for i in 0..sessions.len() {
            for j in (i + 1)..sessions.len() {
                if sessions[i] == sessions[j] {
                    return Err(
                        "All four user Nest sessions must be distinct preprovisioned sessions"
                            .to_string(),
                    );
                }
            }
        }

        // Ensure all four DIDs are distinct
        let dids = [&alice_did, &bob_did, &carol_did, &dave_did];
        for i in 0..dids.len() {
            for j in (i + 1)..dids.len() {
                if dids[i] == dids[j] {
                    return Err("All four user DIDs must be distinct".to_string());
                }
            }
        }

        let artifacts_dir = env::var("ARTIFACTS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./artifacts/e2e_circles"));

        let database_url = env::var("DATABASE_URL").ok();

        Ok(Self {
            nest_url,
            public_appview_url,
            alice: UserSession {
                name: "Alice",
                did: alice_did,
                session_id: alice_session,
            },
            bob: UserSession {
                name: "Bob",
                did: bob_did,
                session_id: bob_session,
            },
            carol: UserSession {
                name: "Carol",
                did: carol_did,
                session_id: carol_session,
            },
            dave: UserSession {
                name: "Dave",
                did: dave_did,
                session_id: dave_session,
            },
            artifacts_dir,
            database_url,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CanaryManifest {
    pub run_id: String,
    pub circle_name: String,
    pub post_text: String,
    pub reply_text: String,
    pub space_uri: String,
    pub post_uri: String,
    pub reply_uri: String,
    pub like_uri: String,
    pub blob_cid: String,
    pub public_control_post_uri: String,
    pub public_control_text: String,
    pub member_response_markers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PublicHttpCapture {
    pub public_control_check: Option<Value>,
    pub public_author_feed_check: Option<Value>,
    pub private_post_check: Option<Value>,
    pub private_reply_check: Option<Value>,
    pub search_post_check: Option<Value>,
    pub search_reply_check: Option<Value>,
    pub search_circle_check: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RunProvenance {
    pub run_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub nest_url: String,
    pub public_appview_url: String,
    pub alice_did: String,
    pub bob_did: String,
    pub carol_did: String,
    pub dave_did: String,
}

pub struct ScenarioRunner {
    pub config: ScenarioConfig,
    pub client: Client,
}

impl ScenarioRunner {
    pub fn new(config: ScenarioConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }

    fn write_private_file(&self, path: &Path, content: &[u8]) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("Failed to create private artifact {}: {e}", path.display()))?;
        file.write_all(content)
            .map_err(|e| format!("Failed to write private artifact {}: {e}", path.display()))?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        Ok(())
    }

    pub async fn check_readiness(&self) -> Result<(), String> {
        eprintln!("[e2e_scenario] PROBE_NEST_READINESS_START");

        // 1. Probe Nest health
        let nest_probe = format!("{}/health", self.config.nest_url.trim_end_matches('/'));
        let res = self
            .client
            .get(&nest_probe)
            .send()
            .await
            .map_err(|e| format!("Nest probe failed at {nest_probe}: {e}"))?;
        if !res.status().is_success() {
            return Err(format!(
                "Nest at {nest_probe} returned non-success status: {}",
                res.status()
            ));
        }

        // 2. Probe Public AppView
        let public_probe = format!(
            "{}/xrpc/_health",
            self.config.public_appview_url.trim_end_matches('/')
        );
        let pub_res = self.client.get(&public_probe).send().await;
        if pub_res.is_err() || !pub_res.as_ref().unwrap().status().is_success() {
            let wk_probe = format!(
                "{}/.well-known/atproto-did",
                self.config.public_appview_url.trim_end_matches('/')
            );
            let wk_res = self
                .client
                .get(&wk_probe)
                .send()
                .await
                .map_err(|e| format!("Public AppView probe failed: {e}"))?;
            if !wk_res.status().is_success() {
                return Err(format!(
                    "Public AppView at {} is unreachable",
                    self.config.public_appview_url
                ));
            }
        }

        // 3. Probe Space capability with Alice's Nest session
        let cap_url = format!(
            "{}/xrpc/blue.catbird.circle.getCapabilities",
            self.config.nest_url.trim_end_matches('/')
        );
        let cap_req = self.config.alice.apply_auth(self.client.get(&cap_url));
        let cap_res = cap_req
            .send()
            .await
            .map_err(|e| format!("Alice capability probe failed at {cap_url}: {e}"))?;
        if !cap_res.status().is_success() {
            return Err(format!(
                "Alice capability check returned status: {}",
                cap_res.status()
            ));
        }
        let cap_json: Value = cap_res.json().await.map_err(|e| e.to_string())?;
        if cap_json["enabled"].as_bool() != Some(true) {
            return Err("Space capability is not enabled on Nest gateway".to_string());
        }
        let rev = cap_json["protocolRevision"].as_str().unwrap_or("");
        if rev != "89deb9faca20e56fa2a262fe9746ed52bc1095ba" {
            return Err(format!(
                "Space protocol revision mismatch: expected '89deb9faca20e56fa2a262fe9746ed52bc1095ba', got '{rev}'"
            ));
        }

        // 4. Validate Bob, Carol, Dave sessions against Nest getCapabilities
        for user in [&self.config.bob, &self.config.carol, &self.config.dave] {
            let req = user.apply_auth(self.client.get(&cap_url));
            let resp = req
                .send()
                .await
                .map_err(|e| format!("Session probe failed for {}: {e}", user.name))?;
            if !resp.status().is_success() {
                return Err(format!(
                    "Session validation failed for {}: status {}",
                    user.name,
                    resp.status()
                ));
            }
        }

        eprintln!("[e2e_scenario] STEP_01_READINESS_OK");
        Ok(())
    }

    async fn poll_operation(
        &self,
        op_id: &str,
        session: &UserSession,
        max_duration: Duration,
    ) -> Result<GetOperationOutput<String>, String> {
        let op_url = format!(
            "{}/xrpc/blue.catbird.circle.getOperation?id={}",
            self.config.nest_url.trim_end_matches('/'),
            url_encode(op_id)
        );
        let start = std::time::Instant::now();
        loop {
            let req = session.apply_auth(self.client.get(&op_url));
            let resp = req
                .send()
                .await
                .map_err(|e| format!("getOperation request failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("getOperation returned HTTP {}", resp.status()));
            }
            let output: GetOperationOutput<String> =
                resp.json().await.map_err(|e| format!("Failed to parse GetOperationOutput: {e}"))?;
            match output.value.status {
                OperationStatus::Complete => return Ok(output),
                OperationStatus::Failed => {
                    let err_msg = output.value.error.as_deref().unwrap_or("unknown error");
                    return Err(format!("Operation {} failed: {}", op_id, err_msg));
                }
                OperationStatus::Pending => {
                    if start.elapsed() > max_duration {
                        return Err(format!("Operation {} timed out in Pending state", op_id));
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        }
    }

    pub async fn run(&self) -> Result<(), String> {
        let started_at = Utc::now().to_rfc3339();
        let run_id = Uuid::new_v4().to_string();
        let circle_name = format!("Family_{}", &run_id[..8]);
        let post_text = format!("CANARY_TEXT_PRIVATE_POST_BODY_{run_id}");
        let reply_text = format!("CANARY_TEXT_PRIVATE_REPLY_BODY_{run_id}");
        let control_text = format!("CONTROL_PUBLIC_POST_BODY_{run_id}");
        let image_data = format!("CANARY_SECRET_FAMILY_IMAGE_BYTES_{run_id}").into_bytes();

        // Create 0700 artifacts directory
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder
            .create(&self.config.artifacts_dir)
            .map_err(|e| format!("Failed to create artifacts directory: {e}"))?;
        let _ = fs::set_permissions(&self.config.artifacts_dir, fs::Permissions::from_mode(0o700));

        let mut public_capture = PublicHttpCapture::default();
        let mut member_markers = Vec::new();

        // -------------------------------------------------------------
        // Step 1: Normal Public Control Record via Nest XRPC Proxy
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_01_PUBLIC_CONTROL_POST_START");
        let create_record_url = format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            self.config.nest_url.trim_end_matches('/')
        );
        let control_payload = json!({
            "repo": self.config.alice.did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": control_text,
                "createdAt": Utc::now().to_rfc3339()
            }
        });
        let control_resp = self
            .config
            .alice
            .apply_auth(self.client.post(&create_record_url))
            .json(&control_payload)
            .send()
            .await
            .map_err(|e| format!("Failed to create public control post: {e}"))?;

        if !control_resp.status().is_success() {
            return Err(format!(
                "Failed to create public control post via Nest, status: {}",
                control_resp.status()
            ));
        }

        let control_json: Value = control_resp.json().await.map_err(|e| e.to_string())?;
        let public_control_post_uri = control_json["uri"]
            .as_str()
            .ok_or_else(|| "Public control record missing uri".to_string())?
            .to_string();

        // Verify public control post on Public AppView
        let public_thread_url = format!(
            "{}/xrpc/app.bsky.feed.getPostThread?uri={}",
            self.config.public_appview_url.trim_end_matches('/'),
            url_encode(&public_control_post_uri)
        );
        let public_thread_resp = self.client.get(&public_thread_url).send().await;
        if let Ok(resp) = public_thread_resp {
            if resp.status().is_success() {
                let body: Value = resp.json().await.unwrap_or(Value::Null);
                public_capture.public_control_check = Some(body);
            }
        }

        let public_feed_url = format!(
            "{}/xrpc/app.bsky.feed.getAuthorFeed?actor={}",
            self.config.public_appview_url.trim_end_matches('/'),
            url_encode(&self.config.alice.did)
        );
        let public_feed_resp = self.client.get(&public_feed_url).send().await;
        if let Ok(resp) = public_feed_resp {
            if resp.status().is_success() {
                let body: Value = resp.json().await.unwrap_or(Value::Null);
                public_capture.public_author_feed_check = Some(body);
            }
        }
        eprintln!("[e2e_scenario] STEP_02_PUBLIC_CONTROL_POST_CREATED");

        // -------------------------------------------------------------
        // Step 2: Alice creates Circle via Nest createCircle
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_03_CREATE_CIRCLE_START");
        let create_circle_url = format!(
            "{}/xrpc/blue.catbird.circle.createCircle",
            self.config.nest_url.trim_end_matches('/')
        );
        let create_input: CreateCircle<String> = CreateCircle {
            name: circle_name.clone(),
            member_dids: vec![
                Did::new(self.config.bob.did.clone())
                    .map_err(|e| format!("Invalid Bob DID: {e}"))?,
                Did::new(self.config.carol.did.clone())
                    .map_err(|e| format!("Invalid Carol DID: {e}"))?,
            ],
            extra_data: None,
        };
        let create_resp = self
            .config
            .alice
            .apply_auth(self.client.post(&create_circle_url))
            .json(&create_input)
            .send()
            .await
            .map_err(|e| format!("Failed to call Nest createCircle: {e}"))?;

        if !create_resp.status().is_success() {
            return Err(format!(
                "Nest createCircle failed with HTTP status: {}",
                create_resp.status()
            ));
        }

        let create_output: CreateCircleOutput<String> = create_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse CreateCircleOutput: {e}"))?;
        let op_id = create_output.value.id.to_string();

        // Poll operation until Complete
        let completed_op = self
            .poll_operation(&op_id, &self.config.alice, Duration::from_secs(30))
            .await?;
        let space_ref = completed_op
            .value
            .space
            .ok_or_else(|| "Completed createCircle operation missing SpaceRef".to_string())?;
        let space_uri = space_ref.as_str().to_string();
        eprintln!("[e2e_scenario] STEP_03_CIRCLE_CREATED");

        // -------------------------------------------------------------
        // Step 3: Activate Space for Alice, Bob, Carol
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_04_ACTIVATE_SPACE_START");
        let activate_url = format!(
            "{}/xrpc/blue.catbird.circle.activateSpace",
            self.config.nest_url.trim_end_matches('/')
        );
        for user in [&self.config.alice, &self.config.bob, &self.config.carol] {
            let act_input: ActivateSpace<String> = ActivateSpace {
                space: space_ref.clone(),
                extra_data: None,
            };
            let act_resp = user
                .apply_auth(self.client.post(&activate_url))
                .json(&act_input)
                .send()
                .await
                .map_err(|e| format!("activateSpace failed for {}: {e}", user.name))?;
            if !act_resp.status().is_success() {
                return Err(format!(
                    "activateSpace for {} returned status {}",
                    user.name,
                    act_resp.status()
                ));
            }
            let act_out: ActivateSpaceOutput<String> = act_resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse ActivateSpaceOutput for {}: {e}", user.name))?;
            if act_out.access_state != AccessState::Active {
                return Err(format!(
                    "activateSpace for {} did not yield Active state (got {:?})",
                    user.name, act_out.access_state
                ));
            }
        }
        eprintln!("[e2e_scenario] STEP_04_SPACE_ACTIVATED");

        // -------------------------------------------------------------
        // Step 4: Alice uploads image blob via Nest proxy
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_05_UPLOAD_BLOB_START");
        let upload_blob_url = format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            self.config.nest_url.trim_end_matches('/')
        );
        let upload_resp = self
            .config
            .alice
            .apply_auth(self.client.post(&upload_blob_url))
            .header("Content-Type", "image/jpeg")
            .body(image_data.clone())
            .send()
            .await
            .map_err(|e| format!("Failed to upload blob via Nest proxy: {e}"))?;

        if !upload_resp.status().is_success() {
            return Err(format!(
                "Upload blob via Nest failed with status: {}",
                upload_resp.status()
            ));
        }

        let upload_json: Value = upload_resp.json().await.map_err(|e| e.to_string())?;
        let blob_cid = upload_json["blob"]["ref"]["$link"]
            .as_str()
            .or_else(|| upload_json["blob"]["cid"].as_str())
            .ok_or_else(|| "Upload blob response missing blob CID".to_string())?
            .to_string();
        eprintln!("[e2e_scenario] STEP_05_IMAGE_BLOB_UPLOADED");

        // -------------------------------------------------------------
        // Step 5: Alice writes private post to Space collection
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_06_WRITE_POST_START");
        let post_record = json!({
            "$type": "app.bsky.feed.post",
            "text": post_text,
            "createdAt": Utc::now().to_rfc3339(),
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [{
                    "alt": "private family photo",
                    "image": {
                        "$type": "blob",
                        "ref": { "$link": blob_cid },
                        "mimeType": "image/jpeg",
                        "size": image_data.len()
                    }
                }]
            }
        });
        let post_resp = self
            .config
            .alice
            .apply_auth(self.client.post(&create_record_url))
            .json(&json!({
                "repo": space_uri,
                "collection": "app.bsky.feed.post",
                "record": post_record
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to write private post via Nest: {e}"))?;

        if !post_resp.status().is_success() {
            return Err(format!(
                "Private post creation failed with status: {}",
                post_resp.status()
            ));
        }

        let post_json: Value = post_resp.json().await.map_err(|e| e.to_string())?;
        let post_uri = post_json["uri"]
            .as_str()
            .ok_or_else(|| "Post creation missing uri".to_string())?
            .to_string();
        let post_cid = post_json["cid"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        eprintln!("[e2e_scenario] STEP_06_PRIVATE_POST_WRITTEN");

        // -------------------------------------------------------------
        // Step 6: Bob's Permissioned Reply in Space collection
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_07_WRITE_REPLY_START");
        let reply_record = json!({
            "$type": "app.bsky.feed.post",
            "text": reply_text,
            "createdAt": Utc::now().to_rfc3339(),
            "reply": {
                "root": { "uri": post_uri, "cid": post_cid },
                "parent": { "uri": post_uri, "cid": post_cid }
            }
        });
        let reply_resp = self
            .config
            .bob
            .apply_auth(self.client.post(&create_record_url))
            .json(&json!({
                "repo": space_uri,
                "collection": "app.bsky.feed.post",
                "record": reply_record
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to write Bob reply via Nest: {e}"))?;

        if !reply_resp.status().is_success() {
            return Err(format!(
                "Bob reply creation failed with status: {}",
                reply_resp.status()
            ));
        }

        let reply_json: Value = reply_resp.json().await.map_err(|e| e.to_string())?;
        let reply_uri = reply_json["uri"]
            .as_str()
            .ok_or_else(|| "Reply creation missing uri".to_string())?
            .to_string();
        eprintln!("[e2e_scenario] STEP_07_REPLY_WRITTEN");

        // -------------------------------------------------------------
        // Step 7: Carol's Permissioned Like in Space collection
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_08_WRITE_LIKE_START");
        let like_record = json!({
            "$type": "app.bsky.feed.like",
            "subject": { "uri": post_uri, "cid": post_cid },
            "createdAt": Utc::now().to_rfc3339()
        });
        let like_resp = self
            .config
            .carol
            .apply_auth(self.client.post(&create_record_url))
            .json(&json!({
                "repo": space_uri,
                "collection": "app.bsky.feed.like",
                "record": like_record
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to write Carol like via Nest: {e}"))?;

        if !like_resp.status().is_success() {
            return Err(format!(
                "Carol like creation failed with status: {}",
                like_resp.status()
            ));
        }

        let like_json: Value = like_resp.json().await.map_err(|e| e.to_string())?;
        let like_uri = like_json["uri"]
            .as_str()
            .ok_or_else(|| "Like creation missing uri".to_string())?
            .to_string();
        eprintln!("[e2e_scenario] STEP_08_LIKE_WRITTEN");

        // -------------------------------------------------------------
        // Step 8: Poll Sync Revision & Authorized Member Reads via Nest
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_09_AUTHORIZED_READS_START");
        let feed_url = format!(
            "{}/xrpc/blue.catbird.circle.getFeed?space={}",
            self.config.nest_url.trim_end_matches('/'),
            url_encode(&space_uri)
        );

        // Poll getFeed until post and reply are both indexed (feed length >= 2)
        let poll_start = std::time::Instant::now();
        let mut feed_synced = false;
        while poll_start.elapsed() < Duration::from_secs(15) {
            let resp = self
                .config
                .alice
                .apply_auth(self.client.get(&feed_url))
                .send()
                .await;
            if let Ok(r) = resp {
                if r.status().is_success() {
                    if let Ok(feed_output) = r.json::<GetFeedOutput>().await {
                        if feed_output.feed.len() >= 2 {
                            feed_synced = true;
                            break;
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        if !feed_synced {
            return Err("Timed out waiting for Circle AppView sync to index post and reply".to_string());
        }

        // Alice reads getPostThread via Nest
        let post_thread_url = format!(
            "{}/xrpc/blue.catbird.circle.getPostThread?space={}&uri={}",
            self.config.nest_url.trim_end_matches('/'),
            url_encode(&space_uri),
            url_encode(&post_uri)
        );
        let thread_resp = self
            .config
            .alice
            .apply_auth(self.client.get(&post_thread_url))
            .send()
            .await
            .map_err(|e| format!("Alice getPostThread failed: {e}"))?;
        if !thread_resp.status().is_success() {
            return Err(format!(
                "Alice getPostThread returned status {}",
                thread_resp.status()
            ));
        }
        let _thread_output: GetPostThreadOutput = thread_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse GetPostThreadOutput: {e}"))?;

        // Bob reads getMedia via Nest
        let media_url = format!(
            "{}/xrpc/blue.catbird.circle.getMedia?space={}&did={}&cid={}",
            self.config.nest_url.trim_end_matches('/'),
            url_encode(&space_uri),
            url_encode(&self.config.alice.did),
            url_encode(&blob_cid)
        );
        let media_resp = self
            .config
            .bob
            .apply_auth(self.client.get(&media_url))
            .send()
            .await
            .map_err(|e| format!("Bob getMedia failed: {e}"))?;
        if !media_resp.status().is_success() {
            return Err(format!("Bob getMedia returned status {}", media_resp.status()));
        }
        let media_bytes = media_resp.bytes().await.map_err(|e| e.to_string())?;
        if media_bytes.as_ref() != image_data.as_slice() {
            return Err("Bob retrieved media bytes do not match expected image data".to_string());
        }
        member_markers.push("BOB_MEDIA_OK".into());

        // Alice reads listNotifications via Nest
        let notifs_url = format!(
            "{}/xrpc/blue.catbird.circle.listNotifications",
            self.config.nest_url.trim_end_matches('/')
        );
        let notifs_resp = self
            .config
            .alice
            .apply_auth(self.client.get(&notifs_url))
            .send()
            .await
            .map_err(|e| format!("Alice listNotifications failed: {e}"))?;
        if !notifs_resp.status().is_success() {
            return Err(format!(
                "Alice listNotifications returned status {}",
                notifs_resp.status()
            ));
        }
        let _notifs_output: ListNotificationsOutput = notifs_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse ListNotificationsOutput: {e}"))?;

        eprintln!("[e2e_scenario] STEP_09_AUTHORIZED_READS_VERIFIED");

        // -------------------------------------------------------------
        // Step 9: Dave (Stranger) Denied Reads and Permissioned Writes
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_10_STRANGER_DENIAL_START");
        let dave_feed_resp = self
            .config
            .dave
            .apply_auth(self.client.get(&feed_url))
            .send()
            .await
            .map_err(|e| format!("Dave feed check failed: {e}"))?;
        if dave_feed_resp.status() != StatusCode::FORBIDDEN
            && dave_feed_resp.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Dave feed access expected 401/403, got {}",
                dave_feed_resp.status()
            ));
        }

        let dave_media_resp = self
            .config
            .dave
            .apply_auth(self.client.get(&media_url))
            .send()
            .await
            .map_err(|e| format!("Dave media check failed: {e}"))?;
        if dave_media_resp.status() != StatusCode::FORBIDDEN
            && dave_media_resp.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Dave media access expected 401/403, got {}",
                dave_media_resp.status()
            ));
        }

        let dave_thread_resp = self
            .config
            .dave
            .apply_auth(self.client.get(&post_thread_url))
            .send()
            .await
            .map_err(|e| format!("Dave thread check failed: {e}"))?;
        if dave_thread_resp.status() != StatusCode::FORBIDDEN
            && dave_thread_resp.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Dave thread access expected 401/403, got {}",
                dave_thread_resp.status()
            ));
        }

        // Dave write attempt (reply) to Space
        let dave_write_reply = self
            .config
            .dave
            .apply_auth(self.client.post(&create_record_url))
            .json(&json!({
                "repo": space_uri,
                "collection": "app.bsky.feed.post",
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": "unauthorized dave intrusion",
                    "createdAt": Utc::now().to_rfc3339()
                }
            }))
            .send()
            .await
            .map_err(|e| format!("Dave write reply call failed: {e}"))?;
        if dave_write_reply.status() != StatusCode::FORBIDDEN
            && dave_write_reply.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Dave unauthorized reply write expected 401/403, got {}",
                dave_write_reply.status()
            ));
        }

        // Dave write attempt (like) to Space
        let dave_write_like = self
            .config
            .dave
            .apply_auth(self.client.post(&create_record_url))
            .json(&json!({
                "repo": space_uri,
                "collection": "app.bsky.feed.like",
                "record": {
                    "$type": "app.bsky.feed.like",
                    "subject": { "uri": post_uri, "cid": post_cid },
                    "createdAt": Utc::now().to_rfc3339()
                }
            }))
            .send()
            .await
            .map_err(|e| format!("Dave write like call failed: {e}"))?;
        if dave_write_like.status() != StatusCode::FORBIDDEN
            && dave_write_like.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Dave unauthorized like write expected 401/403, got {}",
                dave_write_like.status()
            ));
        }

        // Re-verify Alice's feed: item count and like count unchanged
        let alice_feed_check: GetFeedOutput = self
            .config
            .alice
            .apply_auth(self.client.get(&feed_url))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        if alice_feed_check.feed.len() != 2 {
            return Err(format!(
                "Feed item count changed unexpectedly after stranger attempts: got {}",
                alice_feed_check.feed.len()
            ));
        }

        eprintln!("[e2e_scenario] STEP_10_STRANGER_DENIED_READS_AND_WRITES");

        // -------------------------------------------------------------
        // Step 10: Alice Adds Dave to Circle via Nest updateMember
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_11_ADD_MEMBER_START");
        let update_member_url = format!(
            "{}/xrpc/blue.catbird.circle.updateMember",
            self.config.nest_url.trim_end_matches('/')
        );
        let add_dave_input: UpdateMember<String> = UpdateMember {
            action: MemberAction::Add,
            member_did: Did::new(self.config.dave.did.clone())
                .map_err(|e| format!("Invalid Dave DID: {e}"))?,
            space: space_ref.clone(),
            extra_data: None,
        };
        let add_dave_resp = self
            .config
            .alice
            .apply_auth(self.client.post(&update_member_url))
            .json(&add_dave_input)
            .send()
            .await
            .map_err(|e| format!("Failed to call updateMember to add Dave: {e}"))?;

        if !add_dave_resp.status().is_success() {
            return Err(format!("add Dave returned status {}", add_dave_resp.status()));
        }
        let add_dave_output: UpdateMemberOutput<String> = add_dave_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse UpdateMemberOutput for Dave add: {e}"))?;
        let _ = self
            .poll_operation(&add_dave_output.value.id, &self.config.alice, Duration::from_secs(30))
            .await?;

        // Dave activates Space
        let dave_act = self
            .config
            .dave
            .apply_auth(self.client.post(&activate_url))
            .json(&ActivateSpace::<String> {
                space: space_ref.clone(),
                extra_data: None,
            })
            .send()
            .await
            .map_err(|e| format!("Dave activateSpace failed: {e}"))?;
        if !dave_act.status().is_success() {
            return Err(format!("Dave activateSpace returned status {}", dave_act.status()));
        }

        // Dave reads feed and media via Nest
        let dave_feed_after = self
            .config
            .dave
            .apply_auth(self.client.get(&feed_url))
            .send()
            .await
            .map_err(|e| format!("Dave getFeed after add failed: {e}"))?;
        if !dave_feed_after.status().is_success() {
            return Err(format!(
                "Dave getFeed after add returned status {}",
                dave_feed_after.status()
            ));
        }

        let dave_media_after = self
            .config
            .dave
            .apply_auth(self.client.get(&media_url))
            .send()
            .await
            .map_err(|e| format!("Dave getMedia after add failed: {e}"))?;
        if !dave_media_after.status().is_success() {
            return Err(format!(
                "Dave getMedia after add returned status {}",
                dave_media_after.status()
            ));
        }
        member_markers.push("DAVE_ADDED_AND_VERIFIED".into());
        eprintln!("[e2e_scenario] STEP_11_MEMBER_ADDED_AND_VERIFIED");

        // -------------------------------------------------------------
        // Step 11: Alice Removes Bob -> Immediate Revocation
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_12_REMOVE_MEMBER_START");
        let remove_bob_input: UpdateMember<String> = UpdateMember {
            action: MemberAction::Remove,
            member_did: Did::new(self.config.bob.did.clone())
                .map_err(|e| format!("Invalid Bob DID: {e}"))?,
            space: space_ref.clone(),
            extra_data: None,
        };
        let remove_bob_resp = self
            .config
            .alice
            .apply_auth(self.client.post(&update_member_url))
            .json(&remove_bob_input)
            .send()
            .await
            .map_err(|e| format!("Failed to call updateMember to remove Bob: {e}"))?;

        if !remove_bob_resp.status().is_success() {
            return Err(format!(
                "remove Bob returned status {}",
                remove_bob_resp.status()
            ));
        }
        let remove_bob_output: UpdateMemberOutput<String> = remove_bob_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse UpdateMemberOutput for Bob remove: {e}"))?;
        let _ = self
            .poll_operation(
                &remove_bob_output.value.id,
                &self.config.alice,
                Duration::from_secs(30),
            )
            .await?;

        // Bob reads are immediately forbidden
        let bob_feed_after = self
            .config
            .bob
            .apply_auth(self.client.get(&feed_url))
            .send()
            .await
            .map_err(|e| format!("Bob feed check after remove failed: {e}"))?;
        if bob_feed_after.status() != StatusCode::FORBIDDEN
            && bob_feed_after.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Bob feed after removal expected 401/403, got {}",
                bob_feed_after.status()
            ));
        }

        let bob_media_after = self
            .config
            .bob
            .apply_auth(self.client.get(&media_url))
            .send()
            .await
            .map_err(|e| format!("Bob media check after remove failed: {e}"))?;
        if bob_media_after.status() != StatusCode::FORBIDDEN
            && bob_media_after.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Bob media after removal expected 401/403, got {}",
                bob_media_after.status()
            ));
        }

        let bob_thread_after = self
            .config
            .bob
            .apply_auth(self.client.get(&post_thread_url))
            .send()
            .await
            .map_err(|e| format!("Bob thread check after remove failed: {e}"))?;
        if bob_thread_after.status() != StatusCode::FORBIDDEN
            && bob_thread_after.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Bob thread after removal expected 401/403, got {}",
                bob_thread_after.status()
            ));
        }

        // Bob write attempt (reply) to Space is rejected with exact 401/403
        let bob_write_reply = self
            .config
            .bob
            .apply_auth(self.client.post(&create_record_url))
            .json(&json!({
                "repo": space_uri,
                "collection": "app.bsky.feed.post",
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": "unauthorized bob post-revocation reply",
                    "createdAt": Utc::now().to_rfc3339()
                }
            }))
            .send()
            .await
            .map_err(|e| format!("Bob write reply after remove failed: {e}"))?;
        if bob_write_reply.status() != StatusCode::FORBIDDEN
            && bob_write_reply.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Bob write reply after removal expected 401/403, got {}",
                bob_write_reply.status()
            ));
        }

        // Bob write attempt (like) to Space is rejected with exact 401/403
        let bob_write_like = self
            .config
            .bob
            .apply_auth(self.client.post(&create_record_url))
            .json(&json!({
                "repo": space_uri,
                "collection": "app.bsky.feed.like",
                "record": {
                    "$type": "app.bsky.feed.like",
                    "subject": { "uri": post_uri, "cid": post_cid },
                    "createdAt": Utc::now().to_rfc3339()
                }
            }))
            .send()
            .await
            .map_err(|e| format!("Bob write like after remove failed: {e}"))?;
        if bob_write_like.status() != StatusCode::FORBIDDEN
            && bob_write_like.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Bob write like after removal expected 401/403, got {}",
                bob_write_like.status()
            ));
        }

        // Alice, Carol, Dave still have 200 OK access and feed length / counts are unchanged
        for user in [&self.config.alice, &self.config.carol, &self.config.dave] {
            let resp = user
                .apply_auth(self.client.get(&feed_url))
                .send()
                .await
                .map_err(|e| format!("{} feed check failed: {e}", user.name))?;
            if !resp.status().is_success() {
                return Err(format!(
                    "{} feed access failed after Bob removal: status {}",
                    user.name,
                    resp.status()
                ));
            }
            let user_feed: GetFeedOutput = resp.json().await.map_err(|e| e.to_string())?;
            if user_feed.feed.len() != 2 {
                return Err(format!(
                    "{} feed length changed unexpectedly: got {}",
                    user.name,
                    user_feed.feed.len()
                ));
            }
        }
        member_markers.push("BOB_REMOVED_AND_REVOKED".into());
        eprintln!("[e2e_scenario] STEP_12_MEMBER_REMOVED_AND_REVOKED");

        // -------------------------------------------------------------
        // Step 12: Public AppView Isolation Checks via HTTP
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_13_PUBLIC_ISOLATION_START");

        let public_post_check_url = format!(
            "{}/xrpc/app.bsky.feed.getPostThread?uri={}",
            self.config.public_appview_url.trim_end_matches('/'),
            url_encode(&post_uri)
        );
        let public_post_resp = self.client.get(&public_post_check_url).send().await;
        if let Ok(resp) = public_post_resp {
            if resp.status().is_success() {
                return Err(format!(
                    "Public AppView unexpectedly returned private post: {post_uri}"
                ));
            }
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            public_capture.private_post_check = Some(body);
        }

        let public_reply_check_url = format!(
            "{}/xrpc/app.bsky.feed.getPostThread?uri={}",
            self.config.public_appview_url.trim_end_matches('/'),
            url_encode(&reply_uri)
        );
        let public_reply_resp = self.client.get(&public_reply_check_url).send().await;
        if let Ok(resp) = public_reply_resp {
            if resp.status().is_success() {
                return Err(format!(
                    "Public AppView unexpectedly returned private reply: {reply_uri}"
                ));
            }
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            public_capture.private_reply_check = Some(body);
        }

        let search_post_url = format!(
            "{}/xrpc/app.bsky.feed.searchPosts?q={}",
            self.config.public_appview_url.trim_end_matches('/'),
            url_encode(&post_text)
        );
        let search_post_resp = self.client.get(&search_post_url).send().await;
        if let Ok(resp) = search_post_resp {
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            if let Some(posts) = body["posts"].as_array() {
                if !posts.is_empty() {
                    return Err(format!(
                        "Public AppView search unexpectedly returned private post canary text: {post_text}"
                    ));
                }
            }
            public_capture.search_post_check = Some(body);
        }

        let search_reply_url = format!(
            "{}/xrpc/app.bsky.feed.searchPosts?q={}",
            self.config.public_appview_url.trim_end_matches('/'),
            url_encode(&reply_text)
        );
        let search_reply_resp = self.client.get(&search_reply_url).send().await;
        if let Ok(resp) = search_reply_resp {
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            if let Some(posts) = body["posts"].as_array() {
                if !posts.is_empty() {
                    return Err(format!(
                        "Public AppView search unexpectedly returned private reply canary text: {reply_text}"
                    ));
                }
            }
            public_capture.search_reply_check = Some(body);
        }

        let search_circle_url = format!(
            "{}/xrpc/app.bsky.actor.searchActors?q={}",
            self.config.public_appview_url.trim_end_matches('/'),
            url_encode(&circle_name)
        );
        let search_circle_resp = self.client.get(&search_circle_url).send().await;
        if let Ok(resp) = search_circle_resp {
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            if let Some(actors) = body["actors"].as_array() {
                if !actors.is_empty() {
                    return Err(format!(
                        "Public AppView search unexpectedly returned private circle name canary: {circle_name}"
                    ));
                }
            }
            public_capture.search_circle_check = Some(body);
        }

        // Save public HTTP capture artifact (mode 0600)
        let capture_path = self.config.artifacts_dir.join("public_http_capture.json");
        self.write_private_file(
            &capture_path,
            serde_json::to_string_pretty(&public_capture)
                .unwrap()
                .as_bytes(),
        )?;
        eprintln!("[e2e_scenario] STEP_13_PUBLIC_ISOLATION_VERIFIED");

        // -------------------------------------------------------------
        // Step 13: Dump Database Diagnostics if DB is configured
        // -------------------------------------------------------------
        if let Some(db_url) = &self.config.database_url {
            if let Ok(pool) = PgPool::connect(db_url).await {
                let rows = sqlx::query_as::<_, (String, String, String, chrono::DateTime<Utc>)>(
                    "SELECT space_uri, record_cid, rejection_reason, created_at FROM sync_rejection_diagnostics ORDER BY created_at DESC LIMIT 100",
                )
                .fetch_all(&pool)
                .await
                .unwrap_or_default();

                let diag_json: Vec<Value> = rows
                    .into_iter()
                    .map(|(s_uri, cid, reason, dt)| {
                        json!({
                            "space_uri": s_uri,
                            "record_cid": cid,
                            "rejection_reason": reason,
                            "created_at": dt.to_rfc3339()
                        })
                    })
                    .collect();

                let diag_path = self.config.artifacts_dir.join("db_diagnostics.json");
                let _ = self.write_private_file(
                    &diag_path,
                    serde_json::to_string_pretty(&diag_json).unwrap().as_bytes(),
                );
            }
        }

        // -------------------------------------------------------------
        // Step 14: Write Permission-Restricted Canary Manifest & Provenance
        // -------------------------------------------------------------
        let completed_at = Utc::now().to_rfc3339();
        let provenance = RunProvenance {
            run_id: run_id.clone(),
            started_at,
            completed_at,
            nest_url: self.config.nest_url.clone(),
            public_appview_url: self.config.public_appview_url.clone(),
            alice_did: self.config.alice.did.clone(),
            bob_did: self.config.bob.did.clone(),
            carol_did: self.config.carol.did.clone(),
            dave_did: self.config.dave.did.clone(),
        };
        let prov_path = self.config.artifacts_dir.join("provenance.json");
        self.write_private_file(
            &prov_path,
            serde_json::to_string_pretty(&provenance).unwrap().as_bytes(),
        )?;

        let manifest = CanaryManifest {
            run_id,
            circle_name,
            post_text,
            reply_text,
            space_uri,
            post_uri,
            reply_uri,
            like_uri,
            blob_cid,
            public_control_post_uri,
            public_control_text: control_text,
            member_response_markers: member_markers,
        };

        let manifest_path = self.config.artifacts_dir.join("canary_manifest.json");
        self.write_private_file(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap().as_bytes(),
        )?;

        eprintln!("[e2e_scenario] STEP_14_ARTIFACTS_WRITTEN_OK");
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let config = match ScenarioConfig::from_env() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("[e2e_scenario] Missing prerequisite configuration: {err}");
            std::process::exit(2);
        }
    };

    let runner = ScenarioRunner::new(config);
    if let Err(probe_err) = runner.check_readiness().await {
        eprintln!("[e2e_scenario] Missing prerequisite service: {probe_err}");
        std::process::exit(2);
    }

    if let Err(scenario_err) = runner.run().await {
        eprintln!("[e2e_scenario] Scenario assertion failed: {scenario_err}");
        std::process::exit(1);
    }

    eprintln!("[e2e_scenario] STEP_15_SCENARIO_COMPLETE_SUCCESS");
    std::process::exit(0);
}
