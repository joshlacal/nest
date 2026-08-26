//! Real External Multi-User E2E Scenario for Catbird Circles.
//!
//! Drives the complete Circle lifecycle across real external HTTP services:
//! - Four distinct preprovisioned Nest sessions for Alice, Bob, Carol, Dave
//! - Nest gateway (for createCircle, activateSpace, updateMember, getOperation,
//!   com.atproto.space.applyWrites, com.atproto.repo.uploadBlob, and read forwarding)
//! - Space-capable PDS instances and Circle AppView
//! - Public AppView (for public control record and public boundary isolation verification)
//! - Circle AppView PostgreSQL database (for verified sync revision and rejection audit)
//!
//! Exit codes:
//! - 0: All lifecycle assertions passed (emits STEP_15_SCENARIO_COMPLETE).
//! - 1: Assertion failure / invariant violation.
//! - 2: Missing prerequisite / unusable credential / unreachable service endpoint.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use catbird_atproto::generated::app_bsky::actor::search_actors::{
    SearchActors, SearchActorsOutput,
};
use catbird_atproto::generated::app_bsky::embed::images::{Image, Images};
use catbird_atproto::generated::app_bsky::feed::get_author_feed::{
    GetAuthorFeed, GetAuthorFeedOutput,
};
use catbird_atproto::generated::app_bsky::feed::get_post_thread::{
    GetPostThread, GetPostThreadError, GetPostThreadOutput, GetPostThreadOutputThread,
};
use catbird_atproto::generated::app_bsky::feed::get_timeline::{GetTimeline, GetTimelineOutput};
use catbird_atproto::generated::app_bsky::feed::like::Like;
use catbird_atproto::generated::app_bsky::feed::post::{Post, PostEmbed, ReplyRef};
use catbird_atproto::generated::app_bsky::feed::search_posts::{SearchPosts, SearchPostsOutput};
use catbird_atproto::generated::app_bsky::feed::ThreadViewPostRepliesItem;
use catbird_atproto::generated::app_bsky::notification::list_notifications::{
    ListNotifications, ListNotificationsOutput, NotificationReason as PublicNotificationReason,
};
use catbird_atproto::generated::blue_catbird::circle::activate_space::{
    ActivateSpace, ActivateSpaceOutput,
};
use catbird_atproto::generated::blue_catbird::circle::create_circle::{
    CreateCircle, CreateCircleOutput,
};
use catbird_atproto::generated::blue_catbird::circle::defs::{
    AccessState, MemberAction, NotificationReason as CircleNotificationReason, OperationStatus,
    SpaceRef,
};
use catbird_atproto::generated::blue_catbird::circle::get_capabilities::{
    GetCapabilities, GetCapabilitiesOutput,
};
use catbird_atproto::generated::blue_catbird::circle::get_feed::{GetFeed, GetFeedOutput};
use catbird_atproto::generated::blue_catbird::circle::get_media::GetMedia;
use catbird_atproto::generated::blue_catbird::circle::get_operation::{
    GetOperation, GetOperationOutput,
};
use catbird_atproto::generated::blue_catbird::circle::get_post_thread::{
    GetPostThread as CircleGetPostThread, GetPostThreadOutput as CircleGetPostThreadOutput,
};
use catbird_atproto::generated::blue_catbird::circle::list_circles::{
    ListCircles, ListCirclesOutput,
};
use catbird_atproto::generated::blue_catbird::circle::list_notifications::{
    ListNotifications as CircleListNotifications,
    ListNotificationsOutput as CircleListNotificationsOutput,
};
use catbird_atproto::generated::blue_catbird::circle::update_member::{
    UpdateMember, UpdateMemberOutput,
};
use catbird_atproto::generated::com_atproto::repo::create_record::{
    CreateRecord, CreateRecordOutput,
};
use catbird_atproto::generated::com_atproto::repo::strong_ref::StrongRef;
use catbird_atproto::generated::com_atproto::repo::upload_blob::UploadBlobOutput;
use catbird_atproto::generated::com_atproto::server::describe_server::DescribeServerOutput;
use catbird_atproto::generated::com_atproto::server::get_service_auth::{
    GetServiceAuth, GetServiceAuthOutput,
};
use catbird_atproto::generated::com_atproto::space::apply_writes::{
    ApplyWrites, ApplyWritesOutput, ApplyWritesOutputResultsItem, ApplyWritesWritesItem, Create,
};
use catbird_atproto::generated::com_atproto::space::get_latest_commit::{
    GetLatestCommit, GetLatestCommitOutput,
};
use catbird_atproto::generated::com_atproto::space::list_spaces::{ListSpaces, ListSpacesOutput};
use catbird_atproto::generated::com_atproto::space::notify_write::NotifyWrite;
use catbird_atproto::jacquard_common::types::ident::AtIdentifier;
use catbird_atproto::jacquard_common::types::string::{AtUri, Cid, Datetime, Did, Nsid};
use catbird_atproto::jacquard_common::types::value::Data;
use chrono::Utc;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use url::Url;
use uuid::Uuid;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn get_revision(path: &str) -> String {
    if let Ok(output) = Command::new("jj")
        .args([
            "log",
            "-R",
            path,
            "-r",
            "@",
            "-T",
            "commit_id",
            "--no-graph",
        ])
        .output()
    {
        if output.status.success() {
            if let Ok(s) = String::from_utf8(output.stdout) {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }
    if let Ok(output) = Command::new("git")
        .args(["-C", path, "rev-parse", "HEAD"])
        .output()
    {
        if output.status.success() {
            if let Ok(s) = String::from_utf8(output.stdout) {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }
    "unknown".to_string()
}

fn record_data<T: Serialize>(record: &T) -> Result<Data<String>, String> {
    let val =
        serde_json::to_value(record).map_err(|e| format!("Failed to serialize record: {e}"))?;
    serde_json::from_value(val)
        .map_err(|e| format!("Failed to convert serialized record to Data: {e}"))
}

#[derive(Debug, Clone)]
pub struct UserSession {
    pub name: &'static str,
    pub did: String,
    pub session_id: String,
    pub pds_url: String,
}

impl UserSession {
    pub fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header("Cookie", format!("catbird_session={}", self.session_id))
            .header("Authorization", format!("Bearer {}", self.session_id))
    }
}

#[derive(Debug, Clone)]
pub struct ScenarioConfig {
    pub run_id: String,
    pub nest_url: String,
    pub circle_appview_url: String,
    pub circle_appview_service_did: String,
    pub public_appview_url: String,
    pub database_url: String,

    pub alice: UserSession,
    pub bob: UserSession,
    pub carol: UserSession,
    pub dave: UserSession,

    pub artifacts_dir: PathBuf,
}

impl ScenarioConfig {
    pub fn from_env() -> Result<Self, String> {
        let run_id = env::var("RUN_ID").unwrap_or_else(|_| Uuid::new_v4().to_string());

        let nest_url = env::var("NEST_URL")
            .map_err(|_| "NEST_URL is required (e.g. http://127.0.0.1:3000)".to_string())?;
        let circle_appview_url = env::var("CIRCLE_APPVIEW_URL").map_err(|_| {
            "CIRCLE_APPVIEW_URL is required (e.g. http://127.0.0.1:3002)".to_string()
        })?;
        let circle_appview_service_did = env::var("CIRCLE_APPVIEW_SERVICE_DID")
            .map_err(|_| "CIRCLE_APPVIEW_SERVICE_DID is required (e.g. did:web:circles.catbird.blue#atproto_circle)".to_string())?;
        let public_appview_url = env::var("PUBLIC_APPVIEW_URL").map_err(|_| {
            "PUBLIC_APPVIEW_URL is required (e.g. https://public.api.bsky.app)".to_string()
        })?;
        let database_url = env::var("DATABASE_URL").map_err(|_| {
            "DATABASE_URL is required (PostgreSQL connection string for Circle AppView)".to_string()
        })?;

        let alice_did = env::var("ALICE_DID")
            .map_err(|_| "ALICE_DID is required (e.g. did:plc:alice...)".to_string())?;
        let alice_session = env::var("ALICE_SESSION_ID")
            .map_err(|_| "ALICE_SESSION_ID is required (Nest session cookie/token)".to_string())?;
        let alice_pds = env::var("ALICE_PDS_URL")
            .map_err(|_| "ALICE_PDS_URL is required (Space-capable PDS endpoint)".to_string())?;

        let bob_did = env::var("BOB_DID")
            .map_err(|_| "BOB_DID is required (e.g. did:plc:bob...)".to_string())?;
        let bob_session = env::var("BOB_SESSION_ID")
            .map_err(|_| "BOB_SESSION_ID is required (Nest session cookie/token)".to_string())?;
        let bob_pds = env::var("BOB_PDS_URL")
            .map_err(|_| "BOB_PDS_URL is required (Space-capable PDS endpoint)".to_string())?;

        let carol_did = env::var("CAROL_DID")
            .map_err(|_| "CAROL_DID is required (e.g. did:plc:carol...)".to_string())?;
        let carol_session = env::var("CAROL_SESSION_ID")
            .map_err(|_| "CAROL_SESSION_ID is required (Nest session cookie/token)".to_string())?;
        let carol_pds = env::var("CAROL_PDS_URL")
            .map_err(|_| "CAROL_PDS_URL is required (Space-capable PDS endpoint)".to_string())?;

        let dave_did = env::var("DAVE_DID")
            .map_err(|_| "DAVE_DID is required (e.g. did:plc:dave...)".to_string())?;
        let dave_session = env::var("DAVE_SESSION_ID")
            .map_err(|_| "DAVE_SESSION_ID is required (Nest session cookie/token)".to_string())?;
        let dave_pds = env::var("DAVE_PDS_URL")
            .map_err(|_| "DAVE_PDS_URL is required (Space-capable PDS endpoint)".to_string())?;

        // Validate URLs
        for (name, u) in [
            ("NEST_URL", &nest_url),
            ("CIRCLE_APPVIEW_URL", &circle_appview_url),
            ("PUBLIC_APPVIEW_URL", &public_appview_url),
            ("ALICE_PDS_URL", &alice_pds),
            ("BOB_PDS_URL", &bob_pds),
            ("CAROL_PDS_URL", &carol_pds),
            ("DAVE_PDS_URL", &dave_pds),
        ] {
            let parsed = Url::parse(u).map_err(|e| format!("Invalid URL for {name} '{u}': {e}"))?;
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return Err(format!("{name} must use http or https scheme, got '{u}'"));
            }
        }

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
            .map_err(|_| "ARTIFACTS_DIR is required".to_string())?;

        Ok(Self {
            run_id,
            nest_url,
            circle_appview_url,
            circle_appview_service_did,
            public_appview_url,
            database_url,
            alice: UserSession {
                name: "Alice",
                did: alice_did,
                session_id: alice_session,
                pds_url: alice_pds,
            },
            bob: UserSession {
                name: "Bob",
                did: bob_did,
                session_id: bob_session,
                pds_url: bob_pds,
            },
            carol: UserSession {
                name: "Carol",
                did: carol_did,
                session_id: carol_session,
                pds_url: carol_pds,
            },
            dave: UserSession {
                name: "Dave",
                did: dave_did,
                session_id: dave_session,
                pds_url: dave_pds,
            },
            artifacts_dir,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct SessionProbeResponse {
    pub did: String,
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HealthProbeResponse {
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CanaryManifest {
    pub run_id: String,
    pub circle_name: String,
    pub post_text: String,
    pub reply_text: String,
    pub rejected_text: String,
    pub space_uri: String,
    pub post_uri: String,
    pub reply_uri: String,
    pub like_uri: String,
    pub rejected_uri: String,
    pub blob_cid: String,
    pub post_cid: String,
    pub reply_cid: String,
    pub like_cid: String,
    pub rejected_cid: String,
    pub image_canary: String,
    pub public_control_post_uri: String,
    pub public_control_post_cid: String,
    pub public_control_like_uri: String,
    pub public_control_text: String,
    pub rejection_uri_hash: String,
    pub member_response_markers: Vec<String>,
}

impl CanaryManifest {
    pub fn private_canaries(&self) -> Vec<&str> {
        vec![
            self.circle_name.as_str(),
            self.post_text.as_str(),
            self.reply_text.as_str(),
            self.rejected_text.as_str(),
            self.space_uri.as_str(),
            self.post_uri.as_str(),
            self.reply_uri.as_str(),
            self.like_uri.as_str(),
            self.rejected_uri.as_str(),
            self.blob_cid.as_str(),
            self.post_cid.as_str(),
            self.reply_cid.as_str(),
            self.like_cid.as_str(),
            self.rejected_cid.as_str(),
            self.image_canary.as_str(),
        ]
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PublicHttpCapture {
    pub run_id: String,
    pub public_control_post: Value,
    pub public_control_like: Value,
    pub public_control_thread: Value,
    pub public_author_feed: Value,
    pub public_timeline: Value,
    pub public_search_posts: Value,
    pub public_search_actors: Value,
    pub public_notifications: Value,
    pub private_post_thread_negative: Value,
    pub private_reply_thread_negative: Value,
    pub private_post_search_negative: Value,
    pub private_reply_search_negative: Value,
    pub private_circle_actor_search_negative: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RejectionDiagnostic {
    pub run_id: String,
    pub uri_hash: String,
    pub reason_code: String,
    pub observed_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RunProvenance {
    pub run_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub nest_url: String,
    pub circle_appview_url: String,
    pub circle_appview_service_did: String,
    pub public_appview_url: String,
    pub database_kind: String,
    pub alice_did: String,
    pub alice_pds_url: String,
    pub bob_did: String,
    pub bob_pds_url: String,
    pub carol_did: String,
    pub carol_pds_url: String,
    pub dave_did: String,
    pub dave_pds_url: String,
    pub root_revision: String,
    pub nest_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CircleSnapshot {
    feed_count: usize,
    post_uri: String,
    post_cid: String,
    post_like_count: Option<i64>,
    post_reply_count: Option<i64>,
    thread_reply_uris: Vec<String>,
    notifications: Vec<(String, String, String, Option<String>)>,
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
        eprintln!("[e2e_scenario] PROBE_SERVICES_READINESS_START");

        // 1. Probe Circle AppView health: GET CIRCLE_APPVIEW_URL/xrpc/_health -> require 2xx and status == "ok"
        let appview_probe = format!(
            "{}/xrpc/_health",
            self.config.circle_appview_url.trim_end_matches('/')
        );
        let appview_res = self
            .client
            .get(&appview_probe)
            .send()
            .await
            .map_err(|e| format!("Circle AppView probe failed: {e}"))?;
        if !appview_res.status().is_success() {
            return Err(format!(
                "Circle AppView probe returned non-success status: {}",
                appview_res.status()
            ));
        }
        let appview_health: HealthProbeResponse = appview_res
            .json()
            .await
            .map_err(|e| format!("Failed to parse Circle AppView health response: {e}"))?;
        if appview_health.status != "ok" {
            return Err(format!(
                "Circle AppView health status is not 'ok': '{}'",
                appview_health.status
            ));
        }

        // 2. Probe Nest health
        let nest_probe = format!("{}/health", self.config.nest_url.trim_end_matches('/'));
        let res = self
            .client
            .get(&nest_probe)
            .send()
            .await
            .map_err(|e| format!("Nest probe failed: {e}"))?;
        if !res.status().is_success() {
            return Err(format!(
                "Nest returned non-success status: {}",
                res.status()
            ));
        }

        // 3. Probe Public AppView
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
                    "Public AppView returned non-2xx status: {}",
                    wk_res.status()
                ));
            }
        }

        // 4. Probe configured user PDS instances: direct and session-routed describeServer
        for user in [
            &self.config.alice,
            &self.config.bob,
            &self.config.carol,
            &self.config.dave,
        ] {
            // Direct PDS describeServer
            let pds_desc_url = format!(
                "{}/xrpc/com.atproto.server.describeServer",
                user.pds_url.trim_end_matches('/')
            );
            let direct_res = self
                .client
                .get(&pds_desc_url)
                .send()
                .await
                .map_err(|e| format!("Direct describeServer failed for {}: {e}", user.name))?;
            if !direct_res.status().is_success() {
                return Err(format!(
                    "Direct describeServer for {} returned status {}",
                    user.name,
                    direct_res.status()
                ));
            }
            let direct_desc: DescribeServerOutput<String> =
                direct_res.json().await.map_err(|e| {
                    format!(
                        "Failed to parse direct describeServer for {}: {e}",
                        user.name
                    )
                })?;

            // Session-routed describeServer via Nest
            let nest_desc_url = format!(
                "{}/xrpc/com.atproto.server.describeServer",
                self.config.nest_url.trim_end_matches('/')
            );
            let routed_res = user
                .apply_auth(self.client.get(&nest_desc_url))
                .send()
                .await
                .map_err(|e| format!("Routed describeServer failed for {}: {e}", user.name))?;
            if !routed_res.status().is_success() {
                return Err(format!(
                    "Session-routed describeServer for {} returned status {}",
                    user.name,
                    routed_res.status()
                ));
            }
            let routed_desc: DescribeServerOutput<String> =
                routed_res.json().await.map_err(|e| {
                    format!(
                        "Failed to parse routed describeServer for {}: {e}",
                        user.name
                    )
                })?;

            if direct_desc.did.as_str() != routed_desc.did.as_str() {
                return Err(format!(
                    "PDS DID mismatch for {}: direct PDS returned '{}', session-routed returned '{}'",
                    user.name,
                    direct_desc.did.as_str(),
                    routed_desc.did.as_str()
                ));
            }
        }

        // 5. Validate Nest session-to-DID mapping for each user via /auth/session
        let session_endpoint = format!(
            "{}/auth/session",
            self.config.nest_url.trim_end_matches('/')
        );
        for user in [
            &self.config.alice,
            &self.config.bob,
            &self.config.carol,
            &self.config.dave,
        ] {
            let req = user.apply_auth(self.client.get(&session_endpoint));
            let resp = req
                .send()
                .await
                .map_err(|e| format!("Session check failed for {}: {e}", user.name))?;
            if !resp.status().is_success() {
                return Err(format!(
                    "Session validation failed for {}: /auth/session returned status {}",
                    user.name,
                    resp.status()
                ));
            }
            let session_info: SessionProbeResponse = resp.json().await.map_err(|e| {
                format!(
                    "Failed to parse /auth/session response for {}: {e}",
                    user.name
                )
            })?;
            if session_info.did != user.did {
                return Err(format!(
                    "Session DID mismatch for {}: declared '{}', Nest session returned '{}'",
                    user.name, user.did, session_info.did
                ));
            }
        }

        // 6. Validate Space capability, protocol revision, and listSpaces for all users
        let cap_url = format!(
            "{}/xrpc/blue.catbird.circle.getCapabilities",
            self.config.nest_url.trim_end_matches('/')
        );
        for user in [
            &self.config.alice,
            &self.config.bob,
            &self.config.carol,
            &self.config.dave,
        ] {
            let req = user
                .apply_auth(self.client.get(&cap_url))
                .query(&GetCapabilities);
            let resp = req
                .send()
                .await
                .map_err(|e| format!("Capability probe failed for {}: {e}", user.name))?;
            if !resp.status().is_success() {
                return Err(format!(
                    "Capability check failed for {}: status {}",
                    user.name,
                    resp.status()
                ));
            }
            let cap_out: GetCapabilitiesOutput<String> = resp.json().await.map_err(|e| {
                format!(
                    "Failed to parse GetCapabilitiesOutput for {}: {e}",
                    user.name
                )
            })?;
            if !cap_out.enabled {
                return Err(format!(
                    "Space capability is not enabled on Nest gateway for {}",
                    user.name
                ));
            }
            if !cap_out.supports_images {
                return Err(format!(
                    "supports_images is not true on Nest gateway for {}",
                    user.name
                ));
            }
            let rev = cap_out.protocol_revision.as_str();
            if rev != "89deb9faca20e56fa2a262fe9746ed52bc1095ba" {
                return Err(format!(
                    "Space protocol revision mismatch for {}: expected '89deb9faca20e56fa2a262fe9746ed52bc1095ba', got '{rev}'",
                    user.name
                ));
            }

            // Probe listSpaces through Nest using generated ListSpaces query
            let list_spaces_url = format!(
                "{}/xrpc/com.atproto.space.listSpaces",
                self.config.nest_url.trim_end_matches('/')
            );
            let ls_query: ListSpaces<String> = ListSpaces {
                cursor: None,
                did: Some(Did::new(user.did.clone()).map_err(|e| format!("Invalid DID: {e}"))?),
                limit: Some(1),
                r#type: None,
            };
            let ls_resp = user
                .apply_auth(self.client.get(&list_spaces_url))
                .query(&ls_query)
                .send()
                .await
                .map_err(|e| format!("listSpaces probe failed for {}: {e}", user.name))?;
            if !ls_resp.status().is_success() {
                return Err(format!(
                    "listSpaces probe for {} returned status {}",
                    user.name,
                    ls_resp.status()
                ));
            }
            let _ls_out: ListSpacesOutput<String> = ls_resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse ListSpacesOutput for {}: {e}", user.name))?;
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
            "{}/xrpc/blue.catbird.circle.getOperation",
            self.config.nest_url.trim_end_matches('/')
        );
        let query: GetOperation<String> = GetOperation {
            id: op_id.to_string(),
        };
        let start = std::time::Instant::now();
        loop {
            let req = session.apply_auth(self.client.get(&op_url)).query(&query);
            let resp = req
                .send()
                .await
                .map_err(|e| format!("getOperation request failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("getOperation returned status {}", resp.status()));
            }
            let output: GetOperationOutput<String> = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse GetOperationOutput: {e}"))?;
            match output.value.status {
                OperationStatus::Complete => return Ok(output),
                OperationStatus::Failed => {
                    let err_msg = output.value.error.as_deref().unwrap_or("unknown error");
                    return Err(format!("Operation failed: {}", err_msg));
                }
                OperationStatus::Pending => {
                    if start.elapsed() > max_duration {
                        return Err("Operation timed out in Pending state".to_string());
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        }
    }

    async fn apply_create_raw<T: Serialize>(
        &self,
        session: &UserSession,
        space: &str,
        collection: &str,
        record: &T,
    ) -> Result<(String, String), (StatusCode, String)> {
        let apply_url = format!(
            "{}/xrpc/com.atproto.space.applyWrites",
            self.config.nest_url.trim_end_matches('/')
        );
        let data = record_data(record).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let create_item = Create {
            collection: Nsid::new(collection.to_string()).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid collection NSID: {e}"),
                )
            })?,
            rkey: None,
            value: data,
            extra_data: None,
        };
        let input: ApplyWrites<String> = ApplyWrites {
            repo: Did::new(session.did.clone())
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid repo DID: {e}")))?,
            space: space.to_string(),
            validate: Some(true),
            writes: vec![ApplyWritesWritesItem::Create(Box::new(create_item))],
            extra_data: None,
        };
        let req = session.apply_auth(self.client.post(&apply_url));
        let resp = req.json(&input).send().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("applyWrites transport failed: {e}"),
            )
        })?;
        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err((status, body_text));
        }
        let output: ApplyWritesOutput<String> = resp.json().await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse ApplyWritesOutput: {e}"),
            )
        })?;
        let results = output.results.ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "ApplyWritesOutput missing results array".to_string(),
            )
        })?;
        if results.len() != 1 {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Expected exactly 1 ApplyWrites result, got {}",
                    results.len()
                ),
            ));
        }
        match &results[0] {
            ApplyWritesOutputResultsItem::CreateResult(cr) => {
                let uri = cr.uri.as_str().to_string();
                let cid = cr.cid.as_str().to_string();
                if uri.is_empty() || cid.is_empty() {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "ApplyWrites createResult returned empty URI or CID".to_string(),
                    ));
                }
                Ok((uri, cid))
            }
            other => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Expected CreateResult, got unexpected variant: {other:?}"),
            )),
        }
    }

    async fn apply_create<T: Serialize>(
        &self,
        session: &UserSession,
        space: &str,
        collection: &str,
        record: &T,
    ) -> Result<(String, String), String> {
        self.apply_create_raw(session, space, collection, record)
            .await
            .map_err(|(status, msg)| format!("apply_create failed with HTTP {status}: {msg}"))
    }

    async fn expect_apply_create_denied<T: Serialize>(
        &self,
        session: &UserSession,
        space: &str,
        collection: &str,
        record: &T,
        op_label: &str,
    ) -> Result<(), String> {
        match self
            .apply_create_raw(session, space, collection, record)
            .await
        {
            Ok(_) => Err(format!("{op_label} unexpectedly succeeded")),
            Err((status, _)) => {
                if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
                    Ok(())
                } else {
                    Err(format!(
                        "{op_label} expected exact 401/403, got HTTP {status}"
                    ))
                }
            }
        }
    }

    async fn notify_and_wait_revision(
        &self,
        session: &UserSession,
        space: &str,
        prev_rev: Option<&str>,
    ) -> Result<String, String> {
        // 1. Fetch latest signed commit through Nest using generated GetLatestCommit query input
        let get_commit_url = format!(
            "{}/xrpc/com.atproto.space.getLatestCommit",
            self.config.nest_url.trim_end_matches('/')
        );
        let commit_query: GetLatestCommit<String> = GetLatestCommit {
            repo: Did::new(session.did.clone()).map_err(|e| format!("Invalid repo DID: {e}"))?,
            space: space.to_string(),
        };
        let commit_resp = session
            .apply_auth(self.client.get(&get_commit_url))
            .query(&commit_query)
            .send()
            .await
            .map_err(|e| format!("getLatestCommit failed for {}: {e}", session.name))?;
        if !commit_resp.status().is_success() {
            return Err(format!(
                "getLatestCommit for {} returned HTTP {}",
                session.name,
                commit_resp.status()
            ));
        }
        let commit_output: GetLatestCommitOutput<String> = commit_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse GetLatestCommitOutput: {e}"))?;
        let commit = commit_output.commit;

        if commit.ver != 1 {
            return Err(format!(
                "Expected SignedCommit ver == 1, got {}",
                commit.ver
            ));
        }
        if commit.hash.len() != 32 {
            return Err(format!(
                "Expected SignedCommit hash length 32, got {}",
                commit.hash.len()
            ));
        }
        if commit.ikm.len() != 32 {
            return Err(format!(
                "Expected SignedCommit ikm length 32, got {}",
                commit.ikm.len()
            ));
        }
        if commit.mac.len() != 32 {
            return Err(format!(
                "Expected SignedCommit mac length 32, got {}",
                commit.mac.len()
            ));
        }
        if commit.sig.is_empty() {
            return Err("SignedCommit signature is empty".to_string());
        }
        let rev_str = commit.rev.as_str().to_string();
        if rev_str.is_empty() {
            return Err("SignedCommit revision is empty".to_string());
        }

        // Prove that the signed revision advances
        if let Some(prev) = prev_rev {
            if rev_str.as_str() <= prev {
                return Err("Signed revision did not advance".to_string());
            }
        }

        // 2. Mint fresh PDS service auth token for notifyWrite using generated GetServiceAuth query input
        let get_sa_url = format!(
            "{}/xrpc/com.atproto.server.getServiceAuth",
            self.config.nest_url.trim_end_matches('/')
        );
        let sa_query: GetServiceAuth<String> = GetServiceAuth {
            aud: self.config.circle_appview_service_did.clone(),
            exp: Some(Utc::now().timestamp() + 60),
            lxm: Some(
                Nsid::new("com.atproto.space.notifyWrite".into())
                    .map_err(|e| format!("Invalid NSID: {e}"))?,
            ),
        };
        let sa_resp = session
            .apply_auth(self.client.get(&get_sa_url))
            .query(&sa_query)
            .send()
            .await
            .map_err(|e| format!("getServiceAuth failed for {}: {e}", session.name))?;
        if !sa_resp.status().is_success() {
            return Err(format!(
                "getServiceAuth for {} returned HTTP {}",
                session.name,
                sa_resp.status()
            ));
        }
        let sa_output: GetServiceAuthOutput<String> = sa_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse GetServiceAuthOutput: {e}"))?;
        let service_jwt = sa_output.token;
        if service_jwt.is_empty() {
            return Err("getServiceAuth returned empty token".to_string());
        }

        // 3. Send NotifyWrite directly to Circle AppView
        let notify_url = format!(
            "{}/xrpc/com.atproto.space.notifyWrite",
            self.config.circle_appview_url.trim_end_matches('/')
        );
        let notify_body: NotifyWrite<String> = NotifyWrite {
            hash: commit.hash.clone(),
            repo: Did::new(session.did.clone())
                .map_err(|e| format!("Invalid Did for notifyWrite: {e}"))?,
            rev: commit.rev.clone(),
            space: space.to_string(),
            extra_data: None,
        };
        let notify_resp = self
            .client
            .post(&notify_url)
            .header("Authorization", format!("Bearer {service_jwt}"))
            .json(&notify_body)
            .send()
            .await
            .map_err(|e| format!("notifyWrite failed for {}: {e}", session.name))?;
        if !notify_resp.status().is_success() {
            return Err(format!(
                "notifyWrite for {} returned HTTP {}",
                session.name,
                notify_resp.status()
            ));
        }

        // 4. Poll circle_repo_sync_state table in PostgreSQL until last_rev == commit.rev
        let pool = PgPool::connect(&self.config.database_url)
            .await
            .map_err(|e| format!("Failed to connect to Circle AppView database: {e}"))?;

        let start = std::time::Instant::now();
        let expected_hash = commit.hash.as_ref();
        loop {
            let row: Option<(String, Vec<u8>)> = sqlx::query_as(
                "SELECT last_rev, last_hash FROM circle_repo_sync_state WHERE space_uri = $1 AND author_did = $2",
            )
            .bind(space)
            .bind(&session.did)
            .fetch_optional(&pool)
            .await
            .map_err(|e| format!("Failed to query circle_repo_sync_state: {e}"))?;

            if let Some((db_rev, db_raw_hash)) = &row {
                let db_digest = Sha256::digest(db_raw_hash);
                if db_rev == &rev_str && &db_digest[..] == expected_hash {
                    break;
                }
            }

            if start.elapsed() > Duration::from_secs(15) {
                return Err(
                    "Timed out waiting for Circle AppView sync state to reflect revision"
                        .to_string(),
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Ok(rev_str)
    }

    async fn circle_snapshot(
        &self,
        space_ref: &SpaceRef<String>,
        post_uri: &str,
    ) -> Result<CircleSnapshot, String> {
        let feed_url = format!(
            "{}/xrpc/blue.catbird.circle.getFeed",
            self.config.nest_url.trim_end_matches('/')
        );
        let feed_query: GetFeed<String> = GetFeed {
            cursor: None,
            limit: Some(100),
            space: Some(space_ref.clone()),
        };
        let feed_resp = self
            .config
            .alice
            .apply_auth(self.client.get(&feed_url))
            .query(&feed_query)
            .send()
            .await
            .map_err(|e| format!("Feed query in snapshot failed: {e}"))?;
        if !feed_resp.status().is_success() {
            return Err(format!("Feed query returned HTTP {}", feed_resp.status()));
        }
        let feed_output: GetFeedOutput<String> = feed_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse GetFeedOutput: {e}"))?;

        let post_item = feed_output
            .feed
            .iter()
            .find(|item| item.post.post.uri.as_str() == post_uri)
            .ok_or_else(|| "Target post missing from feed in snapshot".to_string())?;

        let post_cid = post_item.post.post.cid.as_str().to_string();
        let post_like_count = post_item.post.post.like_count;
        let post_reply_count = post_item.post.post.reply_count;

        let thread_url = format!(
            "{}/xrpc/blue.catbird.circle.getPostThread",
            self.config.nest_url.trim_end_matches('/')
        );
        let thread_query: CircleGetPostThread<String> = CircleGetPostThread {
            depth: Some(6),
            parent_height: Some(0),
            space: space_ref.clone(),
            uri: AtUri::new(post_uri.to_string()).map_err(|e| format!("Invalid AtUri: {e}"))?,
        };
        let thread_resp = self
            .config
            .alice
            .apply_auth(self.client.get(&thread_url))
            .query(&thread_query)
            .send()
            .await
            .map_err(|e| format!("Thread query in snapshot failed: {e}"))?;
        if !thread_resp.status().is_success() {
            return Err(format!(
                "Thread query returned HTTP {}",
                thread_resp.status()
            ));
        }
        let thread_output: CircleGetPostThreadOutput<String> = thread_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Circle GetPostThreadOutput: {e}"))?;

        let mut reply_uris = Vec::new();
        if let Some(replies) = &thread_output.thread.replies {
            for r in replies {
                if let ThreadViewPostRepliesItem::ThreadViewPost(reply_tvp) = r {
                    reply_uris.push(reply_tvp.post.uri.as_str().to_string());
                }
            }
        }
        reply_uris.sort();

        let notifs_url = format!(
            "{}/xrpc/blue.catbird.circle.listNotifications",
            self.config.nest_url.trim_end_matches('/')
        );
        let notifs_query: CircleListNotifications<String> = CircleListNotifications {
            cursor: None,
            limit: Some(100),
        };
        let notifs_resp = self
            .config
            .alice
            .apply_auth(self.client.get(&notifs_url))
            .query(&notifs_query)
            .send()
            .await
            .map_err(|e| format!("Notifications query in snapshot failed: {e}"))?;
        if !notifs_resp.status().is_success() {
            return Err(format!(
                "Notifications query returned HTTP {}",
                notifs_resp.status()
            ));
        }
        let notifs_output: CircleListNotificationsOutput<String> = notifs_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Circle ListNotificationsOutput: {e}"))?;

        let mut notif_tuples = Vec::new();
        for n in &notifs_output.notifications {
            let reason_str = match n.reason {
                CircleNotificationReason::Reply => "reply",
                CircleNotificationReason::Like => "like",
                CircleNotificationReason::Invite => "invite",
            };
            let subj = n.subject.as_ref().map(|s| s.as_str().to_string());
            notif_tuples.push((
                n.id.to_string(),
                reason_str.to_string(),
                n.actor.did.as_str().to_string(),
                subj,
            ));
        }
        notif_tuples.sort();

        Ok(CircleSnapshot {
            feed_count: feed_output.feed.len(),
            post_uri: post_uri.to_string(),
            post_cid,
            post_like_count,
            post_reply_count,
            thread_reply_uris: reply_uris,
            notifications: notif_tuples,
        })
    }

    pub async fn run(&self) -> Result<(), String> {
        let started_at = Utc::now().to_rfc3339();
        let run_id = self.config.run_id.clone();
        let circle_name = format!("Family_{}", &run_id[..8]);
        let post_text = format!("CANARY_TEXT_PRIVATE_POST_BODY_{run_id}");
        let reply_text = format!("CANARY_TEXT_PRIVATE_REPLY_BODY_{run_id}");
        let rejected_text = format!("CANARY_TEXT_REJECTED_TOPLEVEL_{run_id}");
        let control_text = format!("CONTROL_PUBLIC_POST_BODY_{run_id}");
        let image_canary = format!("CANARY_SECRET_FAMILY_IMAGE_BYTES_{run_id}");
        let image_data = image_canary.as_bytes().to_vec();

        // Create 0700 artifacts directory
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder
            .create(&self.config.artifacts_dir)
            .map_err(|e| format!("Failed to create artifacts directory: {e}"))?;
        let _ = fs::set_permissions(
            &self.config.artifacts_dir,
            fs::Permissions::from_mode(0o700),
        );

        let mut public_capture = PublicHttpCapture {
            run_id: run_id.clone(),
            ..Default::default()
        };
        let mut member_markers = Vec::new();

        // -------------------------------------------------------------
        // Step 1: Normal Public Control Record & Like via Nest XRPC Proxy
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_01_PUBLIC_CONTROL_POST_START");
        let create_record_url = format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            self.config.nest_url.trim_end_matches('/')
        );

        let control_post_record: Post<String> = Post {
            created_at: Datetime::now(),
            embed: None,
            entities: None,
            facets: None,
            labels: None,
            langs: None,
            reply: None,
            tags: None,
            text: control_text.clone(),
            extra_data: None,
        };
        let control_create_input: CreateRecord<String> = CreateRecord {
            collection: Nsid::new("app.bsky.feed.post".into()).unwrap(),
            record: record_data(&control_post_record)?,
            repo: AtIdentifier::new(self.config.alice.did.clone()).unwrap(),
            rkey: None,
            swap_commit: None,
            validate: Some(true),
            extra_data: None,
        };

        let control_resp = self
            .config
            .alice
            .apply_auth(self.client.post(&create_record_url))
            .json(&control_create_input)
            .send()
            .await
            .map_err(|e| format!("Failed to create public control post: {e}"))?;

        if !control_resp.status().is_success() {
            return Err(format!(
                "Failed to create public control post via Nest, status: {}",
                control_resp.status()
            ));
        }

        let control_output: CreateRecordOutput<String> =
            control_resp.json().await.map_err(|e| {
                format!("Failed to parse CreateRecordOutput for public control post: {e}")
            })?;
        let public_control_post_uri = control_output.uri.as_str().to_string();
        let public_control_post_cid = control_output.cid.as_str().to_string();

        // Bob creates a public like on Alice's public control post
        let control_like_record: Like<String> = Like {
            created_at: Datetime::now(),
            subject: StrongRef {
                cid: Cid::new(public_control_post_cid.as_bytes()).unwrap(),
                uri: AtUri::new(public_control_post_uri.clone()).unwrap(),
                extra_data: None,
            },
            via: None,
            extra_data: None,
        };
        let control_like_input: CreateRecord<String> = CreateRecord {
            collection: Nsid::new("app.bsky.feed.like".into()).unwrap(),
            record: record_data(&control_like_record)?,
            repo: AtIdentifier::new(self.config.bob.did.clone()).unwrap(),
            rkey: None,
            swap_commit: None,
            validate: Some(true),
            extra_data: None,
        };
        let control_like_resp = self
            .config
            .bob
            .apply_auth(self.client.post(&create_record_url))
            .json(&control_like_input)
            .send()
            .await
            .map_err(|e| format!("Failed to create public control like: {e}"))?;

        if !control_like_resp.status().is_success() {
            return Err(format!(
                "Failed to create public control like via Nest, status: {}",
                control_like_resp.status()
            ));
        }
        let control_like_output: CreateRecordOutput<String> =
            control_like_resp.json().await.map_err(|e| {
                format!("Failed to parse CreateRecordOutput for public control like: {e}")
            })?;
        let public_control_like_uri = control_like_output.uri.as_str().to_string();

        // Strict Public Positive Control 1: getPostThread on public control post using generated query input
        let public_thread_url = format!(
            "{}/xrpc/app.bsky.feed.getPostThread",
            self.config.public_appview_url.trim_end_matches('/')
        );
        let public_thread_query: GetPostThread<String> = GetPostThread {
            depth: None,
            parent_height: None,
            uri: AtUri::new(public_control_post_uri.clone())
                .map_err(|e| format!("Invalid AtUri: {e}"))?,
        };
        let public_thread_resp = self
            .client
            .get(&public_thread_url)
            .query(&public_thread_query)
            .send()
            .await
            .map_err(|e| format!("Public AppView getPostThread failed: {e}"))?;
        if !public_thread_resp.status().is_success() {
            return Err(format!(
                "Public AppView getPostThread on control post returned non-2xx status: {}",
                public_thread_resp.status()
            ));
        }
        let public_thread_output: GetPostThreadOutput<String> = public_thread_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse public thread output: {e}"))?;

        match &public_thread_output.thread {
            GetPostThreadOutputThread::ThreadViewPost(tvp) => {
                if tvp.post.uri.as_str() != public_control_post_uri
                    || tvp.post.cid.as_str() != public_control_post_cid
                {
                    return Err("Public control post thread URI/CID mismatch".to_string());
                }
            }
            other => {
                return Err(format!(
                    "Expected ThreadViewPost on control post, got variant: {other:?}"
                ));
            }
        }
        public_capture.public_control_post = serde_json::to_value(&control_output).unwrap();
        public_capture.public_control_like = serde_json::to_value(&control_like_output).unwrap();
        public_capture.public_control_thread = serde_json::to_value(&public_thread_output).unwrap();

        // Strict Public Positive Control 2: getAuthorFeed on Alice using generated query input
        let public_feed_url = format!(
            "{}/xrpc/app.bsky.feed.getAuthorFeed",
            self.config.public_appview_url.trim_end_matches('/')
        );
        let public_feed_query: GetAuthorFeed<String> = GetAuthorFeed {
            actor: AtIdentifier::new(self.config.alice.did.clone())
                .map_err(|e| format!("Invalid Did: {e}"))?,
            cursor: None,
            filter: None,
            include_pins: None,
            limit: Some(100),
        };
        let public_feed_resp = self
            .client
            .get(&public_feed_url)
            .query(&public_feed_query)
            .send()
            .await
            .map_err(|e| format!("Public AppView getAuthorFeed failed: {e}"))?;
        if !public_feed_resp.status().is_success() {
            return Err(format!(
                "Public AppView getAuthorFeed returned non-2xx status: {}",
                public_feed_resp.status()
            ));
        }
        let public_feed_output: GetAuthorFeedOutput<String> = public_feed_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse public author feed: {e}"))?;

        let found_control_feed = public_feed_output
            .feed
            .iter()
            .any(|item| item.post.uri.as_str() == public_control_post_uri);
        if !found_control_feed {
            return Err("Public control post not found in Alice's author feed".to_string());
        }
        public_capture.public_author_feed = serde_json::to_value(&public_feed_output).unwrap();

        // Strict Public Positive Control 3: getTimeline on Alice via Nest using generated query input
        let timeline_url = format!(
            "{}/xrpc/app.bsky.feed.getTimeline",
            self.config.nest_url.trim_end_matches('/')
        );
        let timeline_query: GetTimeline<String> = GetTimeline {
            algorithm: Some("reverse-chronological".into()),
            cursor: None,
            limit: Some(100),
        };
        let timeline_resp = self
            .config
            .alice
            .apply_auth(self.client.get(&timeline_url))
            .query(&timeline_query)
            .send()
            .await
            .map_err(|e| format!("getTimeline failed: {e}"))?;
        if !timeline_resp.status().is_success() {
            return Err(format!(
                "getTimeline returned non-2xx status: {}",
                timeline_resp.status()
            ));
        }
        let timeline_output: GetTimelineOutput<String> = timeline_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse public timeline output: {e}"))?;
        let timeline_has_control = timeline_output.feed.iter().any(|item| {
            item.post.uri.as_str() == public_control_post_uri
                && item.post.cid.as_str() == public_control_post_cid
        });
        if !timeline_has_control {
            return Err("Public control post not found in Alice's timeline".to_string());
        }
        public_capture.public_timeline = serde_json::to_value(&timeline_output).unwrap();

        // Strict Public Positive Control 4: searchPosts for control text using generated query input
        let search_posts_url = format!(
            "{}/xrpc/app.bsky.feed.searchPosts",
            self.config.public_appview_url.trim_end_matches('/')
        );
        let search_control_query: SearchPosts<String> = SearchPosts {
            author: None,
            cursor: None,
            domain: None,
            lang: None,
            limit: None,
            mentions: None,
            q: control_text.clone(),
            since: None,
            sort: None,
            tag: None,
            until: None,
            url: None,
        };
        let search_posts_resp = self
            .client
            .get(&search_posts_url)
            .query(&search_control_query)
            .send()
            .await
            .map_err(|e| format!("Public AppView searchPosts failed: {e}"))?;
        if !search_posts_resp.status().is_success() {
            return Err(format!(
                "Public AppView searchPosts returned non-2xx status: {}",
                search_posts_resp.status()
            ));
        }
        let search_posts_output: SearchPostsOutput<String> = search_posts_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse search posts output: {e}"))?;
        let search_has_control = search_posts_output.posts.iter().any(|post| {
            post.uri.as_str() == public_control_post_uri
                && post.cid.as_str() == public_control_post_cid
        });
        if !search_has_control {
            return Err("Public control post not found in post search".to_string());
        }
        public_capture.public_search_posts = serde_json::to_value(&search_posts_output).unwrap();

        // Strict Public Positive Control 5: searchActors for Alice DID/handle using generated query input
        let search_actors_url = format!(
            "{}/xrpc/app.bsky.actor.searchActors",
            self.config.public_appview_url.trim_end_matches('/')
        );
        let search_actors_query: SearchActors<String> = SearchActors {
            cursor: None,
            limit: None,
            q: Some(self.config.alice.did.clone()),
            term: None,
        };
        let search_actors_resp = self
            .client
            .get(&search_actors_url)
            .query(&search_actors_query)
            .send()
            .await
            .map_err(|e| format!("Public AppView searchActors failed: {e}"))?;
        if !search_actors_resp.status().is_success() {
            return Err(format!(
                "Public AppView searchActors returned non-2xx status: {}",
                search_actors_resp.status()
            ));
        }
        let search_actors_output: SearchActorsOutput<String> = search_actors_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse search actors output: {e}"))?;
        if !search_actors_output
            .actors
            .iter()
            .any(|actor| actor.did.as_str() == self.config.alice.did)
        {
            return Err("Alice not found in public actor search".to_string());
        }
        public_capture.public_search_actors = serde_json::to_value(&search_actors_output).unwrap();

        // Strict Public Positive Control 6: listNotifications on Alice via Nest using generated query input
        let public_notifs_url = format!(
            "{}/xrpc/app.bsky.notification.listNotifications",
            self.config.nest_url.trim_end_matches('/')
        );
        let public_notifs_query: ListNotifications<String> = ListNotifications {
            cursor: None,
            limit: Some(100),
            priority: None,
            reasons: None,
            seen_at: None,
        };
        let public_notifs_resp = self
            .config
            .alice
            .apply_auth(self.client.get(&public_notifs_url))
            .query(&public_notifs_query)
            .send()
            .await
            .map_err(|e| format!("Public listNotifications failed: {e}"))?;
        if !public_notifs_resp.status().is_success() {
            return Err(format!(
                "Public listNotifications returned non-2xx status: {}",
                public_notifs_resp.status()
            ));
        }
        let public_notifs_output: ListNotificationsOutput<String> = public_notifs_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse public notifications output: {e}"))?;
        let notifications_have_control_like =
            public_notifs_output
                .notifications
                .iter()
                .any(|notification| {
                    notification.reason == PublicNotificationReason::Like
                        && notification.author.did.as_str() == self.config.bob.did
                        && notification.reason_subject.as_ref().map(|uri| uri.as_str())
                            == Some(public_control_post_uri.as_str())
                });
        if !notifications_have_control_like {
            return Err("Bob's public control like not found in Alice's notifications".to_string());
        }
        public_capture.public_notifications = serde_json::to_value(&public_notifs_output).unwrap();

        eprintln!("[e2e_scenario] STEP_02_PUBLIC_CONTROL_POST_PROVED");

        // -------------------------------------------------------------
        // Step 2: Alice Creates Circle via Nest createCircle
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_03_CREATE_CIRCLE_START");
        let create_circle_url = format!(
            "{}/xrpc/blue.catbird.circle.createCircle",
            self.config.nest_url.trim_end_matches('/')
        );
        let create_input: CreateCircle<String> = CreateCircle {
            member_dids: vec![
                Did::new(self.config.bob.did.clone()).unwrap(),
                Did::new(self.config.carol.did.clone()).unwrap(),
            ],
            name: circle_name.clone(),
            extra_data: None,
        };

        let create_resp = self
            .config
            .alice
            .apply_auth(self.client.post(&create_circle_url))
            .json(&create_input)
            .send()
            .await
            .map_err(|e| format!("Failed to call createCircle: {e}"))?;

        if !create_resp.status().is_success() {
            return Err(format!(
                "createCircle returned status: {}",
                create_resp.status()
            ));
        }

        let create_output: CreateCircleOutput<String> = create_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse CreateCircleOutput: {e}"))?;
        let op_id = create_output.value.id.as_str();

        let completed_op = self
            .poll_operation(op_id, &self.config.alice, Duration::from_secs(30))
            .await?;
        let space_ref = completed_op
            .value
            .space
            .ok_or_else(|| "Completed createCircle operation missing SpaceRef".to_string())?;
        let space_uri = space_ref.as_str().to_string();

        // Discovery check via listCircles using generated ListCircles query input
        let list_circles_url = format!(
            "{}/xrpc/blue.catbird.circle.listCircles",
            self.config.nest_url.trim_end_matches('/')
        );
        let lc_query: ListCircles<String> = ListCircles {
            cursor: None,
            limit: Some(100),
        };
        for user in [&self.config.alice, &self.config.bob, &self.config.carol] {
            let lc_resp = user
                .apply_auth(self.client.get(&list_circles_url))
                .query(&lc_query)
                .send()
                .await
                .map_err(|e| format!("listCircles failed for {}: {e}", user.name))?;
            if !lc_resp.status().is_success() {
                return Err(format!(
                    "listCircles for {} returned HTTP {}",
                    user.name,
                    lc_resp.status()
                ));
            }
            let lc_out: ListCirclesOutput<String> = lc_resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse ListCirclesOutput for {}: {e}", user.name))?;
            let has_circle = lc_out.circles.iter().any(|c| c.uri.as_str() == space_uri);
            if !has_circle {
                return Err(format!(
                    "Newly created circle not discovered by member {}",
                    user.name
                ));
            }
        }

        // Dave (stranger) does NOT discover the circle
        let dave_lc_resp = self
            .config
            .dave
            .apply_auth(self.client.get(&list_circles_url))
            .query(&lc_query)
            .send()
            .await
            .map_err(|e| format!("Dave listCircles failed: {e}"))?;
        if dave_lc_resp.status().is_success() {
            let dave_lc: ListCirclesOutput<String> =
                dave_lc_resp.json().await.map_err(|e| e.to_string())?;
            if dave_lc.circles.iter().any(|c| c.uri.as_str() == space_uri) {
                return Err("Stranger Dave unexpectedly discovered private circle".to_string());
            }
        }

        eprintln!("[e2e_scenario] STEP_03_CIRCLE_CREATED_AND_DISCOVERED");

        // -------------------------------------------------------------
        // Step 3: Explicitly Activate Space for Alice, Bob, Carol
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
            let act_out: ActivateSpaceOutput<String> = act_resp.json().await.map_err(|e| {
                format!("Failed to parse ActivateSpaceOutput for {}: {e}", user.name)
            })?;
            if act_out.access_state != AccessState::Active {
                return Err(format!(
                    "activateSpace for {} did not yield Active state (got {:?})",
                    user.name, act_out.access_state
                ));
            }
            let expires_at = act_out
                .expires_at
                .ok_or_else(|| format!("activateSpace for {} missing expires_at", user.name))?;
            let exp_dt = chrono::DateTime::parse_from_rfc3339(expires_at.as_str())
                .map_err(|e| format!("Invalid expires_at datetime: {e}"))?
                .with_timezone(&Utc);
            if exp_dt <= Utc::now() {
                return Err(format!(
                    "activateSpace for {} returned expired or non-future expires_at",
                    user.name
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

        let upload_output: UploadBlobOutput<String> = upload_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse UploadBlobOutput: {e}"))?;
        let blob_ref = upload_output.blob;
        let blob_cid = blob_ref.blob().cid().as_str().to_string();
        if blob_cid.is_empty() {
            return Err("Uploaded blob missing CID".to_string());
        }
        if blob_ref.blob().mime_type.as_str() != "image/jpeg" {
            return Err(format!(
                "Uploaded blob MIME type mismatch: expected 'image/jpeg', got '{}'",
                blob_ref.blob().mime_type.as_str()
            ));
        }
        if blob_ref.blob().size != image_data.len() {
            return Err(format!(
                "Uploaded blob size mismatch: expected {}, got {}",
                image_data.len(),
                blob_ref.blob().size
            ));
        }
        eprintln!("[e2e_scenario] STEP_05_IMAGE_BLOB_UPLOADED");

        // -------------------------------------------------------------
        // Step 5: Alice writes private post using permissioned applyWrites
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_06_WRITE_POST_START");
        let post_record: Post<String> = Post {
            created_at: Datetime::now(),
            embed: Some(PostEmbed::Images(Box::new(Images {
                images: vec![Image {
                    alt: "private family photo".into(),
                    aspect_ratio: None,
                    image: blob_ref,
                    extra_data: None,
                }],
                extra_data: None,
            }))),
            entities: None,
            facets: None,
            labels: None,
            langs: None,
            reply: None,
            tags: None,
            text: post_text.clone(),
            extra_data: None,
        };

        let alice_rev0 = self
            .notify_and_wait_revision(&self.config.alice, &space_uri, None)
            .await?;
        let (post_uri, post_cid) = self
            .apply_create(
                &self.config.alice,
                &space_uri,
                "app.bsky.feed.post",
                &post_record,
            )
            .await?;

        // Barrier: notify and wait for AppView sync
        let _alice_rev1 = self
            .notify_and_wait_revision(&self.config.alice, &space_uri, Some(&alice_rev0))
            .await?;
        eprintln!("[e2e_scenario] STEP_06_PRIVATE_POST_WRITTEN_AND_SYNCED");

        // -------------------------------------------------------------
        // Step 6: Bob writes permissioned reply using applyWrites
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_07_WRITE_REPLY_START");
        let reply_record: Post<String> = Post {
            created_at: Datetime::now(),
            embed: None,
            entities: None,
            facets: None,
            labels: None,
            langs: None,
            reply: Some(ReplyRef {
                parent: StrongRef {
                    cid: Cid::new(post_cid.as_bytes()).unwrap(),
                    uri: AtUri::new(post_uri.clone()).unwrap(),
                    extra_data: None,
                },
                root: StrongRef {
                    cid: Cid::new(post_cid.as_bytes()).unwrap(),
                    uri: AtUri::new(post_uri.clone()).unwrap(),
                    extra_data: None,
                },
                extra_data: None,
            }),
            tags: None,
            text: reply_text.clone(),
            extra_data: None,
        };

        let bob_rev0 = self
            .notify_and_wait_revision(&self.config.bob, &space_uri, None)
            .await?;
        let (reply_uri, reply_cid) = self
            .apply_create(
                &self.config.bob,
                &space_uri,
                "app.bsky.feed.post",
                &reply_record,
            )
            .await?;

        // Barrier: notify and wait for AppView sync
        let bob_rev1 = self
            .notify_and_wait_revision(&self.config.bob, &space_uri, Some(&bob_rev0))
            .await?;
        eprintln!("[e2e_scenario] STEP_07_REPLY_WRITTEN_AND_SYNCED");

        // -------------------------------------------------------------
        // Step 7: Carol writes permissioned like using applyWrites
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_08_WRITE_LIKE_START");
        let like_record: Like<String> = Like {
            created_at: Datetime::now(),
            subject: StrongRef {
                cid: Cid::new(post_cid.as_bytes()).unwrap(),
                uri: AtUri::new(post_uri.clone()).unwrap(),
                extra_data: None,
            },
            via: None,
            extra_data: None,
        };

        let carol_rev0 = self
            .notify_and_wait_revision(&self.config.carol, &space_uri, None)
            .await?;
        let (like_uri, like_cid) = self
            .apply_create(
                &self.config.carol,
                &space_uri,
                "app.bsky.feed.like",
                &like_record,
            )
            .await?;

        // Barrier: notify and wait for AppView sync
        let _carol_rev1 = self
            .notify_and_wait_revision(&self.config.carol, &space_uri, Some(&carol_rev0))
            .await?;
        eprintln!("[e2e_scenario] STEP_08_LIKE_WRITTEN_AND_SYNCED");

        // -------------------------------------------------------------
        // Step 8: Authorized Member Reads & Count Assertions
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_09_AUTHORIZED_READS_START");
        let feed_url = format!(
            "{}/xrpc/blue.catbird.circle.getFeed",
            self.config.nest_url.trim_end_matches('/')
        );
        let feed_query: GetFeed<String> = GetFeed {
            cursor: None,
            limit: Some(100),
            space: Some(space_ref.clone()),
        };

        // Feed contains exactly 1 top-level post (replies do not appear as top-level feed items)
        let alice_feed_resp = self
            .config
            .alice
            .apply_auth(self.client.get(&feed_url))
            .query(&feed_query)
            .send()
            .await
            .map_err(|e| format!("Alice getFeed failed: {e}"))?;
        if !alice_feed_resp.status().is_success() {
            return Err(format!(
                "Alice getFeed returned HTTP {}",
                alice_feed_resp.status()
            ));
        }
        let alice_feed: GetFeedOutput<String> = alice_feed_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse GetFeedOutput: {e}"))?;

        if alice_feed.feed.len() != 1 {
            return Err(format!(
                "Expected exactly 1 top-level post in Circle feed, got {}",
                alice_feed.feed.len()
            ));
        }

        let feed_post_item = &alice_feed.feed[0];
        if feed_post_item.post.post.uri.as_str() != post_uri
            || feed_post_item.post.post.cid.as_str() != post_cid
        {
            return Err("Feed post URI/CID mismatch".to_string());
        }
        if feed_post_item.post.post.like_count != Some(1) {
            return Err(format!(
                "Post like_count mismatch: expected Some(1), got {:?}",
                feed_post_item.post.post.like_count
            ));
        }
        if feed_post_item.post.post.reply_count != Some(1) {
            return Err(format!(
                "Post reply_count mismatch: expected Some(1), got {:?}",
                feed_post_item.post.post.reply_count
            ));
        }

        // Alice reads getPostThread via Nest: assert root and Bob reply using generated query
        let post_thread_url = format!(
            "{}/xrpc/blue.catbird.circle.getPostThread",
            self.config.nest_url.trim_end_matches('/')
        );
        let thread_query: CircleGetPostThread<String> = CircleGetPostThread {
            depth: Some(6),
            parent_height: Some(0),
            space: space_ref.clone(),
            uri: AtUri::new(post_uri.clone()).map_err(|e| format!("Invalid AtUri: {e}"))?,
        };
        let thread_resp = self
            .config
            .alice
            .apply_auth(self.client.get(&post_thread_url))
            .query(&thread_query)
            .send()
            .await
            .map_err(|e| format!("Alice getPostThread failed: {e}"))?;
        if !thread_resp.status().is_success() {
            return Err(format!(
                "Alice getPostThread returned status {}",
                thread_resp.status()
            ));
        }
        let thread_output: CircleGetPostThreadOutput<String> = thread_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Circle GetPostThreadOutput: {e}"))?;

        if thread_output.thread.post.uri.as_str() != post_uri
            || thread_output.thread.post.cid.as_str() != post_cid
        {
            return Err("Thread root post URI/CID mismatch".to_string());
        }
        let thread_replies = thread_output.thread.replies.as_deref().unwrap_or(&[]);
        let found_reply = thread_replies.iter().any(|r| {
            if let ThreadViewPostRepliesItem::ThreadViewPost(reply_tvp) = r {
                reply_tvp.post.uri.as_str() == reply_uri && reply_tvp.post.cid.as_str() == reply_cid
            } else {
                false
            }
        });
        if !found_reply {
            return Err("Bob reply not found in thread replies".to_string());
        }

        // Bob reads getMedia via Nest: byte-for-byte image verification using generated query input
        let media_url = format!(
            "{}/xrpc/blue.catbird.circle.getMedia",
            self.config.nest_url.trim_end_matches('/')
        );
        let media_query: GetMedia<String> = GetMedia {
            cid: Cid::new(blob_cid.as_bytes()).map_err(|e| format!("Invalid Cid: {e}"))?,
            did: Did::new(self.config.alice.did.clone())
                .map_err(|e| format!("Invalid Did: {e}"))?,
            space: space_ref.clone(),
        };
        let media_resp = self
            .config
            .bob
            .apply_auth(self.client.get(&media_url))
            .query(&media_query)
            .send()
            .await
            .map_err(|e| format!("Bob getMedia failed: {e}"))?;
        if !media_resp.status().is_success() {
            return Err(format!(
                "Bob getMedia returned status {}",
                media_resp.status()
            ));
        }
        let media_bytes = media_resp.bytes().await.map_err(|e| e.to_string())?;
        if media_bytes.as_ref() != image_data.as_slice() {
            return Err("Bob retrieved media bytes do not match expected image data".to_string());
        }
        member_markers.push("BOB_MEDIA_OK".into());

        // Carol reads getFeed: verify viewer like state
        let carol_feed_resp = self
            .config
            .carol
            .apply_auth(self.client.get(&feed_url))
            .query(&feed_query)
            .send()
            .await
            .map_err(|e| format!("Carol getFeed failed: {e}"))?;
        if !carol_feed_resp.status().is_success() {
            return Err(format!(
                "Carol getFeed returned status {}",
                carol_feed_resp.status()
            ));
        }
        let carol_feed: GetFeedOutput<String> = carol_feed_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Carol GetFeedOutput: {e}"))?;
        if let Some(post_item) = carol_feed.feed.first() {
            let viewer_like = post_item
                .post
                .post
                .viewer
                .as_ref()
                .and_then(|v| v.like.as_ref())
                .map(|u| u.as_str());
            if viewer_like != Some(like_uri.as_str()) {
                return Err("Carol viewer like state mismatch".to_string());
            }
        } else {
            return Err("Post item not found in Carol feed".to_string());
        }

        // Alice reads listNotifications via Nest: assert Bob reply and Carol like notifications using generated query
        let notifs_url = format!(
            "{}/xrpc/blue.catbird.circle.listNotifications",
            self.config.nest_url.trim_end_matches('/')
        );
        let notifs_query: CircleListNotifications<String> = CircleListNotifications {
            cursor: None,
            limit: Some(100),
        };
        let notifs_resp = self
            .config
            .alice
            .apply_auth(self.client.get(&notifs_url))
            .query(&notifs_query)
            .send()
            .await
            .map_err(|e| format!("Alice listNotifications failed: {e}"))?;
        if !notifs_resp.status().is_success() {
            return Err(format!(
                "Alice listNotifications returned status {}",
                notifs_resp.status()
            ));
        }
        let notifs_output: CircleListNotificationsOutput<String> = notifs_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse ListNotificationsOutput: {e}"))?;

        let has_reply_notif = notifs_output.notifications.iter().any(|n| {
            n.reason == CircleNotificationReason::Reply
                && n.actor.did.as_str() == self.config.bob.did
                && n.subject.as_ref().map(|s| s.as_str()) == Some(reply_uri.as_str())
        });
        if !has_reply_notif {
            return Err("Alice did not receive expected reply notification from Bob".to_string());
        }

        let has_like_notif = notifs_output.notifications.iter().any(|n| {
            n.reason == CircleNotificationReason::Like
                && n.actor.did.as_str() == self.config.carol.did
                && n.subject.as_ref().map(|s| s.as_str()) == Some(post_uri.as_str())
        });
        if !has_like_notif {
            return Err("Alice did not receive expected like notification from Carol".to_string());
        }

        eprintln!("[e2e_scenario] STEP_09_AUTHORIZED_READS_VERIFIED");

        // -------------------------------------------------------------
        // Step 9: Deliberate Semantic Rejection (Bob top-level post while active)
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_10_SEMANTIC_REJECTION_START");
        let rejected_post_record: Post<String> = Post {
            created_at: Datetime::now(),
            embed: None,
            entities: None,
            facets: None,
            labels: None,
            langs: None,
            reply: None, // Top-level post by non-owner member Bob
            tags: None,
            text: rejected_text.clone(),
            extra_data: None,
        };

        // PDS accepts the valid record into Bob's space repo
        let (rejected_post_uri, rejected_post_cid) = self
            .apply_create(
                &self.config.bob,
                &space_uri,
                "app.bsky.feed.post",
                &rejected_post_record,
            )
            .await?;

        // Notify AppView and wait for sync commit processing (asserting signed rev advances)
        let _bob_rev2 = self
            .notify_and_wait_revision(&self.config.bob, &space_uri, Some(&bob_rev1))
            .await?;

        // AppView validator rejects the top-level post because Bob is not circle owner
        let alice_feed_after_reject: GetFeedOutput<String> = self
            .config
            .alice
            .apply_auth(self.client.get(&feed_url))
            .query(&feed_query)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;

        if alice_feed_after_reject.feed.len() != 1 {
            return Err(format!(
                "Feed item count changed unexpectedly after rejected write: got {}",
                alice_feed_after_reject.feed.len()
            ));
        }
        if alice_feed_after_reject
            .feed
            .iter()
            .any(|item| item.post.post.uri.as_str() == rejected_post_uri)
        {
            return Err("Rejected top-level post unexpectedly appeared in Circle feed".to_string());
        }

        // Query circle_rejections table for SHA256(rejected_post_uri)
        let pool = PgPool::connect(&self.config.database_url)
            .await
            .map_err(|e| {
                format!("Failed to connect to Circle AppView DB for rejection audit: {e}")
            })?;

        let uri_hash_bytes = Sha256::digest(rejected_post_uri.as_bytes()).to_vec();
        let uri_hash_hex = hex_encode(&uri_hash_bytes);

        let rejection_row: Option<(String, chrono::DateTime<Utc>)> = sqlx::query_as(
            "SELECT reason_code, observed_at FROM circle_rejections WHERE uri_hash = $1",
        )
        .bind(&uri_hash_bytes)
        .fetch_optional(&pool)
        .await
        .map_err(|e| format!("Failed to query circle_rejections: {e}"))?;

        let (reason_code, observed_at) = rejection_row
            .ok_or_else(|| "Expected rejection row in circle_rejections, found none".to_string())?;

        if reason_code != "top_level_author" {
            return Err(format!(
                "Expected rejection reason_code 'top_level_author', got '{reason_code}'"
            ));
        }

        let started_dt = chrono::DateTime::parse_from_rfc3339(&started_at)
            .map_err(|e| e.to_string())?
            .with_timezone(&Utc);
        if observed_at < started_dt {
            return Err("Rejection observed_at is older than run started_at".to_string());
        }

        let diag_entry = RejectionDiagnostic {
            run_id: run_id.clone(),
            uri_hash: uri_hash_hex.clone(),
            reason_code,
            observed_at: observed_at.to_rfc3339(),
        };
        let diag_path = self.config.artifacts_dir.join("db_diagnostics.json");
        self.write_private_file(
            &diag_path,
            serde_json::to_string_pretty(&vec![diag_entry])
                .unwrap()
                .as_bytes(),
        )?;

        eprintln!("[e2e_scenario] STEP_10_SEMANTIC_REJECTION_PROVED");

        // -------------------------------------------------------------
        // Step 10: Snapshot & Stranger (Dave) Denials
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_11_STRANGER_DENIAL_START");
        let pre_dave_snapshot = self.circle_snapshot(&space_ref, &post_uri).await?;

        // Dave feed query
        let dave_feed_resp = self
            .config
            .dave
            .apply_auth(self.client.get(&feed_url))
            .query(&feed_query)
            .send()
            .await
            .map_err(|e| format!("Dave feed check failed: {e}"))?;
        if dave_feed_resp.status() != StatusCode::FORBIDDEN
            && dave_feed_resp.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Dave feed access expected exact 401/403, got {}",
                dave_feed_resp.status()
            ));
        }

        // Dave media query
        let dave_media_resp = self
            .config
            .dave
            .apply_auth(self.client.get(&media_url))
            .query(&media_query)
            .send()
            .await
            .map_err(|e| format!("Dave media check failed: {e}"))?;
        if dave_media_resp.status() != StatusCode::FORBIDDEN
            && dave_media_resp.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Dave media access expected exact 401/403, got {}",
                dave_media_resp.status()
            ));
        }

        // Dave thread query
        let dave_thread_resp = self
            .config
            .dave
            .apply_auth(self.client.get(&post_thread_url))
            .query(&thread_query)
            .send()
            .await
            .map_err(|e| format!("Dave thread check failed: {e}"))?;
        if dave_thread_resp.status() != StatusCode::FORBIDDEN
            && dave_thread_resp.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Dave thread access expected exact 401/403, got {}",
                dave_thread_resp.status()
            ));
        }

        // Dave permissioned reply write attempt -> require exact 401/403
        let dave_reply_record: Post<String> = Post {
            created_at: Datetime::now(),
            embed: None,
            entities: None,
            facets: None,
            labels: None,
            langs: None,
            reply: Some(ReplyRef {
                parent: StrongRef {
                    cid: Cid::new(post_cid.as_bytes()).unwrap(),
                    uri: AtUri::new(post_uri.clone()).unwrap(),
                    extra_data: None,
                },
                root: StrongRef {
                    cid: Cid::new(post_cid.as_bytes()).unwrap(),
                    uri: AtUri::new(post_uri.clone()).unwrap(),
                    extra_data: None,
                },
                extra_data: None,
            }),
            tags: None,
            text: "unauthorized dave intrusion reply".into(),
            extra_data: None,
        };
        self.expect_apply_create_denied(
            &self.config.dave,
            &space_uri,
            "app.bsky.feed.post",
            &dave_reply_record,
            "Dave unauthorized reply write",
        )
        .await?;

        // Dave permissioned like write attempt -> require exact 401/403
        let dave_like_record: Like<String> = Like {
            created_at: Datetime::now(),
            subject: StrongRef {
                cid: Cid::new(post_cid.as_bytes()).unwrap(),
                uri: AtUri::new(post_uri.clone()).unwrap(),
                extra_data: None,
            },
            via: None,
            extra_data: None,
        };
        self.expect_apply_create_denied(
            &self.config.dave,
            &space_uri,
            "app.bsky.feed.like",
            &dave_like_record,
            "Dave unauthorized like write",
        )
        .await?;

        // Re-verify Alice's snapshot: exact equality
        let post_dave_snapshot = self.circle_snapshot(&space_ref, &post_uri).await?;
        if pre_dave_snapshot != post_dave_snapshot {
            return Err("Circle snapshot changed after unauthorized stranger attempts".to_string());
        }

        eprintln!("[e2e_scenario] STEP_11_STRANGER_DENIED_READS_AND_WRITES");

        // -------------------------------------------------------------
        // Step 11: Alice Adds Dave to Circle via Nest updateMember
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_12_ADD_MEMBER_START");
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
            return Err(format!(
                "add Dave returned status {}",
                add_dave_resp.status()
            ));
        }
        let add_dave_output: UpdateMemberOutput<String> = add_dave_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse UpdateMemberOutput for Dave add: {e}"))?;
        let _ = self
            .poll_operation(
                &add_dave_output.value.id,
                &self.config.alice,
                Duration::from_secs(30),
            )
            .await?;

        // Dave activates Space and asserts active + future expires_at
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
            return Err(format!(
                "Dave activateSpace returned status {}",
                dave_act.status()
            ));
        }
        let dave_act_out: ActivateSpaceOutput<String> = dave_act
            .json()
            .await
            .map_err(|e| format!("Failed to parse Dave ActivateSpaceOutput: {e}"))?;
        if dave_act_out.access_state != AccessState::Active {
            return Err("Dave activateSpace did not yield Active access state".to_string());
        }
        let dave_exp = dave_act_out
            .expires_at
            .ok_or_else(|| "Dave activateSpace missing expires_at".to_string())?;
        let dave_exp_dt = chrono::DateTime::parse_from_rfc3339(dave_exp.as_str())
            .map_err(|e| format!("Invalid Dave expires_at: {e}"))?
            .with_timezone(&Utc);
        if dave_exp_dt <= Utc::now() {
            return Err("Dave activateSpace returned non-future expires_at".to_string());
        }

        // Dave discovers the circle
        let dave_lc_after: ListCirclesOutput<String> = self
            .config
            .dave
            .apply_auth(self.client.get(&list_circles_url))
            .query(&lc_query)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        if !dave_lc_after
            .circles
            .iter()
            .any(|c| c.uri.as_str() == space_uri)
        {
            return Err("Dave failed to discover circle after being added".to_string());
        }

        // Dave reads feed, thread, and media via Nest: full typed history & byte equality
        let dave_feed_after = self
            .config
            .dave
            .apply_auth(self.client.get(&feed_url))
            .query(&feed_query)
            .send()
            .await
            .map_err(|e| format!("Dave getFeed after add failed: {e}"))?;
        if !dave_feed_after.status().is_success() {
            return Err(format!(
                "Dave getFeed after add returned status {}",
                dave_feed_after.status()
            ));
        }
        let dave_feed_out: GetFeedOutput<String> = dave_feed_after
            .json()
            .await
            .map_err(|e| format!("Failed to parse Dave GetFeedOutput: {e}"))?;
        if dave_feed_out.feed.len() != 1 {
            return Err(format!(
                "Expected 1 feed item for Dave, got {}",
                dave_feed_out.feed.len()
            ));
        }
        if dave_feed_out.feed[0].post.post.uri.as_str() != post_uri
            || dave_feed_out.feed[0].post.post.cid.as_str() != post_cid
        {
            return Err("Dave feed item post URI/CID mismatch".to_string());
        }
        if dave_feed_out.feed[0].post.post.like_count != Some(1)
            || dave_feed_out.feed[0].post.post.reply_count != Some(1)
        {
            return Err("Dave feed item counts mismatch".to_string());
        }

        // Dave reads thread
        let dave_thread_resp = self
            .config
            .dave
            .apply_auth(self.client.get(&post_thread_url))
            .query(&thread_query)
            .send()
            .await
            .map_err(|e| format!("Dave getPostThread after add failed: {e}"))?;
        if !dave_thread_resp.status().is_success() {
            return Err(format!(
                "Dave getPostThread after add returned status {}",
                dave_thread_resp.status()
            ));
        }
        let dave_thread_out: CircleGetPostThreadOutput<String> = dave_thread_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Dave CircleGetPostThreadOutput: {e}"))?;
        if dave_thread_out.thread.post.uri.as_str() != post_uri
            || dave_thread_out.thread.post.cid.as_str() != post_cid
        {
            return Err("Dave thread root post URI/CID mismatch".to_string());
        }
        let dave_thread_replies = dave_thread_out.thread.replies.as_deref().unwrap_or(&[]);
        let dave_found_reply = dave_thread_replies.iter().any(|r| {
            if let ThreadViewPostRepliesItem::ThreadViewPost(reply_tvp) = r {
                reply_tvp.post.uri.as_str() == reply_uri && reply_tvp.post.cid.as_str() == reply_cid
            } else {
                false
            }
        });
        if !dave_found_reply {
            return Err("Dave did not see Bob reply in thread".to_string());
        }

        // Dave reads media
        let dave_media_after = self
            .config
            .dave
            .apply_auth(self.client.get(&media_url))
            .query(&media_query)
            .send()
            .await
            .map_err(|e| format!("Dave getMedia after add failed: {e}"))?;
        if !dave_media_after.status().is_success() {
            return Err(format!(
                "Dave getMedia after add returned status {}",
                dave_media_after.status()
            ));
        }
        let dave_media_bytes = dave_media_after.bytes().await.map_err(|e| e.to_string())?;
        if dave_media_bytes.as_ref() != image_data.as_slice() {
            return Err("Dave retrieved media bytes do not match expected image data".to_string());
        }

        member_markers.push("DAVE_ADDED_AND_VERIFIED".into());
        eprintln!("[e2e_scenario] STEP_12_MEMBER_ADDED_AND_VERIFIED");

        // -------------------------------------------------------------
        // Step 12: Alice Removes Bob -> Immediate Revocation
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_13_REMOVE_MEMBER_START");
        let pre_bob_remove_snapshot = self.circle_snapshot(&space_ref, &post_uri).await?;

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

        // Bob discovery disappears
        let bob_lc_after: ListCirclesOutput<String> = self
            .config
            .bob
            .apply_auth(self.client.get(&list_circles_url))
            .query(&lc_query)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        if bob_lc_after
            .circles
            .iter()
            .any(|c| c.uri.as_str() == space_uri)
        {
            return Err("Bob still discovers circle after being removed".to_string());
        }

        // Bob reads are immediately forbidden with exact 401/403
        let bob_feed_after = self
            .config
            .bob
            .apply_auth(self.client.get(&feed_url))
            .query(&feed_query)
            .send()
            .await
            .map_err(|e| format!("Bob feed check after remove failed: {e}"))?;
        if bob_feed_after.status() != StatusCode::FORBIDDEN
            && bob_feed_after.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Bob feed after removal expected exact 401/403, got {}",
                bob_feed_after.status()
            ));
        }

        let bob_media_after = self
            .config
            .bob
            .apply_auth(self.client.get(&media_url))
            .query(&media_query)
            .send()
            .await
            .map_err(|e| format!("Bob media check after remove failed: {e}"))?;
        if bob_media_after.status() != StatusCode::FORBIDDEN
            && bob_media_after.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Bob media after removal expected exact 401/403, got {}",
                bob_media_after.status()
            ));
        }

        let bob_thread_after = self
            .config
            .bob
            .apply_auth(self.client.get(&post_thread_url))
            .query(&thread_query)
            .send()
            .await
            .map_err(|e| format!("Bob thread check after remove failed: {e}"))?;
        if bob_thread_after.status() != StatusCode::FORBIDDEN
            && bob_thread_after.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Bob thread after removal expected exact 401/403, got {}",
                bob_thread_after.status()
            ));
        }

        // Bob activation attempt is rejected with exact 401/403
        let bob_act_after = self
            .config
            .bob
            .apply_auth(self.client.post(&activate_url))
            .json(&ActivateSpace::<String> {
                space: space_ref.clone(),
                extra_data: None,
            })
            .send()
            .await
            .map_err(|e| format!("Bob activateSpace after remove failed: {e}"))?;
        if bob_act_after.status() != StatusCode::FORBIDDEN
            && bob_act_after.status() != StatusCode::UNAUTHORIZED
        {
            return Err(format!(
                "Bob activateSpace after removal expected exact 401/403, got {}",
                bob_act_after.status()
            ));
        }

        // Bob permissioned writes are rejected with exact 401/403
        let bob_reply_record: Post<String> = Post {
            created_at: Datetime::now(),
            embed: None,
            entities: None,
            facets: None,
            labels: None,
            langs: None,
            reply: Some(ReplyRef {
                parent: StrongRef {
                    cid: Cid::new(post_cid.as_bytes()).unwrap(),
                    uri: AtUri::new(post_uri.clone()).unwrap(),
                    extra_data: None,
                },
                root: StrongRef {
                    cid: Cid::new(post_cid.as_bytes()).unwrap(),
                    uri: AtUri::new(post_uri.clone()).unwrap(),
                    extra_data: None,
                },
                extra_data: None,
            }),
            tags: None,
            text: "unauthorized bob post-revocation reply".into(),
            extra_data: None,
        };
        self.expect_apply_create_denied(
            &self.config.bob,
            &space_uri,
            "app.bsky.feed.post",
            &bob_reply_record,
            "Bob reply write after removal",
        )
        .await?;

        let bob_like_record: Like<String> = Like {
            created_at: Datetime::now(),
            subject: StrongRef {
                cid: Cid::new(post_cid.as_bytes()).unwrap(),
                uri: AtUri::new(post_uri.clone()).unwrap(),
                extra_data: None,
            },
            via: None,
            extra_data: None,
        };
        self.expect_apply_create_denied(
            &self.config.bob,
            &space_uri,
            "app.bsky.feed.like",
            &bob_like_record,
            "Bob like write after removal",
        )
        .await?;

        // Full Circle snapshot equality post-Bob-removal
        let post_bob_snapshot = self.circle_snapshot(&space_ref, &post_uri).await?;
        if post_bob_snapshot != pre_bob_remove_snapshot {
            return Err(
                "Circle snapshot modified after member removal denial assertions".to_string(),
            );
        }

        member_markers.push("BOB_REMOVED_AND_REVOKED".into());
        eprintln!("[e2e_scenario] STEP_13_MEMBER_REMOVED_AND_REVOKED");

        // -------------------------------------------------------------
        // Step 13: Public AppView Isolation Checks via HTTP
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] STEP_14_PUBLIC_ISOLATION_START");

        let public_post_check_url = format!(
            "{}/xrpc/app.bsky.feed.getPostThread",
            self.config.public_appview_url.trim_end_matches('/')
        );
        let public_post_query: GetPostThread<String> = GetPostThread {
            depth: None,
            parent_height: None,
            uri: AtUri::new(post_uri.clone()).map_err(|e| format!("Invalid AtUri: {e}"))?,
        };
        let public_post_resp = self
            .client
            .get(&public_post_check_url)
            .query(&public_post_query)
            .send()
            .await
            .map_err(|e| format!("Public AppView post check call failed: {e}"))?;
        if public_post_resp.status().is_success() {
            return Err("Public AppView unexpectedly returned private post".to_string());
        }
        if public_post_resp.status() != StatusCode::BAD_REQUEST
            && public_post_resp.status() != StatusCode::NOT_FOUND
        {
            return Err(format!(
                "Public AppView getPostThread on private post returned unexpected status: {}",
                public_post_resp.status()
            ));
        }
        let post_err: GetPostThreadError = public_post_resp.json().await.map_err(|e| {
            format!("Failed to parse private post error body into GetPostThreadError: {e}")
        })?;
        match &post_err {
            GetPostThreadError::NotFound(_) => {}
            other => {
                return Err(format!(
                    "Public AppView getPostThread returned unexpected error variant: {other}"
                ));
            }
        }
        public_capture.private_post_thread_negative = serde_json::to_value(&post_err).unwrap();

        let public_reply_query: GetPostThread<String> = GetPostThread {
            depth: None,
            parent_height: None,
            uri: AtUri::new(reply_uri.clone()).map_err(|e| format!("Invalid AtUri: {e}"))?,
        };
        let public_reply_resp = self
            .client
            .get(&public_post_check_url)
            .query(&public_reply_query)
            .send()
            .await
            .map_err(|e| format!("Public AppView reply check call failed: {e}"))?;
        if public_reply_resp.status().is_success() {
            return Err("Public AppView unexpectedly returned private reply".to_string());
        }
        if public_reply_resp.status() != StatusCode::BAD_REQUEST
            && public_reply_resp.status() != StatusCode::NOT_FOUND
        {
            return Err(format!(
                "Public AppView getPostThread on private reply returned unexpected status: {}",
                public_reply_resp.status()
            ));
        }
        let reply_err: GetPostThreadError = public_reply_resp.json().await.map_err(|e| {
            format!("Failed to parse private reply error body into GetPostThreadError: {e}")
        })?;
        match &reply_err {
            GetPostThreadError::NotFound(_) => {}
            other => {
                return Err(format!("Public AppView getPostThread for reply returned unexpected error variant: {other}"));
            }
        }
        public_capture.private_reply_thread_negative = serde_json::to_value(&reply_err).unwrap();

        let search_post_query: SearchPosts<String> = SearchPosts {
            author: None,
            cursor: None,
            domain: None,
            lang: None,
            limit: None,
            mentions: None,
            q: post_text.clone(),
            since: None,
            sort: None,
            tag: None,
            until: None,
            url: None,
        };
        let search_post_resp = self
            .client
            .get(&search_posts_url)
            .query(&search_post_query)
            .send()
            .await
            .map_err(|e| format!("Public AppView search post call failed: {e}"))?;
        if !search_post_resp.status().is_success() {
            return Err(format!(
                "Public AppView searchPosts returned non-2xx status: {}",
                search_post_resp.status()
            ));
        }
        let search_post_output: SearchPostsOutput<String> = search_post_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse search post output: {e}"))?;
        if !search_post_output.posts.is_empty() {
            return Err(
                "Public AppView search unexpectedly returned private post canary text".to_string(),
            );
        }
        public_capture.private_post_search_negative =
            serde_json::to_value(&search_post_output).unwrap();

        let search_reply_query: SearchPosts<String> = SearchPosts {
            author: None,
            cursor: None,
            domain: None,
            lang: None,
            limit: None,
            mentions: None,
            q: reply_text.clone(),
            since: None,
            sort: None,
            tag: None,
            until: None,
            url: None,
        };
        let search_reply_resp = self
            .client
            .get(&search_posts_url)
            .query(&search_reply_query)
            .send()
            .await
            .map_err(|e| format!("Public AppView search reply call failed: {e}"))?;
        if !search_reply_resp.status().is_success() {
            return Err(format!(
                "Public AppView searchPosts returned non-2xx status: {}",
                search_reply_resp.status()
            ));
        }
        let search_reply_output: SearchPostsOutput<String> = search_reply_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse search reply output: {e}"))?;
        if !search_reply_output.posts.is_empty() {
            return Err(
                "Public AppView search unexpectedly returned private reply canary text".to_string(),
            );
        }
        public_capture.private_reply_search_negative =
            serde_json::to_value(&search_reply_output).unwrap();

        let search_circle_query: SearchActors<String> = SearchActors {
            cursor: None,
            limit: None,
            q: Some(circle_name.clone()),
            term: None,
        };
        let search_circle_resp = self
            .client
            .get(&search_actors_url)
            .query(&search_circle_query)
            .send()
            .await
            .map_err(|e| format!("Public AppView search circle call failed: {e}"))?;
        if !search_circle_resp.status().is_success() {
            return Err(format!(
                "Public AppView searchActors returned non-2xx status: {}",
                search_circle_resp.status()
            ));
        }
        let search_circle_output: SearchActorsOutput<String> = search_circle_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse search actors output: {e}"))?;
        if !search_circle_output.actors.is_empty() {
            return Err(
                "Public AppView search unexpectedly returned private circle name canary"
                    .to_string(),
            );
        }
        public_capture.private_circle_actor_search_negative =
            serde_json::to_value(&search_circle_output).unwrap();

        // Authoritative Canary Manifest
        let manifest = CanaryManifest {
            run_id: run_id.clone(),
            circle_name: circle_name.clone(),
            post_text: post_text.clone(),
            reply_text: reply_text.clone(),
            rejected_text: rejected_text.clone(),
            space_uri: space_uri.clone(),
            post_uri: post_uri.clone(),
            reply_uri: reply_uri.clone(),
            like_uri: like_uri.clone(),
            rejected_uri: rejected_post_uri.clone(),
            blob_cid: blob_cid.clone(),
            post_cid: post_cid.clone(),
            reply_cid: reply_cid.clone(),
            like_cid: like_cid.clone(),
            rejected_cid: rejected_post_cid.clone(),
            image_canary: image_canary.clone(),
            public_control_post_uri: public_control_post_uri.clone(),
            public_control_post_cid: public_control_post_cid.clone(),
            public_control_like_uri: public_control_like_uri.clone(),
            public_control_text: control_text.clone(),
            rejection_uri_hash: uri_hash_hex,
            member_response_markers: member_markers,
        };

        // Negative canary scan: none of the private canaries must appear in public captures
        let capture_json_str = serde_json::to_string(&public_capture)
            .map_err(|e| format!("Failed to serialize public capture: {e}"))?;

        // Positive control check: public_control_post_uri and CID must be present
        if !capture_json_str.contains(&public_control_post_uri)
            || !capture_json_str.contains(&public_control_post_cid)
        {
            return Err("Public control post URI/CID missing from public HTTP capture".to_string());
        }

        for canary in manifest.private_canaries() {
            if capture_json_str.contains(canary) {
                return Err(
                    "Privacy leak detected: private canary found in public HTTP capture body"
                        .to_string(),
                );
            }
        }

        // Save public HTTP capture artifact (mode 0600)
        let capture_path = self.config.artifacts_dir.join("public_http_capture.json");
        self.write_private_file(
            &capture_path,
            serde_json::to_string_pretty(&public_capture)
                .unwrap()
                .as_bytes(),
        )?;
        eprintln!("[e2e_scenario] STEP_14_PUBLIC_ISOLATION_VERIFIED");

        // -------------------------------------------------------------
        // Step 14: Write Permission-Restricted Canary Manifest & Provenance
        // -------------------------------------------------------------
        let completed_at = Utc::now().to_rfc3339();

        let root_revision = get_revision("../..");
        let nest_revision = get_revision("..");

        let provenance = RunProvenance {
            run_id: run_id.clone(),
            started_at,
            completed_at,
            nest_url: self.config.nest_url.clone(),
            circle_appview_url: self.config.circle_appview_url.clone(),
            circle_appview_service_did: self.config.circle_appview_service_did.clone(),
            public_appview_url: self.config.public_appview_url.clone(),
            database_kind: "postgresql".to_string(),
            alice_did: self.config.alice.did.clone(),
            alice_pds_url: self.config.alice.pds_url.clone(),
            bob_did: self.config.bob.did.clone(),
            bob_pds_url: self.config.bob.pds_url.clone(),
            carol_did: self.config.carol.did.clone(),
            carol_pds_url: self.config.carol.pds_url.clone(),
            dave_did: self.config.dave.did.clone(),
            dave_pds_url: self.config.dave.pds_url.clone(),
            root_revision,
            nest_revision,
        };
        let prov_path = self.config.artifacts_dir.join("provenance.json");
        self.write_private_file(
            &prov_path,
            serde_json::to_string_pretty(&provenance)
                .unwrap()
                .as_bytes(),
        )?;

        let manifest_path = self.config.artifacts_dir.join("canary_manifest.json");
        self.write_private_file(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap().as_bytes(),
        )?;

        eprintln!("[e2e_scenario] STEP_15_ARTIFACTS_WRITTEN_OK");
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

    eprintln!("[e2e_scenario] STEP_15_SCENARIO_COMPLETE");
    std::process::exit(0);
}
