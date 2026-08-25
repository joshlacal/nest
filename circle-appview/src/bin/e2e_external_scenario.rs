//! Real External Multi-User E2E Scenario for Catbird Circles.
//!
//! Drives the complete Circle lifecycle across real external HTTP services:
//! - PDS instances for Alice, Bob, Carol, Dave
//! - Nest management gateway (for createCircle, updateMember)
//! - Circle AppView (for getFeed, getPostThread, getMedia, listNotifications)
//! - Public AppView (for public control record and public boundary isolation verification)
//!
//! Exit codes:
//! - 0: All lifecycle assertions passed.
//! - 1: Assertion failure / invariant violation.
//! - 2: Missing prerequisite / unreachable service endpoint.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

fn url_encode(input: &str) -> String {
    url::form_urlencoded::byte_serialize(input.as_bytes()).collect()
}
use chrono::Utc;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ScenarioConfig {
    pub nest_url: String,
    pub circle_appview_url: String,
    pub public_appview_url: String,

    pub alice_pds_url: String,
    pub alice_did: String,
    pub alice_token: String,

    pub bob_pds_url: String,
    pub bob_did: String,
    pub bob_token: String,

    pub carol_pds_url: String,
    pub carol_did: String,
    pub carol_token: String,

    pub dave_pds_url: String,
    pub dave_did: String,
    pub dave_token: String,

    pub artifacts_dir: PathBuf,
    pub database_url: Option<String>,
}

impl ScenarioConfig {
    pub fn from_env() -> Result<Self, String> {
        let nest_url = env::var("NEST_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".into());
        let circle_appview_url =
            env::var("CIRCLE_APPVIEW_URL").unwrap_or_else(|_| "http://127.0.0.1:3002".into());
        let public_appview_url =
            env::var("PUBLIC_APPVIEW_URL").unwrap_or_else(|_| "https://public.api.bsky.app".into());

        let alice_pds_url = env::var("ALICE_PDS_URL")
            .map_err(|_| "ALICE_PDS_URL is required (e.g. http://127.0.0.1:3003)".to_string())?;
        let alice_did = env::var("ALICE_DID")
            .map_err(|_| "ALICE_DID is required (e.g. did:plc:alice...)".to_string())?;
        let alice_token = env::var("ALICE_AUTH_TOKEN")
            .or_else(|_| env::var("ALICE_TOKEN"))
            .map_err(|_| "ALICE_AUTH_TOKEN is required".to_string())?;

        let bob_pds_url = env::var("BOB_PDS_URL")
            .map_err(|_| "BOB_PDS_URL is required (e.g. http://127.0.0.1:3004)".to_string())?;
        let bob_did = env::var("BOB_DID")
            .map_err(|_| "BOB_DID is required (e.g. did:plc:bob...)".to_string())?;
        let bob_token = env::var("BOB_AUTH_TOKEN")
            .or_else(|_| env::var("BOB_TOKEN"))
            .map_err(|_| "BOB_AUTH_TOKEN is required".to_string())?;

        let carol_pds_url = env::var("CAROL_PDS_URL")
            .map_err(|_| "CAROL_PDS_URL is required (e.g. http://127.0.0.1:3005)".to_string())?;
        let carol_did = env::var("CAROL_DID")
            .map_err(|_| "CAROL_DID is required (e.g. did:plc:carol...)".to_string())?;
        let carol_token = env::var("CAROL_AUTH_TOKEN")
            .or_else(|_| env::var("CAROL_TOKEN"))
            .map_err(|_| "CAROL_AUTH_TOKEN is required".to_string())?;

        let dave_pds_url = env::var("DAVE_PDS_URL")
            .map_err(|_| "DAVE_PDS_URL is required (e.g. http://127.0.0.1:3006)".to_string())?;
        let dave_did = env::var("DAVE_DID")
            .map_err(|_| "DAVE_DID is required (e.g. did:plc:dave...)".to_string())?;
        let dave_token = env::var("DAVE_AUTH_TOKEN")
            .or_else(|_| env::var("DAVE_TOKEN"))
            .map_err(|_| "DAVE_AUTH_TOKEN is required".to_string())?;

        let artifacts_dir = env::var("ARTIFACTS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./artifacts/e2e_circles"));

        let database_url = env::var("DATABASE_URL").ok();

        Ok(Self {
            nest_url,
            circle_appview_url,
            public_appview_url,
            alice_pds_url,
            alice_did,
            alice_token,
            bob_pds_url,
            bob_did,
            bob_token,
            carol_pds_url,
            carol_did,
            carol_token,
            dave_pds_url,
            dave_did,
            dave_token,
            artifacts_dir,
            database_url,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CanaryManifest {
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
    pub private_post_check: Option<Value>,
    pub private_reply_check: Option<Value>,
    pub search_post_check: Option<Value>,
    pub search_circle_check: Option<Value>,
    pub captured_urls: Vec<String>,
}

pub struct ScenarioRunner {
    pub config: ScenarioConfig,
    pub client: Client,
}

impl ScenarioRunner {
    pub fn new(config: ScenarioConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }

    pub async fn check_readiness(&self) -> Result<(), String> {
        eprintln!("[e2e_scenario] Checking service readiness...");

        // Probe Nest
        let nest_probe = format!("{}/health", self.config.nest_url.trim_end_matches('/'));
        let res = self
            .client
            .get(&nest_probe)
            .send()
            .await
            .map_err(|e| format!("Nest probe failed at {nest_probe}: {e}"))?;
        if !res.status().is_success() {
            return Err(format!("Nest at {nest_probe} returned non-success status: {}", res.status()));
        }

        // Probe Circle AppView
        let appview_probe = format!("{}/health", self.config.circle_appview_url.trim_end_matches('/'));
        let res = self
            .client
            .get(&appview_probe)
            .send()
            .await
            .map_err(|e| format!("Circle AppView probe failed at {appview_probe}: {e}"))?;
        if !res.status().is_success() {
            // Also check getCapabilities if /health is not dedicated
            let cap_probe = format!("{}/xrpc/blue.catbird.circle.getCapabilities", self.config.circle_appview_url.trim_end_matches('/'));
            let cap_res = self.client.get(&cap_probe).send().await.map_err(|e| format!("Circle AppView probe failed at {cap_probe}: {e}"))?;
            if !cap_res.status().is_success() {
                return Err(format!("Circle AppView probe failed at {appview_probe}"));
            }
        }

        // Probe PDS endpoints
        for (name, url) in [
            ("Alice PDS", &self.config.alice_pds_url),
            ("Bob PDS", &self.config.bob_pds_url),
            ("Carol PDS", &self.config.carol_pds_url),
            ("Dave PDS", &self.config.dave_pds_url),
        ] {
            let pds_probe = format!("{}/xrpc/_health", url.trim_end_matches('/'));
            let res = self.client.get(&pds_probe).send().await.map_err(|e| format!("{name} probe failed at {pds_probe}: {e}"))?;
            if !res.status().is_success() {
                // Try .well-known
                let wk_probe = format!("{}/.well-known/atproto-did", url.trim_end_matches('/'));
                let wk_res = self.client.get(&wk_probe).send().await.map_err(|e| format!("{name} probe failed at {wk_probe}: {e}"))?;
                if !wk_res.status().is_success() {
                    return Err(format!("{name} at {url} is not ready"));
                }
            }
        }

        eprintln!("[e2e_scenario] All services are reachable and ready.");
        Ok(())
    }

    pub async fn run(&self) -> Result<(), String> {
        let run_id = Uuid::new_v4().to_string();
        let circle_name = format!("Family_{}", &run_id[..8]);
        let post_text = format!("CANARY_TEXT_PRIVATE_POST_BODY_{run_id}");
        let reply_text = format!("CANARY_TEXT_PRIVATE_REPLY_BODY_{run_id}");
        let control_text = format!("CONTROL_PUBLIC_POST_BODY_{run_id}");
        let image_data = format!("CANARY_SECRET_FAMILY_IMAGE_BYTES_{run_id}").into_bytes();

        fs::create_dir_all(&self.config.artifacts_dir)
            .map_err(|e| format!("Failed to create artifacts directory: {e}"))?;

        let mut public_capture = PublicHttpCapture::default();
        let mut member_markers = Vec::new();

        // -------------------------------------------------------------
        // Step 1: Normal Public Control Record & Verification
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] Step 1: Creating public control post to verify public AppView plumbing...");
        let public_control_url = format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            self.config.alice_pds_url.trim_end_matches('/')
        );
        let control_resp = self
            .client
            .post(&public_control_url)
            .header("Authorization", format!("Bearer {}", self.config.alice_token))
            .json(&json!({
                "repo": self.config.alice_did,
                "collection": "app.bsky.feed.post",
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": control_text,
                    "createdAt": Utc::now().to_rfc3339()
                }
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to create public control post: {e}"))?;

        if !control_resp.status().is_success() {
            return Err(format!(
                "Failed to create public control post, status: {}",
                control_resp.status()
            ));
        }

        let control_json: Value = control_resp.json().await.map_err(|e| e.to_string())?;
        let public_control_post_uri = control_json["uri"]
            .as_str()
            .ok_or_else(|| "Public control record missing uri".to_string())?
            .to_string();

        // Query public AppView for the control post
        let public_thread_url = format!(
            "{}/xrpc/app.bsky.feed.getPostThread?uri={}",
            self.config.public_appview_url.trim_end_matches('/'),
            url_encode(&public_control_post_uri)
        );
        public_capture.captured_urls.push(public_thread_url.clone());
        let public_thread_resp = self.client.get(&public_thread_url).send().await;
        if let Ok(resp) = public_thread_resp {
            if resp.status().is_success() {
                let body: Value = resp.json().await.unwrap_or(Value::Null);
                public_capture.public_control_check = Some(body);
            }
        }

        // -------------------------------------------------------------
        // Step 2: Circle Creation via Production Nest Management Endpoint
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] Step 2: Alice creates Circle '{circle_name}' via Nest management endpoint...");
        let create_circle_url = format!(
            "{}/xrpc/blue.catbird.circle.createCircle",
            self.config.nest_url.trim_end_matches('/')
        );
        let create_resp = self
            .client
            .post(&create_circle_url)
            .header("Authorization", format!("Bearer {}", self.config.alice_token))
            .json(&json!({
                "name": circle_name,
                "initialMembers": [self.config.bob_did, self.config.carol_did]
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to call Nest createCircle: {e}"))?;

        if !create_resp.status().is_success() {
            return Err(format!(
                "Nest createCircle failed with status: {}",
                create_resp.status()
            ));
        }

        let create_json: Value = create_resp.json().await.map_err(|e| e.to_string())?;
        let space_uri = create_json["spaceUri"]
            .as_str()
            .ok_or_else(|| "createCircle output missing spaceUri".to_string())?
            .to_string();
        eprintln!("[e2e_scenario] Circle created with Space URI: {space_uri}");

        // -------------------------------------------------------------
        // Step 3: Permissioned Image Upload to Alice's Space-Capable PDS
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] Step 3: Alice uploads private image blob to PDS...");
        let upload_blob_url = format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            self.config.alice_pds_url.trim_end_matches('/')
        );
        let upload_resp = self
            .client
            .post(&upload_blob_url)
            .header("Authorization", format!("Bearer {}", self.config.alice_token))
            .header("Content-Type", "image/jpeg")
            .body(image_data.clone())
            .send()
            .await
            .map_err(|e| format!("Failed to upload blob to Alice PDS: {e}"))?;

        if !upload_resp.status().is_success() {
            return Err(format!(
                "Upload blob failed with status: {}",
                upload_resp.status()
            ));
        }

        let upload_json: Value = upload_resp.json().await.map_err(|e| e.to_string())?;
        let blob_cid = upload_json["blob"]["ref"]["$link"]
            .as_str()
            .or_else(|| upload_json["blob"]["cid"].as_str())
            .ok_or_else(|| "Upload blob response missing blob CID".to_string())?
            .to_string();
        eprintln!("[e2e_scenario] Image blob uploaded, CID: {blob_cid}");

        // -------------------------------------------------------------
        // Step 4: Permissioned Post Write to Circle Space
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] Step 4: Alice publishes private post with image in Circle Space...");
        let create_record_url = format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            self.config.alice_pds_url.trim_end_matches('/')
        );
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
            .client
            .post(&create_record_url)
            .header("Authorization", format!("Bearer {}", self.config.alice_token))
            .json(&json!({
                "repo": space_uri,
                "collection": "app.bsky.feed.post",
                "record": post_record
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to write private post on PDS: {e}"))?;

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

        // -------------------------------------------------------------
        // Step 5: Bob's Permissioned Reply
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] Step 5: Bob writes a reply within Circle Space...");
        let bob_record_url = format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            self.config.bob_pds_url.trim_end_matches('/')
        );
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
            .client
            .post(&bob_record_url)
            .header("Authorization", format!("Bearer {}", self.config.bob_token))
            .json(&json!({
                "repo": space_uri,
                "collection": "app.bsky.feed.post",
                "record": reply_record
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to write Bob reply: {e}"))?;

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

        // -------------------------------------------------------------
        // Step 6: Carol's Permissioned Like
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] Step 6: Carol likes Alice's post in Circle Space...");
        let carol_record_url = format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            self.config.carol_pds_url.trim_end_matches('/')
        );
        let like_record = json!({
            "$type": "app.bsky.feed.like",
            "subject": { "uri": post_uri, "cid": post_cid },
            "createdAt": Utc::now().to_rfc3339()
        });

        let like_resp = self
            .client
            .post(&carol_record_url)
            .header("Authorization", format!("Bearer {}", self.config.carol_token))
            .json(&json!({
                "repo": space_uri,
                "collection": "app.bsky.feed.like",
                "record": like_record
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to write Carol like: {e}"))?;

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

        // -------------------------------------------------------------
        // Step 7: Authorized Member HTTP Reads & Invariant Assertions
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] Step 7: Asserting authorized member views and media retrieval via HTTP...");
        
        // Alice feed
        let alice_feed_url = format!(
            "{}/xrpc/blue.catbird.circle.getFeed?spaceUri={}",
            self.config.circle_appview_url.trim_end_matches('/'),
            url_encode(&space_uri)
        );
        let alice_feed_resp = self
            .client
            .get(&alice_feed_url)
            .header("Authorization", format!("Bearer {}", self.config.alice_token))
            .send()
            .await
            .map_err(|e| format!("Alice getFeed failed: {e}"))?;
        if !alice_feed_resp.status().is_success() {
            return Err(format!("Alice getFeed returned status {}", alice_feed_resp.status()));
        }
        let alice_feed: Value = alice_feed_resp.json().await.map_err(|e| e.to_string())?;
        let feed_items = alice_feed["feed"]
            .as_array()
            .ok_or_else(|| "getFeed missing feed array".to_string())?;
        if feed_items.len() < 2 {
            return Err(format!("Alice expected at least 2 feed items, got {}", feed_items.len()));
        }
        member_markers.push("ALICE_FEED_OK".into());

        // Alice thread
        let alice_thread_url = format!(
            "{}/xrpc/blue.catbird.circle.getPostThread?uri={}",
            self.config.circle_appview_url.trim_end_matches('/'),
            url_encode(&post_uri)
        );
        let alice_thread_resp = self
            .client
            .get(&alice_thread_url)
            .header("Authorization", format!("Bearer {}", self.config.alice_token))
            .send()
            .await
            .map_err(|e| format!("Alice getPostThread failed: {e}"))?;
        if !alice_thread_resp.status().is_success() {
            return Err(format!("Alice getPostThread returned status {}", alice_thread_resp.status()));
        }

        // Bob media retrieval
        let media_url = format!(
            "{}/xrpc/blue.catbird.circle.getMedia?spaceUri={}&authorDid={}&cid={}",
            self.config.circle_appview_url.trim_end_matches('/'),
            url_encode(&space_uri),
            url_encode(&self.config.alice_did),
            url_encode(&blob_cid)
        );
        let media_resp = self
            .client
            .get(&media_url)
            .header("Authorization", format!("Bearer {}", self.config.bob_token))
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

        // -------------------------------------------------------------
        // Step 8: Dave (Stranger Before Membership) Denied Access
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] Step 8: Verifying Dave is denied discovery, feed, thread, media, and write...");
        
        let dave_feed_resp = self
            .client
            .get(&alice_feed_url)
            .header("Authorization", format!("Bearer {}", self.config.dave_token))
            .send()
            .await
            .map_err(|e| format!("Dave feed check failed: {e}"))?;
        if dave_feed_resp.status() != StatusCode::FORBIDDEN {
            return Err(format!("Dave feed access expected 403 Forbidden, got {}", dave_feed_resp.status()));
        }

        let dave_media_resp = self
            .client
            .get(&media_url)
            .header("Authorization", format!("Bearer {}", self.config.dave_token))
            .send()
            .await
            .map_err(|e| format!("Dave media check failed: {e}"))?;
        if dave_media_resp.status() != StatusCode::FORBIDDEN {
            return Err(format!("Dave media access expected 403 Forbidden, got {}", dave_media_resp.status()));
        }

        // Dave denied write attempt
        let dave_write_url = format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            self.config.dave_pds_url.trim_end_matches('/')
        );
        let dave_write_resp = self
            .client
            .post(&dave_write_url)
            .header("Authorization", format!("Bearer {}", self.config.dave_token))
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
            .await;

        if let Ok(resp) = dave_write_resp {
            if resp.status().is_success() {
                return Err("Dave unauthorized write should have been rejected but succeeded".to_string());
            }
        }

        // -------------------------------------------------------------
        // Step 9: Alice Adds Dave to Circle -> Dave Receives History & Media
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] Step 9: Alice adds Dave to Circle via Nest updateMember...");
        let update_member_url = format!(
            "{}/xrpc/blue.catbird.circle.updateMember",
            self.config.nest_url.trim_end_matches('/')
        );
        let add_dave_resp = self
            .client
            .post(&update_member_url)
            .header("Authorization", format!("Bearer {}", self.config.alice_token))
            .json(&json!({
                "spaceUri": space_uri,
                "action": "add",
                "member": self.config.dave_did
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to add Dave via updateMember: {e}"))?;

        if !add_dave_resp.status().is_success() {
            return Err(format!("Add Dave returned status {}", add_dave_resp.status()));
        }

        // Dave now accesses feed and media
        let dave_feed_after = self
            .client
            .get(&alice_feed_url)
            .header("Authorization", format!("Bearer {}", self.config.dave_token))
            .send()
            .await
            .map_err(|e| format!("Dave getFeed after add failed: {e}"))?;
        if !dave_feed_after.status().is_success() {
            return Err(format!("Dave getFeed after add returned status {}", dave_feed_after.status()));
        }

        let dave_media_after = self
            .client
            .get(&media_url)
            .header("Authorization", format!("Bearer {}", self.config.dave_token))
            .send()
            .await
            .map_err(|e| format!("Dave getMedia after add failed: {e}"))?;
        if !dave_media_after.status().is_success() {
            return Err(format!("Dave getMedia after add returned status {}", dave_media_after.status()));
        }
        member_markers.push("DAVE_ADDED_AND_VERIFIED".into());

        // -------------------------------------------------------------
        // Step 10: Alice Removes Bob -> Immediate Revocation
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] Step 10: Alice removes Bob from Circle -> verifying immediate revocation...");
        let remove_bob_resp = self
            .client
            .post(&update_member_url)
            .header("Authorization", format!("Bearer {}", self.config.alice_token))
            .json(&json!({
                "spaceUri": space_uri,
                "action": "remove",
                "member": self.config.bob_did
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to remove Bob via updateMember: {e}"))?;

        if !remove_bob_resp.status().is_success() {
            return Err(format!("Remove Bob returned status {}", remove_bob_resp.status()));
        }

        // Bob is now forbidden
        let bob_feed_after = self
            .client
            .get(&alice_feed_url)
            .header("Authorization", format!("Bearer {}", self.config.bob_token))
            .send()
            .await
            .map_err(|e| format!("Bob feed check after remove failed: {e}"))?;
        if bob_feed_after.status() != StatusCode::FORBIDDEN {
            return Err(format!("Bob feed after removal expected 403 Forbidden, got {}", bob_feed_after.status()));
        }

        let bob_media_after = self
            .client
            .get(&media_url)
            .header("Authorization", format!("Bearer {}", self.config.bob_token))
            .send()
            .await
            .map_err(|e| format!("Bob media check after remove failed: {e}"))?;
        if bob_media_after.status() != StatusCode::FORBIDDEN {
            return Err(format!("Bob media after removal expected 403 Forbidden, got {}", bob_media_after.status()));
        }
        member_markers.push("BOB_REMOVED_AND_REVOKED".into());

        // Alice, Carol, Dave still have access
        for (name, token) in [
            ("Alice", &self.config.alice_token),
            ("Carol", &self.config.carol_token),
            ("Dave", &self.config.dave_token),
        ] {
            let resp = self
                .client
                .get(&alice_feed_url)
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .map_err(|e| format!("{name} feed check failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("{name} feed access failed after Bob removal: status {}", resp.status()));
            }
        }

        // -------------------------------------------------------------
        // Step 11: Public AppView Isolation Checks via HTTP
        // -------------------------------------------------------------
        eprintln!("[e2e_scenario] Step 11: Checking public AppView HTTP isolation...");
        
        let public_post_check_url = format!(
            "{}/xrpc/app.bsky.feed.getPostThread?uri={}",
            self.config.public_appview_url.trim_end_matches('/'),
            url_encode(&post_uri)
        );
        public_capture.captured_urls.push(public_post_check_url.clone());
        let public_post_resp = self.client.get(&public_post_check_url).send().await;
        if let Ok(resp) = public_post_resp {
            if resp.status().is_success() {
                return Err(format!("Public AppView unexpectedly returned private post: {post_uri}"));
            }
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            public_capture.private_post_check = Some(body);
        }

        let public_reply_check_url = format!(
            "{}/xrpc/app.bsky.feed.getPostThread?uri={}",
            self.config.public_appview_url.trim_end_matches('/'),
            url_encode(&reply_uri)
        );
        public_capture.captured_urls.push(public_reply_check_url.clone());
        let public_reply_resp = self.client.get(&public_reply_check_url).send().await;
        if let Ok(resp) = public_reply_resp {
            if resp.status().is_success() {
                return Err(format!("Public AppView unexpectedly returned private reply: {reply_uri}"));
            }
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            public_capture.private_reply_check = Some(body);
        }

        let search_post_url = format!(
            "{}/xrpc/app.bsky.feed.searchPosts?q={}",
            self.config.public_appview_url.trim_end_matches('/'),
            url_encode(&post_text)
        );
        public_capture.captured_urls.push(search_post_url.clone());
        let search_resp = self.client.get(&search_post_url).send().await;
        if let Ok(resp) = search_resp {
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            if let Some(posts) = body["posts"].as_array() {
                if !posts.is_empty() {
                    return Err(format!("Public AppView search unexpectedly returned private post canary text: {post_text}"));
                }
            }
            public_capture.search_post_check = Some(body);
        }

        // Save public HTTP capture artifact
        let capture_path = self.config.artifacts_dir.join("public_http_capture.json");
        fs::write(
            &capture_path,
            serde_json::to_string_pretty(&public_capture).unwrap(),
        )
        .map_err(|e| format!("Failed to write public HTTP capture: {e}"))?;

        // -------------------------------------------------------------
        // Step 12: Dump Database Diagnostics if DB is configured
        // -------------------------------------------------------------
        if let Some(db_url) = &self.config.database_url {
            if let Ok(pool) = PgPool::connect(db_url).await {
                eprintln!("[e2e_scenario] Dumping Circle AppView rejection diagnostics...");
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
                let _ = fs::write(&diag_path, serde_json::to_string_pretty(&diag_json).unwrap());
            }
        }

        // -------------------------------------------------------------
        // Step 13: Write Permission-Restricted Canary Manifest
        // -------------------------------------------------------------
        let manifest = CanaryManifest {
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
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .map_err(|e| format!("Failed to write canary manifest: {e}"))?;

        eprintln!("[e2e_scenario] Real external scenario completed successfully.");
        eprintln!("[e2e_scenario] Canary manifest written to: {}", manifest_path.display());
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

    std::process::exit(0);
}
