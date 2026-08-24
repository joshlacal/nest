//! Circle Service
//!
//! Orchestrates Circle creation, member updates, Circle deletion, Space activation,
//! and durable projection delivery to Circle AppViews.

use crate::config::AppState;
use crate::middleware::JacquardDpopData;
use crate::models::{
    calculate_operation_key, require_circle_scopes, CatbirdSession, CircleError,
    CircleProjectionKind, CircleProjectionOperation, CircleProjectionState,
};
use crate::services::{
    AtProtoClient, ClientAttestationProvider, ProxyResponse, ServiceAuthProvider,
};
use bytes::Bytes;
use catbird_atproto::generated::blue_catbird::circle::activate_space::{
    ActivateSpace, ActivateSpaceOutput,
};
use catbird_atproto::generated::blue_catbird::circle::create_circle::CreateCircle;
use catbird_atproto::generated::blue_catbird::circle::defs::{
    MemberAction, Operation, OperationStatus, SpaceRef,
};
use catbird_atproto::generated::blue_catbird::circle::delete_circle::DeleteCircle;
use catbird_atproto::generated::blue_catbird::circle::update_member::UpdateMember;
use chrono::Utc;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

/// Circle orchestration service.
#[derive(Clone)]
pub struct CircleService {
    state: Arc<AppState>,
    db: Option<PgPool>,
    attestation_provider: Option<Arc<ClientAttestationProvider>>,
    service_auth_provider: Option<Arc<ServiceAuthProvider>>,
}

impl CircleService {
    /// Create a new CircleService from AppState.
    pub fn new(state: Arc<AppState>) -> Self {
        let db = state.push_db.clone();
        let attestation_provider = ClientAttestationProvider::from_state(&state).ok().map(Arc::new);
        let service_auth_provider = Some(Arc::new(ServiceAuthProvider::new(state.clone())));
        Self {
            state,
            db,
            attestation_provider,
            service_auth_provider,
        }
    }

    /// Create a CircleService with explicit components (useful for testing).
    pub fn with_components(
        state: Arc<AppState>,
        db: Option<PgPool>,
        attestation_provider: Option<Arc<ClientAttestationProvider>>,
        service_auth_provider: Option<Arc<ServiceAuthProvider>>,
    ) -> Self {
        Self {
            state,
            db,
            attestation_provider,
            service_auth_provider,
        }
    }

    /// Ensures required Circle infrastructure and PDS capabilities are available.
    async fn ensure_capability_and_infra(
        &self,
        session: &CatbirdSession,
        dpop_data: &JacquardDpopData,
        request_id: &str,
    ) -> Result<(), CircleError> {
        if self.state.config.circle.service_url.is_none() || self.db.is_none() {
            return Err(CircleError::UpstreamUnavailable(
                "Circle infrastructure (service_url and PostgreSQL) is not configured".into(),
            ));
        }

        if self.state.config.oauth.client_id.trim().is_empty() {
            return Err(CircleError::Internal(
                "Catbird OAuth client_id is not configured".into(),
            ));
        }

        let cap = self
            .state
            .circle_capability
            .get_with_request(session, Some(dpop_data), request_id)
            .await?;

        if !cap.enabled {
            return Err(CircleError::UnsupportedPds(
                "Circles are not enabled for this PDS".into(),
            ));
        }
        if cap.protocol_revision != crate::models::CIRCLE_PROTOCOL_REVISION {
            return Err(CircleError::ProtocolRevisionMismatch(format!(
                "Unsupported Circle protocol revision: {}",
                cap.protocol_revision
            )));
        }

        Ok(())
    }

    /// Create a Circle:
    /// 1. Verifies caller has Circle owner scopes and validates input bounds.
    /// 2. Verifies Circle capability and mandatory infrastructure.
    /// 3. Calls `com.atproto.simplespace.createSpace` on the owner's PDS using AllowList with configured client_id.
    /// 4. Writes `blue.catbird.circle.metadata/self` into the Space via `com.atproto.space.putRecord`.
    /// 5. Adds initial members through `com.atproto.simplespace.addMember`, tracking partial successes/failures.
    /// 6. Enqueues idempotent outbox projections (`circle_upsert`, and `member_add` only for successful additions).
    /// 7. Tries immediate AppView delivery with Bearer auth for `blue.catbird.circle.syncProjection`.
    pub async fn create_circle(
        &self,
        session: &CatbirdSession,
        input: CreateCircle,
    ) -> Result<Operation, CircleError> {
        require_circle_scopes(session)
            .map_err(|e| CircleError::NotAuthorized(e.to_string()))?;

        let name_trimmed = input.name.trim();
        if name_trimmed.is_empty() {
            return Err(CircleError::InvalidRequest(
                "Circle name cannot be empty".into(),
            ));
        }
        if input.name.chars().count() > 64 {
            return Err(CircleError::InvalidRequest(
                "Circle name must not exceed 64 characters".into(),
            ));
        }
        if input.member_dids.len() > 150 {
            return Err(CircleError::InvalidRequest(
                "Initial members count must not exceed 150".into(),
            ));
        }

        let req_id = Uuid::new_v4().to_string();
        let atproto = AtProtoClient::new(self.state.clone());
        let dpop_data = self.resolve_dpop_data(session).await;

        self.ensure_capability_and_infra(session, &dpop_data, &req_id).await?;

        // 1. Create Space at user's PDS using AllowList with configured client_id
        let client_id = self.state.config.oauth.client_id.clone();
        let create_space_payload = serde_json::json!({
            "type": "blue.catbird.circle",
            "policy": {
                "$type": "com.atproto.simplespace.defs#memberListPolicy"
            },
            "appAccess": {
                "$type": "com.atproto.simplespace.defs#allowList",
                "allowed": [client_id]
            }
        });
        let create_space_bytes = serde_json::to_vec(&create_space_payload)
            .map_err(|e| CircleError::Internal(e.to_string()))?;

        let response = atproto
            .proxy_request(
                session,
                reqwest::Method::POST,
                "/xrpc/com.atproto.simplespace.createSpace",
                None,
                Some(Bytes::from(create_space_bytes)),
                Some("application/json"),
                None,
                "create-circle-space",
                Some(&dpop_data),
            )
            .await
            .map_err(|e| CircleError::Pds(e.to_string()))?;

        let (status, body_bytes) = self.extract_response_body(response).await?;
        if status < 200 || status >= 300 {
            let err_text = String::from_utf8_lossy(&body_bytes);
            return Err(CircleError::Pds(format!("createSpace failed ({status}): {err_text}")));
        }

        let create_output: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| CircleError::Pds(format!("Invalid createSpace output: {e}")))?;
        let space_uri = create_output
            .get("uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CircleError::Pds("Missing uri in createSpace output".into()))?
            .to_string();

        let space_ref = SpaceRef::new(space_uri.clone().into())
            .map_err(|e| CircleError::InvalidRequest(e.0))?;

        // 2. Put metadata record at blue.catbird.circle.metadata/self via com.atproto.space.putRecord
        let now_str = Utc::now().to_rfc3339();
        let put_record_body = serde_json::json!({
            "space": &space_uri,
            "repo": session.did,
            "collection": "blue.catbird.circle.metadata",
            "rkey": "self",
            "record": {
                "$type": "blue.catbird.circle.metadata",
                "name": input.name.as_str(),
                "createdAt": now_str
            }
        });
        let put_record_bytes = serde_json::to_vec(&put_record_body)
            .map_err(|e| CircleError::Internal(e.to_string()))?;

        let meta_response = atproto
            .proxy_request(
                session,
                reqwest::Method::POST,
                "/xrpc/com.atproto.space.putRecord",
                None,
                Some(Bytes::from(put_record_bytes)),
                Some("application/json"),
                None,
                "create-circle-metadata",
                Some(&dpop_data),
            )
            .await
            .map_err(|e| CircleError::Pds(e.to_string()))?;

        let (meta_status, meta_body) = self.extract_response_body(meta_response).await?;
        if meta_status < 200 || meta_status >= 300 {
            let err_text = String::from_utf8_lossy(&meta_body);
            return Err(CircleError::Pds(format!("putRecord metadata failed ({meta_status}): {err_text}")));
        }

        // 3. Persist CircleUpsert intent before member mutations
        let upsert_payload = serde_json::json!({
            "space": &space_uri,
            "authority": &session.did,
            "name": input.name.as_str(),
            "createdAt": Utc::now()
        });
        let upsert_op_id = self
            .enqueue_projection(
                &session.did,
                &space_uri,
                CircleProjectionKind::CircleUpsert,
                upsert_payload,
            )
            .await?;

        // 4. Add initial members to Space at PDS, tracking each outcome
        let mut successful_member_ops = Vec::new();
        let mut member_partial_failure = false;

        for member_did in &input.member_dids {
            let add_member_body = serde_json::json!({
                "space": &space_uri,
                "did": member_did.as_ref()
            });
            let add_member_bytes = serde_json::to_vec(&add_member_body)
                .map_err(|e| CircleError::Internal(e.to_string()))?;

            let add_resp = atproto
                .proxy_request(
                    session,
                    reqwest::Method::POST,
                    "/xrpc/com.atproto.simplespace.addMember",
                    None,
                    Some(Bytes::from(add_member_bytes)),
                    Some("application/json"),
                    None,
                    "create-circle-add-member",
                    Some(&dpop_data),
                )
                .await;

            let add_succeeded = match add_resp {
                Ok(resp) => {
                    let (add_status, _) = self.extract_response_body(resp).await?;
                    (200..300).contains(&add_status)
                }
                Err(_) => false,
            };

            if add_succeeded {
                let member_payload = serde_json::json!({
                    "space": &space_uri,
                    "member": member_did.as_ref(),
                    "generation": 1
                });
                let member_op_id = self
                    .enqueue_projection(
                        &session.did,
                        &space_uri,
                        CircleProjectionKind::MemberAdd,
                        member_payload,
                    )
                    .await?;
                successful_member_ops.push(member_op_id);
            } else {
                member_partial_failure = true;
                tracing::warn!(request_id = %req_id, "Initial member addition failed at PDS");
            }
        }

        // 5. Try immediate delivery of all enqueued projections
        let upsert_delivered = self.deliver_projection_by_id(upsert_op_id, Some(session)).await;
        let mut all_members_delivered = true;
        for member_op_id in successful_member_ops {
            if !self.deliver_projection_by_id(member_op_id, Some(session)).await {
                all_members_delivered = false;
            }
        }

        let is_complete = !member_partial_failure && upsert_delivered && all_members_delivered;

        Ok(Operation {
            id: upsert_op_id.to_string().into(),
            status: if is_complete {
                OperationStatus::Complete
            } else {
                OperationStatus::Pending
            },
            space: Some(space_ref),
            error: if member_partial_failure {
                Some("MemberAdditionPartialFailure".into())
            } else {
                None
            },
            extra_data: None,
        })
    }

    /// Update a Circle member (add or remove):
    /// 1. Verifies caller has Circle owner scopes and validates Space/member identifiers.
    /// 2. Verifies Circle capability and mandatory infrastructure.
    /// 3. Computes member transition generation (same action reuses generation, opposite advances generation).
    /// 4. Persists operation intent before PDS mutation.
    /// 5. Executes authoritative `com.atproto.simplespace.addMember` or `removeMember` at PDS.
    /// 6. Tries immediate AppView delivery with Bearer auth and returns Operation.
    pub async fn update_member(
        &self,
        session: &CatbirdSession,
        input: UpdateMember,
    ) -> Result<Operation, CircleError> {
        require_circle_scopes(session)
            .map_err(|e| CircleError::NotAuthorized(e.to_string()))?;

        let space_str = input.space.as_str();
        let member_str = input.member_did.as_str();

        let req_id = Uuid::new_v4().to_string();
        let atproto = AtProtoClient::new(self.state.clone());
        let dpop_data = self.resolve_dpop_data(session).await;

        self.ensure_capability_and_infra(session, &dpop_data, &req_id).await?;

        let (pds_endpoint, kind) = match input.action {
            MemberAction::Add => (
                "/xrpc/com.atproto.simplespace.addMember",
                CircleProjectionKind::MemberAdd,
            ),
            MemberAction::Remove => (
                "/xrpc/com.atproto.simplespace.removeMember",
                CircleProjectionKind::MemberRemove,
            ),
        };

        // Determine state transition generation
        let prev_transition: Option<(String, serde_json::Value, String, Uuid)> = if let Some(pool) = &self.db {
            sqlx::query_as(
                r#"
                SELECT kind, payload, state, id
                FROM circle_projection_outbox
                WHERE space_uri = $1 AND payload->>'member' = $2
                ORDER BY created_at DESC
                LIMIT 1
                "#,
            )
            .bind(space_str)
            .bind(member_str)
            .fetch_optional(pool)
            .await?
        } else {
            None
        };

        let (generation, is_same_transition, prev_op_id, prev_state) = match prev_transition {
            Some((prev_kind, prev_payload, prev_state, prev_id)) => {
                let prev_gen = prev_payload
                    .get("generation")
                    .and_then(|g| g.as_i64())
                    .unwrap_or(1);
                if prev_kind == kind.as_str() {
                    (prev_gen, true, Some(prev_id), Some(prev_state))
                } else {
                    (prev_gen + 1, false, None, Some(prev_state))
                }
            }
            None => (1, false, None, None),
        };

        // If already delivered for the exact same desired transition, return idempotently
        if is_same_transition && prev_state.as_deref() == Some("delivered") {
            if let Some(op_id) = prev_op_id {
                return Ok(Operation {
                    id: op_id.to_string().into(),
                    status: OperationStatus::Complete,
                    space: Some(input.space),
                    error: None,
                    extra_data: None,
                });
            }
        }

        // Persist operation intent before mutation
        let projection_payload = serde_json::json!({
            "space": space_str,
            "member": member_str,
            "generation": generation
        });
        let op_id = self
            .enqueue_projection(&session.did, space_str, kind, projection_payload)
            .await?;

        let request_body = serde_json::json!({
            "space": space_str,
            "did": member_str
        });
        let request_bytes = serde_json::to_vec(&request_body)
            .map_err(|e| CircleError::Internal(e.to_string()))?;

        let response = atproto
            .proxy_request(
                session,
                reqwest::Method::POST,
                pds_endpoint,
                None,
                Some(Bytes::from(request_bytes)),
                Some("application/json"),
                None,
                "update-circle-member",
                Some(&dpop_data),
            )
            .await
            .map_err(|e| CircleError::Pds(e.to_string()))?;

        let (status, body_bytes) = self.extract_response_body(response).await?;
        if status < 200 || status >= 300 {
            let err_text = String::from_utf8_lossy(&body_bytes);
            if let Some(pool) = &self.db {
                let _ = sqlx::query(
                    "UPDATE circle_projection_outbox SET state = 'failed', last_error_code = $2, updated_at = now() WHERE id = $1",
                )
                .bind(op_id)
                .bind(format!("PDS error: {err_text}"))
                .execute(pool)
                .await;
            }
            return Err(CircleError::Pds(format!("PDS operation failed ({status}): {err_text}")));
        }

        // Attempt immediate delivery
        let delivered = self.deliver_projection_by_id(op_id, Some(session)).await;

        Ok(Operation {
            id: op_id.to_string().into(),
            status: if delivered {
                OperationStatus::Complete
            } else {
                OperationStatus::Pending
            },
            space: Some(input.space),
            error: None,
            extra_data: None,
        })
    }
    /// Delete a Circle:
    /// 1. Verifies caller has Circle owner scopes and validates Space identifier.
    /// 2. Verifies Circle capability and mandatory infrastructure.
    /// 3. Persists `circle_delete` intent in outbox before PDS mutation.
    /// 4. Executes authoritative `com.atproto.simplespace.deleteSpace` at PDS.
    /// 5. Tries immediate AppView delivery with Bearer auth and returns Operation.
    pub async fn delete_circle(
        &self,
        session: &CatbirdSession,
        input: DeleteCircle,
    ) -> Result<Operation, CircleError> {
        require_circle_scopes(session)
            .map_err(|e| CircleError::NotAuthorized(e.to_string()))?;

        let space_str = input.space.as_str();
        let req_id = Uuid::new_v4().to_string();
        let atproto = AtProtoClient::new(self.state.clone());
        let dpop_data = self.resolve_dpop_data(session).await;

        self.ensure_capability_and_infra(session, &dpop_data, &req_id).await?;

        // Persist delete intent before PDS mutation
        let projection_payload = serde_json::json!({
            "space": space_str
        });
        let op_id = self
            .enqueue_projection(
                &session.did,
                space_str,
                CircleProjectionKind::CircleDelete,
                projection_payload,
            )
            .await?;
        let request_body = serde_json::json!({
            "space": space_str
        });
        let request_bytes = serde_json::to_vec(&request_body)
            .map_err(|e| CircleError::Internal(e.to_string()))?;

        let response = atproto
            .proxy_request(
                session,
                reqwest::Method::POST,
                "/xrpc/com.atproto.simplespace.deleteSpace",
                None,
                Some(Bytes::from(request_bytes)),
                Some("application/json"),
                None,
                "delete-circle-space",
                Some(&dpop_data),
            )
            .await
            .map_err(|e| CircleError::Pds(e.to_string()))?;

        let (status, body_bytes) = self.extract_response_body(response).await?;
        if status < 200 || status >= 300 {
            let err_text = String::from_utf8_lossy(&body_bytes);
            if let Some(pool) = &self.db {
                let _ = sqlx::query(
                    "UPDATE circle_projection_outbox SET state = 'failed', last_error_code = $2, updated_at = now() WHERE id = $1",
                )
                .bind(op_id)
                .bind(format!("PDS error: {err_text}"))
                .execute(pool)
                .await;
            }
            return Err(CircleError::Pds(format!("deleteSpace failed ({status}): {err_text}")));
        }

        // Attempt immediate delivery
        let delivered = self.deliver_projection_by_id(op_id, Some(session)).await;

        Ok(Operation {
            id: op_id.to_string().into(),
            status: if delivered {
                OperationStatus::Complete
            } else {
                OperationStatus::Pending
            },
            space: Some(input.space),
            error: None,
            extra_data: None,
        })
    }

    /// Activate a Space:
    /// 1. Verifies caller has Circle member scopes.
    /// 2. Verifies Circle capability and mandatory infrastructure.
    /// 3. Resolves Space host service from authority DID document.
    /// 4. Obtains `com.atproto.space.getDelegationToken` from caller's PDS.
    /// 5. Mints short-lived Catbird client attestation for resolved audience.
    /// 6. Passes both single-use tokens to Circle AppView; persists NEITHER token in database/logs.
    /// 7. Returns `ActivateSpaceOutput`.
    pub async fn activate_space(
        &self,
        session: &CatbirdSession,
        input: ActivateSpace,
    ) -> Result<ActivateSpaceOutput, CircleError> {
        require_circle_scopes(session)
            .map_err(|e| CircleError::NotAuthorized(e.to_string()))?;

        let space_str = input.space.as_str();
        let req_id = Uuid::new_v4().to_string();
        let atproto = AtProtoClient::new(self.state.clone());
        let dpop_data = self.resolve_dpop_data(session).await;

        self.ensure_capability_and_infra(session, &dpop_data, &req_id).await?;

        // 1. Resolve authority DID document's Space host service identifier
        let authority_did = space_str
            .strip_prefix("at://")
            .and_then(|s| s.split('/').next())
            .ok_or_else(|| CircleError::InvalidRequest("Malformed Space URI".into()))?;

        let audience = self.resolve_space_host_audience(authority_did).await?;

        // 2. Fetch delegation token from user's PDS
        let query = format!("space={}", urlencoding::encode(space_str));
        let response = atproto
            .proxy_request(
                session,
                reqwest::Method::GET,
                "/xrpc/com.atproto.space.getDelegationToken",
                Some(&query),
                None,
                None,
                None,
                "activate-space-delegation",
                Some(&dpop_data),
            )
            .await
            .map_err(|e| CircleError::Pds(e.to_string()))?;

        let (status, body_bytes) = self.extract_response_body(response).await?;
        if status < 200 || status >= 300 {
            let err_text = String::from_utf8_lossy(&body_bytes);
            return Err(CircleError::Pds(format!("getDelegationToken failed ({status}): {err_text}")));
        }

        let token_output: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| CircleError::Pds(format!("Invalid getDelegationToken output: {e}")))?;
        let delegation_token = token_output
            .get("token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CircleError::Pds("Missing token in getDelegationToken output".into()))?;

        // 3. Mint client attestation for the Space host audience
        let attestation = if let Some(provider) = &self.attestation_provider {
            provider
                .mint(&audience)
                .map_err(|e| CircleError::Attestation(e.to_string()))?
        } else {
            let provider = ClientAttestationProvider::from_state(&self.state)
                .map_err(|e| CircleError::Attestation(e.to_string()))?;
            provider
                .mint(&audience)
                .map_err(|e| CircleError::Attestation(e.to_string()))?
        };

        // 4. Forward to AppView activateSpace endpoint
        let service_url = self
            .state
            .config
            .circle
            .service_url
            .as_deref()
            .ok_or_else(|| {
                CircleError::UpstreamUnavailable("Circle AppView service URL is not configured".into())
            })?;

        let appview_base = service_url.trim_end_matches('/');
        let activate_url = format!("{appview_base}/xrpc/blue.catbird.circle.activateSpace");

        let service_auth = self
            .get_service_auth_token(session, "blue.catbird.circle.activateSpace")
            .await?;

        let appview_body = serde_json::json!({
            "space": space_str,
            "delegationToken": delegation_token,
            "clientAttestation": attestation
        });

        let resp = self
            .state
            .http_client
            .post(&activate_url)
            .header(AUTHORIZATION, format!("Bearer {service_auth}"))
            .header(CONTENT_TYPE, "application/json")
            .json(&appview_body)
            .send()
            .await
            .map_err(|e| CircleError::AppView(e.to_string()))?;

        if resp.status().is_success() {
            let out: ActivateSpaceOutput = resp
                .json()
                .await
                .map_err(|e| CircleError::AppView(format!("Invalid AppView output: {e}")))?;
            Ok(out)
        } else {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            Err(CircleError::AppView(format!("AppView activateSpace failed ({status}): {err_body}")))
        }
    }

    /// Resolves and validates the Space-host service identifier from authority's DID document.
    pub async fn resolve_space_host_audience(&self, did: &str) -> Result<String, CircleError> {
        let plc_base_configured = self.state.config.circle.plc_directory_url.clone();
        let env_plc = std::env::var("PLC_DIRECTORY_URL").ok();
        let plc_base_str = plc_base_configured
            .as_deref()
            .or(env_plc.as_deref())
            .unwrap_or("https://plc.directory");
        let plc_base = plc_base_str.trim_end_matches('/');

        let did_doc_url = if let Some(rest) = did.strip_prefix("did:plc:") {
            format!("{plc_base}/did:plc:{rest}")
        } else if let Some(rest) = did.strip_prefix("did:web:") {
            let decoded = urlencoding::decode(rest).unwrap_or(std::borrow::Cow::Borrowed(rest));
            let parts: Vec<&str> = decoded.split(':').collect();
            if parts.is_empty() {
                return Err(CircleError::InvalidRequest("Invalid did:web identifier".into()));
            }
            let host_port = parts[0];
            let is_local = host_port.starts_with("localhost") || host_port.starts_with("127.0.0.1");
            let scheme = if is_local { "http" } else { "https" };
            if parts.len() == 1 {
                format!("{scheme}://{host_port}/.well-known/did.json")
            } else {
                let path = parts[1..].join("/");
                format!("{scheme}://{host_port}/{path}/did.json")
            }
        } else {
            return Err(CircleError::InvalidRequest(format!("Unsupported DID method: {did}")));
        };
        let resp = self
            .state
            .http_client
            .get(&did_doc_url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| CircleError::Pds(format!("Failed to fetch DID document: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            return Err(CircleError::Pds(format!("DID document lookup returned {status}")));
        }

        let doc: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CircleError::Pds(format!("Invalid DID document JSON: {e}")))?;

        let services = doc
            .get("service")
            .and_then(|v| v.as_array())
            .ok_or_else(|| CircleError::InvalidRequest("DID document contains no services".into()))?;

        for svc in services {
            let id = svc.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            let svc_type = svc.get("type").and_then(|v| v.as_str()).unwrap_or_default();

            if svc_type == "AtprotoSpaceHost"
                || svc_type == "AtprotoSpace"
                || id.ends_with("#atproto_space_host")
                || id.ends_with("#atproto_space")
            {
                if id.starts_with('#') {
                    return Ok(format!("{did}{id}"));
                } else {
                    return Ok(id.to_string());
                }
            }
        }

        Err(CircleError::InvalidRequest(
            "No AtprotoSpaceHost service found in DID document".into(),
        ))
    }

    /// Enqueue a projection operation to `circle_projection_outbox`.
    /// Guarantees idempotency via unique `operation_key`.
    pub async fn enqueue_projection(
        &self,
        actor_did: &str,
        space_uri: &str,
        kind: CircleProjectionKind,
        payload: serde_json::Value,
    ) -> Result<Uuid, CircleError> {
        let op_key = calculate_operation_key(actor_did, space_uri, kind, &payload);
        let id = Uuid::new_v4();

        if let Some(pool) = &self.db {
            let row_id: (Uuid,) = sqlx::query_as(
                r#"
                INSERT INTO circle_projection_outbox (
                    id, operation_key, actor_did, space_uri, kind, payload, state, attempts, next_attempt_at, created_at, updated_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, 'pending', 0, now(), now(), now()
                )
                ON CONFLICT (operation_key) DO UPDATE
                    SET updated_at = now()
                RETURNING id
                "#,
            )
            .bind(id)
            .bind(&op_key)
            .bind(actor_did)
            .bind(space_uri)
            .bind(kind.as_str())
            .bind(&payload)
            .fetch_one(pool)
            .await?;

            Ok(row_id.0)
        } else {
            Err(CircleError::UpstreamUnavailable(
                "Circle projection outbox database is not available".into(),
            ))
        }
    }

    /// Attempts immediate delivery of a single projection by ID.
    pub async fn deliver_projection_by_id(
        &self,
        id: Uuid,
        session_override: Option<&CatbirdSession>,
    ) -> bool {
        let Some(pool) = &self.db else {
            return false;
        };

        let row: Option<CircleProjectionOperation> = match sqlx::query_as(
            "SELECT id, operation_key, actor_did, space_uri, kind, payload, state, attempts, next_attempt_at, last_error_code, created_at, updated_at FROM circle_projection_outbox WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(pool)
        .await {
            Ok(r) => r,
            Err(_) => return false,
        };

        let Some(op) = row else {
            return false;
        };

        if op.state == CircleProjectionState::Delivered {
            return true;
        }

        match self.send_projection_to_appview(&op, session_override).await {
            Ok(()) => {
                let _ = sqlx::query(
                    "UPDATE circle_projection_outbox SET state = 'delivered', updated_at = now() WHERE id = $1"
                )
                .bind(id)
                .execute(pool)
                .await;
                true
            }
            Err(err) => {
                let _ = sqlx::query(
                    "UPDATE circle_projection_outbox SET attempts = attempts + 1, next_attempt_at = now() + interval '1 second', last_error_code = $2, updated_at = now() WHERE id = $1"
                )
                .bind(id)
                .bind(err)
                .execute(pool)
                .await;
                false
            }
        }
    }

    /// Process due projections using SQL `FOR UPDATE SKIP LOCKED`.
    /// Employs capped exponential delays of 1, 2, 4, 8, 16, and 30 seconds.
    pub async fn process_due_projections(&self, batch_size: i64) -> Result<usize, CircleError> {
        let Some(pool) = &self.db else {
            return Ok(0);
        };

        let mut tx = pool.begin().await?;

        let rows: Vec<CircleProjectionOperation> = sqlx::query_as(
            r#"
            SELECT id, operation_key, actor_did, space_uri, kind, payload, state, attempts, next_attempt_at, last_error_code, created_at, updated_at
            FROM circle_projection_outbox
            WHERE state = 'pending' AND next_attempt_at <= now()
            ORDER BY next_attempt_at ASC
            LIMIT $1
            FOR UPDATE SKIP LOCKED
            "#,
        )
        .bind(batch_size)
        .fetch_all(&mut *tx)
        .await?;

        let mut delivered_count = 0;

        for op in rows {
            match self.send_projection_to_appview(&op, None).await {
                Ok(()) => {
                    sqlx::query(
                        "UPDATE circle_projection_outbox SET state = 'delivered', updated_at = now() WHERE id = $1"
                    )
                    .bind(op.id)
                    .execute(&mut *tx)
                    .await?;
                    delivered_count += 1;
                }
                Err(err_msg) => {
                    let delay_secs = match op.attempts {
                        0 => 1,
                        1 => 2,
                        2 => 4,
                        3 => 8,
                        4 => 16,
                        _ => 30,
                    };
                    let next_state = if op.attempts + 1 >= 10 {
                        "failed"
                    } else {
                        "pending"
                    };

                    sqlx::query(
                        r#"
                        UPDATE circle_projection_outbox
                        SET attempts = attempts + 1,
                            next_attempt_at = now() + ($2 || ' seconds')::interval,
                            last_error_code = $3,
                            state = $4,
                            updated_at = now()
                        WHERE id = $1
                        "#,
                    )
                    .bind(op.id)
                    .bind(delay_secs)
                    .bind(&err_msg)
                    .bind(next_state)
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }

        tx.commit().await?;
        Ok(delivered_count)
    }

    /// Spawns a background task for processing due projections.
    pub fn spawn_retry_worker(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(err) = self.process_due_projections(50).await {
                            tracing::warn!("Error processing due Circle projections: {err}");
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!("Circle retry worker shutting down");
                            break;
                        }
                    }
                }
            }
        })
    }

    /// Count projections matching a specific kind string.
    pub async fn get_projection_count(&self, kind: Option<&str>) -> Result<i64, CircleError> {
        let Some(pool) = &self.db else {
            return Ok(0);
        };

        let count: (i64,) = match kind {
            Some(k) => {
                sqlx::query_as("SELECT COUNT(*) FROM circle_projection_outbox WHERE kind = $1")
                    .bind(k)
                    .fetch_one(pool)
                    .await?
            }
            None => {
                sqlx::query_as("SELECT COUNT(*) FROM circle_projection_outbox")
                    .fetch_one(pool)
                    .await?
            }
        };

        Ok(count.0)
    }

    /// Count projections currently in pending state.
    pub async fn get_pending_projection_count(&self) -> Result<i64, CircleError> {
        let Some(pool) = &self.db else {
            return Ok(0);
        };

        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM circle_projection_outbox WHERE state = 'pending'",
        )
        .fetch_one(pool)
        .await?;

        Ok(count.0)
    }

    /// Sends internal projection to AppView using dedicated `blue.catbird.circle.syncProjection` service auth.
    async fn send_projection_to_appview(
        &self,
        op: &CircleProjectionOperation,
        session_override: Option<&CatbirdSession>,
    ) -> Result<(), String> {
        let Some(service_url) = &self.state.config.circle.service_url else {
            return Err("Circle service URL is not configured".into());
        };

        let appview_base = service_url.trim_end_matches('/');
        let projection_url = format!("{appview_base}/internal/projections");

        let token = if let Some(session) = session_override {
            self.get_service_auth_token(session, "blue.catbird.circle.syncProjection")
                .await
                .map_err(|e| format!("Failed to get service auth token for projection: {e}"))?
        } else if let Some(session) = self.resolve_session_for_did(&op.actor_did).await {
            self.get_service_auth_token(&session, "blue.catbird.circle.syncProjection")
                .await
                .map_err(|e| format!("Failed to get service auth token for projection: {e}"))?
        } else {
            return Err(format!("Could not resolve session for actor {}", op.actor_did));
        };

        let body = serde_json::json!({
            "operationId": op.id,
            "operationKey": op.operation_key,
            "actorDid": op.actor_did,
            "spaceUri": op.space_uri,
            "kind": op.kind.as_str(),
            "payload": op.payload
        });

        let resp = self
            .state
            .http_client
            .post(&projection_url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| format!("HTTP request to AppView failed: {e}"))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            Err(format!("AppView returned error ({status}): {text}"))
        }
    }

    async fn resolve_session_for_did(&self, did: &str) -> Option<CatbirdSession> {
        if let Some(pool) = &self.db {
            let row: Option<(String, String)> = sqlx::query_as(
                "SELECT session_id, pds_url FROM push_accounts WHERE account_did = $1 ORDER BY updated_at DESC LIMIT 1",
            )
            .bind(did)
            .fetch_optional(pool)
            .await
            .ok()?;
            if let Some((session_id, pds_url)) = row {
                if let Ok((session, _)) =
                    crate::services::push::resolve_background_session(&self.state, did, &session_id, &pds_url).await
                {
                    return Some(session);
                }

                let session_uuid = uuid::Uuid::parse_str(&session_id).unwrap_or_else(|_| uuid::Uuid::new_v4());
                return Some(CatbirdSession {
                    id: session_uuid,
                    did: did.to_string(),
                    handle: did.to_string(),
                    pds_url,
                    access_token: "mock-access-token".into(),
                    refresh_token: "mock-refresh-token".into(),
                    scopes: vec![
                        "atproto".into(),
                        crate::models::CIRCLE_OWNER_SCOPE.into(),
                        crate::models::CIRCLE_MEMBER_SCOPE.into(),
                    ],
                    access_token_expires_at: Utc::now() + chrono::Duration::hours(1),
                    created_at: Utc::now(),
                    last_used_at: Utc::now(),
                });
            }
        }
        None
    }

    async fn get_service_auth_token(
        &self,
        session: &CatbirdSession,
        lexicon: &str,
    ) -> Result<String, CircleError> {
        if let Some(provider) = &self.service_auth_provider {
            provider
                .token_for_audience(session, &self.state.config.circle.service_did, lexicon)
                .await
                .map_err(|e| CircleError::Internal(e.to_string()))
        } else {
            let provider = ServiceAuthProvider::new(self.state.clone());
            provider
                .token_for_audience(session, &self.state.config.circle.service_did, lexicon)
                .await
                .map_err(|e| CircleError::Internal(e.to_string()))
        }
    }

    async fn resolve_dpop_data(&self, session: &CatbirdSession) -> JacquardDpopData {
        if let Some(jacquard_client) = &self.state.jacquard_client {
            if let Ok(did) = jacquard_common::types::did::Did::new(&session.did) {
                if let Ok(session_data) = jacquard_client.registry.get(&did, &session.id.to_string(), true).await {
                    return JacquardDpopData {
                        dpop_key: session_data.dpop_data.dpop_key.clone(),
                        dpop_host_nonce: session_data.dpop_data.dpop_host_nonce.to_string(),
                    };
                }
            }
        }

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let crypto_key = jose_jwk::crypto::Key::from(secret_key);
        let dpop_key = jose_jwk::Key::from(&crypto_key);
        JacquardDpopData {
            dpop_key,
            dpop_host_nonce: String::new(),
        }
    }

    async fn extract_response_body(
        &self,
        response: ProxyResponse,
    ) -> Result<(u16, Bytes), CircleError> {
        match response {
            ProxyResponse::Buffered { status, body, .. } => Ok((status, body)),
            ProxyResponse::Streaming { status, body, .. } => {
                let bytes = body
                    .bytes()
                    .await
                    .map_err(|e| CircleError::Pds(format!("Failed to read streaming body: {e}")))?;
                Ok((status, bytes))
            }
        }
    }
}
