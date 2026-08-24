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
/// Error occurred during projection delivery to Circle AppView.
#[derive(Debug, thiserror::Error)]
pub enum ProjectionDeliveryError {
    #[error("Session recovery unavailable: {0}")]
    SessionUnavailable(String),
    #[error("Service auth failed: {0}")]
    ServiceAuth(#[from] CircleError),
    #[error("HTTP request to AppView failed: {0}")]
    Http(String),
    #[error("AppView returned error ({status}): {message}")]
    AppView { status: u16, message: String },
    #[error("Client attestation minting failed: {0}")]
    ClientAttestation(String),
    #[error("Missing client attestation provider")]
    MissingAttestationProvider,
    #[error("Circle service URL is not configured")]
    NotConfigured,
}

impl ProjectionDeliveryError {
    /// Returns true if this error is an authentication or session-unavailable error that must NEVER be terminalized.
    pub fn is_never_terminal_auth_error(&self) -> bool {
        match self {
            Self::SessionUnavailable(_) => true,
            Self::ServiceAuth(CircleError::NotAuthorized(_)) => true,
            Self::ServiceAuth(CircleError::AccessRemoved(_)) => true,
            Self::ServiceAuth(CircleError::UpstreamUnavailable(_)) => true,
            Self::AppView { status, .. }
                if *status == 401
                    || *status == 403
                    || *status == 503
                    || *status == 502
                    || *status == 504
                    || *status == 429 =>
            {
                true
            }
            Self::ClientAttestation(_) => true,
            Self::MissingAttestationProvider => true,
            Self::Http(_) => true,
            _ => false,
        }
    }
}

/// Check if an HTTP status code represents a retryable / indeterminate XRPC error.
pub fn is_retryable_status(status: u16) -> bool {
    status >= 500 || status == 408 || status == 425 || status == 429
}
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

    /// Records an indeterminate transport/network error without marking the row as terminal failed.
    /// The projection remains in 'executing' state so crash reconciliation can pick it up.
    async fn record_indeterminate_transport_error(&self, id: Uuid, err: &str, claim_token: Option<Uuid>) {
        if let Some(pool) = &self.db {
            if let Some(token) = claim_token {
                let _ = sqlx::query(
                    "UPDATE circle_projection_outbox SET last_error_code = $2, updated_at = now() WHERE id = $1 AND state = 'executing' AND (claim_token = $3 OR claim_token IS NULL)"
                )
                .bind(id)
                .bind(err)
                .bind(token)
                .execute(pool)
                .await;
            } else {
                let _ = sqlx::query(
                    "UPDATE circle_projection_outbox SET last_error_code = $2, updated_at = now() WHERE id = $1 AND state = 'executing'"
                )
                .bind(id)
                .bind(err)
                .execute(pool)
                .await;
            }
        }
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
        let mut seen_members = std::collections::HashSet::with_capacity(input.member_dids.len());
        for member_did in &input.member_dids {
            if !seen_members.insert(member_did.as_str()) {
                return Err(CircleError::InvalidRequest(
                    format!("Duplicate member DID in initial members list: {}", member_did),
                ));
            }
        }

        let req_id = Uuid::new_v4().to_string();
        let atproto = AtProtoClient::new(self.state.clone());
        let dpop_data = self.resolve_dpop_data(session).await;

        self.ensure_capability_and_infra(session, &dpop_data, &req_id).await?;
        let _ = self.rebind_actor_sessions(&session.did, &session.id.to_string()).await;

        // 1. Generate skey and space_uri before createSpace, and persist intent first
        let skey = Uuid::new_v4().simple().to_string();
        let pre_space_uri = format!("at://{}/space/blue.catbird.circle/{}", session.did, skey);

        let upsert_payload = serde_json::json!({
            "space": &pre_space_uri,
            "authority": &session.did,
            "name": input.name.as_str(),
            "createdAt": Utc::now(),
            "generation": 1
        });
        let upsert_op_id = self
            .enqueue_projection(
                &session.did,
                &session.id.to_string(),
                &pre_space_uri,
                CircleProjectionKind::CircleUpsert,
                upsert_payload,
                CircleProjectionState::Intent,
            )
            .await?;

        // Atomically claim the operation: intent -> executing
        let upsert_claim_token = self.claim_projection(upsert_op_id, &session.id.to_string()).await?;

        // 2. Create Space at user's PDS using AllowList with configured client_id
        let client_id = self.state.config.oauth.client_id.clone();
        let create_space_payload = serde_json::json!({
            "type": "blue.catbird.circle",
            "skey": &skey,
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

        let response = match atproto
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
        {
            Ok(r) => r,
            Err(e) => {
                self.record_indeterminate_transport_error(
                    upsert_op_id,
                    &format!("Network error creating space: {e}"),
                    upsert_claim_token,
                )
                .await;
                return Err(CircleError::Pds(e.to_string()));
            }
        };

        let (status, body_bytes) = self.extract_response_body(response).await?;
        if is_retryable_status(status) {
            let err_text = String::from_utf8_lossy(&body_bytes);
            self.record_indeterminate_transport_error(
                upsert_op_id,
                &format!("createSpace returned server/retryable error ({status}): {err_text}"),
                upsert_claim_token,
            )
            .await;
            return Err(CircleError::UpstreamUnavailable(format!("createSpace returned {status}: {err_text}")));
        }
        if status < 200 || status >= 300 {
            let err_text = String::from_utf8_lossy(&body_bytes);
            let _ = self
                .set_projection_state(
                    upsert_op_id,
                    CircleProjectionState::Failed,
                    Some(&format!("createSpace failed ({status}): {err_text}")),
                    upsert_claim_token,
                )
                .await;
            return Err(CircleError::Pds(format!("createSpace failed ({status}): {err_text}")));
        }

        let create_output: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| CircleError::Pds(format!("Invalid createSpace output: {e}")))?;
        let space_uri = create_output
            .get("uri")
            .and_then(|v| v.as_str())
            .unwrap_or(&pre_space_uri)
            .to_string();

        let space_ref = SpaceRef::new(space_uri.clone().into())
            .map_err(|e| CircleError::InvalidRequest(e.0))?;

        // 3. Put metadata record at blue.catbird.circle.metadata/self via com.atproto.space.putRecord
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
            .await;

        let meta_resp = match meta_response {
            Ok(resp) => resp,
            Err(e) => {
                self.record_indeterminate_transport_error(
                    upsert_op_id,
                    &format!("Network error creating metadata: {e}"),
                    upsert_claim_token,
                )
                .await;
                return Err(CircleError::Pds(e.to_string()));
            }
        };

        let (meta_status, meta_body) = self.extract_response_body(meta_resp).await?;
        if is_retryable_status(meta_status) {
            let err_text = String::from_utf8_lossy(&meta_body);
            self.record_indeterminate_transport_error(
                upsert_op_id,
                &format!("putRecord metadata returned server/retryable error ({meta_status}): {err_text}"),
                upsert_claim_token,
            )
            .await;
            return Err(CircleError::UpstreamUnavailable(format!("putRecord metadata returned {meta_status}: {err_text}")));
        }
        if meta_status < 200 || meta_status >= 300 {
            let err_text = String::from_utf8_lossy(&meta_body);
            let _ = self
                .set_projection_state(
                    upsert_op_id,
                    CircleProjectionState::Failed,
                    Some(&format!("putRecord metadata failed ({meta_status}): {err_text}")),
                    upsert_claim_token,
                )
                .await;
            return Err(CircleError::Pds(format!("putRecord metadata failed ({meta_status}): {err_text}")));
        }

        // Metadata succeeded -> transition CircleUpsert to Pending
        self.set_projection_state(upsert_op_id, CircleProjectionState::Pending, None, upsert_claim_token).await?;

        // 4. Add initial members to Space at PDS, tracking each outcome durably
        let mut successful_member_ops = Vec::new();
        let mut has_terminal_member_failure = false;
        let mut has_indeterminate_member = false;

        for member_did in &input.member_dids {
            let member_payload = serde_json::json!({
                "space": &space_uri,
                "member": member_did.as_ref(),
                "generation": 1
            });
            let member_op_id = self
                .enqueue_projection(
                    &session.did,
                    &session.id.to_string(),
                    &space_uri,
                    CircleProjectionKind::MemberAdd,
                    member_payload,
                    CircleProjectionState::Intent,
                )
                .await?;

            let maybe_claim = self.claim_projection(member_op_id, &session.id.to_string()).await?;
            let member_claim_token = match maybe_claim {
                Some(token) => token,
                None => {
                    // Re-use persisted state without executing unfenced PDS mutations
                    let (claimed_state, _): (String, Option<String>) = if let Some(pool) = &self.db {
                        sqlx::query_as("SELECT state, last_error_code FROM circle_projection_outbox WHERE id = $1")
                            .bind(member_op_id)
                            .fetch_one(pool)
                            .await
                            .unwrap_or_else(|_| ("executing".into(), None))
                    } else {
                        ("executing".into(), None)
                    };
                    if claimed_state == "pending" || claimed_state == "delivered" {
                        successful_member_ops.push(member_op_id);
                    } else if claimed_state == "failed" {
                        has_terminal_member_failure = true;
                    } else {
                        has_indeterminate_member = true;
                    }
                    continue;
                }
            };

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

            match add_resp {
                Ok(resp) => {
                    let (add_status, body) = self.extract_response_body(resp).await?;
                    if (200..300).contains(&add_status) {
                        self.set_projection_state(member_op_id, CircleProjectionState::Pending, None, Some(member_claim_token)).await?;
                        successful_member_ops.push(member_op_id);
                    } else if is_retryable_status(add_status) {
                        let err_text = String::from_utf8_lossy(&body);
                        self.record_indeterminate_transport_error(
                            member_op_id,
                            &format!("PDS server/retryable error ({add_status}): {err_text}"),
                            Some(member_claim_token),
                        )
                        .await;
                        has_indeterminate_member = true;
                    } else {
                        let err_text = String::from_utf8_lossy(&body);
                        let _ = self
                            .set_projection_state(
                                member_op_id,
                                CircleProjectionState::Failed,
                                Some(&format!("PDS error ({add_status}): {err_text}")),
                                Some(member_claim_token),
                            )
                            .await;
                        has_terminal_member_failure = true;
                        tracing::warn!(request_id = %req_id, "Initial member addition deterministically failed at PDS");
                    }
                }
                Err(e) => {
                    self.record_indeterminate_transport_error(
                        member_op_id,
                        &format!("Network error: {e}"),
                        Some(member_claim_token),
                    )
                    .await;
                    has_indeterminate_member = true;
                }
            }
        }
        // 5. Try immediate delivery of all due projections
        let upsert_delivered = self.deliver_projection_by_id(upsert_op_id, Some(session)).await;
        let mut all_members_delivered = true;
        for member_op_id in &successful_member_ops {
            if !self.deliver_projection_by_id(*member_op_id, Some(session)).await {
                all_members_delivered = false;
            }
        }

        let is_complete = upsert_delivered && all_members_delivered && !has_indeterminate_member && !has_terminal_member_failure;

        let status = if has_terminal_member_failure {
            OperationStatus::Failed
        } else if is_complete {
            OperationStatus::Complete
        } else {
            OperationStatus::Pending
        };

        Ok(Operation {
            id: upsert_op_id.to_string().into(),
            status,
            space: Some(space_ref),
            error: if has_terminal_member_failure {
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
    /// 4. Persists operation intent with state 'intent' before PDS mutation.
    /// 5. Executes authoritative `com.atproto.simplespace.addMember` or `removeMember` at PDS.
    /// 6. Transitions outbox row to 'pending' upon PDS success, or 'failed' upon PDS failure.
    /// 7. Tries immediate AppView delivery with Bearer auth and returns Operation.
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
        let _ = self.rebind_actor_sessions(&session.did, &session.id.to_string()).await;

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
            .enqueue_projection(
                &session.did,
                &session.id.to_string(),
                space_str,
                kind,
                projection_payload,
                CircleProjectionState::Intent,
            )
            .await?;

        // Check if another concurrent duplicate already transitioned this to pending/delivered
        if let Some(pool) = &self.db {
            let current: Option<(String,)> = sqlx::query_as(
                "SELECT state FROM circle_projection_outbox WHERE id = $1",
            )
            .bind(op_id)
            .fetch_optional(pool)
            .await?;

            if let Some((current_state,)) = current {
                if current_state == "delivered" {
                    return Ok(Operation {
                        id: op_id.to_string().into(),
                        status: OperationStatus::Complete,
                        space: Some(input.space),
                        error: None,
                        extra_data: None,
                    });
                }
                if current_state == "pending" {
                    let delivered = self.deliver_projection_by_id(op_id, Some(session)).await;
                    return Ok(Operation {
                        id: op_id.to_string().into(),
                        status: if delivered {
                            OperationStatus::Complete
                        } else {
                            OperationStatus::Pending
                        },
                        space: Some(input.space),
                        error: None,
                        extra_data: None,
                    });
                }
            }
        }

        // Atomically claim the operation (intent/failed/stale -> executing)
        let claim_token = self.claim_projection(op_id, &session.id.to_string()).await?;
        let Some(claim_token) = claim_token else {
            if let Some(pool) = &self.db {
                let current: Option<(String, Option<String>)> = sqlx::query_as(
                    "SELECT state, last_error_code FROM circle_projection_outbox WHERE id = $1",
                )
                .bind(op_id)
                .fetch_optional(pool)
                .await?;

                if let Some((current_state, last_err)) = current {
                    if current_state == "failed" {
                        return Ok(Operation {
                            id: op_id.to_string().into(),
                            status: OperationStatus::Failed,
                            space: Some(input.space),
                            error: last_err.map(|s| s.into()).or_else(|| Some("OperationFailed".into())),
                            extra_data: None,
                        });
                    }
                    if current_state == "delivered" {
                        return Ok(Operation {
                            id: op_id.to_string().into(),
                            status: OperationStatus::Complete,
                            space: Some(input.space),
                            error: None,
                            extra_data: None,
                        });
                    }
                }
            }
            return Ok(Operation {
                id: op_id.to_string().into(),
                status: OperationStatus::Pending,
                space: Some(input.space),
                error: None,
                extra_data: None,
            });
        };

        let request_body = serde_json::json!({
            "space": space_str,
            "did": member_str
        });
        let request_bytes = serde_json::to_vec(&request_body)
            .map_err(|e| CircleError::Internal(e.to_string()))?;

        let response = match atproto
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
        {
            Ok(resp) => resp,
            Err(e) => {
                self.record_indeterminate_transport_error(
                    op_id,
                    &format!("Network error: {e}"),
                    Some(claim_token),
                )
                .await;
                return Err(CircleError::Pds(e.to_string()));
            }
        };

        let (status, body_bytes) = self.extract_response_body(response).await?;
        if is_retryable_status(status) {
            let err_text = String::from_utf8_lossy(&body_bytes);
            self.record_indeterminate_transport_error(
                op_id,
                &format!("PDS operation returned server/retryable error ({status}): {err_text}"),
                Some(claim_token),
            )
            .await;
            return Err(CircleError::UpstreamUnavailable(format!("PDS operation returned {status}: {err_text}")));
        }
        if status < 200 || status >= 300 {
            let err_text = String::from_utf8_lossy(&body_bytes);
            let _ = self
                .set_projection_state(
                    op_id,
                    CircleProjectionState::Failed,
                    Some(&format!("PDS operation failed ({status}): {err_text}")),
                    Some(claim_token),
                )
                .await;
            return Err(CircleError::Pds(format!("PDS operation failed ({status}): {err_text}")));
        }

        // PDS mutation succeeded -> transition to Pending
        self.set_projection_state(op_id, CircleProjectionState::Pending, None, Some(claim_token)).await?;

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
    /// 3. Persists `circle_delete` intent in outbox with state 'intent' before PDS mutation.
    /// 4. Executes authoritative `com.atproto.simplespace.deleteSpace` at PDS.
    /// 5. Transitions outbox row to 'pending' upon PDS success, or 'failed' upon PDS failure.
    /// 6. Tries immediate AppView delivery with Bearer auth and returns Operation.
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
        let _ = self.rebind_actor_sessions(&session.did, &session.id.to_string()).await;

        // Determine delete generation: advance previous generation if known, else default to 1
        let latest_gen: Option<(serde_json::Value,)> = if let Some(pool) = &self.db {
            sqlx::query_as(
                r#"
                SELECT payload
                FROM circle_projection_outbox
                WHERE space_uri = $1 AND kind IN ('circle_upsert', 'circle_delete')
                ORDER BY created_at DESC
                LIMIT 1
                "#,
            )
            .bind(space_str)
            .fetch_optional(pool)
            .await?
        } else {
            None
        };

        let delete_generation = match latest_gen {
            Some((payload,)) => {
                let prev_gen = payload.get("generation").and_then(|g| g.as_i64()).unwrap_or(1);
                prev_gen + 1
            }
            None => 1,
        };

        // Persist delete intent before PDS mutation
        let projection_payload = serde_json::json!({
            "space": space_str,
            "generation": delete_generation
        });
        let op_id = self
            .enqueue_projection(
                &session.did,
                &session.id.to_string(),
                space_str,
                CircleProjectionKind::CircleDelete,
                projection_payload,
                CircleProjectionState::Intent,
            )
            .await?;

        // Check if already pending/delivered
        if let Some(pool) = &self.db {
            let current: Option<(String,)> = sqlx::query_as(
                "SELECT state FROM circle_projection_outbox WHERE id = $1",
            )
            .bind(op_id)
            .fetch_optional(pool)
            .await?;

            if let Some((current_state,)) = current {
                if current_state == "delivered" {
                    return Ok(Operation {
                        id: op_id.to_string().into(),
                        status: OperationStatus::Complete,
                        space: Some(input.space),
                        error: None,
                        extra_data: None,
                    });
                }
                if current_state == "pending" {
                    let delivered = self.deliver_projection_by_id(op_id, Some(session)).await;
                    return Ok(Operation {
                        id: op_id.to_string().into(),
                        status: if delivered {
                            OperationStatus::Complete
                        } else {
                            OperationStatus::Pending
                        },
                        space: Some(input.space),
                        error: None,
                        extra_data: None,
                    });
                }
            }
        }

        // Atomically claim the operation
        let claim_token = self.claim_projection(op_id, &session.id.to_string()).await?;
        let Some(claim_token) = claim_token else {
            if let Some(pool) = &self.db {
                let current: Option<(String, Option<String>)> = sqlx::query_as(
                    "SELECT state, last_error_code FROM circle_projection_outbox WHERE id = $1",
                )
                .bind(op_id)
                .fetch_optional(pool)
                .await?;

                if let Some((current_state, last_err)) = current {
                    if current_state == "failed" {
                        return Ok(Operation {
                            id: op_id.to_string().into(),
                            status: OperationStatus::Failed,
                            space: Some(input.space),
                            error: last_err.map(|s| s.into()).or_else(|| Some("OperationFailed".into())),
                            extra_data: None,
                        });
                    }
                    if current_state == "delivered" {
                        return Ok(Operation {
                            id: op_id.to_string().into(),
                            status: OperationStatus::Complete,
                            space: Some(input.space),
                            error: None,
                            extra_data: None,
                        });
                    }
                }
            }
            return Ok(Operation {
                id: op_id.to_string().into(),
                status: OperationStatus::Pending,
                space: Some(input.space),
                error: None,
                extra_data: None,
            });
        };

        let request_body = serde_json::json!({
            "space": space_str
        });
        let request_bytes = serde_json::to_vec(&request_body)
            .map_err(|e| CircleError::Internal(e.to_string()))?;

        let response = match atproto
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
        {
            Ok(resp) => resp,
            Err(e) => {
                self.record_indeterminate_transport_error(
                    op_id,
                    &format!("Network error: {e}"),
                    Some(claim_token),
                )
                .await;
                return Err(CircleError::Pds(e.to_string()));
            }
        };

        let (status, body_bytes) = self.extract_response_body(response).await?;
        if is_retryable_status(status) {
            let err_text = String::from_utf8_lossy(&body_bytes);
            self.record_indeterminate_transport_error(
                op_id,
                &format!("deleteSpace returned server/retryable error ({status}): {err_text}"),
                Some(claim_token),
            )
            .await;
            return Err(CircleError::UpstreamUnavailable(format!("deleteSpace returned {status}: {err_text}")));
        }
        if status < 200 || status >= 300 {
            let err_text = String::from_utf8_lossy(&body_bytes);
            let _ = self
                .set_projection_state(
                    op_id,
                    CircleProjectionState::Failed,
                    Some(&format!("deleteSpace failed ({status}): {err_text}")),
                    Some(claim_token),
                )
                .await;
            return Err(CircleError::Pds(format!("deleteSpace failed ({status}): {err_text}")));
        }

        // PDS mutation succeeded -> transition to Pending
        self.set_projection_state(op_id, CircleProjectionState::Pending, None, Some(claim_token)).await?;

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
        let _ = self.rebind_actor_sessions(&session.did, &session.id.to_string()).await;

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
            let decoded = urlencoding::decode(rest).map_err(|_| CircleError::InvalidRequest("Invalid did:web encoding".into()))?;
            let parts: Vec<&str> = decoded.split(':').collect();
            if parts.is_empty() || parts[0].trim().is_empty() {
                return Err(CircleError::InvalidRequest("Invalid did:web identifier".into()));
            }
            let host_port = parts[0];
            if parts.len() == 1 {
                format!("https://{host_port}/.well-known/did.json")
            } else {
                let path = parts[1..].join("/");
                format!("https://{host_port}/{path}/did.json")
            }
        } else {
            return Err(CircleError::InvalidRequest(format!("Unsupported DID method: {did}")));
        };

        // Validate URL against SSRF policy
        crate::services::ssrf::validate_pds_url(&did_doc_url)
            .map_err(|e| CircleError::InvalidRequest(format!("DID document URL rejected by SSRF policy: {e}")))?;

        let parsed_url = url::Url::parse(&did_doc_url)
            .map_err(|e| CircleError::InvalidRequest(format!("Invalid DID document URL: {e}")))?;
        let host = parsed_url.host_str().ok_or_else(|| {
            CircleError::InvalidRequest("Missing host in DID document URL".into())
        })?;
        let port = parsed_url.port_or_known_default().unwrap_or(443);

        // Resolve DNS and reject any private, loopback, or link-local address
        let addr_str = format!("{host}:{port}");
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&addr_str)
            .await
            .map_err(|e| CircleError::InvalidRequest(format!("DNS resolution failed for {host}: {e}")))?
            .collect();

        if addrs.is_empty() {
            return Err(CircleError::InvalidRequest(format!(
                "DNS resolution returned no addresses for {host}"
            )));
        }

        for addr in &addrs {
            #[cfg(debug_assertions)]
            if addr.ip().is_loopback() {
                continue;
            }
            if crate::services::ssrf::is_private_ip(&addr.ip()) {
                return Err(CircleError::InvalidRequest(format!(
                    "Host '{host}' resolved to restricted IP address: {}",
                    addr.ip()
                )));
            }
        }

        // Pin the validated public resolution to reqwest to prevent DNS rebinding / TOCTOU
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .resolve_to_addrs(host, &addrs)
            .build()
            .map_err(|e| CircleError::Internal(e.to_string()))?;

        let resp = client
            .get(&did_doc_url)
            .send()
            .await
            .map_err(|e| CircleError::Pds(format!("Failed to fetch DID document: {}", e.without_url())))?;

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

        let expected_short_space = "#atproto_space_host";
        let expected_full_space = format!("{did}#atproto_space_host");
        let expected_short_pds = "#atproto_pds";
        let expected_full_pds = format!("{did}#atproto_pds");

        // 1. Try exact #atproto_space_host first (exact ID match only)
        for svc in services {
            let id = svc.get("id").and_then(|v| v.as_str()).unwrap_or_default();

            if id == expected_short_space || id == expected_full_space {
                return Ok(expected_full_space);
            }
        }

        // 2. Fallback to exact #atproto_pds (exact ID match only)
        for svc in services {
            let id = svc.get("id").and_then(|v| v.as_str()).unwrap_or_default();

            if id == expected_short_pds || id == expected_full_pds {
                return Ok(expected_full_pds);
            }
        }

        Err(CircleError::InvalidRequest(
            "No #atproto_space_host or #atproto_pds service found in authority DID document".into(),
        ))
    }
    /// Atomically claim an operation for execution: transitions 'intent' or 'failed' or expired 'executing' -> 'executing'.
    /// Resets attempts to 0, clears last_error_code, generates a fresh claim_token UUID, and sets execution_started_at to now().
    pub async fn claim_projection(&self, id: Uuid, session_id: &str) -> Result<Option<Uuid>, CircleError> {
        if let Some(pool) = &self.db {
            let claim_token = Uuid::new_v4();
            let res = sqlx::query(
                r#"
                UPDATE circle_projection_outbox
                SET state = 'executing',
                    session_id = $2,
                    claim_token = $3,
                    attempts = 0,
                    last_error_code = NULL,
                    execution_started_at = now(),
                    updated_at = now()
                WHERE id = $1 AND (
                    state = 'intent'
                    OR state = 'failed'
                    OR (state = 'executing' AND (execution_started_at IS NULL OR execution_started_at < now() - interval '30 seconds'))
                )
                "#,
            )
            .bind(id)
            .bind(session_id)
            .bind(claim_token)
            .execute(pool)
            .await?;

            if res.rows_affected() > 0 {
                Ok(Some(claim_token))
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(Uuid::new_v4()))
        }
    }

    /// Rebind actor's non-terminal projection outbox records to the latest session ID.
    /// Does not modify execution lease or updated_at timestamps.
    pub async fn rebind_actor_sessions(&self, actor_did: &str, session_id: &str) -> Result<(), CircleError> {
        if let Some(pool) = &self.db {
            sqlx::query(
                r#"
                UPDATE circle_projection_outbox
                SET session_id = $1
                WHERE actor_did = $2
                  AND state IN ('pending', 'intent', 'executing')
                  AND session_id != $1
                "#,
            )
            .bind(session_id)
            .bind(actor_did)
            .execute(pool)
            .await?;
        }
        Ok(())
    }

    /// Update projection state in outbox with conditional transitions.
    /// Never downgrades `pending` or `delivered` to `failed` or `intent`.
    /// If a claim_token is provided, requires matching claim token (or NULL) on executing records to prevent stale completions.
    pub async fn set_projection_state(
        &self,
        id: Uuid,
        state: CircleProjectionState,
        error_code: Option<&str>,
        claim_token: Option<Uuid>,
    ) -> Result<bool, CircleError> {
        if let Some(pool) = &self.db {
            let rows_affected = match (state, claim_token) {
                (CircleProjectionState::Failed, Some(token)) => {
                    sqlx::query(
                        r#"
                        UPDATE circle_projection_outbox
                        SET state = 'failed',
                            claim_token = NULL,
                            last_error_code = $2,
                            updated_at = now()
                        WHERE id = $1 AND state IN ('intent', 'executing') AND (claim_token = $3 OR claim_token IS NULL)
                        "#,
                    )
                    .bind(id)
                    .bind(error_code)
                    .bind(token)
                    .execute(pool)
                    .await?
                    .rows_affected()
                }
                (CircleProjectionState::Failed, None) => {
                    sqlx::query(
                        r#"
                        UPDATE circle_projection_outbox
                        SET state = 'failed',
                            claim_token = NULL,
                            last_error_code = $2,
                            updated_at = now()
                        WHERE id = $1 AND state IN ('intent', 'executing')
                        "#,
                    )
                    .bind(id)
                    .bind(error_code)
                    .execute(pool)
                    .await?
                    .rows_affected()
                }
                (CircleProjectionState::Pending, Some(token)) => {
                    sqlx::query(
                        r#"
                        UPDATE circle_projection_outbox
                        SET state = 'pending',
                            claim_token = NULL,
                            last_error_code = NULL,
                            updated_at = now()
                        WHERE id = $1 AND state IN ('intent', 'executing') AND (claim_token = $2 OR claim_token IS NULL)
                        "#,
                    )
                    .bind(id)
                    .bind(token)
                    .execute(pool)
                    .await?
                    .rows_affected()
                }
                (CircleProjectionState::Pending, None) => {
                    sqlx::query(
                        r#"
                        UPDATE circle_projection_outbox
                        SET state = 'pending',
                            claim_token = NULL,
                            last_error_code = NULL,
                            updated_at = now()
                        WHERE id = $1 AND state IN ('intent', 'executing')
                        "#,
                    )
                    .bind(id)
                    .execute(pool)
                    .await?
                    .rows_affected()
                }
                (CircleProjectionState::Delivered, _) => {
                    sqlx::query(
                        r#"
                        UPDATE circle_projection_outbox
                        SET state = 'delivered',
                            claim_token = NULL,
                            last_error_code = NULL,
                            updated_at = now()
                        WHERE id = $1 AND state IN ('intent', 'executing', 'pending')
                        "#,
                    )
                    .bind(id)
                    .execute(pool)
                    .await?
                    .rows_affected()
                }
                (CircleProjectionState::Executing, _) => {
                    sqlx::query(
                        r#"
                        UPDATE circle_projection_outbox
                        SET state = 'executing',
                            execution_started_at = now(),
                            updated_at = now()
                        WHERE id = $1 AND state IN ('intent', 'failed')
                        "#,
                    )
                    .bind(id)
                    .execute(pool)
                    .await?
                    .rows_affected()
                }
                (CircleProjectionState::Intent, _) => {
                    sqlx::query(
                        r#"
                        UPDATE circle_projection_outbox
                        SET state = 'intent',
                            updated_at = now()
                        WHERE id = $1 AND state = 'intent'
                        "#,
                    )
                    .bind(id)
                    .execute(pool)
                    .await?
                    .rows_affected()
                }
            };
            Ok(rows_affected > 0)
        } else {
            Ok(true)
        }
    }

    /// Enqueue a projection operation to `circle_projection_outbox`.
    /// Guarantees idempotency via unique `operation_key`.
    pub async fn enqueue_projection(
        &self,
        actor_did: &str,
        session_id: &str,
        space_uri: &str,
        kind: CircleProjectionKind,
        payload: serde_json::Value,
        state: CircleProjectionState,
    ) -> Result<Uuid, CircleError> {
        let op_key = calculate_operation_key(actor_did, space_uri, kind, &payload);
        let id = Uuid::new_v4();

        if let Some(pool) = &self.db {
            let row_id: (Uuid,) = sqlx::query_as(
                r#"
                INSERT INTO circle_projection_outbox (
                    id, operation_key, actor_did, session_id, space_uri, kind, payload, state, attempts, next_attempt_at, created_at, updated_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, 0, now(), now(), now()
                )
                ON CONFLICT (operation_key) DO UPDATE
                    SET session_id = EXCLUDED.session_id
                RETURNING id
                "#,
            )
            .bind(id)
            .bind(&op_key)
            .bind(actor_did)
            .bind(session_id)
            .bind(space_uri)
            .bind(kind.as_str())
            .bind(&payload)
            .bind(state.as_str())
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
            "SELECT id, operation_key, actor_did, session_id, space_uri, kind, payload, state, attempts, next_attempt_at, last_error_code, execution_started_at, claim_token, created_at, updated_at FROM circle_projection_outbox WHERE id = $1"
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
                let err_msg = err.to_string();
                let _ = sqlx::query(
                    "UPDATE circle_projection_outbox SET attempts = attempts + 1, next_attempt_at = now() + interval '1 second', last_error_code = $2, updated_at = now() WHERE id = $1"
                )
                .bind(id)
                .bind(&err_msg)
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

        // Reconcile stale intents or executing operations first
        let _ = self.reconcile_stale_projections(batch_size).await;

        let mut tx = pool.begin().await?;

        let rows: Vec<CircleProjectionOperation> = sqlx::query_as(
            "SELECT id, operation_key, actor_did, session_id, space_uri, kind, payload, state, attempts, next_attempt_at, last_error_code, execution_started_at, claim_token, created_at, updated_at FROM circle_projection_outbox WHERE state = 'pending' AND next_attempt_at <= now() ORDER BY next_attempt_at ASC LIMIT $1 FOR UPDATE SKIP LOCKED"
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
                Err(delivery_err) => {
                    let delay_secs = match op.attempts {
                        0 => 1,
                        1 => 2,
                        2 => 4,
                        3 => 8,
                        4 => 16,
                        _ => 30,
                    };
                    let is_auth_error = delivery_err.is_never_terminal_auth_error();
                    let next_state = if !is_auth_error && op.attempts + 1 >= 10 {
                        "failed"
                    } else {
                        "pending"
                    };
                    let err_msg = delivery_err.to_string();

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

    /// Reconciles stale intent and executing operations by verifying or replaying deterministic PDS desired state.
    /// Lists candidates without bulk lease, claims each individually before replay with a unique claim_token,
    /// and requires matching claim_token on completion.
    pub async fn reconcile_stale_projections(&self, batch_size: i64) -> Result<usize, CircleError> {
        let Some(pool) = &self.db else {
            return Ok(0);
        };

        // 1. List stale candidate rows without bulk lease
        let rows: Vec<CircleProjectionOperation> = sqlx::query_as(
            r#"
            SELECT id, operation_key, actor_did, session_id, space_uri, kind, payload, state, attempts, next_attempt_at, last_error_code, execution_started_at, claim_token, created_at, updated_at
            FROM circle_projection_outbox
            WHERE (state = 'intent' AND (created_at < now() - interval '30 seconds' OR updated_at < now() - interval '30 seconds'))
               OR (state = 'executing' AND (execution_started_at IS NULL OR execution_started_at < now() - interval '30 seconds'))
            ORDER BY created_at ASC
            LIMIT $1
            "#,
        )
        .bind(batch_size)
        .fetch_all(pool)
        .await?;

        if rows.is_empty() {
            return Ok(0);
        }

        let mut reconciled_count = 0;
        for op in rows {
            let session = match self.resolve_session_for_op(&op).await {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Claim each candidate immediately before replay with UUID claim token
            let claim_token = match self.claim_projection(op.id, &session.id.to_string()).await? {
                Some(token) => token,
                None => continue,
            };

            let atproto = AtProtoClient::new(self.state.clone());
            let dpop_data = self.resolve_dpop_data(&session).await;

            match op.kind {
                CircleProjectionKind::CircleUpsert => {
                    let query = format!(
                        "space={}&repo={}&collection=blue.catbird.circle.metadata&rkey=self",
                        urlencoding::encode(&op.space_uri),
                        urlencoding::encode(&op.actor_did)
                    );
                    let resp = atproto.proxy_request(
                        &session,
                        reqwest::Method::GET,
                        "/xrpc/com.atproto.space.getRecord",
                        Some(&query),
                        None,
                        None,
                        None,
                        "reconcile-check-metadata",
                        Some(&dpop_data),
                    ).await;

                    let metadata_exists = match resp {
                        Ok(r) => {
                            let (status, _) = self.extract_response_body(r).await.unwrap_or((500, Bytes::new()));
                            (200..300).contains(&status)
                        }
                        Err(_) => false,
                    };

                    if metadata_exists {
                        if self.set_projection_state(op.id, CircleProjectionState::Pending, None, Some(claim_token)).await? {
                            reconciled_count += 1;
                        }
                        continue;
                    }

                    let skey = op.space_uri.rsplit('/').next().unwrap_or("circle");
                    let client_id = self.state.config.oauth.client_id.clone();
                    let create_space_payload = serde_json::json!({
                        "type": "blue.catbird.circle",
                        "skey": skey,
                        "policy": {
                            "$type": "com.atproto.simplespace.defs#memberListPolicy"
                        },
                        "appAccess": {
                            "$type": "com.atproto.simplespace.defs#allowList",
                            "allowed": [client_id]
                        }
                    });

                    if let Ok(create_bytes) = serde_json::to_vec(&create_space_payload) {
                        let create_resp = atproto.proxy_request(
                            &session,
                            reqwest::Method::POST,
                            "/xrpc/com.atproto.simplespace.createSpace",
                            None,
                            Some(Bytes::from(create_bytes)),
                            Some("application/json"),
                            None,
                            "reconcile-create-space",
                            Some(&dpop_data),
                        ).await;

                        let space_created = match create_resp {
                            Ok(r) => {
                                let (status, body) = self.extract_response_body(r).await.unwrap_or((500, Bytes::new()));
                                if (200..300).contains(&status) {
                                    true
                                } else {
                                    let err_text = String::from_utf8_lossy(&body);
                                    if err_text.to_lowercase().contains("already exists") || status == 409 {
                                        true
                                    } else if is_retryable_status(status) {
                                        self.record_indeterminate_transport_error(
                                            op.id,
                                            &format!("Reconciliation createSpace server/retryable error ({status}): {err_text}"),
                                            Some(claim_token),
                                        ).await;
                                        false
                                    } else {
                                        let _ = self.set_projection_state(
                                            op.id,
                                            CircleProjectionState::Failed,
                                            Some(&format!("Reconciliation createSpace error ({status}): {err_text}")),
                                            Some(claim_token),
                                        ).await;
                                        false
                                    }
                                }
                            }
                            Err(e) => {
                                self.record_indeterminate_transport_error(
                                    op.id,
                                    &format!("Reconciliation createSpace network error: {e}"),
                                    Some(claim_token),
                                ).await;
                                false
                            }
                        };

                        if space_created {
                            let circle_name = op.payload.get("name").and_then(|v| v.as_str()).unwrap_or("Circle");
                            let now_str = Utc::now().to_rfc3339();
                            let put_record_body = serde_json::json!({
                                "space": &op.space_uri,
                                "repo": session.did,
                                "collection": "blue.catbird.circle.metadata",
                                "rkey": "self",
                                "record": {
                                    "$type": "blue.catbird.circle.metadata",
                                    "name": circle_name,
                                    "createdAt": now_str
                                }
                            });
                            if let Ok(put_bytes) = serde_json::to_vec(&put_record_body) {
                                let put_resp = atproto.proxy_request(
                                    &session,
                                    reqwest::Method::POST,
                                    "/xrpc/com.atproto.space.putRecord",
                                    None,
                                    Some(Bytes::from(put_bytes)),
                                    Some("application/json"),
                                    None,
                                    "reconcile-create-metadata",
                                    Some(&dpop_data),
                                ).await;

                                match put_resp {
                                    Ok(r) => {
                                        let (status, body) = self.extract_response_body(r).await.unwrap_or((500, Bytes::new()));
                                        if (200..300).contains(&status) {
                                            if self.set_projection_state(op.id, CircleProjectionState::Pending, None, Some(claim_token)).await? {
                                                reconciled_count += 1;
                                            }
                                        } else if is_retryable_status(status) {
                                            let err_text = String::from_utf8_lossy(&body);
                                            self.record_indeterminate_transport_error(
                                                op.id,
                                                &format!("Reconciliation putRecord server/retryable error ({status}): {err_text}"),
                                                Some(claim_token),
                                            ).await;
                                        } else {
                                            let err_text = String::from_utf8_lossy(&body);
                                            let _ = self.set_projection_state(
                                                op.id,
                                                CircleProjectionState::Failed,
                                                Some(&format!("Reconciliation putRecord error ({status}): {err_text}")),
                                                Some(claim_token),
                                            ).await;
                                        }
                                    }
                                    Err(e) => {
                                        self.record_indeterminate_transport_error(
                                            op.id,
                                            &format!("Reconciliation putRecord network error: {e}"),
                                            Some(claim_token),
                                        ).await;
                                    }
                                }
                            }
                        }
                    }
                }
                CircleProjectionKind::MemberAdd => {
                    let member_did = op.payload.get("member").and_then(|v| v.as_str()).unwrap_or_default();
                    let add_body = serde_json::json!({
                        "space": &op.space_uri,
                        "did": member_did
                    });
                    if let Ok(bytes) = serde_json::to_vec(&add_body) {
                        let add_resp = atproto.proxy_request(
                            &session,
                            reqwest::Method::POST,
                            "/xrpc/com.atproto.simplespace.addMember",
                            None,
                            Some(Bytes::from(bytes)),
                            Some("application/json"),
                            None,
                            "reconcile-add-member",
                            Some(&dpop_data),
                        ).await;
                        match add_resp {
                            Ok(r) => {
                                let (status, body) = self.extract_response_body(r).await.unwrap_or((500, Bytes::new()));
                                let body_text = String::from_utf8_lossy(&body);
                                if (200..300).contains(&status) || body_text.to_lowercase().contains("already") || status == 409 {
                                    if self.set_projection_state(op.id, CircleProjectionState::Pending, None, Some(claim_token)).await? {
                                        reconciled_count += 1;
                                    }
                                } else if is_retryable_status(status) {
                                    self.record_indeterminate_transport_error(
                                        op.id,
                                        &format!("Reconciliation addMember server/retryable error ({status}): {body_text}"),
                                        Some(claim_token),
                                    ).await;
                                } else {
                                    let _ = self.set_projection_state(
                                        op.id,
                                        CircleProjectionState::Failed,
                                        Some(&format!("Reconciliation addMember error ({status}): {body_text}")),
                                        Some(claim_token),
                                    ).await;
                                }
                            }
                            Err(e) => {
                                self.record_indeterminate_transport_error(
                                    op.id,
                                    &format!("Reconciliation addMember network error: {e}"),
                                    Some(claim_token),
                                ).await;
                            }
                        }
                    }
                }
                CircleProjectionKind::MemberRemove => {
                    let member_did = op.payload.get("member").and_then(|v| v.as_str()).unwrap_or_default();
                    let remove_body = serde_json::json!({
                        "space": &op.space_uri,
                        "did": member_did
                    });
                    if let Ok(bytes) = serde_json::to_vec(&remove_body) {
                        let remove_resp = atproto.proxy_request(
                            &session,
                            reqwest::Method::POST,
                            "/xrpc/com.atproto.simplespace.removeMember",
                            None,
                            Some(Bytes::from(bytes)),
                            Some("application/json"),
                            None,
                            "reconcile-remove-member",
                            Some(&dpop_data),
                        ).await;
                        match remove_resp {
                            Ok(r) => {
                                let (status, body) = self.extract_response_body(r).await.unwrap_or((500, Bytes::new()));
                                let body_text = String::from_utf8_lossy(&body);
                                if (200..300).contains(&status) || status == 404 || body_text.to_lowercase().contains("not found") || body_text.to_lowercase().contains("not a member") {
                                    if self.set_projection_state(op.id, CircleProjectionState::Pending, None, Some(claim_token)).await? {
                                        reconciled_count += 1;
                                    }
                                } else if is_retryable_status(status) {
                                    self.record_indeterminate_transport_error(
                                        op.id,
                                        &format!("Reconciliation removeMember server/retryable error ({status}): {body_text}"),
                                        Some(claim_token),
                                    ).await;
                                } else {
                                    let _ = self.set_projection_state(
                                        op.id,
                                        CircleProjectionState::Failed,
                                        Some(&format!("Reconciliation removeMember error ({status}): {body_text}")),
                                        Some(claim_token),
                                    ).await;
                                }
                            }
                            Err(e) => {
                                self.record_indeterminate_transport_error(
                                    op.id,
                                    &format!("Reconciliation removeMember network error: {e}"),
                                    Some(claim_token),
                                ).await;
                            }
                        }
                    }
                }
                CircleProjectionKind::CircleDelete => {
                    let delete_body = serde_json::json!({
                        "space": &op.space_uri
                    });
                    if let Ok(bytes) = serde_json::to_vec(&delete_body) {
                        let del_resp = atproto.proxy_request(
                            &session,
                            reqwest::Method::POST,
                            "/xrpc/com.atproto.simplespace.deleteSpace",
                            None,
                            Some(Bytes::from(bytes)),
                            Some("application/json"),
                            None,
                            "reconcile-delete-space",
                            Some(&dpop_data),
                        ).await;
                        match del_resp {
                            Ok(r) => {
                                let (status, body) = self.extract_response_body(r).await.unwrap_or((500, Bytes::new()));
                                let body_text = String::from_utf8_lossy(&body);
                                if (200..300).contains(&status) || status == 404 || body_text.to_lowercase().contains("not found") {
                                    if self.set_projection_state(op.id, CircleProjectionState::Pending, None, Some(claim_token)).await? {
                                        reconciled_count += 1;
                                    }
                                } else if is_retryable_status(status) {
                                    self.record_indeterminate_transport_error(
                                        op.id,
                                        &format!("Reconciliation deleteSpace server/retryable error ({status}): {body_text}"),
                                        Some(claim_token),
                                    ).await;
                                } else {
                                    let _ = self.set_projection_state(
                                        op.id,
                                        CircleProjectionState::Failed,
                                        Some(&format!("Reconciliation deleteSpace error ({status}): {body_text}")),
                                        Some(claim_token),
                                    ).await;
                                }
                            }
                            Err(e) => {
                                self.record_indeterminate_transport_error(
                                    op.id,
                                    &format!("Reconciliation deleteSpace network error: {e}"),
                                    Some(claim_token),
                                ).await;
                            }
                        }
                    }
                }
            }
        }

        Ok(reconciled_count)
    }

    /// Spawns a background task for processing due projections and monitors liveness.
    pub fn spawn_retry_worker(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let worker_alive = self.state.circle_worker_alive.clone();
        tokio::spawn(async move {
            struct WorkerGuard(Arc<std::sync::atomic::AtomicBool>);
            impl Drop for WorkerGuard {
                fn drop(&mut self) {
                    self.0.store(false, std::sync::atomic::Ordering::SeqCst);
                }
            }
            worker_alive.store(true, std::sync::atomic::Ordering::SeqCst);
            let _guard = WorkerGuard(worker_alive.clone());

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        worker_alive.store(true, std::sync::atomic::Ordering::SeqCst);
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
    ) -> Result<(), ProjectionDeliveryError> {
        let Some(service_url) = &self.state.config.circle.service_url else {
            return Err(ProjectionDeliveryError::NotConfigured);
        };

        let appview_base = service_url.trim_end_matches('/');
        let projection_url = format!("{appview_base}/internal/projections");

        let token = if let Some(session) = session_override {
            self.get_service_auth_token(session, "blue.catbird.circle.syncProjection")
                .await?
        } else {
            let session = self
                .resolve_session_for_op(op)
                .await
                .map_err(ProjectionDeliveryError::SessionUnavailable)?;
            self.get_service_auth_token(&session, "blue.catbird.circle.syncProjection")
                .await?
        };

        let body = serde_json::json!({
            "operationId": op.id,
            "operationKey": op.operation_key,
            "actorDid": op.actor_did,
            "spaceUri": op.space_uri,
            "kind": op.kind.as_str(),
            "payload": op.payload
        });

        let appview_aud = &self.state.config.circle.service_did;
        let attestation = if let Some(provider) = &self.attestation_provider {
            provider
                .mint(appview_aud)
                .map_err(|e| ProjectionDeliveryError::ClientAttestation(e.to_string()))?
        } else {
            return Err(ProjectionDeliveryError::MissingAttestationProvider);
        };

        let req = self
            .state
            .http_client
            .post(&projection_url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(CONTENT_TYPE, "application/json")
            .header("X-Nest-Client-Attestation", attestation);
        let resp = req
            .json(&body)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| ProjectionDeliveryError::Http(e.without_url().to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            Err(ProjectionDeliveryError::AppView {
                status,
                message: text,
            })
        }
    }

    async fn resolve_session_for_op(
        &self,
        op: &CircleProjectionOperation,
    ) -> Result<CatbirdSession, String> {
        use jacquard_common::types::did::Did;

        let _auth_store = self
            .state
            .auth_store
            .as_ref()
            .ok_or_else(|| "Auth store not configured".to_string())?;

        let jacquard_client = self
            .state
            .jacquard_client
            .as_ref()
            .or_else(|| self.state.catmos_jacquard_client.as_ref())
            .ok_or_else(|| "Jacquard client not configured".to_string())?;

        let did = Did::new(&op.actor_did)
            .map_err(|e| format!("Invalid actor DID: {e}"))?;

        let session_data = jacquard_client
            .registry
            .get(&did, &op.session_id, true)
            .await
            .map_err(|e| format!("Jacquard session recovery failed: {e}"))?;

        let expires_at = session_data
            .token_set
            .expires_at
            .as_ref()
            .and_then(|dt| chrono::DateTime::parse_from_rfc3339(dt.as_str()).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(3600));

        let session = CatbirdSession {
            id: uuid::Uuid::parse_str(&op.session_id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
            did: op.actor_did.clone(),
            handle: op.actor_did.clone(),
            pds_url: session_data.host_url.to_string(),
            access_token: session_data.token_set.access_token.to_string(),
            refresh_token: session_data
                .token_set
                .refresh_token
                .as_ref()
                .map(|t| t.to_string())
                .unwrap_or_default(),
            scopes: session_data.scopes.iter().map(|s| s.to_string()).collect(),
            access_token_expires_at: expires_at,
            created_at: Utc::now(),
            last_used_at: Utc::now(),
        };

        Ok(session)
    }

    async fn get_service_auth_token(
        &self,
        session: &CatbirdSession,
        lexicon: &str,
    ) -> Result<String, CircleError> {
        let result = if let Some(provider) = &self.service_auth_provider {
            provider
                .token_for_audience(session, &self.state.config.circle.service_did, lexicon)
                .await
        } else {
            let provider = ServiceAuthProvider::new(self.state.clone());
            provider
                .token_for_audience(session, &self.state.config.circle.service_did, lexicon)
                .await
        };

        result.map_err(|e| match e {
            crate::error::AppError::AtprotoResponse { status: _, error, message } => {
                match error.as_str() {
                    "AuthRequired" => CircleError::NotAuthorized(message),
                    "AccessRemoved" => CircleError::AccessRemoved(message),
                    "InvalidRequest" => CircleError::InvalidRequest(message),
                    _ => CircleError::UpstreamUnavailable(message),
                }
            }
            crate::error::AppError::Upstream { message, .. } => CircleError::UpstreamUnavailable(message),
            crate::error::AppError::HttpClient(e) => CircleError::UpstreamUnavailable(e.to_string()),
            crate::error::AppError::Unauthorized(msg) => CircleError::NotAuthorized(msg),
            crate::error::AppError::BadRequest(msg) => CircleError::InvalidRequest(msg),
            other => CircleError::Internal(other.to_string()),
        })
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
