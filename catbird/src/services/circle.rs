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
    AccessState, MemberAction, Operation, OperationStatus, SpaceRef,
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

    /// Create a Circle:
    /// 1. Verifies caller has Circle owner scopes.
    /// 2. Calls `com.atproto.simplespace.createSpace` on the owner's PDS.
    /// 3. Writes `blue.catbird.circle.metadata/self` into the owner's permissioned repo.
    /// 4. Adds initial members through `com.atproto.simplespace.addMember`.
    /// 5. Enqueues idempotent outbox projections (`circle_upsert`, `member_add`).
    /// 6. Tries immediate AppView delivery and returns the Operation.
    pub async fn create_circle(
        &self,
        session: &CatbirdSession,
        input: CreateCircle,
    ) -> Result<Operation, CircleError> {
        require_circle_scopes(session)
            .map_err(|e| CircleError::NotAuthorized(e.to_string()))?;

        if input.name.trim().is_empty() {
            return Err(CircleError::InvalidRequest("Circle name cannot be empty".into()));
        }

        let atproto = AtProtoClient::new(self.state.clone());
        let dpop_data = self.resolve_dpop_data(session).await;

        // 1. Create Space at user's PDS
        let create_space_body = serde_json::json!({
            "type": "blue.catbird.circle",
            "policy": {
                "$type": "com.atproto.simplespace.defs#memberListPolicy"
            },
            "appAccess": {
                "$type": "com.atproto.simplespace.defs#open"
            }
        });
        let create_space_bytes = serde_json::to_vec(&create_space_body)
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

        // 2. Put metadata record at blue.catbird.circle.metadata/self
        let now_str = Utc::now().to_rfc3339();
        let put_record_body = serde_json::json!({
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
                "/xrpc/com.atproto.repo.putRecord",
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

        // 3. Add initial members to Space
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
                .await
                .map_err(|e| CircleError::Pds(e.to_string()))?;

            let (add_status, add_body) = self.extract_response_body(add_resp).await?;
            if add_status < 200 || add_status >= 300 {
                let err_text = String::from_utf8_lossy(&add_body);
                tracing::warn!(space = %space_uri, member = %member_did.as_ref(), "Failed to add initial member: {err_text}");
            }
        }

        // 4. Enqueue outbox projections
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

        for member_did in &input.member_dids {
            let member_payload = serde_json::json!({
                "space": &space_uri,
                "member": member_did.as_ref()
            });
            let _ = self
                .enqueue_projection(
                    &session.did,
                    &space_uri,
                    CircleProjectionKind::MemberAdd,
                    member_payload,
                )
                .await;
        }

        // Try immediate delivery
        let delivered = self.deliver_projection_by_id(upsert_op_id).await;

        Ok(Operation {
            id: upsert_op_id.to_string().into(),
            status: if delivered {
                OperationStatus::Complete
            } else {
                OperationStatus::Pending
            },
            space: Some(space_ref),
            error: None,
            extra_data: None,
        })
    }

    /// Update a Circle member (add or remove):
    /// 1. Verifies caller has Circle owner scopes.
    /// 2. Executes authoritative `com.atproto.simplespace.addMember` or `removeMember` at PDS.
    /// 3. Enqueues the corresponding projection into `circle_projection_outbox`.
    /// 4. Tries immediate AppView delivery and returns the Operation.
    pub async fn update_member(
        &self,
        session: &CatbirdSession,
        input: UpdateMember,
    ) -> Result<Operation, CircleError> {
        require_circle_scopes(session)
            .map_err(|e| CircleError::NotAuthorized(e.to_string()))?;

        let space_str = input.space.as_str();
        let member_str = input.member_did.as_str();

        let atproto = AtProtoClient::new(self.state.clone());
        let dpop_data = self.resolve_dpop_data(session).await;

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
            return Err(CircleError::Pds(format!("PDS operation failed ({status}): {err_text}")));
        }

        // PDS succeeded! Enqueue durable projection in outbox
        let projection_payload = serde_json::json!({
            "space": space_str,
            "member": member_str
        });
        let op_id = self
            .enqueue_projection(&session.did, space_str, kind, projection_payload)
            .await?;

        // Attempt immediate delivery
        let delivered = self.deliver_projection_by_id(op_id).await;

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
    /// 1. Verifies caller has Circle owner scopes.
    /// 2. Executes authoritative `com.atproto.simplespace.deleteSpace` at PDS.
    /// 3. Enqueues `circle_delete` projection into `circle_projection_outbox`.
    /// 4. Tries immediate AppView delivery and returns the Operation.
    pub async fn delete_circle(
        &self,
        session: &CatbirdSession,
        input: DeleteCircle,
    ) -> Result<Operation, CircleError> {
        require_circle_scopes(session)
            .map_err(|e| CircleError::NotAuthorized(e.to_string()))?;

        let space_str = input.space.as_str();
        let atproto = AtProtoClient::new(self.state.clone());
        let dpop_data = self.resolve_dpop_data(session).await;

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
            return Err(CircleError::Pds(format!("deleteSpace failed ({status}): {err_text}")));
        }

        // PDS succeeded! Enqueue durable projection in outbox
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

        // Attempt immediate delivery
        let delivered = self.deliver_projection_by_id(op_id).await;

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
    /// 2. Obtains `com.atproto.space.getDelegationToken` from caller's PDS.
    /// 3. Resolves Space host audience and mints short-lived Catbird client attestation.
    /// 4. Passes both single-use tokens to Circle AppView; persists NEITHER token in database/logs.
    /// 5. Returns `ActivateSpaceOutput`.
    pub async fn activate_space(
        &self,
        session: &CatbirdSession,
        input: ActivateSpace,
    ) -> Result<ActivateSpaceOutput, CircleError> {
        require_circle_scopes(session)
            .map_err(|e| CircleError::NotAuthorized(e.to_string()))?;

        let space_str = input.space.as_str();
        let atproto = AtProtoClient::new(self.state.clone());
        let dpop_data = self.resolve_dpop_data(session).await;

        // 1. Fetch delegation token from user's PDS
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

        // 2. Mint client attestation for the Space host audience
        let authority_did = space_str
            .strip_prefix("at://")
            .and_then(|s| s.split('/').next())
            .unwrap_or("");
        let audience = if authority_did.contains('#') {
            authority_did.to_string()
        } else {
            format!("{authority_did}#atproto_space_host")
        };

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
        // 3. Forward to AppView activateSpace endpoint if AppView is configured
        if let Some(service_url) = &self.state.config.circle.service_url {
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
                return Ok(out);
            } else {
                let status = resp.status();
                let err_body = resp.text().await.unwrap_or_default();
                return Err(CircleError::AppView(format!("AppView activateSpace failed ({status}): {err_body}")));
            }
        }

        // Default active response when AppView is in-process or mock
        Ok(ActivateSpaceOutput {
            access_state: AccessState::Active,
            expires_at: Some(catbird_atproto::types::datetime::Datetime::now()),
            extra_data: None,
        })
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
            Ok(id)
        }
    }

    /// Attempts immediate delivery of a single projection by ID.
    pub async fn deliver_projection_by_id(&self, id: Uuid) -> bool {
        let Some(pool) = &self.db else {
            return true;
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

        match self.send_projection_to_appview(&op).await {
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
            match self.send_projection_to_appview(&op).await {
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

    async fn send_projection_to_appview(
        &self,
        op: &CircleProjectionOperation,
    ) -> Result<(), String> {
        let Some(service_url) = &self.state.config.circle.service_url else {
            // If no service URL configured (e.g. mock test), treat as delivered
            return Ok(());
        };

        let appview_base = service_url.trim_end_matches('/');
        let projection_url = format!("{appview_base}/internal/projections");

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
