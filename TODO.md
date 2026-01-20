# Nest Implementation Checklist

## Phase 1: Foundation & Setup
- [ ] **Project Structure:** Ensure `axum`, `tokio`, `tracing`, `config` are set up in `main.rs`.
- [ ] **Redis Connection:** Implement `services/cache.rs` to handle Redis connections and basic Get/Set/Expire operations.
- [ ] **Config:** Load `CLIENT_ID`, `CLIENT_SECRET` (Private Key), `REDIS_URL`, `PUBLIC_URL` from environment variables.
- [ ] **Logging:** Setup `tracing-subscriber` for structured JSON logging.

## Phase 2: AT Protocol & OAuth (Confidential Client)
- [ ] **Metadata Endpoint:** Serve `client-metadata.json` and `jwks.json` at `/.well-known/oauth-client-metadata`.
- [ ] **Key Management:** Implement `services/crypto.rs` to load/generate ES256 keys for DPoP and Client Assertions.
- [ ] **OAuth Client:** Use `atrium-oauth` to configure a **Confidential Client**.
- [ ] **Login Route:** `GET /auth/login` -> Initiates PAR -> Redirects to PDS.
- [ ] **Callback Route:** `GET /auth/callback` -> Exchanges Code -> Stores in Redis -> Sets **HttpOnly Cookie** -> Redirects to App Scheme.
- [ ] **Logout Route:** `POST /auth/logout` -> Revokes Token at PDS -> Deletes Redis Key -> Clears Cookie.

## Phase 3: The Proxy Middleware
- [ ] **Auth Middleware:**
    - [ ] Intercept request.
    - [ ] Validate `Catbird-Session-ID` cookie.
    - [ ] Retrieve ATProto tokens from Redis.
    - [ ] Check Access Token expiry.
    - [ ] **Token Refresh (if needed):** Perform refresh flow, update Redis.
    - [ ] Inject `Authorization: DPoP ...` header.
- [ ] **Proxy Handler:**
    - [ ] Wildcard route `/*path`.
    - [ ] Forward request to `session.pds_url` + `path`.
    - [ ] Stream response back.

## Phase 4: Enrichment Engine
- [ ] **JSON Interceptor:** Create middleware to buffer response body and parse as `serde_json::Value`.
- [ ] **Enrichment Logic:**
    - [ ] Recursive walker to find objects with `$type` = `app.bsky.feed.defs#blockedPost`.
    - [ ] Inject `catbirdContext` or modify fields.
- [ ] **Optimization:** Ensure this only runs on specific routes (e.g., `getPostThread`).

## Phase 5: Production Readiness
- [ ] **Health Checks:** `/health` endpoint.
- [ ] **Metrics:** Prometheus metrics.
- [ ] **Docker:** `Dockerfile` for deployment.