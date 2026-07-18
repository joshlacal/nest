# nest - BFF Gateway

## Overview

Nest is a Rust-based Backend-for-Frontend (BFF) gateway for the Catbird iOS app. It acts as a **Confidential OAuth Client** for AT Protocol, managing authentication, DPoP signatures, and session storage server-side. Clients hold only an opaque Nest session identifier, transported in an HttpOnly cookie or as a Bearer token; Nest holds the ATProto tokens.

Petrel supports three auth modes. Nest enables the third:
1. **Legacy**: Direct password auth to PDS
2. **Public**: Direct OAuth to PDS
3. **Confidential**: Proxied OAuth via Nest (this project)

## Build & Run

```bash
# Build
cd nest/catbird && cargo build

# Run (requires .env or env vars)
cd nest/catbird && cargo run

# Test
cd nest/catbird && cargo test

# Format + lint
cd nest/catbird && cargo fmt && cargo clippy
```

## Environment Variables

For an OAuth-capable deployment, configure:
- `CATBIRD__SERVER__BASE_URL` - Nest's public URL
- `CATBIRD__REDIS__URL` - standalone Redis/Valkey connection string
- `CATBIRD__OAUTH__CLIENT_ID` - OAuth client ID
- `CATBIRD__OAUTH__REDIRECT_URI` - OAuth callback URL
- `CATBIRD__OAUTH__PRIVATE_KEY_PATH` or `CATBIRD__OAUTH__PRIVATE_KEY_BASE64` - ES256 client-signing key; Nest does not use a `CLIENT_SECRET`
- `SESSION_ENCRYPTION_KEY` - base64 encoding of exactly 32 random bytes
- `SESSION_IDENTIFIER_HMAC_KEY` - a distinct base64 encoding of exactly 32 random bytes

Optional rotation settings are `SESSION_ENCRYPTION_KEY_ID` and `SESSION_ENCRYPTION_PREVIOUS_KEYS`. Never commit any key value. `CATBIRD__SERVER__ALLOWED_ORIGINS` is a comma-separated list of exact canonical HTTP(S) origins; an empty list denies cross-origin browser access. `CATBIRD__SERVER__TRUSTED_PROXY_IPS` lists exact socket-peer IPs allowed to supply forwarding headers. Do not add end-user addresses to the trusted-proxy list.

## Architecture

```
Catbird iOS --[HttpOnly Cookie or Bearer Session ID]--> Nest Gateway --[DPoP + Access Token]--> User PDS
```

### Request Flow
1. iOS sends a request with the Nest session cookie or Bearer session ID
2. Nest validates the opaque session identifier against Redis
3. Nest retrieves/refreshes ATProto access token from Redis
4. Nest signs request with DPoP and forwards to PDS
5. Nest returns the upstream body unchanged through bounded buffering or streaming
6. Selected successful moderation mutations may also be mirrored into Nest's push state

### MLS proxy path (nest is NOT MLS-free)

MLS implementation and storage live in **mls-ds**, but Nest retains a conditional MLS proxy. When `mls.service_url` and `mls.gateway_did` are configured, MLS lexicons (`blue.catbird.mlsChat.*`) are intercepted in `handlers/atproto.rs` and routed through `MlsAuthService` (`services/mls_auth.rs`). Nest requires an authoritative local session/device binding and mints a short-lived, lexicon-scoped service JWT plus a DPoP proof using the configured gateway DID, service DID, and proof origin. The downstream MLS service remains responsible for validating those credentials and enforcing authorization; Nest's local checks are not a substitute. Without the direct-routing configuration, MLS lexicons follow the normal PDS proxy path.

### Source Structure

```
nest/catbird/src/
├── main.rs              # Entry point, Axum router setup
├── lib.rs               # Library exports
├── error.rs             # Error types
├── metrics.rs           # Prometheus metrics
├── config/              # Configuration loading
├── handlers/
│   ├── atproto.rs       # OAuth, session exchange, and XRPC proxy handlers
│   ├── exchange_store.rs # One-time browser exchange-code storage
│   └── mod.rs
├── middleware/
│   ├── auth.rs          # Session validation middleware
│   ├── rate_limit.rs    # Redis-shared limits with bounded local fallback
│   └── mod.rs
├── models/              # Request/response types
├── routes/              # Route definitions
└── services/
    ├── atproto_client.rs  # Upstream PDS client
    ├── crypto.rs          # DPoP key management
    ├── mls_auth.rs        # Conditional MLS delegated-auth proxy
    ├── outbound_policy.rs # Redirect-safe outbound request policy
    ├── redis_auth_store.rs # Encrypted Redis OAuth/session state
    └── ssrf.rs            # SSRF prevention
```

## Key Dependencies

- **axum** 0.7 - Web framework
- **jacquard-oauth / jacquard-common / jacquard-identity** - AT Protocol OAuth and identity
- **redis** 0.25 - Session storage
- **p256 / jose-jwk** - DPoP, JWK, and JWT signing primitives
- **sqlx** - Optional Postgres-backed push state and migrations
- **tower-http** - CORS, tracing, request IDs

## Auth Flow

1. **Login**: The client starts login with a browser nonce -> Nest generates PAR -> redirects to the PDS
2. **Callback**: The PDS redirects to Nest -> Nest performs the provider token exchange, creates the Redis-backed OAuth session, and redirects with a short-lived one-time exchange code
3. **Session exchange**: The client sends the code, original browser nonce, and exact browser Origin to `POST /auth/exchange` -> Nest atomically redeems the code, sets an HttpOnly cookie, and returns the opaque session ID
4. **Requests**: The cookie or Bearer session ID is validated -> the access token is retrieved/refreshed -> Nest sends a DPoP-signed request to the PDS

## Deployment

Nest runs as a systemd service (`catbird-nest-prod.service`) on port 3000, launched via `doppler run --project catbird-nest --config prd -- .../target/release/catbird`.

> **Note:** `catbird-nest-dev.service` is the **disabled legacy unit** (inactive/dead) — `dev-api.catbird.blue` was retired ~Apr 2026. `catbird-nest-prod` is the live deployment.

```bash
# Restart after deploy
sudo systemctl restart catbird-nest-prod

# Check status
sudo systemctl status catbird-nest-prod

# View logs
sudo journalctl -u catbird-nest-prod -f
```

Secrets are managed via Doppler — never hardcode credentials. The server is Linux x86_64; build release binaries on the server or cross-compile.

## Security Notes

- Clients never hold ATProto refresh tokens - only an opaque Nest session ID in an HttpOnly cookie or Bearer token
- Nest generates DPoP proofs for authenticated upstream requests
- SSRF prevention on upstream requests (`services/ssrf.rs`)
- Exact-origin CORS is deny-by-default; forwarding headers are trusted only from explicitly configured socket peers
- Redis-shared rate limiting with a bounded local fallback protects login, browser exchange, and authenticated XRPC routes
- Redis for session storage (not in-process memory)
- Direct MLS routing requires local device binding, but downstream JWT/DPoP validation and authorization remain the MLS service's responsibility
- Never commit secrets, tokens, or credentials to this repo
