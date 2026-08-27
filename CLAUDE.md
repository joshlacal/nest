# nest - BFF Gateway

## Overview

Nest is a Rust-based Backend-for-Frontend (BFF) gateway for the Catbird iOS app. It acts as a **Confidential OAuth Client** for AT Protocol, managing authentication, DPoP signatures, and session storage server-side. The iOS client only holds a session cookie - Nest holds the real tokens.

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

Required:
- `REDIS_URL` - Redis/Valkey connection string (session storage)
- `CLIENT_ID` / `CLIENT_SECRET` - OAuth confidential client credentials
- `REDIRECT_URI` - OAuth callback URL
- `BASE_URL` - Nest's public URL

## Architecture

```
Catbird iOS --[Session Cookie]--> Nest Gateway --[DPoP + Access Token]--> User PDS
```

### Request Flow
1. iOS sends request with session cookie
2. Nest validates cookie against Redis
3. Nest retrieves/refreshes ATProto access token from Redis
4. Nest signs request with DPoP and forwards to PDS
5. Nest optionally enriches response (content injection)
6. Returns modified JSON to iOS

### MLS proxy path (nest is NOT MLS-free)

MLS implementation and storage live in **mls-ds**, but nest retains an **active MLS proxy**. MLS lexicons (`blue.catbird.mlsChat.*`) are intercepted in `handlers/atproto.rs` and routed through `MlsAuthService` (`services/mls_auth.rs`) to local mls-ds at `http://127.0.0.1:3001`, with a minted service-auth JWT (`aud=did:web:chat.catbird.blue`, `gateway_did=did:web:api.catbird.blue`). Do not assume "MLS moved to mls-ds" means nest no longer touches MLS — it is on the hot request path.

### Push notifications (nest owns ALL push — social + chat)

Since July 2026, nest is the single push-notification owner for Catbird
(`bluesky-push-notifier` is **deprecated**). Two pieces:

- **`services/push/`** — APNS delivery pipeline: `apns.rs` (sender),
  `decision.rs` (should-notify logic — use staleness guards, not
  notification-type exclusion), `preferences.rs`, `queue.rs`,
  `registry.rs` (device tokens), `subscriptions.rs` (activity
  subscriptions), `moderation_verdict.rs`, `thread_mutes.rs`.
  Moderation is resolved per actor from `app.bsky.actor.defs#viewerState` via
  one authenticated `getProfile`, cached briefly in `actor_moderation_verdict`.
  Nest does **not** mirror mutes, blocks or moderation-list membership — doing
  so put unbounded list pagination inside the decision path and wedged the
  worker. See ADR-022.
- **`services/chat_poll/`** — polls `chat.bsky.convo.getLog` for enrolled
  accounts and enqueues chat push (`poller.rs`, `scheduler.rs`,
  `rate_budget.rs` per-PDS budgets, `mute_sync.rs`). Dormant in prod as of
  Jul 2026 (Bsky chat parity program).

Client-facing endpoints in `handlers/push.rs`: `register_push`,
`unregister_push`, `get_preferences`, `put_preferences_v2`,
`list_activity_subscriptions`, `put_activity_subscription`.


### Circles (nest holds NO Circle role)

Nest holds **zero Circle role**. Nest does not create Circles, track membership, hold Circle projections/leases/outbox, mint client attestations for the AppView, or bridge push notifications. The Circle AppView (`nest/circle-appview`) is a standalone service with its own OAuth confidential client identity. Nest is solely a confidential OAuth gateway and generic `/*lexicon` proxy; its only relevance to Circles is that the generic proxy forwards client-supplied `atproto-proxy` headers upstream to route requests to the standalone Circle AppView (`did:web:circles.catbird.blue#atproto_circles`).
### Source Structure

```
nest/catbird/src/
├── main.rs              # Entry point, Axum router setup
├── lib.rs               # Library exports
├── error.rs             # Error types
├── metrics.rs           # Prometheus metrics
├── config/              # Configuration loading
├── bin/
│   └── session_migrate.rs # One-off session-store migration tool
├── handlers/
│   ├── atproto.rs       # XRPC proxy handler
│   ├── push.rs          # Push registration + preferences endpoints
│   ├── chat_poll.rs     # Chat-poll enrollment endpoints
│   └── mod.rs
├── middleware/
│   ├── auth.rs          # Session validation middleware
│   ├── rate_limit.rs    # Rate limiting (tower_governor)
│   └── mod.rs
├── models/              # Request/response types
├── routes/              # Route definitions
└── services/
    ├── atproto_client.rs  # Upstream PDS client
    ├── crypto.rs          # DPoP key management
    ├── mls_auth.rs        # MLS proxy: mints service-auth JWT, forwards MLS lexicons to mls-ds (live hot path)
    ├── oauth.rs           # OAuth flow (PAR, token exchange)
    ├── push/              # APNS push pipeline (see Push notifications above)
    ├── chat_poll/         # chat.bsky poller (see Push notifications above)
    ├── redis_auth_store.rs # Session/auth persistence in Redis/Valkey
    ├── redis_crypto.rs    # Encryption for Redis-stored secrets
    └── ssrf.rs            # SSRF prevention
```

## Key Dependencies

- **axum** 0.7 - Web framework
- **atrium-api / atrium-oauth** - AT Protocol SDK (git dependency)
- **redis** 0.25 - Session storage
- **p256 / jsonwebtoken** - DPoP and JWT signing
- **tower-http** - CORS, tracing, request IDs
- **tower_governor** - Rate limiting

## Auth Flow

1. **Login**: iOS requests login URL -> Nest generates PAR -> redirects to PDS
2. **Callback**: PDS redirects to Nest -> token exchange (Private Key JWT) -> creates Redis session -> redirects to iOS with session cookie
3. **Requests**: Cookie validated -> access token retrieved from Redis -> refreshed if expired -> DPoP-signed request to PDS

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

- iOS client never holds refresh tokens - only session cookies
- DPoP handled entirely by Nest
- SSRF prevention on upstream requests (`services/ssrf.rs`)
- Rate limiting on all endpoints
- Redis for session storage (not in-process memory)
- Never commit secrets, tokens, or credentials to this repo
