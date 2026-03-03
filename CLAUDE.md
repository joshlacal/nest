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

### Source Structure

```
nest/catbird/src/
├── main.rs              # Entry point, Axum router setup
├── lib.rs               # Library exports
├── error.rs             # Error types
├── metrics.rs           # Prometheus metrics
├── config/              # Configuration loading
├── handlers/
│   ├── atproto.rs       # XRPC proxy handler
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
    ├── mls_auth.rs        # MLS authentication helpers
    ├── oauth.rs           # OAuth flow (PAR, token exchange)
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

## Security Notes

- iOS client never holds refresh tokens - only session cookies
- DPoP handled entirely by Nest
- SSRF prevention on upstream requests (`services/ssrf.rs`)
- Rate limiting on all endpoints
- Redis for session storage (not in-process memory)
