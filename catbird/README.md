# Catbird Nest Gateway

**Catbird Nest** is a Backend-for-Frontend (BFF) gateway for the AT Protocol (Bluesky). It acts as a **Confidential OAuth Client**, handling all authentication complexity so that mobile apps can remain simple "dumb" clients.

## Why a BFF Gateway?

Mobile apps (iOS/Android) are "public clients" and cannot securely store secrets. ATProto OAuth requires:
- **DPoP (Demonstration of Proof-of-Possession)** - cryptographic proof for every request
- **Client Assertions** - JWT-based client authentication
- **Token Rotation** - automatic refresh token management

By moving this complexity to a server-side gateway, the mobile app only needs to:
1. Hold an opaque Nest session ID in an HttpOnly cookie or Bearer token
2. Make requests to the Catbird gateway
3. Let the gateway handle all ATProto authentication

## Architecture

```
┌─────────────┐  Cookie or Bearer ID   ┌─────────────────┐     ATProto OAuth     ┌─────────────┐
│  iOS App    │ ────────────────────▶  │  Catbird Nest   │ ──────────────────▶   │    PDS      │
│  (Catbird)  │                        │    Gateway      │                       │ (bsky.social│
└─────────────┘                        └─────────────────┘                       └─────────────┘
                                              │
                                              ▼
                                       ┌─────────────┐
                                       │    Redis    │
                                       │  (Sessions) │
                                       └─────────────┘
```

### Request Flow

1. **Client Request**: App sends an HttpOnly session cookie or Bearer session ID
2. **Session Lookup**: Gateway validates the opaque session identifier in Redis
3. **Token Refresh**: If ATProto token expired, automatically refresh it
4. **Proxy Request**: Forward to the user's PDS with DPoP-bound access-token authentication
5. **Response**: Return the upstream body unchanged through bounded buffering or streaming; selected successful moderation mutations may also be mirrored into push state

## Features

- **Confidential OAuth Client**: Secure server-side OAuth with client assertions
- **DPoP Support**: Automatic DPoP proof generation for authenticated proxied PDS requests
- **Token Management**: Automatic access token refresh using refresh tokens
- **Session Management**: Encrypted Redis-backed sessions with configurable TTL and opaque identifiers
- **Rate Limiting**: Redis-shared limits with a bounded local fallback for login, browser exchange, and authenticated XRPC routes
- **Network Boundaries**: Exact-origin, deny-by-default browser CORS and explicit socket-peer trust for forwarding headers
- **Health Checks**: Health, Redis-backed readiness, and process-liveness endpoints

## Tech Stack

- **Framework**: [Axum](https://github.com/tokio-rs/axum) - Fast, ergonomic web framework
- **HTTP Client**: [Reqwest](https://github.com/seanmonstar/reqwest) - Robust HTTP client
- **AT Protocol**: Jacquard (`jacquard-oauth`, `jacquard-common`, `jacquard-identity`)
- **Session Store**: [Redis](https://redis.io/) - In-memory data store
- **Crypto**: [p256](https://github.com/RustCrypto/elliptic-curves) - ECDSA signatures for OAuth
- **Serialization**: [Serde](https://serde.rs/) - JSON handling with surgical precision

## Getting Started

### Prerequisites

- Rust 1.75+
- Standalone Redis or Valkey 7.0+ (Redis Cluster is intentionally unsupported)
- An ES256 key pair for OAuth client authentication
- Distinct session-encryption and identifier-HMAC secrets, each encoded from exactly 32 random bytes and supplied outside source control

### Installation

1. Clone and build:
   ```bash
   cd catbird
   cargo build --release
   ```

2. Configure environment:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. Start Redis:
   ```bash
   redis-server
   ```

4. Run the gateway:
   ```bash
   cargo run
   ```

### Configuration

Configuration can be provided via:
- Environment variables (prefix: `CATBIRD__`)
- Config files (`config/default.toml`, `config/local.toml`)

Key settings:

| Variable | Description | Default |
|----------|-------------|---------|
| `CATBIRD__SERVER__PORT` | Server port | 3000 |
| `CATBIRD__SERVER__BASE_URL` | Public URL of this gateway | http://localhost:3000 |
| `CATBIRD__SERVER__ALLOWED_ORIGINS` | Comma-separated exact canonical browser origins; empty denies cross-origin access | empty |
| `CATBIRD__SERVER__TRUSTED_PROXY_IPS` | Exact socket-peer IPs allowed to assert forwarding headers | empty |
| `CATBIRD__REDIS__URL` | Redis connection URL | redis://127.0.0.1:6379 |
| `CATBIRD__OAUTH__CLIENT_ID` | OAuth client ID | http://localhost:3000 |
| `CATBIRD__OAUTH__REDIRECT_URI` | OAuth callback URL | http://localhost:3000/auth/callback |
| `CATBIRD__OAUTH__PRIVATE_KEY_PATH` or `CATBIRD__OAUTH__PRIVATE_KEY_BASE64` | ES256 client-signing key source | none |
| `SESSION_ENCRYPTION_KEY` | Base64 encoding of exactly 32 random bytes | required for OAuth sessions |
| `SESSION_IDENTIFIER_HMAC_KEY` | Distinct base64 encoding of exactly 32 random bytes | required for OAuth sessions |

Nest requires a standalone Redis/Valkey server. OAuth lifecycle operations use
multi-key atomic scripts and migration/audit tooling scans the complete session
keyspace. Both gateway startup and `session_migrate` query `INFO cluster` and
fail closed unless the server explicitly reports `cluster_enabled:0`; a cluster
node or an account that cannot prove its topology is rejected before session
state is read or changed.

Never commit OAuth or session-key values. `SESSION_ENCRYPTION_KEY_ID` and
`SESSION_ENCRYPTION_PREVIOUS_KEYS` support controlled encryption-key rotation.
Only configure `CATBIRD__SERVER__TRUSTED_PROXY_IPS` with the socket-peer IPs of
proxies that correctly manage forwarding headers; do not list end-user IPs.

### Browser OAuth Session Exchange

Login begins with a browser nonce. After the PDS callback and provider token
exchange, Nest stores the server-side OAuth session and redirects to the approved
client target with a short-lived, one-time exchange code. The client sends that
code, the original browser nonce, and its exact Origin to `POST /auth/exchange`.
Nest atomically redeems the origin/nonce-bound code, sets an HttpOnly cookie, and
returns the opaque session ID. Protected routes accept either that cookie or an
`Authorization: Bearer <session-id>` header.

### Conditional MLS Routing

When `CATBIRD__MLS__SERVICE_URL` and `CATBIRD__MLS__GATEWAY_DID` are configured,
Nest routes `blue.catbird.mlsChat.*` lexicons directly to the configured service.
Nest requires an authoritative local session/device binding and constructs a
short-lived, lexicon-scoped service JWT plus DPoP proof from the configured
gateway DID, service DID, and proof origin. The downstream MLS service must still
validate those credentials and enforce authorization. Without direct-routing
configuration, MLS lexicons use the normal PDS proxy path.

## API Endpoints

### Health
- `GET /health` - Service health payload
- `GET /ready` - Redis-backed readiness probe
- `GET /live` - Process-liveness probe

### Authentication
- `GET|POST /auth/login` - Initiate OAuth login with a browser nonce
- `GET /auth/callback` - Complete the provider exchange and issue a one-time client exchange code
- `POST /auth/exchange` - Redeem the origin/nonce-bound code for an HttpOnly cookie and session ID
- `POST /auth/logout` - Logout and revoke tokens
- `GET /auth/session` - Get current session info

### XRPC Proxy
- `GET /xrpc/*` - Proxy GET requests to PDS
- `POST /xrpc/*` - Proxy POST requests to PDS

### OAuth Metadata
- `GET /.well-known/oauth-client-metadata` - OAuth client metadata
- `GET /.well-known/jwks.json` - Public keys for client auth

## Development

```bash
# Run with debug logging
RUST_LOG=catbird=debug cargo run

# Run tests
cargo test

# Format code
cargo fmt

# Lint
cargo clippy
```

## License

MIT
