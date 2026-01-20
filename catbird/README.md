# Catbird Nest Gateway

**Catbird Nest** is a Backend-for-Frontend (BFF) gateway for the AT Protocol (Bluesky). It acts as a **Confidential OAuth Client**, handling all authentication complexity so that mobile apps can remain simple "dumb" clients.

## Why a BFF Gateway?

Mobile apps (iOS/Android) are "public clients" and cannot securely store secrets. ATProto OAuth requires:
- **DPoP (Demonstration of Proof-of-Possession)** - cryptographic proof for every request
- **Client Assertions** - JWT-based client authentication
- **Token Rotation** - automatic refresh token management

By moving this complexity to a server-side gateway, the mobile app only needs to:
1. Hold a simple session cookie/token from Catbird
2. Make requests to the Catbird gateway
3. Let the gateway handle all ATProto authentication

## Architecture

```
┌─────────────┐     Simple Session     ┌─────────────────┐     ATProto OAuth     ┌─────────────┐
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

1. **iOS Request**: App sends request with Catbird session cookie
2. **Session Lookup**: Gateway validates session in Redis
3. **Token Refresh**: If ATProto token expired, automatically refresh it
4. **Proxy Request**: Forward to user's PDS with proper DPoP/Bearer auth
5. **Enrichment**: Parse response, enrich blocked posts with metadata
6. **Response**: Return modified JSON to iOS app

## Features

- **Confidential OAuth Client**: Secure server-side OAuth with client assertions
- **DPoP Support**: Automatic DPoP header generation for all PDS requests
- **Token Management**: Automatic access token refresh using refresh tokens
- **Response Enrichment**: Detect and annotate blocked/hidden posts
- **Session Management**: Redis-backed sessions with configurable TTL
- **Health Checks**: Kubernetes-ready health, readiness, and liveness probes

## Tech Stack

- **Framework**: [Axum](https://github.com/tokio-rs/axum) - Fast, ergonomic web framework
- **HTTP Client**: [Reqwest](https://github.com/seanmonstar/reqwest) - Robust HTTP client
- **Session Store**: [Redis](https://redis.io/) - In-memory data store
- **Crypto**: [p256](https://github.com/RustCrypto/elliptic-curves) - ECDSA signatures for OAuth
- **Serialization**: [Serde](https://serde.rs/) - JSON handling with surgical precision

## Getting Started

### Prerequisites

- Rust 1.75+
- Redis 7.0+
- An ES256 key pair for OAuth client authentication

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
| `CATBIRD__REDIS__URL` | Redis connection URL | redis://127.0.0.1:6379 |
| `CATBIRD__OAUTH__CLIENT_ID` | OAuth client ID (your domain) | - |
| `CATBIRD__OAUTH__REDIRECT_URI` | OAuth callback URL | - |

## API Endpoints

### Health
- `GET /health` - Health check with Redis status
- `GET /ready` - Readiness probe
- `GET /live` - Liveness probe

### Authentication
- `POST /auth/login` - Initiate OAuth login
- `GET /auth/callback` - OAuth callback handler
- `POST /auth/logout` - Logout and revoke tokens
- `GET /auth/session` - Get current session info

### XRPC Proxy
- `GET /xrpc/*` - Proxy GET requests to PDS
- `POST /xrpc/*` - Proxy POST requests to PDS

### OAuth Metadata
- `GET /.well-known/oauth-client-metadata` - OAuth client metadata
- `GET /.well-known/jwks.json` - Public keys for client auth

## Response Enrichment

The gateway automatically enriches blocked posts with Catbird metadata:

```json
{
  "$type": "app.bsky.feed.defs#blockedPost",
  "uri": "at://did:plc:xxx/app.bsky.feed.post/abc",
  "blocked": true,
  "catbird": {
    "enriched": true,
    "originalType": "app.bsky.feed.defs#blockedPost",
    "reason": "user_blocked",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

This allows the iOS app to show rich UI for blocked content instead of generic placeholders.

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