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

# Before a release build: both crates must resolve ../../catbird-atproto at the
# commit in scripts/canonical-sibling-provenance.conf, with matching lock files
nest/scripts/check-canonical-sibling-provenance.sh
```

### Ignored tests

`#[ignore]` marks tests that need a resource `cargo test` cannot provide by
itself. Do not add new ones; a new test that needs a database uses the existing
disposable fixtures. Run the database-backed set with a throwaway loopback
Postgres (any port but 5432) and Redis (any port but 6379):

```bash
LITE_PUSH_DISPOSABLE=1 DATABASE_URL=postgres://postgres@127.0.0.1:<pg-port>/postgres \
  REDIS_URL=redis://127.0.0.1:<redis-port> cargo test -- --include-ignored
```

Ignored tests added with the sealed wake envelope and session-scoped wake keys,
and the exact dependency each needs:

| Test | Needs |
|------|-------|
| `services::push::request_events::paired_harness::live_ds_worker_to_nest` | A running mls-ds worker process started by `mls-ds/e2e-tests`, plus `CATBIRD_REQUEST_PUSH_PAIRED_DIR` and `CATBIRD_REQUEST_PUSH_TEST_DB`. Fails standalone by design. |
| `services::push::request_events::c32_paired_harness::live_ds_worker_to_nest_c32` | Same paired mls-ds process and variables as above. |
| `tests/c26_paired_nest.rs` `live_c26_nest_proxy_worker` | A delivery-service URL and fixture paths written to its stdin by the mls-ds e2e scenario `c26_maximum_device_limits`, which launches it as a companion process. |
| `tests/push_session_signout.rs` `signing_out_a_session_revokes_only_its_wake_keys` | Disposable Postgres and Redis (command above). |
| `tests/push_session_signout.rs` `wake_keys_follow_an_upgraded_session_and_are_revoked_with_it` | Disposable Postgres and Redis. |
| `tests/push_session_signout.rs` `cleanup_retired_session_revokes_leaving_session_wake_keys_and_preserves_other_sessions` | Disposable Postgres and Redis. |

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

### Chat proxy path (nest is NOT MLS-free)

MLS implementation and storage live in **mls-ds**, but nest is on the hot chat request path. `handlers/atproto.rs::proxy_xrpc` sends every `blue.catbird.chat.*` NSID except `blue.catbird.chat.defs` through `MlsAuthService::proxy_clean_chat_request` (`services/mls_auth.rs`) to `CATBIRD__MLS__SERVICE_URL` whenever chat routing is enabled (`mls.service_url` set, `chat.enabled`, or `CHAT_ENABLED=1`). Each request carries a fresh PDS-issued user service-auth token (`aud` = `CATBIRD__MLS__SERVICE_DID`, default `did:web:mlschat.catbird.blue`; `lxm` = the NSID) and an `x-catbird-chat-device-id` header.

- `CHAT_ENDPOINTS` (36 NSIDs, count pinned in `tests/integration_tests.rs`, matching `blue.catbird.chat.authFull`) is the `lxm` allowlist. `services/service_auth.rs` refuses to mint a token for a chat NSID that is not listed, so a procedure missing from the list fails for every client. The list includes the encrypted direct-request procedures (`prepareDirectRequest`, `publishDirectRequest`, `publishDirectRequestKeys`, `cancelDirectRequestPreparation`, `getDirectRequestOutcome`), `approveDevice`, `acknowledgeEntries`, `registerPushGateway`, `relaySpaceCredential`, `relaySpaceRead`, and `getDeviceKey`.
- Method names are matched byte for byte, so `validate_proxy_lexicon` refuses any name with an uppercase letter in its authority and any letter-case variant of a gated, blocked or specially routed method (`is_non_canonical_policy_nsid`). The reference PDS matches method names case-insensitively; without this a variant such as `com.atproto.server.getserviceauth` would skip the gateway's check and still be served upstream.
- `proxy_body_limit` bounds the request body before any token is minted: 16 MiB for `publishDirectRequest` and `publishDirectRequestKeys`, 64 KiB for `prepareDirectRequest` and `cancelDirectRequestPreparation`, 10 MiB for everything else. A larger body gets `413 RequestTooLarge` and never reaches the DS or the PDS.
- Legacy `blue.catbird.mlsChat.*` is no longer intercepted (`MlsAuthService::is_mls_lexicon` matches clean-chat only); it goes through the generic PDS proxy like any other NSID.

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
- **`services/push/gateway.rs` — D2 MLS Push Gateway** (handlers in `handlers/push_gateway.rs`).
  - `POST /xrpc/blue.catbird.push.registerKey` (session auth) stores the device's encrypted native APNs/FCM token and returns an opaque 256-bit `pushKey` bound to the account DID, device ID, app ID and one delivery service DID. The device then registers that key with its DS through `blue.catbird.chat.registerPushGateway`.
  - **Which delivery service a key is bound to** (`resolve_user_push_delivery_service`): the `#atproto_mls` service in the account's DID document when it has one; that entry always wins and a malformed one fails registration. Otherwise the `deliveryService` of the account's public `blue.catbird.chat.declaration/self` record, read with one credential-free `com.atproto.repo.getRecord` from the DID document's `#atproto_pds` (`services/push/delivery_service_declaration.rs`: no redirects, 10 s deadline, 64 KiB cap, strict decode; only a structured `RecordNotFound` means "no record"). A declared service is accepted only if it is on the allowlist: `mls.service_did` by default, or `CATBIRD_PUSH_DECLARATION_DELIVERY_SERVICES` (comma-separated DIDs; set but empty turns the fallback off). The binding is stored with the key and never re-read on `deliver`; it changes only when the device registers again. Failures: `400 InvalidMlsServiceDid` when nothing usable is declared, the declared service is not allowed, or the account's DID document can never be read (the directory or host answers 404 or 410, the DID is not a valid `did:plc` or `did:web`, a `did:web` host is refused by the SSRF check, or the document is over 256 KiB); `503 TemporarilyUnavailable` when the DID document or PDS failed in a way a retry can fix (no connection, any other HTTP status, an interrupted body). `getServiceAuth` uses the DID-document lookup only (`resolve_user_mls_service_did`) and must not gain this fallback without a separate decision.
  - `POST /xrpc/blue.catbird.push.deliver` sits outside session auth. The DS signs a `#atproto` DID-JWT (ES256 or ES256K) bound to `htm`, `htu` (path `/xrpc/blue.catbird.push.deliver`), `iat`/`exp` (±60 s skew, ≤60 s lifetime), a single-use `jti` and the body SHA-256. Bodies are capped at 16 KiB.
  - The payload is wake metadata only: `wakeKind` (`applicationMessage`, `controlTransition`, `directRequest` or `welcome`), `conversationId`, `generation`, `seq`, `epoch`, and an optional `ciphertext` of at most 2,200 bytes. Any other field, including `aps`, `title` or `body`, is `400 InvalidRequest`. Nest writes the only display text: APNs gets `aps.alert.body = "New message"` with `mutable-content: 1` plus a `catbird` object (`recipientAccountHash`, the wake fields, `fetchRequired`); FCM gets a high-priority data-only message whose `data.catbird` is that object as a JSON string.
  - Unknown, revoked or wrong-DS `pushKey`s all get the same `202 {"accepted": true}` (constant-time comparison). `410 PushTokenGone` is returned only when the calling DS is the key's bound service and the provider reported the native token unregistered. Per-DS and per-key token buckets drop floods before any provider call.
  - `deliver` has its own pre-authentication limit, `PUSH_DELIVER_IP_LIMIT` (1,200 requests a minute per source IP, `middleware/rate_limit.rs`), counted separately from the sign-in limiter. Over it the caller gets `429 RateLimited`. The caller's DID document is read with a 256 KiB cap enforced while streaming, because it is fetched before the signature is verified.
  - Each key records the fingerprint of the session that registered it (`push_gateway_keys.auth_session_fingerprint`). The key is revoked when that session signs out or calls `unregisterPush` for the same app, follows the session through a scope upgrade, and is deleted with the account in account erasure. There is no `unregisterKey` method.
  - FCM delivery needs `CATBIRD_FCM_PROJECT_ID` and `CATBIRD_FCM_BEARER_TOKEN`. WebPush is not configured.
  - **Direct-request wakes:** the DS worker wakes a recipient's devices (`wakeKind=directRequest`) for a published encrypted direct request. A provider failure is redelivered by the DS's durable retry, a lost gateway ACK is retried with an identical wake (same collapse ID and envelope), a request answered before the wake is never woken, and a device that re-registered with an FCM token is woken only through FCM. The paired qualification tests are in `services/push/request_events/` (`#[cfg(test)]`, `#[ignore]`): `paired_harness::live_ds_worker_to_nest` (t16) and `c32_paired_harness::live_ds_worker_to_nest_c32` (C32). `mls-ds/e2e-tests` starts them as a second process with `CATBIRD_REQUEST_PUSH_PAIRED_DIR` (a `/tmp/<prefix>*` directory) and `CATBIRD_REQUEST_PUSH_TEST_DB`; they do not run standalone.

Client-facing endpoints in `handlers/push.rs`: `register_push`,
`unregister_push`, `get_preferences`, `put_preferences_v2`,
`list_activity_subscriptions`, `put_activity_subscription`. MLS wake keys are
registered through `blue.catbird.push.registerKey` (above).


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
│   ├── atproto.rs       # XRPC proxy handler (chat routing + body limits)
│   ├── push.rs          # Push registration + preferences endpoints
│   ├── push_gateway.rs  # D2 MLS push gateway: registerKey, deliver
│   ├── oauth_upgrade.rs # Progressive scope upgrade endpoints
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
    ├── mls_auth.rs        # Chat proxy: CHAT_ENDPOINTS, proxy_body_limit, forwards blue.catbird.chat.* to mls-ds (live hot path)
    ├── service_auth.rs    # PDS service-auth minting; per-audience lxm allowlists
    ├── oauth_authorize.rs # PAR with byte-exact raw scopes
    ├── oauth_upgrade.rs   # Progressive scope upgrade (allowlisted scopes only)
    ├── push/              # APNS pipeline + D2 gateway (see Push notifications above)
    ├── chat_poll/         # chat.bsky poller (see Push notifications above)
    ├── redis_auth_store.rs # Session/auth persistence in Redis/Valkey
    ├── redis_crypto.rs    # Encryption for Redis-stored secrets
    └── ssrf.rs            # SSRF prevention
```

## Key Dependencies

- **axum** 0.7 - Web framework
- **jacquard-oauth / jacquard-common / jacquard-identity** - AT Protocol OAuth, XRPC and identity (git dependency, pinned rev)
- **redis** 0.25 - Session storage
- **p256 / jsonwebtoken** - DPoP and JWT signing
- **tower-http** - CORS, tracing, request IDs
- **tower_governor** - Rate limiting

## Auth Flow

1. **Login**: iOS requests login URL -> Nest generates PAR -> redirects to PDS
2. **Callback**: PDS redirects to Nest -> token exchange (Private Key JWT) -> creates Redis session -> redirects to iOS with session cookie
3. **Requests**: Cookie validated -> access token retrieved from Redis -> refreshed if expired -> DPoP-signed request to PDS
4. **Scope upgrade** (`services/oauth_upgrade.rs`): `POST /auth/upgrade` (session + browser nonce) -> PDS consent -> fixed callback `https://catbird.blue/oauth/permission-callback` -> `POST /auth/upgrade/exchange` -> `POST /auth/upgrade/commit`. Commit activates the candidate session atomically; the old session stays live until then. Only `ALLOWED_UPGRADE_SCOPES` can be requested.

### Labyrinth Space scopes

Labyrinth history backup needs two Space scopes, in these exact explicit forms (`models/oauth_upgrade.rs`; `MAX_SCOPE_LEN` is 512, with explicit allowlist pass-through for `ALLOWLISTED_UPGRADE_SCOPES`):

- `LABYRINTH_MAILBOX_SPACE_SCOPE`: `space:blue.catbird.labyrinth.mailbox?action=create&action=delete&action=read&action=update&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.circleOwnerState&collection=blue.catbird.labyrinth.device&collection=blue.catbird.labyrinth.epoch&collection=blue.catbird.labyrinth.epochMember&collection=blue.catbird.labyrinth.otcSession&collection=blue.catbird.labyrinth.ownerBatch&collection=blue.catbird.labyrinth.readState&collection=blue.catbird.labyrinth.virtualDevice&manage=create&manage=delete`
- `LABYRINTH_CONVERSATION_SPACE_SCOPE`: `space:blue.catbird.labyrinth.conversation?action=create&action=delete&action=read&action=update&authority=*&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.authorRedaction&collection=blue.catbird.labyrinth.batch&collection=blue.catbird.labyrinth.mek`
- Create-only MLS transparency repo scopes (`B4`/`Y-6`): `repo:blue.catbird.chat.device?action=create` (`MLS_CHAT_DEVICE_REPO_SCOPE`) and `repo:blue.catbird.chat.deviceRevocation?action=create` (`MLS_CHAT_DEVICE_REVOCATION_REPO_SCOPE`).

`oauth_authorize::start_auth_with_raw_scopes` sends them byte-exact at PAR, because jacquard's normalization rewrites `space:` scopes and Swan rejects the result with `invalid_scope`. The retired forms `space:blue.catbird.labyrinth.mailbox?manage=create&manage=delete` and `space:blue.catbird.labyrinth.conversation?authority=*` are no longer allowlisted. Clients (Rust `catbird_mls::REQUIRED_LABYRINTH_OAUTH_SCOPES`, CatbirdMLSCore `MLSAppGroupStorage.requiredSpacesScopes`, Android `MlsSdkManager.REQUIRED_SPACES_OAUTH_SCOPES`, catmos `src/lib/labyrinth-ui.ts` `REQUIRED_LABYRINTH_OAUTH_SCOPES`) report a session that holds only the retired forms as missing both scopes, so the user must re-authorize; a Nest session does that through the upgrade flow above. Both scopes are part of `default_max_scopes()` and the commented `CATBIRD__OAUTH__MAX_SCOPES` example in `catbird/.env.example` and `catbird/config/default.toml`.

Catmos keeps two scope lists. `CATMOS_OAUTH_SCOPES` (default `atproto transition:generic`) is what every Catmos sign-in asks for and must stay narrow, because a PDS without Spaces support would refuse a sign-in that asks for `space:` scopes. `CATMOS_OAUTH_MAX_SCOPES` (whitespace-separated, optional) is the ceiling a Catmos session may reach through `/auth/upgrade`; it always includes the sign-in scopes, and when unset it adds `default_catmos_upgrade_scopes()` (blob, the mailboxKeys repo scope, the chat.device and deviceRevocation create scopes, and both Labyrinth space scopes). Never widen `CATMOS_OAUTH_SCOPES` to unlock encrypted chat.

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
