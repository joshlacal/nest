-- Authenticated Push Gateway keys (D2, Spec §6.2)
-- Binds each CSPRNG push_key (stored as SHA-256) to (account_did, device_id, app_id, allowed_mls_service_did)
-- with AES-256-GCM encrypted native APNs/FCM/WebPush tokens at rest.

CREATE TABLE IF NOT EXISTS push_gateway_keys (
    push_key_sha256         BYTEA PRIMARY KEY CHECK (octet_length(push_key_sha256) = 32),
    account_did             TEXT NOT NULL,
    device_id               TEXT NOT NULL,
    app_id                  TEXT NOT NULL,
    platform                TEXT NOT NULL CHECK (platform IN ('apns', 'apnsSandbox', 'fcm', 'webpush')),
    encrypted_native_token  BYTEA NOT NULL,
    allowed_mls_service_did TEXT NOT NULL,
    unregistered_at         TIMESTAMPTZ,
    revoked_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_did, device_id, app_id)
);

CREATE INDEX IF NOT EXISTS idx_push_gateway_keys_account_did
    ON push_gateway_keys (account_did);
