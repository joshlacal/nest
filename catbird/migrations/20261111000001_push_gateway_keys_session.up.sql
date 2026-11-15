-- Bind each push gateway key to the session that registered it, so signing that
-- session out (or unregistering its push token) can revoke exactly its keys.
-- Stored as the same SHA-256 session fingerprint as user_devices.auth_session_fingerprint;
-- never the raw bearer. Nullable with no default: adding it does not rewrite the table.

ALTER TABLE push_gateway_keys
    ADD COLUMN IF NOT EXISTS auth_session_fingerprint TEXT;

CREATE INDEX IF NOT EXISTS idx_push_gateway_keys_account_session
    ON push_gateway_keys (account_did, auth_session_fingerprint);
