DROP INDEX IF EXISTS idx_push_gateway_keys_account_session;

ALTER TABLE push_gateway_keys
    DROP COLUMN IF EXISTS auth_session_fingerprint;
