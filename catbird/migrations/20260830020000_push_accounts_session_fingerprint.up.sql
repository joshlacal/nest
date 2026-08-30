-- Finding 26 / Finding 2: Add additive session_fingerprint column to push_accounts for rolling-deploy safety.
-- Old replicas continuing to query push_accounts.session_id will not see in-place rewritten SHA-256 fingerprints
-- and will therefore not misinterpret active sessions as revoked.
ALTER TABLE push_accounts ADD COLUMN IF NOT EXISTS session_fingerprint TEXT;
CREATE INDEX IF NOT EXISTS idx_push_accounts_session_fingerprint ON push_accounts(session_fingerprint);

-- Backfill session_fingerprint for existing rows using sha256 of session_id.
-- Notice: session_id is left untouched for backward compatibility with old replicas during rolling deploy.
UPDATE push_accounts
SET session_fingerprint = encode(sha256(session_id::bytea), 'hex')
WHERE session_fingerprint IS NULL;
