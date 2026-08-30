-- Finding 26 / Finding 2: Down migration
DROP INDEX IF EXISTS idx_push_accounts_session_fingerprint;
ALTER TABLE push_accounts DROP COLUMN IF EXISTS session_fingerprint;
