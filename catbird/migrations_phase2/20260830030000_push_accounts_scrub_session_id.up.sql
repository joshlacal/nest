-- Phase 2 Cutover Migration (Manual / Standalone - DO NOT AUTO-APPLY at startup)
--
-- PRECONDITION FOR EXECUTION:
-- 1. All running replicas of Nest (`catbird`) have been upgraded to the Phase 2 code build.
-- 2. Phase 2 writers in all running replicas have stopped binding raw session strings into `push_accounts.session_id`
--    (writers bind `session_fingerprint` or sentinel into `session_id`, or omit raw values).
-- 3. All replicas have been verified to read exclusively from `push_accounts.session_fingerprint`.
-- 4. All background session resolution operates by DID + fingerprint verification.
-- 5. No legacy replicas remain querying or writing plaintext `push_accounts.session_id`.
--
-- ACTION:
-- Scrubs remaining plaintext bearer session IDs from the shared `push_accounts.session_id` column
-- by overwriting them with the non-replayable SHA-256 fingerprint, and enforces NOT NULL on `session_fingerprint`.
-- 1. Backfill any missing fingerprints (safeguard)
UPDATE push_accounts
SET session_fingerprint = encode(sha256(session_id::bytea), 'hex')
WHERE session_fingerprint IS NULL;

-- 2. Overwrite plaintext bearer session_id at rest with non-replayable fingerprint representation
UPDATE push_accounts
SET session_id = session_fingerprint
WHERE session_id IS NOT NULL AND session_id != session_fingerprint;

-- 3. Enforce NOT NULL on session_fingerprint
ALTER TABLE push_accounts ALTER COLUMN session_fingerprint SET NOT NULL;
