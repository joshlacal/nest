-- Add moderation cache generation to invalidate stale in-flight fetches.
-- Steps:
-- 1. push_accounts.moderation_generation increments on every invalidate_recipient.
-- 2. fetch_and_persist_live snapshots the generation before the network fetch,
--    then re-verifies it inside the account-lock transaction before writing;
--    a mismatch means an older fetch returned after an invalidation, so the
--    write is discarded.
ALTER TABLE push_accounts ADD COLUMN IF NOT EXISTS moderation_generation BIGINT NOT NULL DEFAULT 1;
ALTER TABLE actor_moderation_verdict ADD COLUMN IF NOT EXISTS generation BIGINT NOT NULL DEFAULT 1;
