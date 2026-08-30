ALTER TABLE push_accounts DROP COLUMN IF EXISTS moderation_generation;
ALTER TABLE actor_moderation_verdict DROP COLUMN IF EXISTS generation;
