-- Drop the moderation mirror. Nest resolves mutes, blocks and moderation-list
-- membership per actor from app.bsky.actor.defs#viewerState instead of
-- replicating them locally; no code has read or written these tables since the
-- ADR-022 cutover.
--
-- DESTRUCTIVE: moderation_list_members alone held ~385k rows / 422 MB. The data
-- is a cache of appview state, not a source of truth, so it is reconstructible
-- by definition — but it is not recoverable from this migration.
DROP TABLE IF EXISTS moderation_list_members;
DROP TABLE IF EXISTS moderation_list_subscriptions;
DROP TABLE IF EXISTS user_mutes;
DROP TABLE IF EXISTS user_blocks;

-- Watermarks for the mirror's two sync passes. Nothing writes them now.
ALTER TABLE push_accounts DROP COLUMN IF EXISTS last_actor_sync_at;
ALTER TABLE push_accounts DROP COLUMN IF EXISTS last_list_sync_at;
