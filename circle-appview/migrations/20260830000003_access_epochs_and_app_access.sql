-- Additive migration for Task 6: access epochs, appAccess lifecycle state, and thread indexes

-- 1. Access epoch and appAccess tracking on circles
ALTER TABLE circles ADD COLUMN IF NOT EXISTS access_epoch BIGINT NOT NULL DEFAULT 1;
ALTER TABLE circles ADD COLUMN IF NOT EXISTS app_access_granted BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE circles ADD COLUMN IF NOT EXISTS app_access_revoked_at TIMESTAMPTZ;

-- 2. Access epoch and appAccess tracking on circle_member_cache_meta
ALTER TABLE circle_member_cache_meta ADD COLUMN IF NOT EXISTS access_epoch BIGINT NOT NULL DEFAULT 1;
ALTER TABLE circle_member_cache_meta ADD COLUMN IF NOT EXISTS app_access_granted BOOLEAN NOT NULL DEFAULT true;

-- 3. Set-based thread expansion and CID authorization indexes
CREATE INDEX IF NOT EXISTS circle_records_space_parent_idx ON circle_records (space_uri, parent_uri, created_at ASC, uri ASC);
CREATE INDEX IF NOT EXISTS circle_records_space_root_idx ON circle_records (space_uri, root_uri, created_at ASC, uri ASC);
CREATE INDEX IF NOT EXISTS circle_records_space_uri_idx ON circle_records (space_uri, uri);
CREATE INDEX IF NOT EXISTS circle_records_space_author_cid_idx ON circle_records (space_uri, author_did, cid);
CREATE INDEX IF NOT EXISTS circle_likes_space_post_author_idx ON circle_likes (space_uri, post_uri, author_did);

-- 4. Batched purge and notification cleanup index
CREATE INDEX IF NOT EXISTS circle_notifications_space_uri_idx ON circle_notifications (space_uri);
