-- Migration to support independent read and write flags for space members
ALTER TABLE circle_member_cache ADD COLUMN IF NOT EXISTS can_read BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE circle_member_cache ADD COLUMN IF NOT EXISTS can_write BOOLEAN NOT NULL DEFAULT true;

CREATE INDEX IF NOT EXISTS circle_member_cache_read_idx ON circle_member_cache (space_uri, member_did) WHERE can_read = true;
CREATE INDEX IF NOT EXISTS circle_member_cache_write_idx ON circle_member_cache (space_uri, member_did) WHERE can_write = true;
