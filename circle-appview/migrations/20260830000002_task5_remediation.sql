-- Task 5 Remediation Migration
-- 1. Add generation to circle_member_cache_meta
ALTER TABLE circle_member_cache_meta ADD COLUMN IF NOT EXISTS generation BIGINT NOT NULL DEFAULT 1;

-- 2. Scope circle_rejections to space_uri, author_did, rev, uri_hash
DROP TABLE IF EXISTS circle_rejections;
CREATE TABLE circle_rejections (
    space_uri TEXT NOT NULL REFERENCES circles(space_uri) ON DELETE CASCADE,
    author_did TEXT NOT NULL,
    rev TEXT NOT NULL,
    uri_hash BYTEA NOT NULL,
    reason_code TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (space_uri, author_did, rev, uri_hash)
);

CREATE INDEX IF NOT EXISTS circle_rejections_observed_at_idx ON circle_rejections (observed_at);
CREATE INDEX IF NOT EXISTS circle_rejections_uri_hash_idx ON circle_rejections (uri_hash);

-- 3. Checkpoint progress table for fair revision sweeps
CREATE TABLE IF NOT EXISTS circle_sweep_checkpoint (
    checkpoint_key TEXT PRIMARY KEY,
    last_space_uri TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
