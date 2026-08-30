-- Task 5 Remediation Migration
-- 1. Add generation to circle_member_cache_meta
ALTER TABLE circle_member_cache_meta ADD COLUMN IF NOT EXISTS generation BIGINT NOT NULL DEFAULT 1;

-- 2. Scope circle_rejections to space_uri, author_did, rev, uri_hash additively
ALTER TABLE circle_rejections ADD COLUMN IF NOT EXISTS space_uri TEXT;
ALTER TABLE circle_rejections ADD COLUMN IF NOT EXISTS author_did TEXT NOT NULL DEFAULT '';
ALTER TABLE circle_rejections ADD COLUMN IF NOT EXISTS rev TEXT NOT NULL DEFAULT '';

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'circle_rejections_pkey'
    ) THEN
        ALTER TABLE circle_rejections DROP CONSTRAINT circle_rejections_pkey;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'circle_rejections_compound_pkey'
    ) THEN
        UPDATE circle_rejections SET space_uri = '' WHERE space_uri IS NULL;
        ALTER TABLE circle_rejections ALTER COLUMN space_uri SET DEFAULT '';
        ALTER TABLE circle_rejections ALTER COLUMN space_uri SET NOT NULL;
        ALTER TABLE circle_rejections ADD CONSTRAINT circle_rejections_compound_pkey PRIMARY KEY (space_uri, author_did, rev, uri_hash);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS circle_rejections_observed_at_idx ON circle_rejections (observed_at);
CREATE INDEX IF NOT EXISTS circle_rejections_uri_hash_idx ON circle_rejections (uri_hash);

-- 3. Checkpoint progress table for fair revision sweeps
CREATE TABLE IF NOT EXISTS circle_sweep_checkpoint (
    checkpoint_key TEXT PRIMARY KEY,
    last_space_uri TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
