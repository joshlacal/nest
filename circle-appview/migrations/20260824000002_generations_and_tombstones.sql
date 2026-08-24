-- Migration: Add generations, deletion tombstones, and projection receipt payload digest

ALTER TABLE circle_members ADD COLUMN IF NOT EXISTS generation BIGINT NOT NULL DEFAULT 0;

ALTER TABLE projection_receipts ADD COLUMN IF NOT EXISTS payload_digest BYTEA;

CREATE TABLE IF NOT EXISTS circle_tombstones (
    space_uri TEXT PRIMARY KEY,
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
