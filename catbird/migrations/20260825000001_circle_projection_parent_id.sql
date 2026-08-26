-- Add parent_id column for parent-child operation lifecycle aggregation
ALTER TABLE circle_projection_outbox ADD COLUMN IF NOT EXISTS parent_id UUID;
CREATE INDEX IF NOT EXISTS idx_circle_projection_outbox_parent ON circle_projection_outbox (parent_id);
