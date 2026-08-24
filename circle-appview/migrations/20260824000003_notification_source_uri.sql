-- Migration: Add source_uri to circle_notifications for provenance tracking, purge legacy rows, and enforce uniqueness

-- Purge pre-existing legacy notifications during alpha migration
DELETE FROM circle_notifications;

ALTER TABLE circle_notifications ADD COLUMN IF NOT EXISTS source_uri TEXT;
ALTER TABLE circle_notifications ALTER COLUMN source_uri SET NOT NULL;

ALTER TABLE circle_notifications DROP CONSTRAINT IF EXISTS circle_notifications_source_uri_unique;
ALTER TABLE circle_notifications ADD CONSTRAINT circle_notifications_source_uri_unique UNIQUE (source_uri);

CREATE INDEX IF NOT EXISTS circle_notifications_source_uri_idx ON circle_notifications (source_uri);
