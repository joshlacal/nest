-- Migration: Add source_uri to circle_notifications for provenance tracking

ALTER TABLE circle_notifications ADD COLUMN IF NOT EXISTS source_uri TEXT;

CREATE INDEX IF NOT EXISTS circle_notifications_source_uri_idx ON circle_notifications (source_uri);
