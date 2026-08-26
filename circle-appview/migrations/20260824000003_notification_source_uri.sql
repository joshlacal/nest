DELETE FROM circle_notifications;
ALTER TABLE circle_notifications ADD COLUMN source_uri TEXT NOT NULL;
ALTER TABLE circle_notifications ADD CONSTRAINT circle_notifications_source_uri_key UNIQUE (source_uri);
CREATE INDEX circle_notifications_source_uri_idx ON circle_notifications (source_uri);
