-- com.atproto.space.registerNotify registrations held at each Circle's space host.
-- The host keeps a registration for 24 h; the AppView renews it 1 h before expires_at.
CREATE TABLE IF NOT EXISTS circle_notify_registrations (
    space_uri TEXT PRIMARY KEY REFERENCES circles(space_uri) ON DELETE CASCADE,
    service TEXT NOT NULL,
    space_host_endpoint TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS circle_notify_registrations_expires_idx
    ON circle_notify_registrations (expires_at);
