-- Nov-12 alpha replaces the legacy registration RPCs with notification data
-- carried by authorizeSpaceSync. Old registrations cannot be translated because
-- their hosts know no endpoint token, so discard them and reauthorize cleanly.
DROP TABLE IF EXISTS circle_notify_registrations;

CREATE TABLE circle_notify_registrations (
    space_uri TEXT PRIMARY KEY REFERENCES circles(space_uri) ON DELETE CASCADE,
    endpoint TEXT NOT NULL,
    token TEXT NOT NULL CHECK (char_length(token) BETWEEN 1 AND 512),
    checkpoint_rev TEXT,
    pending_rev TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
