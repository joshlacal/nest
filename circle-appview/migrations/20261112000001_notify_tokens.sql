-- Nov-12 alpha replaces the legacy registration RPCs with notification data
-- carried by authorizeSpaceSync. Old registrations cannot be translated because
-- their hosts know no endpoint token, so discard them and reauthorize cleanly.
DROP TABLE IF EXISTS circle_notify_registrations;

CREATE TABLE circle_notify_registrations (
    -- Confirmation may arrive during authorizeSpaceSync, before local activation creates circles.
    space_uri TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    token BYTEA NOT NULL CHECK (octet_length(token) BETWEEN 29 AND 1024),
    checkpoint_rev TEXT,
    pending_rev TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
