-- Nov-12 alpha introduces notification tokens carried by authorizeSpaceSync.
-- Legacy circle_notify_registrations lease rows are preserved untouched for
-- non-destructive rollback safety; active Spaces store confirmation/update
-- tokens and revision checkpoints in circle_space_notify_tokens.
CREATE TABLE IF NOT EXISTS circle_space_notify_tokens (
    -- Confirmation may arrive during authorizeSpaceSync, before local activation creates circles.
    space_uri TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    token BYTEA NOT NULL CHECK (octet_length(token) BETWEEN 29 AND 1024),
    checkpoint_rev TEXT,
    pending_rev TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
