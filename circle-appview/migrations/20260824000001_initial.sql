CREATE TABLE circles (
    space_uri TEXT PRIMARY KEY,
    circle_id TEXT NOT NULL,
    authority_did TEXT NOT NULL,
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 64),
    created_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ
);

CREATE TABLE circle_member_cache (
    space_uri TEXT NOT NULL REFERENCES circles(space_uri) ON DELETE CASCADE,
    member_did TEXT NOT NULL,
    cached_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (space_uri, member_did)
);

CREATE TABLE circle_member_cache_meta (
    space_uri TEXT PRIMARY KEY REFERENCES circles(space_uri) ON DELETE CASCADE,
    last_refreshed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    member_count INT NOT NULL DEFAULT 0
);

CREATE TABLE circle_records (
    uri TEXT PRIMARY KEY,
    cid TEXT NOT NULL,
    space_uri TEXT NOT NULL REFERENCES circles(space_uri) ON DELETE CASCADE,
    author_did TEXT NOT NULL,
    collection TEXT NOT NULL,
    rkey TEXT NOT NULL,
    record_json JSONB NOT NULL,
    indexed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL,
    parent_uri TEXT,
    root_uri TEXT,
    deleted_at TIMESTAMPTZ
);

CREATE TABLE circle_likes (
    uri TEXT PRIMARY KEY REFERENCES circle_records(uri) ON DELETE CASCADE,
    space_uri TEXT NOT NULL REFERENCES circles(space_uri) ON DELETE CASCADE,
    post_uri TEXT NOT NULL REFERENCES circle_records(uri) ON DELETE CASCADE,
    author_did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (space_uri, post_uri, author_did)
);

CREATE TABLE circle_repo_sync_state (
    space_uri TEXT NOT NULL REFERENCES circles(space_uri) ON DELETE CASCADE,
    author_did TEXT NOT NULL,
    last_rev TEXT NOT NULL,
    last_hash BYTEA NOT NULL,
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (space_uri, author_did)
);

CREATE TABLE circle_notifications (
    id UUID PRIMARY KEY,
    recipient_did TEXT NOT NULL,
    space_uri TEXT NOT NULL REFERENCES circles(space_uri) ON DELETE CASCADE,
    actor_did TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('reply','like','invite')),
    subject_uri TEXT,
    is_read BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE circle_preferences (
    space_uri TEXT NOT NULL REFERENCES circles(space_uri) ON DELETE CASCADE,
    member_did TEXT NOT NULL,
    muted BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (space_uri, member_did)
);

CREATE TABLE circle_reports (
    id UUID PRIMARY KEY,
    reporter_did TEXT NOT NULL,
    space_uri TEXT NOT NULL REFERENCES circles(space_uri) ON DELETE CASCADE,
    subject_uri TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('spam','abuse','other')),
    details TEXT CHECK (char_length(details) <= 500),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE circle_rejections (
    uri_hash BYTEA PRIMARY KEY,
    reason_code TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth_jti_nonce (
    jti TEXT PRIMARY KEY,
    issuer_did TEXT NOT NULL,
    audience TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX circle_records_feed_idx ON circle_records (space_uri, indexed_at DESC, uri DESC);
CREATE INDEX circle_notifications_feed_idx ON circle_notifications (recipient_did, created_at DESC, id DESC);
CREATE INDEX circle_repo_sync_writer_idx ON circle_repo_sync_state (space_uri, author_did);
CREATE INDEX circle_member_cache_idx ON circle_member_cache (space_uri, member_did);
