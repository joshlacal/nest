-- Account status is a separately confirmed serving gate, never a membership grant.
CREATE TABLE circle_account_status (
    did TEXT PRIMARY KEY,
    active BOOLEAN NOT NULL,
    status TEXT,
    pds_url TEXT NOT NULL,
    confirmed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_seq BIGINT NOT NULL CHECK (source_seq >= 0),
    relay_url TEXT NOT NULL,
    CHECK (NOT active OR status IS NULL)
);

-- One row per configured source. Cursor only advances after lifecycle effects.
CREATE TABLE circle_identity_cursor (
    relay_url TEXT PRIMARY KEY,
    cursor BIGINT NOT NULL CHECK (cursor >= 0),
    last_event_at TIMESTAMPTZ,
    last_received_at TIMESTAMPTZ,
    last_connected_at TIMESTAMPTZ,
    reconciled_at TIMESTAMPTZ,
    reconcile_after TEXT NOT NULL DEFAULT '',
    caught_up BOOLEAN NOT NULL DEFAULT false,
    replay_invalid BOOLEAN NOT NULL DEFAULT false,
    blocked_reason TEXT
);
CREATE INDEX circle_account_status_inactive_idx ON circle_account_status(did) WHERE NOT active;
