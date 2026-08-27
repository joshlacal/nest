-- Recreate the mirror's schema. Contents are NOT restored: these tables only
-- ever held a cache of appview state, and the ADR-022 code path does not
-- repopulate them.
CREATE TABLE IF NOT EXISTS user_mutes (
    user_did   TEXT NOT NULL,
    muted_did  TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_did, muted_did)
);

CREATE TABLE IF NOT EXISTS user_blocks (
    user_did    TEXT NOT NULL,
    blocked_did TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_did, blocked_did)
);

CREATE TABLE IF NOT EXISTS moderation_list_subscriptions (
    id             UUID NOT NULL DEFAULT gen_random_uuid(),
    user_did       TEXT NOT NULL,
    list_uri       TEXT NOT NULL,
    list_purpose   TEXT NOT NULL,
    list_name      TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_synced_at TIMESTAMPTZ,
    PRIMARY KEY (id),
    UNIQUE (user_did, list_uri)
);

CREATE TABLE IF NOT EXISTS moderation_list_members (
    id          UUID NOT NULL DEFAULT gen_random_uuid(),
    list_uri    TEXT NOT NULL,
    subject_did TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    UNIQUE (list_uri, subject_did)
);

ALTER TABLE push_accounts ADD COLUMN IF NOT EXISTS last_actor_sync_at TIMESTAMPTZ;
ALTER TABLE push_accounts ADD COLUMN IF NOT EXISTS last_list_sync_at TIMESTAMPTZ;
