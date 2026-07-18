CREATE TABLE IF NOT EXISTS moderation_snapshot_generations (
    user_did TEXT PRIMARY KEY,
    actor_generation BIGINT NOT NULL DEFAULT 0 CHECK (actor_generation >= 0),
    list_generation BIGINT NOT NULL DEFAULT 0 CHECK (list_generation >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
