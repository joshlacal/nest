-- Circle Projection Outbox
--
-- Tracks pending and delivered projections to Circle AppViews.
-- Guarantees at-least-once projection delivery after authoritative PDS operations.

CREATE TABLE circle_projection_outbox (
    id UUID PRIMARY KEY,
    operation_key TEXT NOT NULL UNIQUE,
    actor_did TEXT NOT NULL,
    session_id TEXT NOT NULL,
    space_uri TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('circle_upsert','member_add','member_remove','circle_delete')),
    payload JSONB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('intent','executing','pending','delivered','failed')) DEFAULT 'intent',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error_code TEXT,
    execution_started_at TIMESTAMPTZ,
    claim_token UUID,
    parent_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_circle_projection_outbox_parent ON circle_projection_outbox (parent_id);

CREATE INDEX idx_circle_projection_outbox_due ON circle_projection_outbox (state, next_attempt_at) WHERE state = 'pending';
CREATE INDEX idx_circle_projection_outbox_space ON circle_projection_outbox (space_uri);
