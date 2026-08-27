-- Cached moderation verdict and display label for an actor as seen by a recipient.
-- Populated on-demand from authenticated app.bsky.actor.getProfile calls during push
-- decision evaluation, eliminating local graph/list mirror synchronization.
CREATE TABLE actor_moderation_verdict (
    recipient_did TEXT NOT NULL,
    actor_did     TEXT NOT NULL,
    verdict       JSONB NOT NULL,
    display_label TEXT,
    fetched_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (recipient_did, actor_did)
);

-- Index on fetched_at allows periodic pruning of stale cached verdicts by age.
CREATE INDEX actor_moderation_verdict_fetched_at_idx ON actor_moderation_verdict (fetched_at);
