-- A claim is an attempt, not evidence that its cursor reached a successful page.
-- Existing initialized accounts have no attested success timestamp and must be
-- reviewed before resuming; do not backfill this from last_poll_at.
ALTER TABLE chat_poll_state
    ADD COLUMN last_successful_poll_at TIMESTAMPTZ,
    ADD COLUMN catch_up_required_at TIMESTAMPTZ,
    ADD COLUMN catch_up_reason TEXT;

-- Distinguish read suppression from the combined processed/notified watermark.
ALTER TABLE chat_notified_watermarks ADD COLUMN last_read_rev TEXT;

CREATE INDEX idx_chat_poll_unheld_due ON chat_poll_state (next_poll_at)
    WHERE catch_up_required_at IS NULL;

-- Retain the generation across poll unenrollment so an old background snapshot
-- cannot overwrite a later explicit mute/unmute or a newer complete snapshot.
CREATE TABLE chat_mute_sync_generations (
    account_did TEXT PRIMARY KEY,
    generation BIGINT NOT NULL DEFAULT 0
);
