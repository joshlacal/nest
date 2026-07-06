-- Per-(account, convo) high-water mark of the last chat log rev that was
-- either notified or read. CreateMessage events at rev <= last_rev are
-- never pushed. Replaces the single-scalar last_notified_message_id
-- (column retained, no longer read).
CREATE TABLE chat_notified_watermarks (
    account_did TEXT NOT NULL,
    convo_id    TEXT NOT NULL,
    last_rev    TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_did, convo_id)
);
