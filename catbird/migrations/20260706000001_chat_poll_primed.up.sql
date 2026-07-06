ALTER TABLE chat_poll_state ADD COLUMN primed_at TIMESTAMPTZ;

-- Already-enrolled accounts (a non-null chat_cursor from a prior poll) have
-- already fast-forwarded past their backlog under the old gate; without this
-- backfill they'd get primed_at = NULL and silently re-enter the prime pass
-- after deploy, re-watermarking past any messages that arrive during the
-- forced re-prime without ever pushing for them.
UPDATE chat_poll_state SET primed_at = NOW() WHERE chat_cursor IS NOT NULL;
