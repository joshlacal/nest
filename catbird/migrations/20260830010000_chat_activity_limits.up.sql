-- Migration: chat_activity_limits (up)
-- 1. Deterministically clean up invalid chat mute rows and trim over-quota rows (> 1000 per account)
DELETE FROM chat_muted_convos
WHERE length(convo_id) = 0
   OR length(convo_id) > 256
   OR convo_id !~ '^[a-zA-Z0-9_\-\.\:\/]+$';

WITH ranked_mutes AS (
    SELECT account_did, convo_id,
           ROW_NUMBER() OVER (
               PARTITION BY account_did
               ORDER BY updated_at DESC, convo_id ASC
           ) as rn
    FROM chat_muted_convos
)
DELETE FROM chat_muted_convos c
USING ranked_mutes r
WHERE c.account_did = r.account_did
  AND c.convo_id = r.convo_id
  AND r.rn > 1000;

-- 2. Deterministically clean up invalid activity subscription rows and trim over-quota rows (> 1000 per subscriber)
DELETE FROM activity_subscriptions
WHERE length(subject_did) < 8
   OR length(subject_did) > 256
   OR NOT (subject_did LIKE 'did:%')
   OR subject_did !~ '^[a-zA-Z0-9\:\%\_\-\.]+$';

WITH ranked_subs AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY subscriber_did
               ORDER BY updated_at DESC, created_at DESC, subject_did ASC
           ) as rn
    FROM activity_subscriptions
)
DELETE FROM activity_subscriptions a
USING ranked_subs r
WHERE a.id = r.id
  AND r.rn > 1000;

-- 3. Add performance and keyset pagination indexes
CREATE INDEX IF NOT EXISTS idx_activity_subscriptions_subscriber_subject
    ON activity_subscriptions (subscriber_did, subject_did ASC);

CREATE INDEX IF NOT EXISTS idx_chat_muted_convos_account
    ON chat_muted_convos (account_did);
