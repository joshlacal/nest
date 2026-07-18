-- Quarantine malformed legacy rows before validating the same 2,048-byte
-- canonical DID boundary enforced by jacquard-common in the application.
-- Activity subscription list, quota, and hydration paths read the live table
-- directly, so removal from that relation also invalidates their visibility.
CREATE TABLE IF NOT EXISTS activity_subscriptions_invalid_quarantine (
    source_id UUID PRIMARY KEY,
    subscriber_did TEXT NOT NULL,
    subject_did TEXT NOT NULL,
    include_posts BOOLEAN NOT NULL,
    include_replies BOOLEAN NOT NULL,
    source_created_at TIMESTAMPTZ NOT NULL,
    source_updated_at TIMESTAMPTZ NOT NULL,
    quarantine_reason TEXT NOT NULL CHECK (
        quarantine_reason IN (
            'invalid_subscriber_did',
            'invalid_subject_did',
            'invalid_subscriber_and_subject_did'
        )
    ),
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

WITH classified AS (
    SELECT
        subscriptions.*,
        NOT (
            octet_length(subscriber_did) <= 2048
            AND subscriber_did ~ '^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$'
        ) AS invalid_subscriber,
        NOT (
            octet_length(subject_did) <= 2048
            AND subject_did ~ '^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$'
        ) AS invalid_subject
    FROM activity_subscriptions AS subscriptions
), invalid AS (
    SELECT
        *,
        CASE
            WHEN invalid_subscriber AND invalid_subject
                THEN 'invalid_subscriber_and_subject_did'
            WHEN invalid_subscriber THEN 'invalid_subscriber_did'
            ELSE 'invalid_subject_did'
        END AS quarantine_reason
    FROM classified
    WHERE invalid_subscriber OR invalid_subject
)
INSERT INTO activity_subscriptions_invalid_quarantine (
    source_id,
    subscriber_did,
    subject_did,
    include_posts,
    include_replies,
    source_created_at,
    source_updated_at,
    quarantine_reason
)
SELECT
    id,
    subscriber_did,
    subject_did,
    include_posts,
    include_replies,
    created_at,
    updated_at,
    quarantine_reason
FROM invalid
ON CONFLICT (source_id) DO NOTHING;

-- Delete only rows whose complete source payload is durably represented in
-- quarantine. A conflicting, mismatched source_id therefore fails closed at
-- constraint validation instead of losing the live row.
DELETE FROM activity_subscriptions AS subscriptions
USING activity_subscriptions_invalid_quarantine AS quarantine
WHERE subscriptions.id = quarantine.source_id
  AND subscriptions.subscriber_did = quarantine.subscriber_did
  AND subscriptions.subject_did = quarantine.subject_did
  AND subscriptions.include_posts = quarantine.include_posts
  AND subscriptions.include_replies = quarantine.include_replies
  AND subscriptions.created_at = quarantine.source_created_at
  AND subscriptions.updated_at = quarantine.source_updated_at
  AND (
      NOT (
          octet_length(subscriptions.subscriber_did) <= 2048
          AND subscriptions.subscriber_did ~ '^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$'
      )
      OR NOT (
          octet_length(subscriptions.subject_did) <= 2048
          AND subscriptions.subject_did ~ '^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$'
      )
  );

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'activity_subscriptions_subscriber_did_canonical'
          AND conrelid = 'activity_subscriptions'::regclass
    ) THEN
        ALTER TABLE activity_subscriptions
            ADD CONSTRAINT activity_subscriptions_subscriber_did_canonical
            CHECK (
                octet_length(subscriber_did) <= 2048
                AND subscriber_did ~ '^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$'
            ) NOT VALID;
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'activity_subscriptions_subject_did_canonical'
          AND conrelid = 'activity_subscriptions'::regclass
    ) THEN
        ALTER TABLE activity_subscriptions
            ADD CONSTRAINT activity_subscriptions_subject_did_canonical
            CHECK (
                octet_length(subject_did) <= 2048
                AND subject_did ~ '^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$'
            ) NOT VALID;
    END IF;
END
$$;

ALTER TABLE activity_subscriptions
    VALIDATE CONSTRAINT activity_subscriptions_subscriber_did_canonical;

ALTER TABLE activity_subscriptions
    VALIDATE CONSTRAINT activity_subscriptions_subject_did_canonical;

COMMENT ON TABLE activity_subscriptions_invalid_quarantine
    IS 'Legacy activity subscription rows removed from live quota and hydration because a DID failed canonical validation.';

COMMENT ON CONSTRAINT activity_subscriptions_subscriber_did_canonical
    ON activity_subscriptions
    IS 'Every activity subscription row requires a canonical AT Protocol subscriber DID of at most 2048 bytes.';

COMMENT ON CONSTRAINT activity_subscriptions_subject_did_canonical
    ON activity_subscriptions
    IS 'Every activity subscription row requires a canonical AT Protocol subject DID of at most 2048 bytes.';
