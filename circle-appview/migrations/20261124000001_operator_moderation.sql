-- Operator moderation (Signal model).
--
-- Reports go from the app through the reporter's PDS straight to Catbird's
-- Ozone service and carry ids only. When the operator takes an account down
-- in Ozone, Ozone labels the account DID `!takedown` (or `!suspend` with an
-- expiry). The label poller (src/moderation/mod.rs) mirrors those labels here,
-- and startup drops any row the current configuration no longer enforces.
-- Newest `cts` wins per (src, did, val); a negation lifts the restriction.
CREATE TABLE IF NOT EXISTS moderation_account_labels (
    src TEXT NOT NULL,
    did TEXT NOT NULL CHECK (did ~ '^did:(plc|web):[A-Za-z0-9._:%-]+$'),
    val TEXT NOT NULL CHECK (char_length(val) BETWEEN 1 AND 128),
    cts TIMESTAMPTZ NOT NULL,
    exp TIMESTAMPTZ,
    neg BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (src, did, val)
);

CREATE INDEX IF NOT EXISTS moderation_account_labels_live_idx
    ON moderation_account_labels (did) WHERE NOT neg;

-- Every account whose content must drop out of views: deactivated, suspended
-- or deleted at its PDS, or taken down by the operator. Feed, thread,
-- notification and listing queries filter authors and owners through this.
CREATE OR REPLACE VIEW circle_inactive_dids AS
    SELECT did FROM circle_account_status WHERE NOT active
    UNION
    SELECT did FROM moderation_account_labels
     WHERE NOT neg AND (exp IS NULL OR exp > now());

-- The operator must never hold the means to decrypt Circle content. Wipe any
-- keys earlier app builds disclosed with a report, then drop the columns.
UPDATE circle_reports
   SET disclosed_post_key = NULL, disclosed_media = NULL
 WHERE disclosed_post_key IS NOT NULL OR disclosed_media IS NOT NULL;

ALTER TABLE circle_reports
    DROP COLUMN IF EXISTS disclosed_post_key,
    DROP COLUMN IF EXISTS disclosed_media;
