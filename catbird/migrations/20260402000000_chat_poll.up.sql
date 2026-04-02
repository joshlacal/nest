CREATE TABLE chat_poll_state (
    account_did         TEXT PRIMARY KEY,
    chat_cursor         TEXT,
    next_poll_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_poll_at        TIMESTAMPTZ,
    poll_tier           SMALLINT NOT NULL DEFAULT 2,
    foreground_lease_until TIMESTAMPTZ,
    pds_host            TEXT NOT NULL,
    last_429_at         TIMESTAMPTZ,
    last_retry_after_secs INTEGER,
    last_notified_message_id TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_chat_poll_due
    ON chat_poll_state (next_poll_at)
    WHERE foreground_lease_until IS NULL OR foreground_lease_until < now();

CREATE TABLE chat_muted_convos (
    account_did TEXT NOT NULL,
    convo_id    TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_did, convo_id)
);
