-- Durable event identities outlive queue completion. Do not purge these without
-- an explicit replay/retention policy: their purpose is to fence producer replay.
-- No message text or device token is retained in either receipt table.
CREATE TABLE push_event_receipts (
    dedupe_key TEXT PRIMARY KEY,
    recipient_did TEXT NOT NULL,
    auth_generation BIGINT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'completed', 'held')),
    hold_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE push_device_deliveries (
    dedupe_key TEXT NOT NULL REFERENCES push_event_receipts(dedupe_key),
    device_id UUID NOT NULL,
    delivery_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    state TEXT NOT NULL CHECK (state IN ('attempting', 'accepted', 'retry', 'held', 'invalid')),
    attempts INTEGER NOT NULL DEFAULT 1,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (dedupe_key, device_id)
);
CREATE INDEX idx_push_device_deliveries_held ON push_device_deliveries(state)
    WHERE state IN ('attempting', 'held');
ALTER TABLE push_event_queue ADD COLUMN delivery_hold_reason TEXT;

-- Existing queue identities are preserved; no backlog is sent, cleared, or
-- cursor moved by this migration. This also protects replay during cutover.
INSERT INTO push_event_receipts(dedupe_key, recipient_did, auth_generation)
SELECT dedupe_key, recipient_did, auth_generation FROM push_event_queue
ON CONFLICT DO NOTHING;

-- Legacy queue payloads cannot establish a read-revision fence. Hold alert
-- delivery explicitly while preserving payloads/cursors for approved catch-up.
UPDATE push_event_queue
SET delivery_hold_reason='legacy_chat_missing_log_rev',
    last_error='legacy_chat_missing_log_rev', updated_at=NOW()
WHERE notification_type='chat_message'
  AND (COALESCE(jsonb_typeof(event_record_json->'logRev'),'null') <> 'string'
       OR NULLIF(btrim(event_record_json->>'logRev'),'') IS NULL);
UPDATE push_event_receipts r
SET state='held',hold_reason=q.delivery_hold_reason,updated_at=NOW()
FROM push_event_queue q
WHERE q.dedupe_key=r.dedupe_key AND q.delivery_hold_reason IS NOT NULL;
