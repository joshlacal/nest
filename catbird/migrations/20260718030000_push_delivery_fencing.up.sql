ALTER TABLE push_event_queue
    ADD COLUMN IF NOT EXISTS lease_owner UUID;
