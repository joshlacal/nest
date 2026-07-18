ALTER TABLE push_event_queue
    DROP COLUMN IF EXISTS lease_owner;
