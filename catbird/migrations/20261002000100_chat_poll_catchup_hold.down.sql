DROP INDEX IF EXISTS idx_chat_poll_unheld_due;
ALTER TABLE chat_notified_watermarks DROP COLUMN last_read_rev;
ALTER TABLE chat_poll_state
    DROP COLUMN last_successful_poll_at,
    DROP COLUMN catch_up_required_at,
    DROP COLUMN catch_up_reason;
