-- Rollback migration for push security hardening (Task 2)
DROP INDEX IF EXISTS idx_push_event_queue_lease_token;
ALTER TABLE push_event_queue DROP COLUMN IF EXISTS lease_version;
ALTER TABLE push_event_queue DROP COLUMN IF EXISTS lease_token;
DROP INDEX IF EXISTS idx_user_devices_active_token;
DROP INDEX IF EXISTS idx_push_accounts_auth_generation;
ALTER TABLE push_event_queue DROP COLUMN IF EXISTS auth_generation;
ALTER TABLE push_accounts DROP COLUMN IF EXISTS auth_generation;
