DROP INDEX IF EXISTS idx_user_devices_active_device_token_owner;

ALTER TABLE user_devices
    DROP CONSTRAINT IF EXISTS user_devices_device_token_format_check,
    DROP CONSTRAINT IF EXISTS user_devices_platform_format_check,
    DROP CONSTRAINT IF EXISTS user_devices_app_id_format_check,
    DROP CONSTRAINT IF EXISTS user_devices_service_did_format_check;

-- Rows deactivated by the forward migration are intentionally not reactivated:
-- restoring duplicate active owners would recreate the security boundary break.
