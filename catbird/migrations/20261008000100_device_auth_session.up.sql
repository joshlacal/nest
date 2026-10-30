-- Persist notification-device ownership in the registration transaction. Legacy
-- NULL rows require verified Redis linkage or an explicitly incomplete cleanup.
ALTER TABLE user_devices ADD COLUMN auth_session_fingerprint TEXT
    CHECK (auth_session_fingerprint IS NULL OR auth_session_fingerprint ~ '^[0-9a-f]{64}$');
