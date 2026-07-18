-- Fail closed for malformed active legacy rows. Keeping the rows inactive
-- preserves operator evidence while ensuring they cannot be delivered. This
-- must run before owner ranking so a newer malformed row cannot displace the
-- newest valid owner and then leave the token with no active owner.
UPDATE user_devices
SET is_active = FALSE,
    apns_environment = NULL,
    last_error = 'invalid_registration_metadata',
    updated_at = clock_timestamp()
WHERE is_active = TRUE
  AND NOT (
      octet_length(device_token) BETWEEN 1 AND 512
      AND device_token ~ '^[A-Za-z0-9._:~-]+$'
      AND octet_length(platform) BETWEEN 1 AND 16
      AND platform = 'ios'
      AND octet_length(app_id) BETWEEN 1 AND 255
      AND app_id ~ '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$'
      AND (
          service_did IS NULL
          OR (
              octet_length(service_did) BETWEEN 1 AND 512
              AND service_did LIKE 'did:%'
              AND service_did ~ '^[!-~]+$'
          )
      )
  );

-- An APNs device token may be actively owned by only one DID. Keep the newest
-- valid registration deterministically; UUID order breaks timestamp ties.
WITH ranked_active_owners AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY device_token
            ORDER BY last_registered_at DESC, id DESC
        ) AS owner_rank
    FROM user_devices
    WHERE is_active = TRUE
)
UPDATE user_devices AS devices
SET is_active = FALSE,
    apns_environment = NULL,
    last_error = 'device_token_transferred',
    updated_at = clock_timestamp()
FROM ranked_active_owners AS ranked
WHERE devices.id = ranked.id
  AND ranked.owner_rank > 1;

CREATE UNIQUE INDEX idx_user_devices_active_device_token_owner
    ON user_devices (device_token)
    WHERE is_active = TRUE;

-- Inactive legacy rows may retain their original values, but no row can become
-- active without satisfying the same bounds enforced by the HTTP boundary.
ALTER TABLE user_devices
    ADD CONSTRAINT user_devices_device_token_format_check
        CHECK (
            NOT is_active
            OR (
                octet_length(device_token) BETWEEN 1 AND 512
                AND device_token ~ '^[A-Za-z0-9._:~-]+$'
            )
        ),
    ADD CONSTRAINT user_devices_platform_format_check
        CHECK (
            NOT is_active
            OR (
                octet_length(platform) BETWEEN 1 AND 16
                AND platform = 'ios'
            )
        ),
    ADD CONSTRAINT user_devices_app_id_format_check
        CHECK (
            NOT is_active
            OR (
                octet_length(app_id) BETWEEN 1 AND 255
                AND app_id ~ '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$'
            )
        ),
    ADD CONSTRAINT user_devices_service_did_format_check
        CHECK (
            NOT is_active
            OR service_did IS NULL
            OR (
                    octet_length(service_did) BETWEEN 1 AND 512
                    AND service_did LIKE 'did:%'
                    AND service_did ~ '^[!-~]+$'
            )
        );
