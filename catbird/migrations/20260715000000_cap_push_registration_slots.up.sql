WITH ranked_slots AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY did
            ORDER BY is_active DESC, last_registered_at DESC, id DESC
        ) AS slot_rank
    FROM user_devices
)
DELETE FROM user_devices AS device
USING ranked_slots AS ranked
WHERE device.id = ranked.id
  AND ranked.slot_rank > 8;
