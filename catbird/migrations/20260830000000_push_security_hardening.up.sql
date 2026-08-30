-- Additive migration for push security hardening (Task 2)

-- Step 1: Deterministic backfill before creating the unique index.
-- Finding 5: Enforce single active owner per device token at database level.
-- If pre-existing data has duplicate active registrations for the same device_token,
-- keep only the single newest active registration (ordered by last_registered_at DESC, updated_at DESC, created_at DESC, id DESC),
-- and deactivate all older duplicates.
WITH ranked_duplicate_tokens AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY device_token
               ORDER BY last_registered_at DESC, updated_at DESC, created_at DESC, id DESC
           ) as rn
    FROM user_devices
    WHERE is_active = TRUE
)
UPDATE user_devices
SET is_active = FALSE,
    last_invalidated_at = NOW(),
    last_error = 'duplicate_token_migration_backfill',
    updated_at = NOW()
WHERE id IN (
    SELECT id FROM ranked_duplicate_tokens WHERE rn > 1
);

-- Step 2: Deterministic backfill for per-account quota excess.
-- If any DID currently has > 10 active devices, keep only the 10 newest active devices,
-- and deactivate older active devices exceeding the quota.
WITH ranked_account_devices AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY did
               ORDER BY last_registered_at DESC, updated_at DESC, created_at DESC, id DESC
           ) as rn
    FROM user_devices
    WHERE is_active = TRUE
)
UPDATE user_devices
SET is_active = FALSE,
    last_invalidated_at = NOW(),
    last_error = 'quota_excess_migration_backfill',
    updated_at = NOW()
WHERE id IN (
    SELECT id FROM ranked_account_devices WHERE rn > 10
);

-- Step 3: Create unique partial index on active device tokens.
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_devices_active_token
    ON user_devices (device_token)
    WHERE is_active = TRUE;

-- Step 4: Finding 29 & Deferred Lease Candidate: Fenced queue leases.
ALTER TABLE push_event_queue ADD COLUMN IF NOT EXISTS lease_token UUID;
ALTER TABLE push_event_queue ADD COLUMN IF NOT EXISTS lease_version BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_push_event_queue_lease_token
    ON push_event_queue (lease_token)
    WHERE lease_token IS NOT NULL;

-- Step 5: Finding Critical 2 & Important 4: Authorization generation & fencing.
ALTER TABLE push_accounts ADD COLUMN IF NOT EXISTS auth_generation BIGINT NOT NULL DEFAULT 1;
ALTER TABLE push_event_queue ADD COLUMN IF NOT EXISTS auth_generation BIGINT NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_push_accounts_auth_generation
    ON push_accounts (account_did, auth_generation);
