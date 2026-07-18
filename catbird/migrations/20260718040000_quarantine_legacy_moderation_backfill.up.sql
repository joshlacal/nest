-- Rows backfilled by 20260715100000 cannot be attributed to the DID whose
-- authenticated PDS produced the legacy global snapshot. Quarantine every such
-- row instead of treating it as tenant-local moderation state.
DELETE FROM moderation_list_members_by_user;

-- ensure_fresh consults push_accounts.last_list_sync_at before any list lookup.
-- Clearing both freshness markers forces the next active use of each DID to
-- complete its authenticated, DID-scoped refresh before list state is trusted.
UPDATE moderation_list_subscriptions
SET last_synced_at = NULL,
    updated_at = NOW()
WHERE last_synced_at IS NOT NULL;

UPDATE push_accounts
SET last_list_sync_at = NULL,
    updated_at = NOW()
WHERE last_list_sync_at IS NOT NULL;
