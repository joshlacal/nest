-- Intentionally fail closed. Rolling the sender binary back would reintroduce
-- duplicate retries and ignore held ambiguous outcomes. Preserve receipt data
-- and use the forward rollback runbook with APNs disabled.
DO $$ BEGIN
    RAISE EXCEPTION 'Push delivery receipts require an explicitly reviewed data-preserving rollback';
END $$;
