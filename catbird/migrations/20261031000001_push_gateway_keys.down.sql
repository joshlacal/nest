-- Intentionally fail closed. Enrolled client wake keys and encrypted provider
-- tokens cannot be reconstructed automatically if discarded; preserve gateway
-- key state and use an explicitly reviewed data-preserving rollback procedure.
DO $$ BEGIN
    RAISE EXCEPTION 'Push gateway keys require an explicitly reviewed data-preserving rollback';
END $$;
