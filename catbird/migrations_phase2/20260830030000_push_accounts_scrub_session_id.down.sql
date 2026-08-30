-- Phase 2 Cutover Down Migration (Manual / Standalone)
--
-- Notice: Plaintext bearer session strings destroyed during Phase 2 scrub cannot be
-- reconstructed from SHA-256 fingerprints. Rolling back Phase 2 will relax the NOT NULL
-- constraint on session_fingerprint, but cannot restore plaintext bearer session IDs.

ALTER TABLE push_accounts ALTER COLUMN session_fingerprint DROP NOT NULL;
