-- Intentionally non-restorative. The deleted rows had no trustworthy producer-DID
-- provenance, so a down migration must not recreate them or mark the cache fresh.
-- A subsequent authenticated per-DID refresh is the only supported restoration.
SELECT 1;
