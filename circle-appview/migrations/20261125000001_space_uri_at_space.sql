-- Space URIs moved from `at://{spaceDid}/space/{rest}` to `at:space/{spaceDid}/{rest}`
-- (atproto permissioned-data-alpha, 2026-11-24). Rewrite every stored Space ref and
-- in-space record URI in place, mirroring the reference PDS `rewriteSpaceUris`.
--
-- * Only values still in the old form are touched, so a re-run is a no-op.
-- * A DID contains no `/`, so the first `/` after `at://` always ends the space DID.
-- * Record VALUES (`record_json`) are left as they are: their CIDs cover them. Reply/like
--   refs inside them are normalized leniently at ingest (validator::from_legacy_space_uri).
-- * `circle_rejections.uri_hash` is SHA-256 of the old record URI and cannot be rewritten;
--   those rows simply stop matching and age out via prune_rejections.
--
-- Columns covered:
--   circles.space_uri
--   circle_member_cache.space_uri, circle_member_cache_meta.space_uri
--   circle_records.uri, .space_uri, .parent_uri, .root_uri
--   circle_likes.uri, .space_uri, .post_uri
--   circle_repo_sync_state.space_uri
--   circle_notifications.space_uri, .subject_uri, .source_uri
--   circle_preferences.space_uri
--   circle_reports.space_uri, .subject_uri
--   circle_rejections.space_uri
--   circle_sweep_checkpoint.last_space_uri
--   circle_notify_registrations.space_uri
--   circle_former_members.space_uri
--   circle_keys.space_uri, .uri
--   circle_space_notify_tokens.space_uri
--
-- circles.space_uri and circle_records.uri are referenced by foreign keys without
-- ON UPDATE CASCADE, so those foreign keys are dropped and re-created (same name and
-- definition) around the rewrite. sqlx runs this file in one transaction.
--
-- Down (manual; sqlx migrations here are forward-only): the same block with
--   regexp_replace(col, '^at:space/([^/]+)/', 'at://\1/space/') WHERE col ~ '^at:space/[^/]+/'

DO $$
DECLARE
    fk RECORD;
    target RECORD;
    saved_fks JSONB := '[]'::jsonb;
BEGIN
    FOR fk IN
        SELECT conrelid::regclass::text AS tbl, conname, pg_get_constraintdef(oid) AS def
          FROM pg_constraint
         WHERE contype = 'f'
           AND confrelid IN ('circles'::regclass, 'circle_records'::regclass)
    LOOP
        saved_fks := saved_fks || jsonb_build_object('tbl', fk.tbl, 'name', fk.conname, 'def', fk.def);
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', fk.tbl, fk.conname);
    END LOOP;

    FOR target IN
        SELECT * FROM (VALUES
            ('circles', 'space_uri'),
            ('circle_member_cache', 'space_uri'),
            ('circle_member_cache_meta', 'space_uri'),
            ('circle_records', 'uri'),
            ('circle_records', 'space_uri'),
            ('circle_records', 'parent_uri'),
            ('circle_records', 'root_uri'),
            ('circle_likes', 'uri'),
            ('circle_likes', 'space_uri'),
            ('circle_likes', 'post_uri'),
            ('circle_repo_sync_state', 'space_uri'),
            ('circle_notifications', 'space_uri'),
            ('circle_notifications', 'subject_uri'),
            ('circle_notifications', 'source_uri'),
            ('circle_preferences', 'space_uri'),
            ('circle_reports', 'space_uri'),
            ('circle_reports', 'subject_uri'),
            ('circle_rejections', 'space_uri'),
            ('circle_sweep_checkpoint', 'last_space_uri'),
            ('circle_notify_registrations', 'space_uri'),
            ('circle_former_members', 'space_uri'),
            ('circle_keys', 'space_uri'),
            ('circle_keys', 'uri'),
            ('circle_space_notify_tokens', 'space_uri')
        ) AS t(tbl, col)
    LOOP
        EXECUTE format(
            'UPDATE %I SET %I = regexp_replace(%I, %L, %L) WHERE %I ~ %L',
            target.tbl, target.col, target.col,
            '^at://([^/]+)/space/', 'at:space/\1/',
            target.col, '^at://[^/]+/space/'
        );
    END LOOP;

    FOR fk IN SELECT * FROM jsonb_to_recordset(saved_fks) AS s(tbl TEXT, name TEXT, def TEXT)
    LOOP
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s', fk.tbl, fk.name, fk.def);
    END LOOP;
END $$;
