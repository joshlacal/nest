ALTER TABLE circles ADD COLUMN space_type TEXT NOT NULL DEFAULT 'blue.catbird.circle';

ALTER TABLE circle_records
  ADD COLUMN key_version BIGINT NULL,
  ADD COLUMN stale_key BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE circle_keys (
  space_uri TEXT NOT NULL REFERENCES circles(space_uri) ON DELETE CASCADE,
  key_version BIGINT NOT NULL,
  uri TEXT NOT NULL,
  cid TEXT NOT NULL,
  owner_did TEXT NOT NULL,
  record_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  indexed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (space_uri, key_version)
);

ALTER TABLE circle_reports
  ADD COLUMN disclosed_post_key BYTEA NULL,
  ADD COLUMN disclosed_media JSONB NULL;
