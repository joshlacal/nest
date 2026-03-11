CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS push_accounts (
    account_did TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    pds_url TEXT NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_actor_sync_at TIMESTAMPTZ,
    last_list_sync_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did TEXT NOT NULL,
    device_token TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE user_devices DROP CONSTRAINT IF EXISTS user_devices_device_token_key;
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT 'ios';
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS app_id TEXT NOT NULL DEFAULT '';
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS service_did TEXT;
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS age_restricted BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS last_registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS last_invalidated_at TIMESTAMPTZ;
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS last_error TEXT;

CREATE INDEX IF NOT EXISTS idx_user_devices_did ON user_devices(did);
CREATE INDEX IF NOT EXISTS idx_user_devices_active ON user_devices(did, is_active);
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_devices_token_did ON user_devices(device_token, did);

CREATE TABLE IF NOT EXISTS push_preferences (
    account_did TEXT PRIMARY KEY REFERENCES push_accounts(account_did) ON DELETE CASCADE,
    preferences_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS activity_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscriber_did TEXT NOT NULL,
    subject_did TEXT NOT NULL,
    include_posts BOOLEAN NOT NULL DEFAULT TRUE,
    include_replies BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(subscriber_did, subject_did)
);

CREATE INDEX IF NOT EXISTS idx_activity_subscriptions_subscriber
    ON activity_subscriptions (subscriber_did);
CREATE INDEX IF NOT EXISTS idx_activity_subscriptions_subject
    ON activity_subscriptions (subject_did);

CREATE TABLE IF NOT EXISTS user_mutes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_did TEXT NOT NULL,
    muted_did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_did, muted_did)
);

CREATE INDEX IF NOT EXISTS idx_user_mutes_user_did ON user_mutes(user_did);

CREATE TABLE IF NOT EXISTS user_blocks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_did TEXT NOT NULL,
    blocked_did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_did, blocked_did)
);

CREATE INDEX IF NOT EXISTS idx_user_blocks_user_did ON user_blocks(user_did);

CREATE TABLE IF NOT EXISTS moderation_list_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_did TEXT NOT NULL,
    list_uri TEXT NOT NULL,
    list_purpose TEXT NOT NULL,
    list_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_synced_at TIMESTAMPTZ,
    UNIQUE(user_did, list_uri)
);

CREATE INDEX IF NOT EXISTS idx_mod_lists_user_did ON moderation_list_subscriptions(user_did);
CREATE INDEX IF NOT EXISTS idx_mod_lists_purpose ON moderation_list_subscriptions(list_purpose);

CREATE TABLE IF NOT EXISTS moderation_list_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    list_uri TEXT NOT NULL,
    subject_did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(list_uri, subject_did)
);

CREATE INDEX IF NOT EXISTS idx_mod_list_members_list ON moderation_list_members(list_uri);
CREATE INDEX IF NOT EXISTS idx_mod_list_members_subject ON moderation_list_members(subject_did);
CREATE INDEX IF NOT EXISTS idx_mod_list_members_composite
    ON moderation_list_members(subject_did, list_uri);

CREATE TABLE IF NOT EXISTS thread_mutes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_did TEXT NOT NULL,
    thread_root_uri TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_did, thread_root_uri)
);

CREATE INDEX IF NOT EXISTS idx_thread_mutes_user_did ON thread_mutes(user_did);
CREATE INDEX IF NOT EXISTS idx_thread_mutes_thread_root ON thread_mutes(thread_root_uri);
CREATE INDEX IF NOT EXISTS idx_thread_mutes_composite ON thread_mutes(user_did, thread_root_uri);

CREATE TABLE IF NOT EXISTS push_event_queue (
    id BIGSERIAL PRIMARY KEY,
    recipient_did TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    notification_type TEXT NOT NULL,
    event_cid TEXT NOT NULL,
    event_path TEXT NOT NULL,
    subject_uri TEXT,
    thread_root_uri TEXT,
    event_record_json JSONB NOT NULL,
    event_timestamp BIGINT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    leased_until TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE push_event_queue ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE push_event_queue ADD COLUMN IF NOT EXISTS available_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE push_event_queue ADD COLUMN IF NOT EXISTS leased_until TIMESTAMPTZ;
ALTER TABLE push_event_queue ADD COLUMN IF NOT EXISTS last_error TEXT;
ALTER TABLE push_event_queue ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE push_event_queue ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_push_event_queue_ready
    ON push_event_queue (available_at, leased_until);
CREATE INDEX IF NOT EXISTS idx_push_event_queue_recipient
    ON push_event_queue (recipient_did);
