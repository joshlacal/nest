CREATE TABLE IF NOT EXISTS moderation_list_members_by_user (
    user_did TEXT NOT NULL,
    list_uri TEXT NOT NULL,
    subject_did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_did, list_uri, subject_did)
);

CREATE INDEX IF NOT EXISTS idx_mod_list_members_by_user_subject
    ON moderation_list_members_by_user(user_did, subject_did);

CREATE INDEX IF NOT EXISTS idx_mod_list_members_by_user_list
    ON moderation_list_members_by_user(user_did, list_uri);

INSERT INTO moderation_list_members_by_user (user_did, list_uri, subject_did)
SELECT DISTINCT subscriptions.user_did, members.list_uri, members.subject_did
FROM moderation_list_members AS members
INNER JOIN moderation_list_subscriptions AS subscriptions
    ON subscriptions.list_uri = members.list_uri
ON CONFLICT (user_did, list_uri, subject_did) DO NOTHING;
