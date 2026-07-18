ALTER TABLE activity_subscriptions
    DROP CONSTRAINT IF EXISTS activity_subscriptions_subject_did_canonical;

ALTER TABLE activity_subscriptions
    DROP CONSTRAINT IF EXISTS activity_subscriptions_subscriber_did_canonical;

-- Deliberately retain activity_subscriptions_invalid_quarantine and do not
-- restore its rows to the live relation. Reintroducing malformed DIDs would
-- repopulate quota and hydration with data the application cannot safely
-- update or delete. An operator may inspect and reconcile the retained rows
-- explicitly after correcting their identities.
