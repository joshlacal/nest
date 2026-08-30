-- Migration: chat_activity_limits (down)

DROP INDEX IF EXISTS idx_chat_muted_convos_account;
DROP INDEX IF EXISTS idx_activity_subscriptions_subscriber_subject;
