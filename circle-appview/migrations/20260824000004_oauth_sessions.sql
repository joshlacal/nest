CREATE TABLE oauth_sessions (
    user_did TEXT PRIMARY KEY,
    access_token BYTEA NOT NULL,
    refresh_token BYTEA,
    token_endpoint TEXT NOT NULL,
    auth_server_iss TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    scope TEXT NOT NULL,
    dpop_key BYTEA NOT NULL CHECK (octet_length(dpop_key) >= 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX oauth_sessions_expires_at_idx ON oauth_sessions (expires_at);
