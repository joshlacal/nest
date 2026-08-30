-- Add index on auth_jti_nonce (expires_at) for efficient background cleanup of expired nonces
CREATE INDEX IF NOT EXISTS auth_jti_nonce_expires_at_idx ON auth_jti_nonce (expires_at);

-- Add composite index on auth_jti_nonce (issuer_did, expires_at) for efficient per-issuer active JTI queries
CREATE INDEX IF NOT EXISTS auth_jti_nonce_issuer_expires_idx ON auth_jti_nonce (issuer_did, expires_at);
