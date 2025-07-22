CREATE TABLE credentials (
    id TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL,
    transports TEXT[],
    aaguid UUID NOT NULL,
    attestation_format TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);

CREATE TABLE webauthn_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data JSONB NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('registration', 'login')),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_webauthn_sessions_id_purpose ON webauthn_sessions(id, purpose);
