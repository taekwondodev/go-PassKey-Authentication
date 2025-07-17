-- name: CreateWebAuthnSession :exec
INSERT INTO webauthn_sessions (id, user_id, data, purpose, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetWebAuthnSession :one
SELECT * FROM webauthn_sessions WHERE id = $1 AND purpose = $2;

-- name: DeleteWebAuthnSession :exec
DELETE FROM webauthn_sessions WHERE id = $1;
