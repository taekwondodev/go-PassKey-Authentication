-- name: CreateCredential :exec
INSERT INTO credentials (
    id, user_id, public_key, sign_count, transports, aaguid, attestation_format, backup_eligible, backup_state
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
);

-- name: GetCredentialsByUserID :many
SELECT * FROM credentials WHERE user_id = $1;

-- name: UpdateCredentialSignCount :exec
UPDATE credentials
SET
    sign_count = $2,
    last_used_at = NOW()
WHERE id = $1;
