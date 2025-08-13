-- name: CreateUser :one
INSERT INTO users (username) VALUES ($1)
RETURNING *;

-- name: CreateUserWithRole :one
INSERT INTO users (username, role) VALUES ($1, $2)
RETURNING *;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: ActivateUser :exec
UPDATE users SET status = 'active' WHERE id = $1;
