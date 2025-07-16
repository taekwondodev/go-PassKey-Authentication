-- name: CreateUser :one
INSERT INTO users (name) VALUES ($1)
RETURNING id, name;

-- name: ListUsers :many
SELECT id, name FROM users;
