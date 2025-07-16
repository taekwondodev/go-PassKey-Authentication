package repository

import (
	"context"
	"go-PassKey-Authentication/internal/db"
)

type UserRepository interface {
	CreateUser(ctx context.Context, name string) (db.User, error)
	ListUsers(ctx context.Context) ([]db.User, error)
}

type repository struct {
	queries *db.Queries
}

func New(queries *db.Queries) UserRepository {
	return &repository{queries: queries}
}

func (r *repository) CreateUser(ctx context.Context, name string) (db.User, error) {
	return r.queries.CreateUser(ctx, name)
}

func (r *repository) ListUsers(ctx context.Context) ([]db.User, error) {
	return r.queries.ListUsers(ctx)
}
