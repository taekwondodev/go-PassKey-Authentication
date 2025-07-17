package repository

import (
	"context"
	"go-PassKey-Authentication/internal/customerrors"
	"go-PassKey-Authentication/internal/db"
	"go-PassKey-Authentication/internal/models"

	"github.com/google/uuid"
)

type UserRepository interface {
	SaveUser(ctx context.Context, username string) (db.User, error)
	SaveSession(ctx context.Context, u models.WebAuthnUser, sessionData any) (uuid.UUID, error)
	GetUserByUsername(ctx context.Context, username string) (db.User, error)
	GetSession(ctx context.Context, sessionID uuid.UUID) (db.WebauthnSession, error)
	SaveCredentials(ctx context.Context, userID uuid.UUID, credentials db.Credential) error
	DeleteSession(ctx context.Context, sessionID uuid.UUID) error
}

type repository struct {
	queries *db.Queries
}

func New(queries *db.Queries) UserRepository {
	return &repository{queries: queries}
}

func (r *repository) SaveUser(ctx context.Context, username string) (db.User, error) {
	user, err := r.queries.GetUserByUsername(ctx, username)
	if err != nil {
		user, err = r.queries.CreateUser(ctx, username)
		if err != nil {
			return db.User{}, customerrors.ErrInternalServer
		}

		return user, nil
	}

	return db.User{}, customerrors.ErrUsernameAlreadyExists
}

func (r *repository) GetUserByUsername(ctx context.Context, username string) (db.User, error) {
	user, err := r.queries.GetUserByUsername(ctx, username)
	if err != nil {
		return db.User{}, customerrors.ErrUserNotFound
	}

	return user, nil
}
