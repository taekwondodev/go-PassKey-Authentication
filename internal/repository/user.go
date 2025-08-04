package repository

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/config"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/customerrors"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/db"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/models"
)

type UserRepository interface {
	SaveUser(ctx context.Context, username, role string) (db.User, error)
	GetUserByUsername(ctx context.Context, username string) (db.User, error)
	SaveRegisterSession(ctx context.Context, u models.WebAuthnUser, sessionData any) (uuid.UUID, error)
	SaveLoginSession(ctx context.Context, u models.WebAuthnUser, sessionData any) (uuid.UUID, error)
	GetRegisterSession(ctx context.Context, sessionID uuid.UUID) (db.WebauthnSession, error)
	GetLoginSession(ctx context.Context, sessionID uuid.UUID) (db.WebauthnSession, error)
	DeleteSession(ctx context.Context, sessionID uuid.UUID) error
	SaveCredentials(ctx context.Context, userID uuid.UUID, credentials *webauthn.Credential) error
	GetCredentialsByUserID(ctx context.Context, userID uuid.UUID) ([]db.Credential, error)
	UpdateCredentials(ctx context.Context, credential *webauthn.Credential) error
	BlacklistToken(ctx context.Context, token string, expiration time.Time) error
	IsTokenBlacklisted(ctx context.Context, token string) (bool, error)
}

type repository struct {
	queries  *db.Queries
	client   *redis.Client
	hashSalt []byte
}

func New(queries *db.Queries, redis *config.RedisConfig) UserRepository {
	return &repository{
		queries:  queries,
		client:   redis.Client,
		hashSalt: redis.HashSalt,
	}
}

func (r *repository) SaveUser(ctx context.Context, username, role string) (db.User, error) {
	user, err := r.queries.GetUserByUsername(ctx, username)
	if err != nil {
		if role != "" {
			user, err = r.queries.CreateUserWithRole(ctx, db.CreateUserWithRoleParams{
				Username: username,
				Role:     role,
			})
		} else {
			user, err = r.queries.CreateUser(ctx, username)
		}
		if err != nil {
			return db.User{}, customerrors.ErrInternalServer
		}

		return user, nil
	}

	return user, customerrors.ErrUsernameAlreadyExists
}

func (r *repository) GetUserByUsername(ctx context.Context, username string) (db.User, error) {
	user, err := r.queries.GetUserByUsername(ctx, username)
	if err != nil {
		return db.User{}, customerrors.ErrUserNotFound
	}

	return user, nil
}
