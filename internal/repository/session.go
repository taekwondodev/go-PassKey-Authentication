package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/taekwondodev/go-PassKey-Authentication/internal/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/customerrors"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/db"
)

func (r *repository) SaveRegisterSession(ctx context.Context, u models.WebAuthnUser, sessionData any) (uuid.UUID, error) {
	sessionID := uuid.New()
	data, err := json.Marshal(sessionData)
	if err != nil {
		return uuid.Nil, customerrors.ErrInternalServer
	}

	err = r.queries.CreateWebAuthnSession(ctx, db.CreateWebAuthnSessionParams{
		ID:        sessionID,
		UserID:    u.ID,
		Purpose:   "registration",
		Data:      data,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(30 * time.Minute), Valid: true},
	})

	return sessionID, err
}

func (r *repository) SaveLoginSession(ctx context.Context, u models.WebAuthnUser, sessionData any) (uuid.UUID, error) {
	sessionID := uuid.New()
	data, err := json.Marshal(sessionData)
	if err != nil {
		return uuid.Nil, customerrors.ErrInternalServer
	}

	err = r.queries.CreateWebAuthnSession(ctx, db.CreateWebAuthnSessionParams{
		ID:        sessionID,
		UserID:    u.ID,
		Purpose:   "login",
		Data:      data,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(30 * time.Minute), Valid: true},
	})

	return sessionID, err
}

func (r *repository) GetRegisterSession(ctx context.Context, sessionID uuid.UUID) (db.WebauthnSession, error) {
	session, err := r.queries.GetWebAuthnSession(ctx, db.GetWebAuthnSessionParams{
		ID:      sessionID,
		Purpose: "registration",
	})

	if err != nil {
		return db.WebauthnSession{}, customerrors.ErrSessionNotFound
	}
	return session, nil
}

func (r *repository) GetLoginSession(ctx context.Context, sessionID uuid.UUID) (db.WebauthnSession, error) {
	session, err := r.queries.GetWebAuthnSession(ctx, db.GetWebAuthnSessionParams{
		ID:      sessionID,
		Purpose: "login",
	})

	if err != nil {
		return db.WebauthnSession{}, customerrors.ErrSessionNotFound
	}
	return session, nil
}

func (r *repository) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	err := r.queries.DeleteWebAuthnSession(ctx, sessionID)
	if err != nil {
		return customerrors.ErrInternalServer
	}
	return nil
}
