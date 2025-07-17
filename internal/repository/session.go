package repository

import (
	"context"
	"encoding/json"
	"go-PassKey-Authentication/internal/customerrors"
	"go-PassKey-Authentication/internal/db"
	"go-PassKey-Authentication/internal/models"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/pgtype"
)

func (r *repository) SaveRegisterSession(ctx context.Context, u models.WebAuthnUser, sessionData any) (uuid.UUID, error) {
	sessionID := uuid.New()
	data, _ := json.Marshal(sessionData)

	err := r.queries.CreateWebAuthnSession(ctx, db.CreateWebAuthnSessionParams{
		ID:        sessionID,
		UserID:    u.ID,
		Purpose:   "registration",
		Data:      data,
		ExpiresAt: pgtype.Timestamp{Time: time.Now().Add(30 * time.Minute), Valid: true},
	})

	return sessionID, err
}

func (r *repository) SaveLoginSession(ctx context.Context, u models.WebAuthnUser, sessionData any) (uuid.UUID, error) {
	sessionID := uuid.New()
	data, _ := json.Marshal(sessionData)

	err := r.queries.CreateWebAuthnSession(ctx, db.CreateWebAuthnSessionParams{
		ID:        sessionID,
		UserID:    u.ID,
		Purpose:   "login",
		Data:      data,
		ExpiresAt: pgtype.Timestamp{Time: time.Now().Add(30 * time.Minute), Valid: true},
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
