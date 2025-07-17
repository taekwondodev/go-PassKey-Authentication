package repository

import (
	"context"
	"go-PassKey-Authentication/internal/customerrors"
	"go-PassKey-Authentication/internal/db"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func (r *repository) SaveCredentials(ctx context.Context, userID uuid.UUID, credential *webauthn.Credential) error {
	var transports []string
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}

	aaguid, err := uuid.FromBytes(credential.Authenticator.AAGUID)
	if err != nil {
		return customerrors.ErrInvalidAAGUID
	}

	var attestationFormat pgtype.Text
	if credential.AttestationType != "" {
		attestationFormat.String = credential.AttestationType
		attestationFormat.Valid = true
	}

	err = r.queries.CreateCredential(ctx, db.CreateCredentialParams{
		ID:                string(credential.ID),
		UserID:            userID,
		PublicKey:         credential.PublicKey,
		SignCount:         int64(credential.Authenticator.SignCount),
		Transports:        transports,
		Aaguid:            aaguid,
		AttestationFormat: attestationFormat,
	})

	if err != nil {
		return customerrors.ErrInternalServer
	}

	return nil
}

func (r *repository) GetCredentialsByUserID(ctx context.Context, userID uuid.UUID) ([]db.Credential, error) {
	credentials, err := r.queries.GetCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, customerrors.ErrInternalServer
	}

	return credentials, nil
}

func (r *repository) UpdateCredentials(ctx context.Context, credential *webauthn.Credential) error {
	err := r.queries.UpdateCredentialSignCount(ctx, db.UpdateCredentialSignCountParams{
		ID:        string(credential.ID),
		SignCount: int64(credential.Authenticator.SignCount),
	})

	if err != nil {
		return customerrors.ErrInternalServer
	}

	return nil
}
