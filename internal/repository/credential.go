package repository

import (
	"context"
	"go-PassKey-Authentication/internal/customerrors"
	"go-PassKey-Authentication/internal/db"

	"github.com/google/uuid"
)

func (r *repository) SaveCredentials(ctx context.Context, userID uuid.UUID, credentials db.Credential) error {
	err := r.queries.CreateCredential(ctx, db.CreateCredentialParams{
		ID:                credentials.ID,
		UserID:            userID,
		PublicKey:         credentials.PublicKey,
		SignCount:         int64(credentials.Authenticator.SignCount),
		Transports:        credentials.Authenticator.Transport,
		Aaguid:            uuid.Nil, // puoi parsare credential.Authenticator.AAGUID se vuoi
		AttestationFormat: credentials.AttestationType,
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

func (r *repository) UpdateCredentials(ctx context.Context, credential db.Credential) error {
	err := r.queries.UpdateCredentialSignCount(ctx, db.UpdateCredentialSignCountParams{
		ID:        credential.ID,
		SignCount: credential.Authenticator.SignCount,
	})

	if err != nil {
		return customerrors.ErrInternalServer
	}

	return nil
}
