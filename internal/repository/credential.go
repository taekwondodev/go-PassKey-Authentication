package repository

import (
	"context"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/customerrors"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/db"
)

func (r *repository) SaveCredentials(ctx context.Context, userID uuid.UUID, credential *webauthn.Credential) error {
	transports, aaguid, attestationFormat, err := r.convertToDbCredential(credential)
	if err != nil {
		return customerrors.ErrInvalidAAGUID
	}

	err = r.queries.CreateCredential(ctx, db.CreateCredentialParams{
		ID:                credential.ID,
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
		ID:        credential.ID,
		SignCount: int64(credential.Authenticator.SignCount),
	})

	if err != nil {
		return customerrors.ErrInternalServer
	}

	return nil
}

func (r *repository) convertToDbCredential(credential *webauthn.Credential) ([]string, uuid.UUID, pgtype.Text, error) {
	var transports []string
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}

	var aaguid uuid.UUID
	var err error

	if len(credential.Authenticator.AAGUID) == 16 {
		aaguid, err = uuid.FromBytes(credential.Authenticator.AAGUID)
		if err != nil {
			return nil, uuid.Nil, pgtype.Text{}, err
		}
	} else {
		// Use a null UUID for invalid/empty AAGUIDs
		aaguid = uuid.Nil
	}

	var attestationFormat pgtype.Text
	if credential.AttestationType != "" {
		attestationFormat.String = credential.AttestationType
		attestationFormat.Valid = true
	}

	return transports, aaguid, attestationFormat, nil
}
