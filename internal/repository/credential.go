package repository

import (
	"context"
	"encoding/base64"

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

	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)

	err = r.queries.CreateCredential(ctx, db.CreateCredentialParams{
		ID:                credentialID,
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
	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)

	err := r.queries.UpdateCredentialSignCount(ctx, db.UpdateCredentialSignCountParams{
		ID:        credentialID,
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

	aaguid, err := uuid.FromBytes(credential.Authenticator.AAGUID)

	var attestationFormat pgtype.Text
	if credential.AttestationType != "" {
		attestationFormat.String = credential.AttestationType
		attestationFormat.Valid = true
	}

	return transports, aaguid, attestationFormat, err
}
