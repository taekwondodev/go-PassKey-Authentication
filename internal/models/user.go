package models

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/db"
)

type User interface {
	WebAuthnID() []byte
	WebAuthnName() string
	WebAuthnDisplayName() string
	WebAuthnCredentials() []webauthn.Credential
}

type WebAuthnUser struct {
	ID          uuid.UUID
	Username    string
	Role        string
	Credentials []webauthn.Credential
}

func New(u db.User, creds []db.Credential) *WebAuthnUser {
	var webauthnCreds []webauthn.Credential
	for _, c := range creds {
		transports := newTransports(c)
		attestationFormat := convertAttestationFormat(c)
		aaguid := convertAAGUID(c)

		webauthnCreds = append(webauthnCreds, webauthn.Credential{
			ID:              c.ID,
			PublicKey:       c.PublicKey,
			AttestationType: attestationFormat,
			Transport:       transports,
			Flags: webauthn.CredentialFlags{
				BackupEligible: c.BackupEligible,
				BackupState:    c.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguid,
				SignCount: uint32(c.SignCount),
			},
		})
	}

	return &WebAuthnUser{
		ID:          u.ID,
		Username:    u.Username,
		Role:        u.Role,
		Credentials: webauthnCreds,
	}
}

func convertAttestationFormat(c db.Credential) string {
	var attestationFormat string
	if c.AttestationFormat.Valid {
		attestationFormat = c.AttestationFormat.String
	}
	return attestationFormat
}

func convertAAGUID(c db.Credential) []byte {
	if c.Aaguid != uuid.Nil {
		return c.Aaguid[:]
	}
	return nil
}

func newTransports(c db.Credential) []protocol.AuthenticatorTransport {
	var transports []protocol.AuthenticatorTransport
	for _, t := range c.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}

	if len(transports) == 0 {
		// Most modern authenticators support internal transport
		transports = append(transports, protocol.Internal)
	}

	return transports
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.ID[:]
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.Username
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.Username
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}
