package models

import (
	"go-PassKey-Authentication/internal/db"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

type User interface {
	WebAuthnID() []byte
	WebAuthnName() string
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
		webauthnCreds = append(webauthnCreds, webauthn.Credential{
			ID:              []byte(c.ID),
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationFormat,
			Transport:       protocol.AuthenticatorTransport(c.Transports),
			Authenticator: webauthn.Authenticator{
				AAGUID:    [16]byte{}, // Puoi parsare c.AAGUID se necessario
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

func (u *WebAuthnUser) WebAuthnID() uuid.UUID {
	return u.ID
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.Username
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}
