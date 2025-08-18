package config

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func InitWebAuthn() (*webauthn.WebAuthn, error) {
	originConfig, err := LoadOriginConfig()
	if err != nil {
		return nil, err
	}

	origins := [1]string{originConfig.FrontendURL}

	return webauthn.New(&webauthn.Config{
		RPDisplayName: "go-PassKey-Authentication",
		RPID:          originConfig.BackendDomain,
		RPOrigins:     origins[:],
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationPreferred,
		},
	})
}
