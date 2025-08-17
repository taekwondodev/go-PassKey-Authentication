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

	origins := [1]string{originConfig.URL}

	return webauthn.New(&webauthn.Config{
		RPDisplayName: "go-PassKey-Authentication",
		RPID:          originConfig.RPID,
		RPOrigins:     origins[:],
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationPreferred,
		},
	})
}
