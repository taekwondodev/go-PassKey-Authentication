package config

import "github.com/go-webauthn/webauthn/webauthn"

func InitWebAuthn() (*webauthn.WebAuthn, error) {
	origins := [1]string{"http://localhost:8080"}

	return webauthn.New(&webauthn.Config{
		RPDisplayName: "go-PassKey-Authentication",
		RPID:          "localhost",
		RPOrigins:     origins[:],
	})
}
