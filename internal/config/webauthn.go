package config

import (
	"fmt"
	"os"

	"github.com/go-webauthn/webauthn/webauthn"
)

func InitWebAuthn() (*webauthn.WebAuthn, error) {
	origin := os.Getenv("ORIGIN")
	if origin == "" {
		return nil, fmt.Errorf("ORIGIN not defined")
	}

	origins := [1]string{origin}

	return webauthn.New(&webauthn.Config{
		RPDisplayName: "go-PassKey-Authentication",
		RPID:          "localhost",
		RPOrigins:     origins[:],
	})
}
