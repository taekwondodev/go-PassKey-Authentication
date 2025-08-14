package dto

import (
	"encoding/json"
	"strings"

	"github.com/taekwondodev/go-PassKey-Authentication/internal/customerrors"
)

type BeginRequest struct {
	Username string `json:"username"`
	Role     string `json:"role,omitzero"`
}

func (r BeginRequest) Validate() error {
	return checkUsername(r.Username)
}

type FinishRequest struct {
	Username    string          `json:"username"`
	SessionID   string          `json:"session_id"`
	Credentials json.RawMessage `json:"credentials"`
}

func (r FinishRequest) Validate() error {
	if err := checkUsername(r.Username); err != nil {
		return err
	}

	if strings.TrimSpace(r.SessionID) == "" {
		return customerrors.ErrSessionIdInvalid
	}

	if err := validateCredentialsJSON(r.Credentials); err != nil {
		return err
	}

	return nil
}

func checkUsername(username string) error {
	if strings.TrimSpace(username) == "" {
		return customerrors.ErrInvalidUsername
	}
	if len(username) < 3 {
		return customerrors.ErrInvalidUsername
	}
	return nil
}

func validateCredentialsJSON(credentials json.RawMessage) error {
	if len(credentials) == 0 {
		return customerrors.ErrInvalidCredentials
	}

	if !json.Valid(credentials) {
		return customerrors.ErrInvalidCredentials
	}

	// Need to be an object
	trimmed := strings.TrimSpace(string(credentials))
	if !strings.HasPrefix(trimmed, "{") {
		return customerrors.ErrInvalidCredentials
	}

	return nil
}
