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

	if len(r.Credentials) == 0 {
		return customerrors.ErrInvalidCredentials
	}
	if !json.Valid(r.Credentials) {
		return customerrors.ErrInvalidCredentials
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
