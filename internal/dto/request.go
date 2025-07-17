package dto

import "encoding/json"

type BeginRequest struct {
	Username string `json:"username"`
	Role     string `json:"role,omitzero"`
}

type FinishRequest struct {
	Username    string          `json:"username"`
	SessionID   string          `json:"session_id"`
	Credentials json.RawMessage `json:"credentials"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}
