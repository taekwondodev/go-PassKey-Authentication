package dto

import "encoding/json"

type BeginRegisterRequest struct {
	Username string `json:"username"`
}

type FinishRegisterRequest struct {
	Username    string          `json:"username"`
	SessionID   string          `json:"session_id"`
	Credentials json.RawMessage `json:"credentials"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}
