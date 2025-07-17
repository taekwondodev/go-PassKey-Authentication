package dto

type BeginResponse struct {
	Options   any    `json:"options"`
	SessionID string `json:"session_id"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

type TokenResponse struct {
	Message      string `json:"message"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitzero"`
}
