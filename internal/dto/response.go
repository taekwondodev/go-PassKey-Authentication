package dto

type BeginResponse struct {
	Options   any    `json:"options"`
	SessionID string `json:"session_id"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

type RefreshTokenResponse struct {
	Message     string `json:"message"`
	AccessToken string `json:"access_token"`
}
