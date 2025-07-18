package service

import (
	"github.com/taekwondodev/go-PassKey-Authentication/internal/dto"

	"github.com/google/uuid"
)

func (s *service) Refresh(req dto.RefreshTokenRequest) (*dto.TokenResponse, error) {
	claims, err := s.jwt.ValidateJWT(req.RefreshToken)
	if err != nil {
		return nil, err
	}

	accessToken, _, err := s.jwt.GenerateJWT(claims.Username, claims.Role, uuid.MustParse(claims.Subject))
	if err != nil {
		return nil, err
	}

	return &dto.TokenResponse{
		Message:     "Update token successfully!",
		AccessToken: accessToken,
	}, nil
}
