package service

import (
	"context"

	"github.com/taekwondodev/go-PassKey-Authentication/internal/customerrors"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/dto"

	"github.com/google/uuid"
)

func (s *service) Refresh(ctx context.Context, req dto.TokenRequest) (*dto.TokenResponse, error) {
	claims, err := s.jwt.ValidateJWT(req.RefreshToken)
	if err != nil {
		return nil, err
	}

	if blackListed, err := s.repo.IsTokenBlacklisted(ctx, req.RefreshToken); err != nil {
		return nil, err
	} else if blackListed {
		return nil, customerrors.ErrTokenBlacklisted
	}

	accessToken, newRefreshToken, err := s.jwt.GenerateJWT(claims.Username, claims.Role, uuid.MustParse(claims.Subject))
	if err != nil {
		return nil, err
	}

	if err := s.repo.BlacklistToken(ctx, req.RefreshToken, claims.ExpiresAt.Time); err != nil {
		return nil, err
	}

	return &dto.TokenResponse{
		Message:      "Update token successfully!",
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *service) Logout(ctx context.Context, req dto.TokenRequest) (*dto.MessageResponse, error) {
	claims, err := s.jwt.ValidateJWT(req.RefreshToken)
	if err != nil {
		return nil, err
	}

	if err := s.repo.BlacklistToken(ctx, req.RefreshToken, claims.ExpiresAt.Time); err != nil {
		return nil, err
	}

	return &dto.MessageResponse{
		Message: "Logout completed successfully!",
	}, nil
}
