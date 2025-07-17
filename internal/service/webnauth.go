package service

import (
	"context"
	"encoding/json"
	"go-PassKey-Authentication/internal/customerrors"
	"go-PassKey-Authentication/internal/dto"
	"go-PassKey-Authentication/internal/models"
	"go-PassKey-Authentication/internal/repository"
	"go-PassKey-Authentication/pkg"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

type AuthService interface {
	BeginRegister(ctx context.Context, username string) (*dto.BeginRegisterResponse, error)
	FinishRegister(ctx context.Context, req dto.FinishRegisterRequest) (*dto.MessageResponse, error)
	Refresh(req dto.RefreshTokenRequest) (*dto.MessageResponse, error)
}

type service struct {
	repo repository.UserRepository
	jwt  pkg.Token
}

func New(repo repository.UserRepository, jwt pkg.Token) AuthService {
	return &service{repo: repo, jwt: jwt}
}

func (s *service) BeginRegister(ctx context.Context, username string) (*dto.BeginRegisterResponse, error) {
	user, err := s.repo.SaveUser(ctx, username)
	webauthnUser := models.New(user, nil)
	opts, sessionData, err := webauthn.WebAuthn.BeginRegistration(webauthnUser)
	if err != nil {
		return nil, customerrors.ErrInternalServer
	}

	sessionID, err := s.repo.SaveSession(ctx, *webauthnUser, sessionData)
	if err != nil {
		return nil, customerrors.ErrInternalServer
	}

	return &dto.BeginRegisterResponse{
		Options:   opts,
		SessionID: sessionID.String(),
	}, nil
}

func (s *service) FinishRegister(ctx context.Context, req dto.FinishRegisterRequest) (*dto.MessageResponse, error) {
	sessionUUID, err := uuid.Parse(req.SessionID)
	if err != nil {
		return nil, customerrors.ErrSessionIdInvalid
	}

	user, err := s.repo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return nil, err
	}

	session, err := s.repo.GetSession(ctx, sessionUUID)
	if err != nil {
		return nil, err
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(session.Data, &sessionData); err != nil {
		return nil, customerrors.ErrInternalServer
	}

	webauthnUser := models.New(user, nil)
	credential, err := webauthn.WebAuthn.FinishRegistration(webauthnUser, sessionData, req.Credentials)
	if err != nil {
		return nil, customerrors.ErrInvalidCredentials
	}

	if err := s.repo.SaveCredential(ctx, user.ID, credential); err != nil {
		return nil, err
	}

	if err := s.repo.DeleteSession(ctx, sessionUUID); err != nil {
		return nil, err
	}

	return &dto.MessageResponse{
		Message: "Registration completed successfully!",
	}, nil
}
