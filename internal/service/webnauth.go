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
	BeginRegister(ctx context.Context, username string) (*dto.BeginResponse, error)
	FinishRegister(ctx context.Context, req dto.FinishRequest) (*dto.MessageResponse, error)
	BeginLogin(ctx context.Context, username string) (*dto.BeginResponse, error)
	FinishLogin(ctx context.Context, req dto.FinishRequest) (*dto.TokenResponse, error)
	Refresh(req dto.RefreshTokenRequest) (*dto.TokenResponse, error)
}

type service struct {
	repo repository.UserRepository
	jwt  pkg.Token
}

func New(repo repository.UserRepository, jwt pkg.Token) AuthService {
	return &service{repo: repo, jwt: jwt}
}

func (s *service) BeginRegister(ctx context.Context, username string) (*dto.BeginResponse, error) {
	user, err := s.repo.SaveUser(ctx, username)
	webauthnUser := models.New(user, nil)
	opts, sessionData, err := webauthn.WebAuthn.BeginRegistration(webauthnUser)
	if err != nil {
		return nil, customerrors.ErrInternalServer
	}

	sessionID, err := s.repo.SaveRegisterSession(ctx, *webauthnUser, sessionData)
	if err != nil {
		return nil, customerrors.ErrInternalServer
	}

	return &dto.BeginResponse{
		Options:   opts,
		SessionID: sessionID.String(),
	}, nil
}

func (s *service) FinishRegister(ctx context.Context, req dto.FinishRequest) (*dto.MessageResponse, error) {
	sessionUUID, err := uuid.Parse(req.SessionID)
	if err != nil {
		return nil, customerrors.ErrSessionIdInvalid
	}

	user, err := s.repo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return nil, err
	}

	session, err := s.repo.GetRegisterSession(ctx, sessionUUID)
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

func (s *service) BeginLogin(ctx context.Context, username string) (*dto.BeginResponse, error) {
	user, err := s.repo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	creds, err := s.repo.GetCredentialsByUserID(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	webauthnUser := models.New(user, creds)
	opts, sessionData, err := webauthn.WebAuthn.BeginLogin(webauthnUser)
	if err != nil {
		return nil, customerrors.ErrInternalServer
	}

	sessionID, err := s.repo.SaveLoginSession(ctx, *webauthnUser, sessionData)
	if err != nil {
		return nil, err
	}

	return &dto.BeginResponse{
		Options:   opts,
		SessionID: sessionID.String(),
	}, nil
}

func (s *service) FinishLogin(ctx context.Context, req dto.FinishRequest) (*dto.TokenResponse, error) {
	sessionUUID, err := uuid.Parse(req.SessionID)
	if err != nil {
		return nil, customerrors.ErrSessionIdInvalid
	}

	user, err := s.repo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return nil, err
	}

	creds, err := s.repo.GetCredentialsByUserID(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	session, err := s.repo.GetLoginSession(ctx, sessionUUID)
	if err != nil {
		return nil, err
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(session.Data, &sessionData); err != nil {
		return nil, customerrors.ErrInternalServer
	}

	webauthnUser := models.New(user, creds)
	credential, err := webauthn.WebAuthn.FinishLogin(webauthnUser, sessionData, req.Credentials)
	if err != nil {
		return nil, customerrors.ErrInvalidCredentials
	}

	if err := s.repo.UpdateCredentials(ctx, credential); err != nil {
		return nil, err
	}

	if err := s.repo.DeleteSession(ctx, sessionUUID); err != nil {
		return nil, err
	}

	// ruolo non deve essere hardcoded
	accessToken, refreshToken, err := s.jwt.GenerateJWT(req.Username, "user", user.ID)
	if err != nil {
		return nil, customerrors.ErrInternalServer
	}

	return &dto.TokenResponse{
		Message:      "Login completed successfully!",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
