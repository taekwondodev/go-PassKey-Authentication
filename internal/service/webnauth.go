package service

import (
	"context"
	"encoding/json"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/customerrors"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/db"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/dto"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/models"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/repository"
	"github.com/taekwondodev/go-PassKey-Authentication/pkg"
)

type AuthService interface {
	BeginRegister(ctx context.Context, username, role string) (*dto.BeginResponse, error)
	FinishRegister(ctx context.Context, req *dto.FinishRequest) (*dto.MessageResponse, error)
	BeginLogin(ctx context.Context, username string) (*dto.BeginResponse, error)
	FinishLogin(ctx context.Context, req *dto.FinishRequest) (*dto.TokenResponse, error)
	Refresh(req dto.RefreshTokenRequest) (*dto.TokenResponse, error)
}

type service struct {
	repo     repository.UserRepository
	jwt      pkg.Token
	webauthn *webauthn.WebAuthn
}

func New(repo repository.UserRepository, jwt pkg.Token, webauthn *webauthn.WebAuthn) AuthService {
	return &service{repo: repo, jwt: jwt, webauthn: webauthn}
}

func (s *service) BeginRegister(ctx context.Context, username, role string) (*dto.BeginResponse, error) {
	user, err := s.repo.SaveUser(ctx, username, role)
	if err != nil {
		return nil, err
	}
	webauthnUser := models.New(user, nil)
	opts, sessionData, err := s.webauthn.BeginRegistration(webauthnUser)
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

func (s *service) FinishRegister(ctx context.Context, req *dto.FinishRequest) (*dto.MessageResponse, error) {
	sessionUUID, user, err := s.getUser(ctx, req)
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

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(req.Credentials)
	if err != nil {
		return nil, customerrors.ErrInvalidCredentials
	}

	webauthnUser := models.New(user, nil)
	credential, err := s.webauthn.CreateCredential(webauthnUser, sessionData, parsedResponse)
	if err != nil {
		return nil, customerrors.ErrInvalidCredentials
	}

	if err := s.repo.SaveCredentials(ctx, user.ID, credential); err != nil {
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
	opts, sessionData, err := s.webauthn.BeginLogin(webauthnUser)
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

func (s *service) FinishLogin(ctx context.Context, req *dto.FinishRequest) (*dto.TokenResponse, error) {
	sessionUUID, user, err := s.getUser(ctx, req)
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

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(req.Credentials)
	if err != nil {
		return nil, customerrors.ErrInvalidCredentials
	}

	webauthnUser := models.New(user, creds)
	credential, err := s.webauthn.ValidateLogin(webauthnUser, sessionData, parsedResponse)
	if err != nil {
		return nil, customerrors.ErrInvalidCredentials
	}

	if err := s.repo.UpdateCredentials(ctx, credential); err != nil {
		return nil, err
	}

	if err := s.repo.DeleteSession(ctx, sessionUUID); err != nil {
		return nil, err
	}

	accessToken, refreshToken, err := s.jwt.GenerateJWT(req.Username, user.Role, user.ID)
	if err != nil {
		return nil, customerrors.ErrInternalServer
	}

	return &dto.TokenResponse{
		Message:      "Login completed successfully!",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *service) getUser(ctx context.Context, req *dto.FinishRequest) (uuid.UUID, db.User, error) {
	sessionUUID, err := uuid.Parse(req.SessionID)
	if err != nil {
		return uuid.Nil, db.User{}, customerrors.ErrSessionIdInvalid
	}

	user, err := s.repo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return uuid.Nil, db.User{}, err
	}
	return sessionUUID, user, nil
}
