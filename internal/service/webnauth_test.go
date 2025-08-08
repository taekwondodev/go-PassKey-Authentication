package service

import (
	"context"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/db"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/dto"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/models"
	"github.com/taekwondodev/go-PassKey-Authentication/pkg"
)

// Test constants
const (
	testUsername  = "testuser"
	testAdminUser = "admin"
	userRole      = "user"
	adminRole     = "admin"
	emptyString   = ""
)

// Test messages
const (
	msgSuccessfulRegistration = "successful registration"
	msgSaveUserFails          = "save user fails"
	msgSaveSessionFails       = "save register session fails"
	msgAdminRegistration      = "admin role registration"
	msgEmptyUsername          = "empty username"
	msgEmptyRole              = "empty role"
)

type mockAuthRepository struct {
	mock.Mock
}

type mockToken struct {
	mock.Mock
}

func (m *mockToken) GenerateJWT(username, role string, sub uuid.UUID) (string, string, error) {
	args := m.Called(username, role, sub)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *mockToken) ValidateJWT(tokenString string) (*pkg.Claims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pkg.Claims), args.Error(1)
}

func (m *mockAuthRepository) SaveUser(ctx context.Context, username, role string) (db.User, error) {
	args := m.Called(ctx, username, role)
	return args.Get(0).(db.User), args.Error(1)
}

func (m *mockAuthRepository) GetUserByUsername(ctx context.Context, username string) (db.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return db.User{}, args.Error(1)
	}
	return args.Get(0).(db.User), args.Error(1)
}

func (m *mockAuthRepository) SaveRegisterSession(ctx context.Context, u models.WebAuthnUser, sessionData any) (uuid.UUID, error) {
	args := m.Called(ctx, u, sessionData)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *mockAuthRepository) SaveLoginSession(ctx context.Context, u models.WebAuthnUser, sessionData any) (uuid.UUID, error) {
	args := m.Called(ctx, u, sessionData)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *mockAuthRepository) GetRegisterSession(ctx context.Context, sessionID uuid.UUID) (db.WebauthnSession, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return db.WebauthnSession{}, args.Error(1)
	}
	return args.Get(0).(db.WebauthnSession), args.Error(1)
}

func (m *mockAuthRepository) GetLoginSession(ctx context.Context, sessionID uuid.UUID) (db.WebauthnSession, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return db.WebauthnSession{}, args.Error(1)
	}
	return args.Get(0).(db.WebauthnSession), args.Error(1)
}

func (m *mockAuthRepository) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *mockAuthRepository) SaveCredentials(ctx context.Context, userID uuid.UUID, credentials *webauthn.Credential) error {
	args := m.Called(ctx, userID, credentials)
	return args.Error(0)
}

func (m *mockAuthRepository) GetCredentialsByUserID(ctx context.Context, userID uuid.UUID) ([]db.Credential, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]db.Credential), args.Error(1)
}

func (m *mockAuthRepository) UpdateCredentials(ctx context.Context, credential *webauthn.Credential) error {
	args := m.Called(ctx, credential)
	return args.Error(0)
}

func (m *mockAuthRepository) BlacklistToken(ctx context.Context, token string, expiration time.Time) error {
	args := m.Called(ctx, token, expiration)
	return args.Error(0)
}

func (m *mockAuthRepository) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func createTestWebAuthn(t *testing.T) *webauthn.WebAuthn {
	config := &webauthn.Config{
		RPDisplayName: "Test Application",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:3000", "https://localhost:3000"},
		Debug:         true, // debug mode for testing
	}

	webAuthn, err := webauthn.New(config)
	if err != nil {
		t.Fatal("Failed to create WebAuthn instance for testing: " + err.Error())
	}

	return webAuthn
}

func setupService(t *testing.T) (*mockAuthRepository, *mockToken, AuthService) {
	mockRepo := new(mockAuthRepository)
	mockToken := new(mockToken)
	testWebAuthn := createTestWebAuthn(t)
	authService := New(mockRepo, mockToken, testWebAuthn)
	return mockRepo, mockToken, authService
}

func createTestUser(username, role string) db.User {
	return db.User{
		ID:       uuid.New(),
		Username: username,
		Role:     role,
	}
}

func setupSuccessfulSaveUser(mockRepo *mockAuthRepository, username, role string) db.User {
	testUser := createTestUser(username, role)
	mockRepo.On("SaveUser", mock.Anything, username, role).Return(testUser, nil)
	return testUser
}

func setupSuccessfulSaveSession(mockRepo *mockAuthRepository) {
	mockRepo.On("SaveRegisterSession", mock.Anything, mock.AnythingOfType("models.WebAuthnUser"), mock.Anything).Return(uuid.New(), nil)
}

func setupFailedSaveUser(mockRepo *mockAuthRepository, username, role string) {
	mockRepo.On("SaveUser", mock.Anything, username, role).Return(db.User{}, assert.AnError)
}

func setupFailedSaveSession(mockRepo *mockAuthRepository) {
	mockRepo.On("SaveRegisterSession", mock.Anything, mock.AnythingOfType("models.WebAuthnUser"), mock.Anything).Return(uuid.Nil, assert.AnError)
}

func validateSuccessfulResult(t *testing.T, result *dto.BeginResponse) {
	assert.NotNil(t, result)
	assert.NotNil(t, result.Options)
	assert.NotEmpty(t, result.SessionID)
	_, err := uuid.Parse(result.SessionID)
	assert.NoError(t, err)
}

func validateNilResult(t *testing.T, result *dto.BeginResponse) {
	assert.Nil(t, result)
}

/*********************************************************************************************************************************/

func TestBeginRegister(t *testing.T) {
	testCases := []struct {
		name           string
		username       string
		role           string
		setupMocks     func(*mockAuthRepository)
		expectedError  bool
		validateResult func(*testing.T, *dto.BeginResponse)
	}{
		{
			name:     msgSuccessfulRegistration,
			username: testUsername,
			role:     userRole,
			setupMocks: func(mockRepo *mockAuthRepository) {
				setupSuccessfulSaveUser(mockRepo, testUsername, userRole)
				setupSuccessfulSaveSession(mockRepo)
			},
			expectedError:  false,
			validateResult: validateSuccessfulResult,
		},
		{
			name:     msgSaveUserFails,
			username: testUsername,
			role:     userRole,
			setupMocks: func(mockRepo *mockAuthRepository) {
				setupFailedSaveUser(mockRepo, testUsername, userRole)
			},
			expectedError:  true,
			validateResult: validateNilResult,
		},
		{
			name:     msgSaveSessionFails,
			username: testUsername,
			role:     userRole,
			setupMocks: func(mockRepo *mockAuthRepository) {
				setupSuccessfulSaveUser(mockRepo, testUsername, userRole)
				setupFailedSaveSession(mockRepo)
			},
			expectedError:  true,
			validateResult: validateNilResult,
		},
		{
			name:     msgAdminRegistration,
			username: testAdminUser,
			role:     adminRole,
			setupMocks: func(mockRepo *mockAuthRepository) {
				setupSuccessfulSaveUser(mockRepo, testAdminUser, adminRole)
				setupSuccessfulSaveSession(mockRepo)
			},
			expectedError:  false,
			validateResult: validateSuccessfulResult,
		},
		{
			name:     msgEmptyUsername,
			username: emptyString,
			role:     userRole,
			setupMocks: func(mockRepo *mockAuthRepository) {
				setupFailedSaveUser(mockRepo, emptyString, userRole)
			},
			expectedError:  true,
			validateResult: validateNilResult,
		},
		{
			name:     msgEmptyRole,
			username: testUsername,
			role:     emptyString,
			setupMocks: func(mockRepo *mockAuthRepository) {
				setupFailedSaveUser(mockRepo, testUsername, emptyString)
			},
			expectedError:  true,
			validateResult: validateNilResult,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			mockRepo, _, authService := setupService(t)
			tc.setupMocks(mockRepo)

			// Execute
			result, err := authService.BeginRegister(context.Background(), tc.username, tc.role)

			// Assert
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			tc.validateResult(t, result)
			mockRepo.AssertExpectations(t)
		})
	}
}
