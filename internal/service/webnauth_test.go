package service

import (
	"context"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
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

// Test data
var (
	testSessionData = []byte(`{"challenge":"dGVzdA","user_id":"dGVzdA","allowed_credentials":null,"user_verification":"preferred","extensions":null}`)
	testCredentials = []byte(`{"rawId":"test","response":{"clientDataJSON":"test","attestationObject":"test"}}`)
	malformedJSON   = []byte(`{"rawId":"test","response":{"clientDataJSON":"test"`)
)

type mockAuthRepository struct {
	mock.Mock
}

type mockToken struct {
	mock.Mock
}

// Mock implementations
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

// Test utilities
func createTestWebAuthn(t *testing.T) *webauthn.WebAuthn {
	config := &webauthn.Config{
		RPDisplayName: "Test Application",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:3000", "https://localhost:3000"},
		Debug:         true,
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

func createTestSession(userID uuid.UUID, data []byte) db.WebauthnSession {
	return db.WebauthnSession{
		ID:        uuid.New(),
		UserID:    userID,
		Data:      data,
		CreatedAt: pgtype.Timestamp{Time: time.Now(), Valid: true},
	}
}

// Mock setup helpers for BeginRegister tests
type beginMockSetup struct {
	saveUserSuccess    bool
	saveSessionSuccess bool
	username           string
	role               string
}

func (ms *beginMockSetup) apply(mockRepo *mockAuthRepository) {
	if ms.saveUserSuccess {
		testUser := createTestUser(ms.username, ms.role)
		mockRepo.On("SaveUser", mock.Anything, ms.username, ms.role).Return(testUser, nil)
	} else {
		mockRepo.On("SaveUser", mock.Anything, ms.username, ms.role).Return(db.User{}, assert.AnError)
	}

	if ms.saveSessionSuccess {
		mockRepo.On("SaveRegisterSession", mock.Anything, mock.AnythingOfType("models.WebAuthnUser"), mock.Anything).Return(uuid.New(), nil)
	} else if ms.saveUserSuccess {
		// Only mock failed session save if user save was successful (otherwise session save won't be called)
		mockRepo.On("SaveRegisterSession", mock.Anything, mock.AnythingOfType("models.WebAuthnUser"), mock.Anything).Return(uuid.Nil, assert.AnError)
	}
}

// Mock setup helpers for FinishRegister tests
type finishMockSetup struct {
	getUserSuccess       bool
	getSessionSuccess    bool
	sessionIDValidFormat bool
	username             string
	role                 string
	sessionData          []byte
}

func (ms *finishMockSetup) apply(mockRepo *mockAuthRepository) {
	// Only setup mocks if the session ID format is valid (otherwise getUser fails early)
	if ms.sessionIDValidFormat {
		if ms.getUserSuccess {
			testUser := createTestUser(ms.username, ms.role)
			mockRepo.On("GetUserByUsername", mock.Anything, ms.username).Return(testUser, nil)

			if ms.getSessionSuccess {
				session := createTestSession(testUser.ID, ms.sessionData)
				mockRepo.On("GetRegisterSession", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return(session, nil)
			} else {
				mockRepo.On("GetRegisterSession", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return(nil, assert.AnError)
			}
		} else {
			mockRepo.On("GetUserByUsername", mock.Anything, ms.username).Return(nil, assert.AnError)
		}
	}
}

// Generic test case types
type beginRegisterTestCase struct {
	name          string
	username      string
	role          string
	mockSetup     beginMockSetup
	expectedError bool
}

type finishRegisterTestCase struct {
	name          string
	request       *dto.FinishRequest
	mockSetup     finishMockSetup
	expectedError bool
}

// Generic test runner
func runBeginRegisterTests(t *testing.T, testCases []beginRegisterTestCase) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockRepo, _, authService := setupService(t)
			tc.mockSetup.apply(mockRepo)

			result, err := authService.BeginRegister(context.Background(), tc.username, tc.role)

			if tc.expectedError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.NotNil(t, result.Options)
				assert.NotEmpty(t, result.SessionID)
				_, uuidErr := uuid.Parse(result.SessionID)
				assert.NoError(t, uuidErr)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func runFinishRegisterTests(t *testing.T, testCases []finishRegisterTestCase) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockRepo, _, authService := setupService(t)
			tc.mockSetup.apply(mockRepo)

			result, err := authService.FinishRegister(context.Background(), tc.request)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Nil(t, result) // All current test cases expect nil result

			mockRepo.AssertExpectations(t)
		})
	}
}

// Test functions
func TestBeginRegister(t *testing.T) {
	testCases := []beginRegisterTestCase{
		{
			name:     "successful registration",
			username: testUsername,
			role:     userRole,
			mockSetup: beginMockSetup{
				saveUserSuccess:    true,
				saveSessionSuccess: true,
				username:           testUsername,
				role:               userRole,
			},
			expectedError: false,
		},
		{
			name:     "save user fails",
			username: testUsername,
			role:     userRole,
			mockSetup: beginMockSetup{
				saveUserSuccess: false,
				username:        testUsername,
				role:            userRole,
			},
			expectedError: true,
		},
		{
			name:     "save session fails",
			username: testUsername,
			role:     userRole,
			mockSetup: beginMockSetup{
				saveUserSuccess:    true,
				saveSessionSuccess: false,
				username:           testUsername,
				role:               userRole,
			},
			expectedError: true,
		},
		{
			name:     "admin role registration",
			username: testAdminUser,
			role:     adminRole,
			mockSetup: beginMockSetup{
				saveUserSuccess:    true,
				saveSessionSuccess: true,
				username:           testAdminUser,
				role:               adminRole,
			},
			expectedError: false,
		},
		{
			name:     "empty username",
			username: emptyString,
			role:     userRole,
			mockSetup: beginMockSetup{
				saveUserSuccess: false,
				username:        emptyString,
				role:            userRole,
			},
			expectedError: true,
		},
		{
			name:     "empty role",
			username: testUsername,
			role:     emptyString,
			mockSetup: beginMockSetup{
				saveUserSuccess: false,
				username:        testUsername,
				role:            emptyString,
			},
			expectedError: true,
		},
	}

	runBeginRegisterTests(t, testCases)
}

func TestFinishRegister(t *testing.T) {
	validSessionID := uuid.New().String()

	testCases := []finishRegisterTestCase{
		{
			name: "invalid session ID format",
			request: &dto.FinishRequest{
				Username:    testUsername,
				SessionID:   "invalid-uuid",
				Credentials: testCredentials,
			},
			mockSetup: finishMockSetup{
				sessionIDValidFormat: false,
			},
			expectedError: true,
		},
		{
			name: "user not found",
			request: &dto.FinishRequest{
				Username:    "nonexistent",
				SessionID:   validSessionID,
				Credentials: testCredentials,
			},
			mockSetup: finishMockSetup{
				sessionIDValidFormat: true,
				getUserSuccess:       false,
				username:             "nonexistent",
			},
			expectedError: true,
		},
		{
			name: "register session not found",
			request: &dto.FinishRequest{
				Username:    testUsername,
				SessionID:   validSessionID,
				Credentials: testCredentials,
			},
			mockSetup: finishMockSetup{
				sessionIDValidFormat: true,
				getUserSuccess:       true,
				getSessionSuccess:    false,
				username:             testUsername,
				role:                 userRole,
			},
			expectedError: true,
		},
		{
			name: "invalid session data format",
			request: &dto.FinishRequest{
				Username:    testUsername,
				SessionID:   validSessionID,
				Credentials: testCredentials,
			},
			mockSetup: finishMockSetup{
				sessionIDValidFormat: true,
				getUserSuccess:       true,
				getSessionSuccess:    true,
				username:             testUsername,
				role:                 userRole,
				sessionData:          []byte(`invalid json`),
			},
			expectedError: true,
		},
		{
			name: "empty username",
			request: &dto.FinishRequest{
				Username:    emptyString,
				SessionID:   validSessionID,
				Credentials: testCredentials,
			},
			mockSetup: finishMockSetup{
				sessionIDValidFormat: true,
				getUserSuccess:       false,
				username:             emptyString,
			},
			expectedError: true,
		},
		{
			name: "empty session ID",
			request: &dto.FinishRequest{
				Username:    testUsername,
				SessionID:   emptyString,
				Credentials: testCredentials,
			},
			mockSetup: finishMockSetup{
				sessionIDValidFormat: false,
			},
			expectedError: true,
		},
		{
			name: "nil credentials",
			request: &dto.FinishRequest{
				Username:    testUsername,
				SessionID:   validSessionID,
				Credentials: nil,
			},
			mockSetup: finishMockSetup{
				sessionIDValidFormat: true,
				getUserSuccess:       true,
				getSessionSuccess:    true,
				username:             testUsername,
				role:                 userRole,
				sessionData:          testSessionData,
			},
			expectedError: true,
		},
		{
			name: "empty credentials",
			request: &dto.FinishRequest{
				Username:    testUsername,
				SessionID:   validSessionID,
				Credentials: []byte{},
			},
			mockSetup: finishMockSetup{
				sessionIDValidFormat: true,
				getUserSuccess:       true,
				getSessionSuccess:    true,
				username:             testUsername,
				role:                 userRole,
				sessionData:          testSessionData,
			},
			expectedError: true,
		},
		{
			name: "malformed JSON credentials",
			request: &dto.FinishRequest{
				Username:    testUsername,
				SessionID:   validSessionID,
				Credentials: malformedJSON,
			},
			mockSetup: finishMockSetup{
				sessionIDValidFormat: true,
				getUserSuccess:       true,
				getSessionSuccess:    true,
				username:             testUsername,
				role:                 userRole,
				sessionData:          testSessionData,
			},
			expectedError: true,
		},
		{
			name: "username with only whitespace",
			request: &dto.FinishRequest{
				Username:    "   ",
				SessionID:   validSessionID,
				Credentials: testCredentials,
			},
			mockSetup: finishMockSetup{
				sessionIDValidFormat: true,
				getUserSuccess:       false,
				username:             "   ",
			},
			expectedError: true,
		},
		{
			name: "session ID with only whitespace",
			request: &dto.FinishRequest{
				Username:    testUsername,
				SessionID:   "   ",
				Credentials: testCredentials,
			},
			mockSetup: finishMockSetup{
				sessionIDValidFormat: false,
			},
			expectedError: true,
		},
	}

	runFinishRegisterTests(t, testCases)
}
