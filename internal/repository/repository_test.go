package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/redis/go-redis/v9"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/customerrors"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/db"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/models"
)

// Test constants
const (
	// SQL Query patterns
	selectUserByUsernameQuery = "SELECT (.+) FROM users WHERE username = \\$1"
	insertUserQuery           = "INSERT INTO users \\(username\\) VALUES \\(\\$1\\)"
	insertUserWithRoleQuery   = "INSERT INTO users \\(username, role\\) VALUES \\(\\$1, \\$2\\)"

	// Session SQL patterns
	createWebAuthnSessionQuery = "INSERT INTO webauthn_sessions \\(id, user_id, data, purpose, expires_at\\)"
	getWebAuthnSessionQuery    = "SELECT (.+) FROM webauthn_sessions WHERE id = \\$1 AND purpose = \\$2"
	deleteWebAuthnSessionQuery = "DELETE FROM webauthn_sessions WHERE id = \\$1"

	// Credential SQL patterns
	createCredentialQuery       = "INSERT INTO credentials \\("
	getCredentialsByUserIDQuery = "SELECT (.+) FROM credentials WHERE user_id = \\$1"
	updateCredentialQuery       = "UPDATE credentials SET sign_count = \\$2 WHERE id = \\$1"

	// Database columns
	colID        = "id"
	colUsername  = "username"
	colRole      = "role"
	colCreatedAt = "created_at"
	colUpdatedAt = "updated_at"
	colIsActive  = "is_active"

	// Session columns
	colSessionID        = "id"
	colUserID           = "user_id"
	colData             = "data"
	colPurpose          = "purpose"
	colSessionCreatedAt = "created_at"
	colExpiresAt        = "expires_at"

	// Credential columns
	colCredentialID        = "id"
	colCredentialUserID    = "user_id"
	colPublicKey           = "public_key"
	colSignCount           = "sign_count"
	colTransports          = "transports"
	colAAGUID              = "aaguid"
	colAttestationFormat   = "attestation_format"
	colCredentialCreatedAt = "created_at"

	// Common test data
	testUsername       = "testuser"
	testAdminUsername  = "adminuser"
	testExistingUser   = "existinguser"
	testInactiveUser   = "inactiveuser"
	testUnicodeUser    = "用户名"
	testCamelCaseUser  = "TestUser"
	testEmailUser      = "user@domain.com"
	testLongUsername   = "verylongusernamethatmightcauseproblemsinsomedatabases"
	testSpecialUser    = "user-with_special.chars+123"
	testSQLInjection   = "'; DROP TABLE users; --"
	testEmptyUsername  = ""
	testWhitespaceRole = "   "

	// Roles
	roleUser   = "user"
	roleAdmin  = "admin"
	roleCustom = "custom"

	// Error messages
	errUserNotFound    = "user not found"
	errDatabaseError   = "database error"
	errConnectionError = "database connection error"
	errConstraintViol  = "duplicate key value violates unique constraint"

	// Session purposes
	purposeRegistration = "registration"
	purposeLogin        = "login"

	// Credential test data
	testCredentialID    = "test-credential-id"
	testPublicKeyData   = "test-public-key-data"
	testAAGUID          = "01020304-0506-0708-090a-0b0c0d0e0f10"
	testAttestationType = "none"
	testTransportUSB    = "usb"
	testTransportNFC    = "nfc"

	// Test descriptions
	descSuccessfulCreation  = "successful user creation"
	descUserAlreadyExists   = "user already exists"
	descDatabaseError       = "database error"
	descSuccessfulRetrieval = "successful user retrieval"
	descUserNotFound        = "user not found"
	descRaceCondition       = "race condition - user created between check and creation"
	descSessionSave         = "successful session save"
	descSessionRetrieve     = "successful session retrieval"
	descSessionNotFound     = "session not found"
	descSessionDelete       = "successful session deletion"
)

// Database column slice for reuse
var userColumns = []string{colID, colUsername, colRole, colCreatedAt, colUpdatedAt, colIsActive}
var sessionColumns = []string{colSessionID, colUserID, colData, colPurpose, colSessionCreatedAt, colExpiresAt}
var credentialColumns = []string{colCredentialID, colCredentialUserID, colPublicKey, colSignCount, colTransports, colAAGUID, colAttestationFormat, colCredentialCreatedAt}

func setupMockDB(t *testing.T) (pgxmock.PgxPoolIface, *db.Queries) {
	mockDB, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("Failed to create pgxmock: %v", err)
	}

	queries := db.New(mockDB)

	t.Cleanup(func() {
		mockDB.Close()
	})

	return mockDB, queries
}

func setupMockRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	t.Cleanup(func() {
		client.Close()
		mr.Close()
	})

	return mr, client
}

func setupMockRepo(t *testing.T) (pgxmock.PgxPoolIface, *miniredis.Miniredis, UserRepository) {
	mockDB, queries := setupMockDB(t)
	mr, redisClient := setupMockRedis(t)

	repo := &repository{
		queries:  queries,
		client:   redisClient,
		hashSalt: []byte("test-hash-salt"),
	}

	return mockDB, mr, repo
}

func setupRepoWithoutRedis(t *testing.T) (pgxmock.PgxPoolIface, UserRepository) {
	mockDB, queries := setupMockDB(t)

	repo := &repository{
		queries:  queries,
		client:   nil,
		hashSalt: []byte("test-hash-salt"),
	}

	return mockDB, repo
}

// Helper functions for creating test data
func createTestUser(username, role string, isActive bool) db.User {
	return db.User{
		ID:        uuid.New(),
		Username:  username,
		Role:      role,
		CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		UpdatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		IsActive:  isActive,
	}
}

func createUserRows(user db.User) *pgxmock.Rows {
	return pgxmock.NewRows(userColumns).
		AddRow(user.ID, user.Username, user.Role, user.CreatedAt, user.UpdatedAt, user.IsActive)
}

func createUserRowsFromData(username, role string, isActive bool) *pgxmock.Rows {
	user := createTestUser(username, role, isActive)
	return createUserRows(user)
}

// Session helper functions
func createTestWebAuthnUser(username string) models.WebAuthnUser {
	return models.WebAuthnUser{
		ID:          uuid.New(),
		Username:    username,
		Role:        roleUser,
		Credentials: []webauthn.Credential{},
	}
}

func createTestSessionData() map[string]interface{} {
	return map[string]interface{}{
		"challenge": "test-challenge",
		"timeout":   300000,
	}
}

func createTestSession(userID uuid.UUID, purpose string) db.WebauthnSession {
	sessionData := createTestSessionData()
	data, _ := json.Marshal(sessionData)

	return db.WebauthnSession{
		ID:        uuid.New(),
		UserID:    userID,
		Data:      data,
		Purpose:   purpose,
		CreatedAt: pgtype.Timestamp{Time: time.Now(), Valid: true},
		ExpiresAt: pgtype.Timestamp{Time: time.Now().Add(30 * time.Minute), Valid: true},
	}
}

func createSessionRows(session db.WebauthnSession) *pgxmock.Rows {
	return pgxmock.NewRows(sessionColumns).
		AddRow(session.ID, session.UserID, session.Data, session.Purpose, session.CreatedAt, session.ExpiresAt)
}

// Credential helper functions
func createTestCredential(userID uuid.UUID) *webauthn.Credential {
	aaguid, _ := uuid.Parse(testAAGUID)
	return &webauthn.Credential{
		ID:              []byte(testCredentialID),
		PublicKey:       []byte(testPublicKeyData),
		AttestationType: testAttestationType,
		Transport:       []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC},
		Authenticator: webauthn.Authenticator{
			AAGUID:    aaguid[:],
			SignCount: 100,
		},
	}
}

func createTestDBCredential(userID uuid.UUID) db.Credential {
	aaguid, _ := uuid.Parse(testAAGUID)
	return db.Credential{
		ID:                testCredentialID,
		UserID:            userID,
		PublicKey:         []byte(testPublicKeyData),
		SignCount:         100,
		Transports:        []string{testTransportUSB, testTransportNFC},
		Aaguid:            aaguid,
		AttestationFormat: pgtype.Text{String: testAttestationType, Valid: true},
		CreatedAt:         pgtype.Timestamp{Time: time.Now(), Valid: true},
	}
}

func createCredentialRows(credentials ...db.Credential) *pgxmock.Rows {
	rows := pgxmock.NewRows(credentialColumns)
	for _, cred := range credentials {
		rows.AddRow(cred.ID, cred.UserID, cred.PublicKey, cred.SignCount, cred.Transports, cred.Aaguid, cred.AttestationFormat, cred.CreatedAt)
	}
	return rows
}

// Mock setup helpers
func expectUserNotFound(mockDB pgxmock.PgxPoolIface, username string) {
	mockDB.ExpectQuery(selectUserByUsernameQuery).
		WithArgs(username).
		WillReturnError(errors.New(errUserNotFound))
}

func expectUserFound(mockDB pgxmock.PgxPoolIface, username, role string, isActive bool) {
	rows := createUserRowsFromData(username, role, isActive)
	mockDB.ExpectQuery(selectUserByUsernameQuery).
		WithArgs(username).
		WillReturnRows(rows)
}

func expectCreateUser(mockDB pgxmock.PgxPoolIface, username string) {
	rows := createUserRowsFromData(username, roleUser, true)
	mockDB.ExpectQuery(insertUserQuery).
		WithArgs(username).
		WillReturnRows(rows)
}

func expectCreateUserWithRole(mockDB pgxmock.PgxPoolIface, username, role string) {
	rows := createUserRowsFromData(username, role, true)
	mockDB.ExpectQuery(insertUserWithRoleQuery).
		WithArgs(username, role).
		WillReturnRows(rows)
}

func expectCreateUserError(mockDB pgxmock.PgxPoolIface, username string, errorMsg string) {
	mockDB.ExpectQuery(insertUserQuery).
		WithArgs(username).
		WillReturnError(errors.New(errorMsg))
}

func expectCreateUserWithRoleError(mockDB pgxmock.PgxPoolIface, username, role, errorMsg string) {
	mockDB.ExpectQuery(insertUserWithRoleQuery).
		WithArgs(username, role).
		WillReturnError(errors.New(errorMsg))
}

// Session mock helpers
func expectCreateSessionSuccess(mockDB pgxmock.PgxPoolIface) {
	mockDB.ExpectExec(createWebAuthnSessionQuery).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
}

func expectCreateSessionError(mockDB pgxmock.PgxPoolIface, errorMsg string) {
	mockDB.ExpectExec(createWebAuthnSessionQuery).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnError(errors.New(errorMsg))
}

func expectGetSessionSuccess(mockDB pgxmock.PgxPoolIface, sessionID uuid.UUID, purpose string, session db.WebauthnSession) {
	rows := createSessionRows(session)
	mockDB.ExpectQuery(getWebAuthnSessionQuery).
		WithArgs(sessionID, purpose).
		WillReturnRows(rows)
}

func expectGetSessionNotFound(mockDB pgxmock.PgxPoolIface, sessionID uuid.UUID, purpose string) {
	mockDB.ExpectQuery(getWebAuthnSessionQuery).
		WithArgs(sessionID, purpose).
		WillReturnError(errors.New(errUserNotFound))
}

func expectDeleteSessionSuccess(mockDB pgxmock.PgxPoolIface, sessionID uuid.UUID) {
	mockDB.ExpectExec(deleteWebAuthnSessionQuery).
		WithArgs(sessionID).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))
}

func expectDeleteSessionError(mockDB pgxmock.PgxPoolIface, sessionID uuid.UUID, errorMsg string) {
	mockDB.ExpectExec(deleteWebAuthnSessionQuery).
		WithArgs(sessionID).
		WillReturnError(errors.New(errorMsg))
}

// Credential mock helpers
func expectCreateCredentialSuccess(mockDB pgxmock.PgxPoolIface) {
	mockDB.ExpectExec(createCredentialQuery).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
}

func expectCreateCredentialError(mockDB pgxmock.PgxPoolIface, errorMsg string) {
	mockDB.ExpectExec(createCredentialQuery).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnError(errors.New(errorMsg))
}

func expectGetCredentialsByUserIDSuccess(mockDB pgxmock.PgxPoolIface, userID uuid.UUID, credentials []db.Credential) {
	rows := createCredentialRows(credentials...)
	mockDB.ExpectQuery(getCredentialsByUserIDQuery).
		WithArgs(userID).
		WillReturnRows(rows)
}

func expectGetCredentialsByUserIDError(mockDB pgxmock.PgxPoolIface, userID uuid.UUID, errorMsg string) {
	mockDB.ExpectQuery(getCredentialsByUserIDQuery).
		WithArgs(userID).
		WillReturnError(errors.New(errorMsg))
}

func expectUpdateCredentialSuccess(mockDB pgxmock.PgxPoolIface, credentialID string, signCount int64) {
	mockDB.ExpectExec(updateCredentialQuery).
		WithArgs(credentialID, signCount).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
}

func expectUpdateCredentialError(mockDB pgxmock.PgxPoolIface, credentialID string, signCount int64, errorMsg string) {
	mockDB.ExpectExec(updateCredentialQuery).
		WithArgs(credentialID, signCount).
		WillReturnError(errors.New(errorMsg))
}

// Validation helpers
func validateUserBasics(t *testing.T, user db.User, expectedUsername, expectedRole string) {
	if user.Username != expectedUsername {
		t.Errorf("Expected username '%s', got '%s'", expectedUsername, user.Username)
	}
	if user.Role != expectedRole {
		t.Errorf("Expected role '%s', got '%s'", expectedRole, user.Role)
	}
}

func validateActiveUser(t *testing.T, user db.User, expectedUsername, expectedRole string) {
	validateUserBasics(t, user, expectedUsername, expectedRole)
	if !user.IsActive {
		t.Error("Expected user to be active")
	}
}

func validateInactiveUser(t *testing.T, user db.User, expectedUsername string) {
	if user.Username != expectedUsername {
		t.Errorf("Expected username '%s', got '%s'", expectedUsername, user.Username)
	}
	if user.IsActive {
		t.Error("Expected user to be inactive")
	}
}

// Test case structures
type saveUserTestCase struct {
	name          string
	username      string
	role          string
	setupMock     func(mockDB pgxmock.PgxPoolIface)
	expectedError error
	validateUser  func(t *testing.T, user db.User)
}

type getUserTestCase struct {
	name          string
	username      string
	setupMock     func(mockDB pgxmock.PgxPoolIface)
	expectedError error
	validateUser  func(t *testing.T, user db.User)
}

type saveSessionTestCase struct {
	name             string
	user             models.WebAuthnUser
	sessionData      interface{}
	setupMock        func(mockDB pgxmock.PgxPoolIface)
	expectedError    error
	validateResponse func(t *testing.T, sessionID uuid.UUID, err error)
}

type getSessionTestCase struct {
	name            string
	sessionID       uuid.UUID
	purpose         string
	setupMock       func(mockDB pgxmock.PgxPoolIface)
	expectedError   error
	validateSession func(t *testing.T, session db.WebauthnSession)
}

type deleteSessionTestCase struct {
	name          string
	sessionID     uuid.UUID
	setupMock     func(mockDB pgxmock.PgxPoolIface)
	expectedError error
}

type saveCredentialTestCase struct {
	name          string
	userID        uuid.UUID
	credential    *webauthn.Credential
	setupMock     func(mockDB pgxmock.PgxPoolIface)
	expectedError error
}

type getCredentialsTestCase struct {
	name                string
	userID              uuid.UUID
	setupMock           func(mockDB pgxmock.PgxPoolIface)
	expectedError       error
	validateCredentials func(t *testing.T, credentials []db.Credential)
}

type updateCredentialTestCase struct {
	name          string
	credential    *webauthn.Credential
	setupMock     func(mockDB pgxmock.PgxPoolIface)
	expectedError error
}

func TestSaveUser(t *testing.T) {
	tests := []saveUserTestCase{
		{
			name:     descSuccessfulCreation + " without role",
			username: testUsername,
			role:     "",
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserNotFound(mockDB, testUsername)
				expectCreateUser(mockDB, testUsername)
			},
			expectedError: nil,
			validateUser: func(t *testing.T, user db.User) {
				validateActiveUser(t, user, testUsername, roleUser)
			},
		},
		{
			name:     descSuccessfulCreation + " with role",
			username: testAdminUsername,
			role:     roleAdmin,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserNotFound(mockDB, testAdminUsername)
				expectCreateUserWithRole(mockDB, testAdminUsername, roleAdmin)
			},
			expectedError: nil,
			validateUser: func(t *testing.T, user db.User) {
				validateActiveUser(t, user, testAdminUsername, roleAdmin)
			},
		},
		{
			name:     descUserAlreadyExists,
			username: testExistingUser,
			role:     "",
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserFound(mockDB, testExistingUser, roleUser, true)
			},
			expectedError: customerrors.ErrUsernameAlreadyExists,
			validateUser:  nil,
		},
		{
			name:     descDatabaseError + " during user creation without role",
			username: testUsername,
			role:     "",
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserNotFound(mockDB, testUsername)
				expectCreateUserError(mockDB, testUsername, errDatabaseError)
			},
			expectedError: customerrors.ErrInternalServer,
			validateUser:  nil,
		},
		{
			name:     descDatabaseError + " during user creation with role",
			username: testAdminUsername,
			role:     roleAdmin,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserNotFound(mockDB, testAdminUsername)
				expectCreateUserWithRoleError(mockDB, testAdminUsername, roleAdmin, errDatabaseError)
			},
			expectedError: customerrors.ErrInternalServer,
			validateUser:  nil,
		},
	}

	runSaveUserTests(t, tests)
}

func TestGetUserByUsername(t *testing.T) {
	tests := []getUserTestCase{
		{
			name:     descSuccessfulRetrieval,
			username: testUsername,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserFound(mockDB, testUsername, roleUser, true)
			},
			expectedError: nil,
			validateUser: func(t *testing.T, user db.User) {
				validateActiveUser(t, user, testUsername, roleUser)
			},
		},
		{
			name:     descUserNotFound,
			username: "nonexistentuser",
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserNotFound(mockDB, "nonexistentuser")
			},
			expectedError: customerrors.ErrUserNotFound,
			validateUser:  nil,
		},
		{
			name:     errConnectionError,
			username: testUsername,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				mockDB.ExpectQuery(selectUserByUsernameQuery).
					WithArgs(testUsername).
					WillReturnError(errors.New(errConnectionError))
			},
			expectedError: customerrors.ErrUserNotFound,
			validateUser:  nil,
		},
		{
			name:     "user with admin role",
			username: testAdminUsername,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserFound(mockDB, testAdminUsername, roleAdmin, true)
			},
			expectedError: nil,
			validateUser: func(t *testing.T, user db.User) {
				validateActiveUser(t, user, testAdminUsername, roleAdmin)
			},
		},
		{
			name:     "inactive user",
			username: testInactiveUser,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserFound(mockDB, testInactiveUser, roleUser, false)
			},
			expectedError: nil,
			validateUser: func(t *testing.T, user db.User) {
				validateInactiveUser(t, user, testInactiveUser)
			},
		},
		{
			name:     "empty username",
			username: testEmptyUsername,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserNotFound(mockDB, testEmptyUsername)
			},
			expectedError: customerrors.ErrUserNotFound,
			validateUser:  nil,
		},
	}

	runGetUserTests(t, tests)
}

func TestSaveUser_AdditionalEdgeCases(t *testing.T) {
	tests := []saveUserTestCase{
		{
			name:     "empty role defaults to CreateUser",
			username: testUsername,
			role:     "",
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserNotFound(mockDB, testUsername)
				expectCreateUser(mockDB, testUsername)
			},
			expectedError: nil,
		},
		{
			name:     "whitespace-only role",
			username: testUsername,
			role:     testWhitespaceRole,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserNotFound(mockDB, testUsername)
				expectCreateUserWithRole(mockDB, testUsername, testWhitespaceRole)
			},
			expectedError: nil,
		},
		{
			name:     "special characters in username for creation",
			username: testSpecialUser,
			role:     roleCustom,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserNotFound(mockDB, testSpecialUser)
				expectCreateUserWithRole(mockDB, testSpecialUser, roleCustom)
			},
			expectedError: nil,
		},
	}

	runSaveUserTests(t, tests)
}

func TestGetUserByUsername_EdgeCases(t *testing.T) {
	tests := []getUserTestCase{
		{
			name:     "unicode username",
			username: testUnicodeUser,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserFound(mockDB, testUnicodeUser, roleUser, true)
			},
			expectedError: nil,
		},
		{
			name:     "case sensitive username lookup",
			username: testCamelCaseUser,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserFound(mockDB, testCamelCaseUser, roleUser, true)
			},
			expectedError: nil,
		},
		{
			name:     "sql injection attempt",
			username: testSQLInjection,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserNotFound(mockDB, testSQLInjection)
			},
			expectedError: customerrors.ErrUserNotFound,
			validateUser:  nil,
		},
		{
			name:     "user with special characters in username",
			username: testEmailUser,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserFound(mockDB, testEmailUser, roleUser, true)
			},
			expectedError: nil,
		},
		{
			name:     "long username",
			username: testLongUsername,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserFound(mockDB, testLongUsername, roleUser, true)
			},
			expectedError: nil,
		},
	}

	runGetUserTests(t, tests)
}

func TestSaveUser_ConcurrentUsernameConflict(t *testing.T) {
	t.Run(descRaceCondition, func(t *testing.T) {
		mockDB, repo := setupRepoWithoutRedis(t)

		expectUserNotFound(mockDB, "raceconditionuser")
		expectCreateUserError(mockDB, "raceconditionuser", errConstraintViol)

		_, err := repo.SaveUser(context.Background(), "raceconditionuser", "")

		if err != customerrors.ErrInternalServer {
			t.Errorf("Expected ErrInternalServer for database constraint violation, got %v", err)
		}

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("Unmet expectations: %v", err)
		}
	})
}

// Test runners
func runSaveUserTests(t *testing.T, tests []saveUserTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			tt.setupMock(mockDB)

			user, err := repo.SaveUser(context.Background(), tt.username, tt.role)

			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("Expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
				if tt.validateUser != nil {
					tt.validateUser(t, user)
				}
			}

			if err := mockDB.ExpectationsWereMet(); err != nil {
				t.Errorf("Unmet expectations: %v", err)
			}
		})
	}
}

func runGetUserTests(t *testing.T, tests []getUserTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			tt.setupMock(mockDB)

			user, err := repo.GetUserByUsername(context.Background(), tt.username)

			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("Expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
				if tt.validateUser != nil {
					tt.validateUser(t, user)
				}
			}

			if err := mockDB.ExpectationsWereMet(); err != nil {
				t.Errorf("Unmet expectations: %v", err)
			}
		})
	}
}

func TestSaveRegisterSession(t *testing.T) {
	tests := []saveSessionTestCase{
		{
			name:        descSessionSave + " - register session",
			user:        createTestWebAuthnUser(testUsername),
			sessionData: createTestSessionData(),
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateSessionSuccess(mockDB)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, sessionID uuid.UUID, err error) {
				if sessionID == uuid.Nil {
					t.Error("Expected non-nil session ID")
				}
			},
		},
		{
			name:        descDatabaseError + " during register session save",
			user:        createTestWebAuthnUser(testUsername),
			sessionData: createTestSessionData(),
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateSessionError(mockDB, errDatabaseError)
			},
			expectedError: errors.New(errDatabaseError),
		},
		{
			name:        "save register session with nil data",
			user:        createTestWebAuthnUser(testUsername),
			sessionData: nil,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateSessionSuccess(mockDB)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, sessionID uuid.UUID, err error) {
				if sessionID == uuid.Nil {
					t.Error("Expected non-nil session ID")
				}
			},
		},
		{
			name: "save register session with complex data",
			user: createTestWebAuthnUser(testUsername),
			sessionData: map[string]interface{}{
				"challenge": "complex-challenge-123",
				"timeout":   600000,
				"allowCredentials": []map[string]string{
					{"id": "cred1", "type": "public-key"},
				},
			},
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateSessionSuccess(mockDB)
			},
			expectedError: nil,
		},
	}

	runSaveSessionTests(t, tests, "register")
}

func TestSaveLoginSession(t *testing.T) {
	tests := []saveSessionTestCase{
		{
			name:        descSessionSave + " - login session",
			user:        createTestWebAuthnUser(testUsername),
			sessionData: createTestSessionData(),
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateSessionSuccess(mockDB)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, sessionID uuid.UUID, err error) {
				if sessionID == uuid.Nil {
					t.Error("Expected non-nil session ID")
				}
			},
		},
		{
			name:        descDatabaseError + " during login session save",
			user:        createTestWebAuthnUser(testUsername),
			sessionData: createTestSessionData(),
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateSessionError(mockDB, errDatabaseError)
			},
			expectedError: errors.New(errDatabaseError),
		},
		{
			name: "save login session with admin user",
			user: models.WebAuthnUser{
				ID:       uuid.New(),
				Username: testAdminUsername,
				Role:     roleAdmin,
			},
			sessionData: createTestSessionData(),
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateSessionSuccess(mockDB)
			},
			expectedError: nil,
		},
	}

	runSaveSessionTests(t, tests, "login")
}

func TestGetRegisterSession(t *testing.T) {
	sessionID := uuid.New()
	userID := uuid.New()
	testSession := createTestSession(userID, purposeRegistration)
	testSession.ID = sessionID

	tests := []getSessionTestCase{
		{
			name:      descSessionRetrieve + " - register session",
			sessionID: sessionID,
			purpose:   purposeRegistration,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectGetSessionSuccess(mockDB, sessionID, purposeRegistration, testSession)
			},
			expectedError: nil,
			validateSession: func(t *testing.T, session db.WebauthnSession) {
				if session.ID != sessionID {
					t.Errorf("Expected session ID %v, got %v", sessionID, session.ID)
				}
				if session.Purpose != purposeRegistration {
					t.Errorf("Expected purpose %s, got %s", purposeRegistration, session.Purpose)
				}
			},
		},
		{
			name:      descSessionNotFound + " - register session",
			sessionID: sessionID,
			purpose:   purposeRegistration,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectGetSessionNotFound(mockDB, sessionID, purposeRegistration)
			},
			expectedError: customerrors.ErrSessionNotFound,
		},
		{
			name:      "database error during register session retrieval",
			sessionID: sessionID,
			purpose:   purposeRegistration,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				mockDB.ExpectQuery(getWebAuthnSessionQuery).
					WithArgs(sessionID, purposeRegistration).
					WillReturnError(errors.New(errConnectionError))
			},
			expectedError: customerrors.ErrSessionNotFound,
		},
	}

	runGetSessionTests(t, tests, "register")
}

func TestGetLoginSession(t *testing.T) {
	sessionID := uuid.New()
	userID := uuid.New()
	testSession := createTestSession(userID, purposeLogin)
	testSession.ID = sessionID

	tests := []getSessionTestCase{
		{
			name:      descSessionRetrieve + " - login session",
			sessionID: sessionID,
			purpose:   purposeLogin,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectGetSessionSuccess(mockDB, sessionID, purposeLogin, testSession)
			},
			expectedError: nil,
			validateSession: func(t *testing.T, session db.WebauthnSession) {
				if session.ID != sessionID {
					t.Errorf("Expected session ID %v, got %v", sessionID, session.ID)
				}
				if session.Purpose != purposeLogin {
					t.Errorf("Expected purpose %s, got %s", purposeLogin, session.Purpose)
				}
			},
		},
		{
			name:      descSessionNotFound + " - login session",
			sessionID: sessionID,
			purpose:   purposeLogin,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectGetSessionNotFound(mockDB, sessionID, purposeLogin)
			},
			expectedError: customerrors.ErrSessionNotFound,
		},
	}

	runGetSessionTests(t, tests, "login")
}

func TestDeleteSession(t *testing.T) {
	sessionID := uuid.New()

	tests := []deleteSessionTestCase{
		{
			name:      descSessionDelete,
			sessionID: sessionID,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectDeleteSessionSuccess(mockDB, sessionID)
			},
			expectedError: nil,
		},
		{
			name:      descDatabaseError + " during session deletion",
			sessionID: sessionID,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectDeleteSessionError(mockDB, sessionID, errDatabaseError)
			},
			expectedError: customerrors.ErrInternalServer,
		},
		{
			name:      "delete non-existent session",
			sessionID: sessionID,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectDeleteSessionError(mockDB, sessionID, "session not found")
			},
			expectedError: customerrors.ErrInternalServer,
		},
	}

	runDeleteSessionTests(t, tests)
}

func TestSessionIntegrationFlow(t *testing.T) {
	t.Run("complete session lifecycle - registration", func(t *testing.T) {
		mockDB, repo := setupRepoWithoutRedis(t)
		user := createTestWebAuthnUser(testUsername)
		sessionData := createTestSessionData()

		// Save register session
		expectCreateSessionSuccess(mockDB)
		sessionID, err := repo.SaveRegisterSession(context.Background(), user, sessionData)
		if err != nil {
			t.Errorf("Expected no error saving session, got %v", err)
		}

		// Retrieve register session
		testSession := createTestSession(user.ID, purposeRegistration)
		testSession.ID = sessionID
		expectGetSessionSuccess(mockDB, sessionID, purposeRegistration, testSession)

		retrievedSession, err := repo.GetRegisterSession(context.Background(), sessionID)
		if err != nil {
			t.Errorf("Expected no error retrieving session, got %v", err)
		}

		if retrievedSession.ID != sessionID {
			t.Errorf("Expected session ID %v, got %v", sessionID, retrievedSession.ID)
		}

		// Delete session
		expectDeleteSessionSuccess(mockDB, sessionID)
		err = repo.DeleteSession(context.Background(), sessionID)
		if err != nil {
			t.Errorf("Expected no error deleting session, got %v", err)
		}

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("Unmet expectations: %v", err)
		}
	})

	t.Run("complete session lifecycle - login", func(t *testing.T) {
		mockDB, repo := setupRepoWithoutRedis(t)
		user := createTestWebAuthnUser(testAdminUsername)
		sessionData := createTestSessionData()

		// Save login session
		expectCreateSessionSuccess(mockDB)
		sessionID, err := repo.SaveLoginSession(context.Background(), user, sessionData)
		if err != nil {
			t.Errorf("Expected no error saving session, got %v", err)
		}

		// Retrieve login session
		testSession := createTestSession(user.ID, purposeLogin)
		testSession.ID = sessionID
		expectGetSessionSuccess(mockDB, sessionID, purposeLogin, testSession)

		retrievedSession, err := repo.GetLoginSession(context.Background(), sessionID)
		if err != nil {
			t.Errorf("Expected no error retrieving session, got %v", err)
		}

		if retrievedSession.Purpose != purposeLogin {
			t.Errorf("Expected purpose %s, got %s", purposeLogin, retrievedSession.Purpose)
		}

		// Delete session
		expectDeleteSessionSuccess(mockDB, sessionID)
		err = repo.DeleteSession(context.Background(), sessionID)
		if err != nil {
			t.Errorf("Expected no error deleting session, got %v", err)
		}

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("Unmet expectations: %v", err)
		}
	})
}

// Session test runners
func runSaveSessionTests(t *testing.T, tests []saveSessionTestCase, sessionType string) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			tt.setupMock(mockDB)

			var sessionID uuid.UUID
			var err error

			if sessionType == "register" {
				sessionID, err = repo.SaveRegisterSession(context.Background(), tt.user, tt.sessionData)
			} else {
				sessionID, err = repo.SaveLoginSession(context.Background(), tt.user, tt.sessionData)
			}

			if tt.expectedError != nil {
				if err == nil || err.Error() != tt.expectedError.Error() {
					t.Errorf("Expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
				if tt.validateResponse != nil {
					tt.validateResponse(t, sessionID, err)
				}
			}

			if err := mockDB.ExpectationsWereMet(); err != nil {
				t.Errorf("Unmet expectations: %v", err)
			}
		})
	}
}

func TestSaveCredentials(t *testing.T) {
	userID := uuid.New()

	tests := []saveCredentialTestCase{
		{
			name:       "successful credential save",
			userID:     userID,
			credential: createTestCredential(userID),
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateCredentialSuccess(mockDB)
			},
			expectedError: nil,
		},
		{
			name:       "database error during credential save",
			userID:     userID,
			credential: createTestCredential(userID),
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateCredentialError(mockDB, errDatabaseError)
			},
			expectedError: customerrors.ErrInternalServer,
		},
		{
			name:   "invalid AAGUID",
			userID: userID,
			credential: &webauthn.Credential{
				ID:              []byte(testCredentialID),
				PublicKey:       []byte(testPublicKeyData),
				AttestationType: testAttestationType,
				Transport:       []protocol.AuthenticatorTransport{protocol.USB},
				Authenticator: webauthn.Authenticator{
					AAGUID:    []byte("invalid-aaguid"), // Invalid length
					SignCount: 100,
				},
			},
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				// No database call expected due to early validation failure
			},
			expectedError: customerrors.ErrInvalidAAGUID,
		},
		{
			name:   "credential with empty attestation type",
			userID: userID,
			credential: &webauthn.Credential{
				ID:              []byte(testCredentialID),
				PublicKey:       []byte(testPublicKeyData),
				AttestationType: "", // Empty attestation type
				Transport:       []protocol.AuthenticatorTransport{protocol.USB},
				Authenticator: webauthn.Authenticator{
					AAGUID:    func() []byte { aaguid, _ := uuid.Parse(testAAGUID); return aaguid[:] }(),
					SignCount: 50,
				},
			},
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateCredentialSuccess(mockDB)
			},
			expectedError: nil,
		},
	}

	runSaveCredentialTests(t, tests)
}

func TestGetCredentialsByUserID(t *testing.T) {
	userID := uuid.New()
	testCredentials := []db.Credential{
		createTestDBCredential(userID),
		{
			ID:                "credential-2",
			UserID:            userID,
			PublicKey:         []byte("public-key-2"),
			SignCount:         200,
			Transports:        []string{testTransportUSB},
			Aaguid:            func() uuid.UUID { aaguid, _ := uuid.Parse(testAAGUID); return aaguid }(),
			AttestationFormat: pgtype.Text{String: "packed", Valid: true},
			CreatedAt:         pgtype.Timestamp{Time: time.Now(), Valid: true},
		},
	}

	tests := []getCredentialsTestCase{
		{
			name:   "successful credentials retrieval",
			userID: userID,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectGetCredentialsByUserIDSuccess(mockDB, userID, testCredentials)
			},
			expectedError: nil,
			validateCredentials: func(t *testing.T, credentials []db.Credential) {
				if len(credentials) != 2 {
					t.Errorf("Expected 2 credentials, got %d", len(credentials))
				}
				if credentials[0].ID != testCredentialID {
					t.Errorf("Expected credential ID %s, got %s", testCredentialID, credentials[0].ID)
				}
			},
		},
		{
			name:   "no credentials found",
			userID: userID,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectGetCredentialsByUserIDSuccess(mockDB, userID, []db.Credential{})
			},
			expectedError: nil,
			validateCredentials: func(t *testing.T, credentials []db.Credential) {
				if len(credentials) != 0 {
					t.Errorf("Expected 0 credentials, got %d", len(credentials))
				}
			},
		},
		{
			name:   "database error during credentials retrieval",
			userID: userID,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectGetCredentialsByUserIDError(mockDB, userID, errDatabaseError)
			},
			expectedError: customerrors.ErrInternalServer,
		},
		{
			name:   "single credential retrieval",
			userID: userID,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectGetCredentialsByUserIDSuccess(mockDB, userID, testCredentials[:1])
			},
			expectedError: nil,
			validateCredentials: func(t *testing.T, credentials []db.Credential) {
				if len(credentials) != 1 {
					t.Errorf("Expected 1 credential, got %d", len(credentials))
				}
				if credentials[0].UserID != userID {
					t.Errorf("Expected user ID %v, got %v", userID, credentials[0].UserID)
				}
			},
		},
	}

	runGetCredentialsTests(t, tests)
}

func TestUpdateCredentials(t *testing.T) {
	credential := createTestCredential(uuid.New())
	updatedCredential := createTestCredential(uuid.New())
	updatedCredential.Authenticator.SignCount = 150

	tests := []updateCredentialTestCase{
		{
			name:       "successful credential update",
			credential: updatedCredential,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUpdateCredentialSuccess(mockDB, string(updatedCredential.ID), int64(updatedCredential.Authenticator.SignCount))
			},
			expectedError: nil,
		},
		{
			name:       "database error during credential update",
			credential: credential,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUpdateCredentialError(mockDB, string(credential.ID), int64(credential.Authenticator.SignCount), errDatabaseError)
			},
			expectedError: customerrors.ErrInternalServer,
		},
		{
			name: "update credential with zero sign count",
			credential: func() *webauthn.Credential {
				cred := createTestCredential(uuid.New())
				cred.Authenticator.SignCount = 0
				return cred
			}(),
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUpdateCredentialSuccess(mockDB, testCredentialID, 0)
			},
			expectedError: nil,
		},
		{
			name:       "update non-existent credential",
			credential: credential,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUpdateCredentialError(mockDB, string(credential.ID), int64(credential.Authenticator.SignCount), "credential not found")
			},
			expectedError: customerrors.ErrInternalServer,
		},
	}

	runUpdateCredentialTests(t, tests)
}

func TestCredentialIntegrationFlow(t *testing.T) {
	t.Run("complete credential lifecycle", func(t *testing.T) {
		mockDB, repo := setupRepoWithoutRedis(t)
		userID := uuid.New()
		credential := createTestCredential(userID)

		// Save credential
		expectCreateCredentialSuccess(mockDB)
		err := repo.SaveCredentials(context.Background(), userID, credential)
		if err != nil {
			t.Errorf("Expected no error saving credential, got %v", err)
		}

		// Get credentials
		dbCredentials := []db.Credential{createTestDBCredential(userID)}
		expectGetCredentialsByUserIDSuccess(mockDB, userID, dbCredentials)

		retrievedCredentials, err := repo.GetCredentialsByUserID(context.Background(), userID)
		if err != nil {
			t.Errorf("Expected no error retrieving credentials, got %v", err)
		}

		if len(retrievedCredentials) != 1 {
			t.Errorf("Expected 1 credential, got %d", len(retrievedCredentials))
		}

		// Update credential
		credential.Authenticator.SignCount = 200
		expectUpdateCredentialSuccess(mockDB, string(credential.ID), int64(credential.Authenticator.SignCount))

		err = repo.UpdateCredentials(context.Background(), credential)
		if err != nil {
			t.Errorf("Expected no error updating credential, got %v", err)
		}

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("Unmet expectations: %v", err)
		}
	})
}

// Credential test runners
func runSaveCredentialTests(t *testing.T, tests []saveCredentialTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			tt.setupMock(mockDB)

			err := repo.SaveCredentials(context.Background(), tt.userID, tt.credential)

			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("Expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}

			if err := mockDB.ExpectationsWereMet(); err != nil {
				t.Errorf("Unmet expectations: %v", err)
			}
		})
	}
}

func runGetCredentialsTests(t *testing.T, tests []getCredentialsTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			tt.setupMock(mockDB)

			credentials, err := repo.GetCredentialsByUserID(context.Background(), tt.userID)

			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("Expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
				if tt.validateCredentials != nil {
					tt.validateCredentials(t, credentials)
				}
			}

			if err := mockDB.ExpectationsWereMet(); err != nil {
				t.Errorf("Unmet expectations: %v", err)
			}
		})
	}
}

func runUpdateCredentialTests(t *testing.T, tests []updateCredentialTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			tt.setupMock(mockDB)

			err := repo.UpdateCredentials(context.Background(), tt.credential)

			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("Expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}

			if err := mockDB.ExpectationsWereMet(); err != nil {
				t.Errorf("Unmet expectations: %v", err)
			}
		})
	}
}

func runGetSessionTests(t *testing.T, tests []getSessionTestCase, sessionType string) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			tt.setupMock(mockDB)

			var session db.WebauthnSession
			var err error

			if sessionType == "register" {
				session, err = repo.GetRegisterSession(context.Background(), tt.sessionID)
			} else {
				session, err = repo.GetLoginSession(context.Background(), tt.sessionID)
			}

			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("Expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
				if tt.validateSession != nil {
					tt.validateSession(t, session)
				}
			}

			if err := mockDB.ExpectationsWereMet(); err != nil {
				t.Errorf("Unmet expectations: %v", err)
			}
		})
	}
}

func runDeleteSessionTests(t *testing.T, tests []deleteSessionTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			tt.setupMock(mockDB)

			err := repo.DeleteSession(context.Background(), tt.sessionID)

			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("Expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}

			if err := mockDB.ExpectationsWereMet(); err != nil {
				t.Errorf("Unmet expectations: %v", err)
			}
		})
	}
}

// Benchmark tests for credential operations
func BenchmarkSaveCredentials(b *testing.B) {
	mockDB, repo := setupRepoWithoutRedis(&testing.T{})
	userID := uuid.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		credential := createTestCredential(userID)
		expectCreateCredentialSuccess(mockDB)
		b.StartTimer()
		repo.SaveCredentials(context.Background(), userID, credential)
	}
}

func BenchmarkGetCredentialsByUserID(b *testing.B) {
	mockDB, repo := setupRepoWithoutRedis(&testing.T{})
	userID := uuid.New()
	credentials := []db.Credential{createTestDBCredential(userID)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		expectGetCredentialsByUserIDSuccess(mockDB, userID, credentials)
		b.StartTimer()
		repo.GetCredentialsByUserID(context.Background(), userID)
	}
}

func BenchmarkUpdateCredentials(b *testing.B) {
	mockDB, repo := setupRepoWithoutRedis(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		credential := createTestCredential(uuid.New())
		expectUpdateCredentialSuccess(mockDB, string(credential.ID), int64(credential.Authenticator.SignCount))
		b.StartTimer()
		repo.UpdateCredentials(context.Background(), credential)
	}
}

// Benchmark tests for session operations
func BenchmarkSaveRegisterSession(b *testing.B) {
	mockDB, repo := setupRepoWithoutRedis(&testing.T{})
	user := createTestWebAuthnUser(testUsername)
	sessionData := createTestSessionData()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		expectCreateSessionSuccess(mockDB)
		b.StartTimer()
		repo.SaveRegisterSession(context.Background(), user, sessionData)
	}
}

func BenchmarkSaveLoginSession(b *testing.B) {
	mockDB, repo := setupRepoWithoutRedis(&testing.T{})
	user := createTestWebAuthnUser(testUsername)
	sessionData := createTestSessionData()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		expectCreateSessionSuccess(mockDB)
		b.StartTimer()
		repo.SaveLoginSession(context.Background(), user, sessionData)
	}
}

func BenchmarkGetRegisterSession(b *testing.B) {
	mockDB, repo := setupRepoWithoutRedis(&testing.T{})
	sessionID := uuid.New()
	userID := uuid.New()
	testSession := createTestSession(userID, purposeRegistration)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		expectGetSessionSuccess(mockDB, sessionID, purposeRegistration, testSession)
		b.StartTimer()
		repo.GetRegisterSession(context.Background(), sessionID)
	}
}

func BenchmarkGetLoginSession(b *testing.B) {
	mockDB, repo := setupRepoWithoutRedis(&testing.T{})
	sessionID := uuid.New()
	userID := uuid.New()
	testSession := createTestSession(userID, purposeLogin)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		expectGetSessionSuccess(mockDB, sessionID, purposeLogin, testSession)
		b.StartTimer()
		repo.GetLoginSession(context.Background(), sessionID)
	}
}

func BenchmarkDeleteSession(b *testing.B) {
	mockDB, repo := setupRepoWithoutRedis(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		sessionID := uuid.New()
		expectDeleteSessionSuccess(mockDB, sessionID)
		b.StartTimer()
		repo.DeleteSession(context.Background(), sessionID)
	}
}

// Benchmark tests for performance
func BenchmarkSaveUser(b *testing.B) {
	mockDB, repo := setupRepoWithoutRedis(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		username := fmt.Sprintf("user%d", i)

		expectUserNotFound(mockDB, username)
		expectCreateUser(mockDB, username)

		b.StartTimer()
		repo.SaveUser(context.Background(), username, "")
	}
}

func BenchmarkGetUserByUsername(b *testing.B) {
	mockDB, repo := setupRepoWithoutRedis(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		username := fmt.Sprintf("user%d", i)

		expectUserFound(mockDB, username, roleUser, true)

		b.StartTimer()
		repo.GetUserByUsername(context.Background(), username)
	}
}

// Integration-style tests for multiple operations
func TestUserRepository_IntegrationFlow(t *testing.T) {
	t.Run("complete user lifecycle", func(t *testing.T) {
		mockDB, repo := setupRepoWithoutRedis(t)
		username := "integrationuser"

		// Step 1: Try to get non-existent user
		expectUserNotFound(mockDB, username)

		_, err := repo.GetUserByUsername(context.Background(), username)
		if err != customerrors.ErrUserNotFound {
			t.Errorf("Expected ErrUserNotFound, got %v", err)
		}

		// Step 2: Create the user
		expectUserNotFound(mockDB, username)
		expectCreateUser(mockDB, username)

		createdUser, err := repo.SaveUser(context.Background(), username, "")
		if err != nil {
			t.Errorf("Expected no error creating user, got %v", err)
		}

		// Step 3: Retrieve the created user
		expectUserFound(mockDB, username, roleUser, true)

		retrievedUser, err := repo.GetUserByUsername(context.Background(), username)
		if err != nil {
			t.Errorf("Expected no error retrieving user, got %v", err)
		}

		if retrievedUser.Username != createdUser.Username {
			t.Errorf("Expected retrieved username %s, got %s", createdUser.Username, retrievedUser.Username)
		}

		// Step 4: Try to create duplicate user
		expectUserFound(mockDB, username, roleUser, true)

		_, err = repo.SaveUser(context.Background(), username, "")
		if err != customerrors.ErrUsernameAlreadyExists {
			t.Errorf("Expected ErrUsernameAlreadyExists, got %v", err)
		}

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("Unmet expectations: %v", err)
		}
	})
}

// Stress test with multiple concurrent operations simulation
func TestUserRepository_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	t.Run("multiple user operations", func(t *testing.T) {
		mockDB, repo := setupRepoWithoutRedis(t)

		// Simulate creating 100 users
		for i := 0; i < 100; i++ {
			username := fmt.Sprintf("stressuser%d", i)

			expectUserNotFound(mockDB, username)
			expectCreateUser(mockDB, username)

			_, err := repo.SaveUser(context.Background(), username, "")
			if err != nil {
				t.Errorf("Failed to create user %s: %v", username, err)
			}
		}

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("Unmet expectations: %v", err)
		}
	})
}
