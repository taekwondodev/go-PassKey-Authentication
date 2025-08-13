package repository

import (
	"context"
	"database/sql"
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
	activateUserQuery         = "UPDATE users SET status = 'active' WHERE id = \\$1"

	// Session SQL patterns
	createWebAuthnSessionQuery = "INSERT INTO webauthn_sessions \\(id, user_id, data, purpose, expires_at\\)"
	getWebAuthnSessionQuery    = "SELECT (.+) FROM webauthn_sessions WHERE id = \\$1 AND purpose = \\$2"
	deleteWebAuthnSessionQuery = "DELETE FROM webauthn_sessions WHERE id = \\$1"

	// Credential SQL patterns
	createCredentialQuery       = "INSERT INTO credentials \\("
	getCredentialsByUserIDQuery = "SELECT (.+) FROM credentials WHERE user_id = \\$1"
	updateCredentialQuery       = "UPDATE credentials SET sign_count = \\$2, last_used_at = NOW\\(\\) WHERE id = \\$1"

	// Database columns
	colID        = "id"
	colUsername  = "username"
	colRole      = "role"
	colStatus    = "status"
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
	colBackupEligible      = "backup_eligible"
	colBackupState         = "backup_state"
	colCredentialCreatedAt = "created_at"
	colLastUsedAt          = "last_used_at"

	// Common test data
	testUsername       = "testuser"
	testAdminUsername  = "admin"
	testExistingUser   = "existing"
	testInactiveUser   = "inactive"
	testActiveUser     = "active"
	testPendingUser    = "pending"
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

	// Token test data
	testToken        = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token"
	testToken2       = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token2"
	testExpiredToken = "expired.jwt.token"
	testInvalidToken = "invalid-token"
	testTokenHash    = "blacklist:test-hash"

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

	// Common error and validation messages
	msgUnmetExpectations             = "Unmet expectations: %v"
	msgExpectedNonNilSessionID       = "Expected non-nil session ID"
	msgExpectedSessionID             = "Expected session ID %v, got %v"
	msgExpectedPurpose               = "Expected purpose %s, got %s"
	msgExpectedNoError               = "Expected no error, got %v"
	msgExpectedNoErrorSaving         = "Expected no error saving session, got %v"
	msgExpectedNoErrorRetrieving     = "Expected no error retrieving session, got %v"
	msgExpectedNoErrorDeleting       = "Expected no error deleting session, got %v"
	msgExpectedNoErrorCreating       = "Expected no error creating user, got %v"
	msgExpectedNoErrorSavingCred     = "Expected no error saving credential, got %v"
	msgExpectedNoErrorRetrievingCred = "Expected no error retrieving credentials, got %v"
	msgExpectedNoErrorUpdating       = "Expected no error updating credential, got %v"
	msgExpectedNoErrorChecking       = "Expected no error checking token, got %v"
	msgExpectedNoErrorBlacklisting   = "Expected no error blacklisting token, got %v"

	// Common suffix strings
	suffixRegisterSession            = " - register session"
	suffixLoginSession               = " - login session"
	suffixDuringRegisterSave         = " during register session save"
	suffixDuringLoginSave            = " during login session save"
	suffixDuringSessionDeletion      = " during session deletion"
	suffixDuringRegisterRetrieval    = " during register session retrieval"
	suffixDuringCredentialsRetrieval = " during credentials retrieval"

	// Session save prefixes
	prefixSaveRegisterSession = "save register session with "
	prefixSaveLoginSession    = "save login session with "

	// Common session data descriptions
	descNilData     = "nil data"
	descComplexData = "complex data"
	descAdminUser   = "admin user"
)

// Database column slice for reuse
var userColumns = []string{colID, colUsername, colRole, colStatus, colCreatedAt, colUpdatedAt, colIsActive}
var sessionColumns = []string{colSessionID, colUserID, colData, colPurpose, colSessionCreatedAt, colExpiresAt}
var credentialColumns = []string{colCredentialID, colCredentialUserID, colPublicKey, colSignCount, colTransports, colAAGUID, colAttestationFormat, colBackupEligible, colBackupState, colCredentialCreatedAt, colLastUsedAt}

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
		Status:    "pending",
		CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		UpdatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		IsActive:  isActive,
	}
}

func createUserRows(user db.User) *pgxmock.Rows {
	return pgxmock.NewRows(userColumns).
		AddRow(user.ID, user.Username, user.Role, user.Status, user.CreatedAt, user.UpdatedAt, user.IsActive)
}

func createUserRowsFromData(userID uuid.UUID, username, role, status string) *pgxmock.Rows {
	return pgxmock.NewRows(userColumns).
		AddRow(userID, username, role, status, pgtype.Timestamptz{Time: time.Now(), Valid: true}, pgtype.Timestamptz{Time: time.Now(), Valid: true}, true)
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
		CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(30 * time.Minute), Valid: true},
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
		Flags: webauthn.CredentialFlags{
			BackupEligible: true,
			BackupState:    false,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    aaguid[:],
			SignCount: 100,
		},
	}
}

func createTestDBCredential(userID uuid.UUID) db.Credential {
	aaguid, _ := uuid.Parse(testAAGUID)
	return db.Credential{
		ID:                []byte(testCredentialID),
		UserID:            userID,
		PublicKey:         []byte(testPublicKeyData),
		SignCount:         100,
		Transports:        []string{testTransportUSB, testTransportNFC},
		Aaguid:            aaguid,
		AttestationFormat: pgtype.Text{String: testAttestationType, Valid: true},
		BackupEligible:    true,
		BackupState:       false,
		CreatedAt:         pgtype.Timestamptz{Time: time.Now(), Valid: true},
		LastUsedAt:        pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}
}

func createCredentialRows(credentials ...db.Credential) *pgxmock.Rows {
	rows := pgxmock.NewRows(credentialColumns)
	for _, cred := range credentials {
		rows.AddRow(cred.ID, cred.UserID, cred.PublicKey, cred.SignCount, cred.Transports, cred.Aaguid, cred.AttestationFormat, cred.BackupEligible, cred.BackupState, cred.CreatedAt, cred.LastUsedAt)
	}
	return rows
}

// Mock setup helpers
func expectUserNotFound(mockDB pgxmock.PgxPoolIface, username string) {
	mockDB.ExpectQuery(selectUserByUsernameQuery).
		WithArgs(username).
		WillReturnError(sql.ErrNoRows)
}

func expectUserFound(mockDB pgxmock.PgxPoolIface, username, role string, status string) {
	rows := createUserRowsFromData(uuid.New(), username, role, status)
	mockDB.ExpectQuery(selectUserByUsernameQuery).
		WithArgs(username).
		WillReturnRows(rows)
}

func expectCreateUser(mockDB pgxmock.PgxPoolIface, username string) {
	rows := createUserRowsFromData(uuid.New(), username, roleUser, "pending")
	mockDB.ExpectQuery(insertUserQuery).
		WithArgs(username).
		WillReturnRows(rows)
}

func expectCreateUserWithRole(mockDB pgxmock.PgxPoolIface, username, role string) {
	rows := createUserRowsFromData(uuid.New(), username, role, "pending")
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
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
}

func expectCreateCredentialError(mockDB pgxmock.PgxPoolIface, errorMsg string) {
	mockDB.ExpectExec(createCredentialQuery).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
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

func expectUpdateCredentialSuccess(mockDB pgxmock.PgxPoolIface, credentialID []byte, signCount int64) {
	mockDB.ExpectExec(updateCredentialQuery).
		WithArgs(credentialID, signCount).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
}

func expectUpdateCredentialError(mockDB pgxmock.PgxPoolIface, credentialID []byte, signCount int64, errorMsg string) {
	mockDB.ExpectExec(updateCredentialQuery).
		WithArgs(credentialID, signCount).
		WillReturnError(errors.New(errorMsg))
}

func expectActivateUserSuccess(mockDB pgxmock.PgxPoolIface, userID uuid.UUID) {
	mockDB.ExpectExec(activateUserQuery).
		WithArgs(userID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
}

func expectActivateUserError(mockDB pgxmock.PgxPoolIface, userID uuid.UUID) {
	mockDB.ExpectExec(activateUserQuery).
		WithArgs(userID).
		WillReturnError(errors.New("database error"))
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
		t.Errorf("Expected user to be active")
	}
	if user.Status != "active" {
		t.Errorf("Expected status 'active', got '%s'", user.Status)
	}
}

func validateInactiveUser(t *testing.T, user db.User, expectedUsername, expectedRole string) {
	validateUserBasics(t, user, expectedUsername, expectedRole)
	if user.IsActive {
		t.Errorf("Expected user to be inactive")
	}
	if user.Status != "pending" {
		t.Errorf("Expected status 'pending', got '%s'", user.Status)
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

type blacklistTokenTestCase struct {
	name          string
	token         string
	expiration    time.Time
	expectedError error
	description   string
}

type activateUserTestCase struct {
	name          string
	userID        uuid.UUID
	setupMock     func(pgxmock.PgxPoolIface, uuid.UUID)
	expectedError error
}

type isTokenBlacklistedTestCase struct {
	name           string
	token          string
	expectedResult bool
	expectedError  error
	setupRedis     func(client *redis.Client)
	description    string
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
				validateUserBasics(t, user, testUsername, roleUser)
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
				validateUserBasics(t, user, testAdminUsername, roleAdmin)
			},
		},
		{
			name:     "user already exists with active status",
			username: testExistingUser,
			role:     "",
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				rows := createUserRowsFromData(uuid.New(), testExistingUser, roleUser, "active")
				mockDB.ExpectQuery(selectUserByUsernameQuery).
					WithArgs(testExistingUser).
					WillReturnRows(rows)
			},
			expectedError: customerrors.ErrUsernameAlreadyExists,
			validateUser:  nil,
		},
		{
			name:     "user already exists with pending status - return existing user",
			username: testPendingUser,
			role:     "",
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				rows := createUserRowsFromData(uuid.New(), testPendingUser, roleUser, "pending")
				mockDB.ExpectQuery(selectUserByUsernameQuery).
					WithArgs(testPendingUser).
					WillReturnRows(rows)
			},
			expectedError: nil,
			validateUser: func(t *testing.T, user db.User) {
				validateUserBasics(t, user, testPendingUser, roleUser)
				if user.Status != "pending" {
					t.Errorf("Expected status 'pending', got '%s'", user.Status)
				}
			},
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
				expectUserFound(mockDB, testUsername, roleUser, "active")
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
				expectUserFound(mockDB, testAdminUsername, roleAdmin, "active")
			},
			expectedError: nil,
			validateUser: func(t *testing.T, user db.User) {
				validateActiveUser(t, user, testAdminUsername, roleAdmin)
			},
		},
		{
			name:     "user with pending status",
			username: testInactiveUser,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				rows := pgxmock.NewRows(userColumns).
					AddRow(uuid.New(), testInactiveUser, roleUser, "pending", pgtype.Timestamptz{Time: time.Now(), Valid: true}, pgtype.Timestamptz{Time: time.Now(), Valid: true}, false)
				mockDB.ExpectQuery(selectUserByUsernameQuery).
					WithArgs(testInactiveUser).
					WillReturnRows(rows)
			},
			expectedError: nil,
			validateUser: func(t *testing.T, user db.User) {
				validateUserBasics(t, user, testInactiveUser, roleUser)
				if user.IsActive {
					t.Errorf("Expected user to be inactive")
				}
				if user.Status != "pending" {
					t.Errorf("Expected status 'pending', got '%s'", user.Status)
				}
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
				expectUserFound(mockDB, testUnicodeUser, roleUser, "active")
			},
			expectedError: nil,
		},
		{
			name:     "case sensitive username lookup",
			username: testCamelCaseUser,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserFound(mockDB, testCamelCaseUser, roleUser, "active")
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
				expectUserFound(mockDB, testEmailUser, roleUser, "active")
			},
			expectedError: nil,
		},
		{
			name:     "long username",
			username: testLongUsername,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUserFound(mockDB, testLongUsername, roleUser, "active")
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
			t.Errorf(msgUnmetExpectations, err)
		}
	})
}

// Test runners
// Generic helper functions to eliminate duplication
func checkTestError(t *testing.T, expectedError, actualError error) {
	if expectedError != nil {
		if actualError != expectedError {
			t.Errorf("Expected error %v, got %v", expectedError, actualError)
		}
	} else {
		if actualError != nil {
			t.Errorf(msgExpectedNoError, actualError)
		}
	}
}

func checkMockExpectations(t *testing.T, mockDB pgxmock.PgxPoolIface) {
	if err := mockDB.ExpectationsWereMet(); err != nil {
		t.Errorf(msgUnmetExpectations, err)
	}
}

// Additional helper function for simple test operations
func runSimpleTests(t *testing.T, testName string, testFunc func() error, expectedError error) {
	t.Run(testName, func(t *testing.T) {
		err := testFunc()
		checkTestError(t, expectedError, err)
	})
}

// Benchmark helper functions
func setupBenchmarkRepo(b *testing.B) (pgxmock.PgxPoolIface, UserRepository) {
	return setupRepoWithoutRedis(&testing.T{})
}

func runBenchmarkOperation(b *testing.B, setupFunc func(int), operation func()) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		setupFunc(i)
		b.StartTimer()
		operation()
	}
}

func runSaveUserTests(t *testing.T, tests []saveUserTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			tt.setupMock(mockDB)

			user, err := repo.SaveUser(context.Background(), tt.username, tt.role)

			checkTestError(t, tt.expectedError, err)
			if err == nil && tt.validateUser != nil {
				tt.validateUser(t, user)
			}

			checkMockExpectations(t, mockDB)
		})
	}
}

func runGetUserTests(t *testing.T, tests []getUserTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			tt.setupMock(mockDB)

			user, err := repo.GetUserByUsername(context.Background(), tt.username)

			checkTestError(t, tt.expectedError, err)
			if err == nil && tt.validateUser != nil {
				tt.validateUser(t, user)
			}

			checkMockExpectations(t, mockDB)
		})
	}
}

func TestSaveRegisterSession(t *testing.T) {
	tests := []saveSessionTestCase{
		{
			name:        descSessionSave + suffixRegisterSession,
			user:        createTestWebAuthnUser(testUsername),
			sessionData: createTestSessionData(),
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateSessionSuccess(mockDB)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, sessionID uuid.UUID, err error) {
				if sessionID == uuid.Nil {
					t.Error(msgExpectedNonNilSessionID)
				}
			},
		},
		{
			name:        descDatabaseError + suffixDuringRegisterSave,
			user:        createTestWebAuthnUser(testUsername),
			sessionData: createTestSessionData(),
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateSessionError(mockDB, errDatabaseError)
			},
			expectedError: errors.New(errDatabaseError),
		},
		{
			name:        prefixSaveRegisterSession + descNilData,
			user:        createTestWebAuthnUser(testUsername),
			sessionData: nil,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateSessionSuccess(mockDB)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, sessionID uuid.UUID, err error) {
				if sessionID == uuid.Nil {
					t.Error(msgExpectedNonNilSessionID)
				}
			},
		},
		{
			name: prefixSaveRegisterSession + descComplexData,
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
			name:        descSessionSave + suffixLoginSession,
			user:        createTestWebAuthnUser(testUsername),
			sessionData: createTestSessionData(),
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateSessionSuccess(mockDB)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, sessionID uuid.UUID, err error) {
				if sessionID == uuid.Nil {
					t.Error(msgExpectedNonNilSessionID)
				}
			},
		},
		{
			name:        descDatabaseError + suffixDuringLoginSave,
			user:        createTestWebAuthnUser(testUsername),
			sessionData: createTestSessionData(),
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateSessionError(mockDB, errDatabaseError)
			},
			expectedError: errors.New(errDatabaseError),
		},
		{
			name: prefixSaveLoginSession + descAdminUser,
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
			name:      descSessionRetrieve + suffixRegisterSession,
			sessionID: sessionID,
			purpose:   purposeRegistration,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectGetSessionSuccess(mockDB, sessionID, purposeRegistration, testSession)
			},
			expectedError: nil,
			validateSession: func(t *testing.T, session db.WebauthnSession) {
				if session.ID != sessionID {
					t.Errorf(msgExpectedSessionID, sessionID, session.ID)
				}
				if session.Purpose != purposeRegistration {
					t.Errorf(msgExpectedPurpose, purposeRegistration, session.Purpose)
				}
			},
		},
		{
			name:      descSessionNotFound + suffixRegisterSession,
			sessionID: sessionID,
			purpose:   purposeRegistration,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectGetSessionNotFound(mockDB, sessionID, purposeRegistration)
			},
			expectedError: customerrors.ErrSessionNotFound,
		},
		{
			name:      descDatabaseError + suffixDuringRegisterRetrieval,
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
			name:      descSessionRetrieve + suffixLoginSession,
			sessionID: sessionID,
			purpose:   purposeLogin,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectGetSessionSuccess(mockDB, sessionID, purposeLogin, testSession)
			},
			expectedError: nil,
			validateSession: func(t *testing.T, session db.WebauthnSession) {
				if session.ID != sessionID {
					t.Errorf(msgExpectedSessionID, sessionID, session.ID)
				}
				if session.Purpose != purposeLogin {
					t.Errorf(msgExpectedPurpose, purposeLogin, session.Purpose)
				}
			},
		},
		{
			name:      descSessionNotFound + suffixLoginSession,
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
			name:      descDatabaseError + suffixDuringSessionDeletion,
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
			t.Errorf(msgExpectedNoErrorSaving, err)
		}

		// Retrieve register session
		testSession := createTestSession(user.ID, purposeRegistration)
		testSession.ID = sessionID
		expectGetSessionSuccess(mockDB, sessionID, purposeRegistration, testSession)

		retrievedSession, err := repo.GetRegisterSession(context.Background(), sessionID)
		if err != nil {
			t.Errorf(msgExpectedNoErrorRetrieving, err)
		}

		if retrievedSession.ID != sessionID {
			t.Errorf(msgExpectedSessionID, sessionID, retrievedSession.ID)
		}

		// Delete session
		expectDeleteSessionSuccess(mockDB, sessionID)
		err = repo.DeleteSession(context.Background(), sessionID)
		if err != nil {
			t.Errorf(msgExpectedNoErrorDeleting, err)
		}

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf(msgUnmetExpectations, err)
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
			t.Errorf(msgExpectedNoErrorSaving, err)
		}

		// Retrieve login session
		testSession := createTestSession(user.ID, purposeLogin)
		testSession.ID = sessionID
		expectGetSessionSuccess(mockDB, sessionID, purposeLogin, testSession)

		retrievedSession, err := repo.GetLoginSession(context.Background(), sessionID)
		if err != nil {
			t.Errorf(msgExpectedNoErrorRetrieving, err)
		}

		if retrievedSession.Purpose != purposeLogin {
			t.Errorf(msgExpectedPurpose, purposeLogin, retrievedSession.Purpose)
		}

		// Delete session
		expectDeleteSessionSuccess(mockDB, sessionID)
		err = repo.DeleteSession(context.Background(), sessionID)
		if err != nil {
			t.Errorf(msgExpectedNoErrorDeleting, err)
		}

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf(msgUnmetExpectations, err)
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
					t.Errorf(msgExpectedNoError, err)
				}
				if tt.validateResponse != nil {
					tt.validateResponse(t, sessionID, err)
				}
			}

			checkMockExpectations(t, mockDB)
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
			name:   "credential with invalid AAGUID length",
			userID: userID,
			credential: &webauthn.Credential{
				ID:              []byte(testCredentialID),
				PublicKey:       []byte(testPublicKeyData),
				AttestationType: testAttestationType,
				Transport:       []protocol.AuthenticatorTransport{protocol.USB},
				Flags: webauthn.CredentialFlags{
					BackupEligible: false,
					BackupState:    false,
				},
				Authenticator: webauthn.Authenticator{
					AAGUID:    []byte("invalid-aaguid"), // Invalid length
					SignCount: 100,
				},
			},
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectCreateCredentialSuccess(mockDB)
			},
			expectedError: nil,
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
			ID:                []byte("credential-2"),
			UserID:            userID,
			PublicKey:         []byte("public-key-2"),
			SignCount:         200,
			Transports:        []string{testTransportUSB},
			Aaguid:            func() uuid.UUID { aaguid, _ := uuid.Parse(testAAGUID); return aaguid }(),
			AttestationFormat: pgtype.Text{String: "packed", Valid: true},
			BackupEligible:    false,
			BackupState:       true,
			CreatedAt:         pgtype.Timestamptz{Time: time.Now(), Valid: true},
			LastUsedAt:        pgtype.Timestamptz{Time: time.Now(), Valid: true},
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
				if string(credentials[0].ID) != testCredentialID {
					t.Errorf("Expected credential ID %s, got %s", testCredentialID, string(credentials[0].ID))
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
			name:   descDatabaseError + suffixDuringCredentialsRetrieval,
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
				expectUpdateCredentialSuccess(mockDB, updatedCredential.ID, int64(updatedCredential.Authenticator.SignCount))
			},
			expectedError: nil,
		},
		{
			name:       "database error during credential update",
			credential: credential,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUpdateCredentialError(mockDB, credential.ID, int64(credential.Authenticator.SignCount), errDatabaseError)
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
				expectUpdateCredentialSuccess(mockDB, []byte(testCredentialID), 0)
			},
			expectedError: nil,
		},
		{
			name:       "update non-existent credential",
			credential: credential,
			setupMock: func(mockDB pgxmock.PgxPoolIface) {
				expectUpdateCredentialError(mockDB, credential.ID, int64(credential.Authenticator.SignCount), "credential not found")
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
			t.Errorf(msgExpectedNoErrorSavingCred, err)
		}

		// Get credentials
		dbCredentials := []db.Credential{createTestDBCredential(userID)}
		expectGetCredentialsByUserIDSuccess(mockDB, userID, dbCredentials)

		retrievedCredentials, err := repo.GetCredentialsByUserID(context.Background(), userID)
		if err != nil {
			t.Errorf(msgExpectedNoErrorRetrievingCred, err)
		}

		if len(retrievedCredentials) != 1 {
			t.Errorf("Expected 1 credential, got %d", len(retrievedCredentials))
		}

		// Update credential
		credential.Authenticator.SignCount = 200
		expectUpdateCredentialSuccess(mockDB, credential.ID, int64(credential.Authenticator.SignCount))

		err = repo.UpdateCredentials(context.Background(), credential)
		if err != nil {
			t.Errorf(msgExpectedNoErrorUpdating, err)
		}

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf(msgUnmetExpectations, err)
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

			checkTestError(t, tt.expectedError, err)
			checkMockExpectations(t, mockDB)
		})
	}
}

func runGetCredentialsTests(t *testing.T, tests []getCredentialsTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			tt.setupMock(mockDB)

			credentials, err := repo.GetCredentialsByUserID(context.Background(), tt.userID)

			checkTestError(t, tt.expectedError, err)
			if err == nil && tt.validateCredentials != nil {
				tt.validateCredentials(t, credentials)
			}

			checkMockExpectations(t, mockDB)
		})
	}
}

func runUpdateCredentialTests(t *testing.T, tests []updateCredentialTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			tt.setupMock(mockDB)

			err := repo.UpdateCredentials(context.Background(), tt.credential)

			checkTestError(t, tt.expectedError, err)
			checkMockExpectations(t, mockDB)
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

			checkTestError(t, tt.expectedError, err)
			if err == nil && tt.validateSession != nil {
				tt.validateSession(t, session)
			}

			checkMockExpectations(t, mockDB)
		})
	}
}

func runDeleteSessionTests(t *testing.T, tests []deleteSessionTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			tt.setupMock(mockDB)

			err := repo.DeleteSession(context.Background(), tt.sessionID)

			checkTestError(t, tt.expectedError, err)
			checkMockExpectations(t, mockDB)
		})
	}
}

// Benchmark tests for token operations
func BenchmarkBlacklistToken(b *testing.B) {
	_, _, repo := setupMockRepo(&testing.T{})
	token := testToken
	expiration := time.Now().Add(1 * time.Hour)

	runBenchmarkOperation(b,
		func(i int) {}, // No setup needed
		func() { repo.BlacklistToken(context.Background(), token, expiration) })
}

func BenchmarkIsTokenBlacklisted(b *testing.B) {
	_, _, repo := setupMockRepo(&testing.T{})
	token := testToken
	expiration := time.Now().Add(1 * time.Hour)

	// Blacklist the token first
	repo.BlacklistToken(context.Background(), token, expiration)

	runBenchmarkOperation(b,
		func(i int) {}, // No setup needed
		func() { repo.IsTokenBlacklisted(context.Background(), token) })
}

// Benchmark tests for credential operations
func BenchmarkSaveCredentials(b *testing.B) {
	mockDB, repo := setupBenchmarkRepo(b)
	userID := uuid.New()
	credential := createTestCredential(userID)

	runBenchmarkOperation(b,
		func(i int) { expectCreateCredentialSuccess(mockDB) },
		func() { repo.SaveCredentials(context.Background(), userID, credential) })
}

func TestBlacklistToken(t *testing.T) {
	tests := []blacklistTokenTestCase{
		{
			name:          "successful token blacklist",
			token:         testToken,
			expiration:    time.Now().Add(1 * time.Hour),
			expectedError: nil,
			description:   "Valid token with future expiration should be blacklisted",
		},
		{
			name:          "token with past expiration",
			token:         testExpiredToken,
			expiration:    time.Now().Add(-1 * time.Hour),
			expectedError: nil,
			description:   "Token with past expiration should return nil (no-op)",
		},
		{
			name:          "token with zero expiration",
			token:         testToken,
			expiration:    time.Now(),
			expectedError: nil,
			description:   "Token with current time expiration should return nil",
		},
		{
			name:          "empty token",
			token:         "",
			expiration:    time.Now().Add(1 * time.Hour),
			expectedError: nil,
			description:   "Empty token should be handled gracefully",
		},
		{
			name:          "very long token",
			token:         "very.long.token.that.might.cause.issues.in.some.systems.with.very.long.jwt.tokens.that.exceed.normal.length.limits",
			expiration:    time.Now().Add(2 * time.Hour),
			expectedError: nil,
			description:   "Very long token should be handled correctly",
		},
		{
			name:          "token with special characters",
			token:         "token.with-special_chars+and/symbols=",
			expiration:    time.Now().Add(30 * time.Minute),
			expectedError: nil,
			description:   "Token with special characters should be handled",
		},
		{
			name:          "duplicate token blacklist attempt",
			token:         testToken,
			expiration:    time.Now().Add(1 * time.Hour),
			expectedError: nil,
			description:   "Attempting to blacklist same token twice should not error",
		},
		{
			name:          "token with minimal expiration",
			token:         "minimal.expiration.token",
			expiration:    time.Now().Add(1 * time.Millisecond),
			expectedError: nil,
			description:   "Token with very short expiration should be handled",
		},
	}

	runBlacklistTokenTests(t, tests)
}

func TestIsTokenBlacklisted(t *testing.T) {
	tests := []isTokenBlacklistedTestCase{
		{
			name:           "token is blacklisted",
			token:          testToken,
			expectedResult: true,
			expectedError:  nil,
			setupRedis: func(client *redis.Client) {
				// No setup needed - we'll blacklist in the test itself
			},
			description: "Blacklisted token should return true",
		},
		{
			name:           "token is not blacklisted",
			token:          testToken2,
			expectedResult: false,
			expectedError:  nil,
			setupRedis: func(client *redis.Client) {
				// No setup needed - token not in Redis
			},
			description: "Non-blacklisted token should return false",
		},
		{
			name:           "empty token check",
			token:          "",
			expectedResult: false,
			expectedError:  nil,
			setupRedis: func(client *redis.Client) {
				// No setup needed
			},
			description: "Empty token should return false",
		},
		{
			name:           "invalid token format",
			token:          testInvalidToken,
			expectedResult: false,
			expectedError:  nil,
			setupRedis: func(client *redis.Client) {
				// No setup needed
			},
			description: "Invalid token format should return false",
		},
		{
			name:           "check multiple tokens",
			token:          testToken,
			expectedResult: false,
			expectedError:  nil,
			setupRedis: func(client *redis.Client) {
				// Set up multiple tokens but not the one we're checking
				ctx := context.Background()
				client.Set(ctx, "blacklist:other1", "1", time.Hour)
				client.Set(ctx, "blacklist:other2", "1", time.Hour)
			},
			description: "Token should not be found among other blacklisted tokens",
		},
		{
			name:           "very long token check",
			token:          "very.long.token.that.might.cause.issues.in.some.systems.with.very.long.jwt.tokens.that.exceed.normal.length.limits",
			expectedResult: false,
			expectedError:  nil,
			setupRedis: func(client *redis.Client) {
				// No setup needed
			},
			description: "Very long token should be handled correctly",
		},
		{
			name:           "token with unicode characters",
			token:          "token.with.unicode.测试.字符",
			expectedResult: false,
			expectedError:  nil,
			setupRedis: func(client *redis.Client) {
				// No setup needed
			},
			description: "Token with unicode characters should be handled",
		},
	}

	runIsTokenBlacklistedTests(t, tests)
}

func TestTokenBlacklistIntegrationFlow(t *testing.T) {
	t.Run("complete token blacklist lifecycle", func(t *testing.T) {
		mockDB, mr, repo := setupMockRepo(t)
		token := testToken
		expiration := time.Now().Add(1 * time.Hour)

		// Check token is not blacklisted initially
		isBlacklisted, err := repo.IsTokenBlacklisted(context.Background(), token)
		if err != nil {
			t.Errorf(msgExpectedNoErrorChecking, err)
		}
		if isBlacklisted {
			t.Error("Expected token to not be blacklisted initially")
		}

		// Blacklist the token
		err = repo.BlacklistToken(context.Background(), token, expiration)
		if err != nil {
			t.Errorf(msgExpectedNoErrorBlacklisting, err)
		}

		// Check token is now blacklisted
		isBlacklisted, err = repo.IsTokenBlacklisted(context.Background(), token)
		if err != nil {
			t.Errorf(msgExpectedNoErrorChecking, err)
		}
		if !isBlacklisted {
			t.Error("Expected token to be blacklisted")
		}

		// Clean up
		_ = mockDB
		_ = mr
	})

	t.Run("expired token cleanup", func(t *testing.T) {
		_, mr, repo := setupMockRepo(t)
		token := testExpiredToken

		// Blacklist token with short expiration
		shortExpiration := time.Now().Add(100 * time.Millisecond)
		err := repo.BlacklistToken(context.Background(), token, shortExpiration)
		if err != nil {
			t.Errorf("Failed to blacklist token: %v", err)
		}

		// Verify token is initially blacklisted
		isBlacklisted, err := repo.IsTokenBlacklisted(context.Background(), token)
		if err != nil {
			t.Errorf(msgExpectedNoErrorChecking, err)
		}
		if !isBlacklisted {
			t.Error("Expected token to be blacklisted initially")
		}

		// Fast forward time in miniredis to simulate expiration
		mr.FastForward(2 * time.Hour)

		// Check that expired token is no longer blacklisted
		isBlacklisted, err = repo.IsTokenBlacklisted(context.Background(), token)
		if err != nil {
			t.Errorf(msgExpectedNoErrorChecking, err)
		}
		if isBlacklisted {
			t.Error("Expected expired token to not be blacklisted")
		}
	})

	t.Run("multiple tokens management", func(t *testing.T) {
		_, _, repo := setupMockRepo(t)
		tokens := []string{
			"token1.jwt.test",
			"token2.jwt.test",
			"token3.jwt.test",
		}
		expiration := time.Now().Add(1 * time.Hour)

		// Blacklist multiple tokens
		for _, token := range tokens {
			err := repo.BlacklistToken(context.Background(), token, expiration)
			if err != nil {
				t.Errorf("Failed to blacklist token %s: %v", token, err)
			}
		}

		// Verify all tokens are blacklisted
		for _, token := range tokens {
			isBlacklisted, err := repo.IsTokenBlacklisted(context.Background(), token)
			if err != nil {
				t.Errorf("Error checking token %s: %v", token, err)
			}
			if !isBlacklisted {
				t.Errorf("Expected token %s to be blacklisted", token)
			}
		}

		// Verify a non-blacklisted token is not affected
		nonBlacklistedToken := "clean.token.test"
		isBlacklisted, err := repo.IsTokenBlacklisted(context.Background(), nonBlacklistedToken)
		if err != nil {
			t.Errorf("Error checking clean token: %v", err)
		}
		if isBlacklisted {
			t.Error("Expected clean token to not be blacklisted")
		}
	})
}

func TestTokenHashingConsistency(t *testing.T) {
	t.Run("same token produces same hash", func(t *testing.T) {
		_, _, repo := setupMockRepo(t)

		// Access the private hashToken method through blacklisting
		token := testToken
		expiration := time.Now().Add(1 * time.Hour)

		// Blacklist token first time
		err1 := repo.BlacklistToken(context.Background(), token, expiration)
		if err1 != nil {
			t.Errorf("First blacklist attempt failed: %v", err1)
		}

		// Check token is blacklisted
		isBlacklisted, err := repo.IsTokenBlacklisted(context.Background(), token)
		if err != nil {
			t.Errorf("Error checking token: %v", err)
		}
		if !isBlacklisted {
			t.Error("Token should be blacklisted after first attempt")
		}

		// Try to blacklist same token again - should not error but may not change anything due to NX flag
		err2 := repo.BlacklistToken(context.Background(), token, expiration)
		// Note: err2 might be nil (Redis NX behavior) - this is expected

		// Token should still be blacklisted regardless
		isBlacklisted2, err := repo.IsTokenBlacklisted(context.Background(), token)
		if err != nil {
			t.Errorf("Error checking token after second blacklist: %v", err)
		}
		if !isBlacklisted2 {
			t.Error("Token should still be blacklisted after second attempt")
		}

		// Test with different token to verify hashing works correctly
		differentToken := testToken2
		isDifferentBlacklisted, err := repo.IsTokenBlacklisted(context.Background(), differentToken)
		if err != nil {
			t.Errorf("Error checking different token: %v", err)
		}
		if isDifferentBlacklisted {
			t.Error("Different token should not be blacklisted")
		}

		// Suppress unused variable warning
		_ = err2
	})

	t.Run("token hashing security", func(t *testing.T) {
		_, _, repo := setupMockRepo(t)

		// Test that similar tokens produce different hashes
		tokens := []string{
			"token.test.1",
			"token.test.2",
			"token_test_1",
			"token-test-1",
		}
		expiration := time.Now().Add(1 * time.Hour)

		// Blacklist first token
		err := repo.BlacklistToken(context.Background(), tokens[0], expiration)
		if err != nil {
			t.Errorf("Failed to blacklist first token: %v", err)
		}

		// Verify first token is blacklisted
		isBlacklisted, err := repo.IsTokenBlacklisted(context.Background(), tokens[0])
		if err != nil {
			t.Errorf("Error checking first token: %v", err)
		}
		if !isBlacklisted {
			t.Error("Expected first token to be blacklisted")
		}

		// Verify similar tokens are NOT blacklisted
		for i, token := range tokens[1:] {
			isBlacklisted, err := repo.IsTokenBlacklisted(context.Background(), token)
			if err != nil {
				t.Errorf("Error checking token %d: %v", i+1, err)
			}
			if isBlacklisted {
				t.Errorf("Expected token %d (%s) to NOT be blacklisted", i+1, token)
			}
		}
	})
}

// Token test runners
func runBlacklistTokenTests(t *testing.T, tests []blacklistTokenTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, repo := setupMockRepo(t)

			err := repo.BlacklistToken(context.Background(), tt.token, tt.expiration)

			checkTestError(t, tt.expectedError, err)
		})
	}
}

func runIsTokenBlacklistedTests(t *testing.T, tests []isTokenBlacklistedTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, mr, repo := setupMockRepo(t)

			// For the blacklisted token test, actually blacklist it first
			if tt.expectedResult == true {
				expiration := time.Now().Add(1 * time.Hour)
				err := repo.BlacklistToken(context.Background(), tt.token, expiration)
				if err != nil {
					t.Errorf("Failed to blacklist token for test: %v", err)
				}
			}

			// Setup Redis state if needed
			if tt.setupRedis != nil {
				// Get Redis client from miniredis
				client := redis.NewClient(&redis.Options{
					Addr: mr.Addr(),
				})
				defer client.Close()
				tt.setupRedis(client)
			}

			result, err := repo.IsTokenBlacklisted(context.Background(), tt.token)

			checkTestError(t, tt.expectedError, err)
			if err == nil && result != tt.expectedResult {
				t.Errorf("Expected result %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func BenchmarkGetCredentialsByUserID(b *testing.B) {
	mockDB, repo := setupBenchmarkRepo(b)
	userID := uuid.New()
	credentials := []db.Credential{createTestDBCredential(userID)}

	runBenchmarkOperation(b,
		func(i int) { expectGetCredentialsByUserIDSuccess(mockDB, userID, credentials) },
		func() { repo.GetCredentialsByUserID(context.Background(), userID) })
}

func BenchmarkUpdateCredentials(b *testing.B) {
	mockDB, repo := setupBenchmarkRepo(b)
	credential := createTestCredential(uuid.New())

	runBenchmarkOperation(b,
		func(i int) {
			expectUpdateCredentialSuccess(mockDB, credential.ID, int64(credential.Authenticator.SignCount))
		},
		func() { repo.UpdateCredentials(context.Background(), credential) })
}

// Benchmark tests for session operations
func BenchmarkSaveRegisterSession(b *testing.B) {
	mockDB, repo := setupBenchmarkRepo(b)
	user := createTestWebAuthnUser(testUsername)
	sessionData := createTestSessionData()

	runBenchmarkOperation(b,
		func(i int) { expectCreateSessionSuccess(mockDB) },
		func() { repo.SaveRegisterSession(context.Background(), user, sessionData) })
}

func BenchmarkSaveLoginSession(b *testing.B) {
	mockDB, repo := setupBenchmarkRepo(b)
	user := createTestWebAuthnUser(testUsername)
	sessionData := createTestSessionData()

	runBenchmarkOperation(b,
		func(i int) { expectCreateSessionSuccess(mockDB) },
		func() { repo.SaveLoginSession(context.Background(), user, sessionData) })
}

func BenchmarkGetRegisterSession(b *testing.B) {
	mockDB, repo := setupBenchmarkRepo(b)
	sessionID := uuid.New()
	userID := uuid.New()
	testSession := createTestSession(userID, purposeRegistration)

	runBenchmarkOperation(b,
		func(i int) { expectGetSessionSuccess(mockDB, sessionID, purposeRegistration, testSession) },
		func() { repo.GetRegisterSession(context.Background(), sessionID) })
}

func BenchmarkGetLoginSession(b *testing.B) {
	mockDB, repo := setupBenchmarkRepo(b)
	sessionID := uuid.New()
	userID := uuid.New()
	testSession := createTestSession(userID, purposeLogin)

	runBenchmarkOperation(b,
		func(i int) { expectGetSessionSuccess(mockDB, sessionID, purposeLogin, testSession) },
		func() { repo.GetLoginSession(context.Background(), sessionID) })
}

func BenchmarkDeleteSession(b *testing.B) {
	mockDB, repo := setupBenchmarkRepo(b)
	sessionID := uuid.New()

	runBenchmarkOperation(b,
		func(i int) { expectDeleteSessionSuccess(mockDB, sessionID) },
		func() { repo.DeleteSession(context.Background(), sessionID) })
}

// Benchmark tests for performance
func BenchmarkSaveUser(b *testing.B) {
	mockDB, repo := setupBenchmarkRepo(b)

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
	mockDB, repo := setupBenchmarkRepo(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		username := fmt.Sprintf("user%d", i)
		expectUserFound(mockDB, username, roleUser, "active")
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
			t.Errorf(msgExpectedNoErrorCreating, err)
		}

		// Step 3: Retrieve the created user
		expectUserFound(mockDB, username, roleUser, "active")

		retrievedUser, err := repo.GetUserByUsername(context.Background(), username)
		if err != nil {
			t.Errorf(msgExpectedNoErrorRetrieving, err)
		}

		if retrievedUser.Username != createdUser.Username {
			t.Errorf("Expected retrieved username %s, got %s", createdUser.Username, retrievedUser.Username)
		}

		// Step 4: Try to create duplicate user
		expectUserFound(mockDB, username, roleUser, "active")

		_, err = repo.SaveUser(context.Background(), username, "")
		if err != customerrors.ErrUsernameAlreadyExists {
			t.Errorf("Expected ErrUsernameAlreadyExists, got %v", err)
		}

		checkMockExpectations(t, mockDB)
	})
}

func TestActivateUser(t *testing.T) {
	testCases := []activateUserTestCase{
		{
			name:   "successful activation",
			userID: uuid.New(),
			setupMock: func(mock pgxmock.PgxPoolIface, userID uuid.UUID) {
				expectActivateUserSuccess(mock, userID)
			},
			expectedError: nil,
		},
		{
			name:   "database error",
			userID: uuid.New(),
			setupMock: func(mock pgxmock.PgxPoolIface, userID uuid.UUID) {
				expectActivateUserError(mock, userID)
			},
			expectedError: customerrors.ErrUserNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB, repo := setupRepoWithoutRedis(t)
			defer mockDB.Close()

			tc.setupMock(mockDB, tc.userID)

			err := repo.ActivateUser(context.Background(), tc.userID)

			if tc.expectedError != nil {
				if err == nil {
					t.Errorf("Expected error %v, but got nil", tc.expectedError)
				} else if err.Error() != tc.expectedError.Error() {
					t.Errorf("Expected error %v, but got %v", tc.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got %v", err)
				}
			}

			if err := mockDB.ExpectationsWereMet(); err != nil {
				t.Errorf("Unmet expectations: %v", err)
			}
		})
	}
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

		checkMockExpectations(t, mockDB)
	})
}
