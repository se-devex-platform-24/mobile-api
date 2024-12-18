package auth

import (
	"testing"
	"time"
)

// MockUser represents test user data
type MockUser struct {
	ID              string
	Email           string
	HashedPassword  string
	MFAEnabled      bool
	MFASecret       string
	LoginAttempts   int
	LastLoginAt     time.Time
	PasswordUpdated time.Time
}

// MockAuthService represents a mock authentication service for testing
type MockAuthService struct {
	Users            map[string]MockUser
	FailNextAttempt  bool
	RateLimitReached bool
}

// NewMockAuthService creates a new mock auth service with test data
func NewMockAuthService() *MockAuthService {
	return &MockAuthService{
		Users: map[string]MockUser{
			"test@example.com": {
				ID:              "user123",
				Email:           "test@example.com",
				HashedPassword:  "$2a$10$abcdefghijklmnopqrstuvwxyz123456",
				MFAEnabled:      true,
				MFASecret:       "ABCDEFGHIJKLMNOP",
				LoginAttempts:   0,
				LastLoginAt:     time.Now(),
				PasswordUpdated: time.Now().Add(-24 * time.Hour),
			},
		},
	}
}

// AssertLoginSuccess is a test helper to verify successful login attempts
func AssertLoginSuccess(t *testing.T, mockAuth *MockAuthService, email string) {
	t.Helper()
	user, exists := mockAuth.Users[email]
	if !exists {
		t.Errorf("Expected user %s to exist", email)
	}
	if user.LoginAttempts != 0 {
		t.Errorf("Expected login attempts to be reset to 0, got %d", user.LoginAttempts)
	}
}

// AssertLoginFailure is a test helper to verify failed login attempts
func AssertLoginFailure(t *testing.T, mockAuth *MockAuthService, email string, expectedAttempts int) {
	t.Helper()
	user, exists := mockAuth.Users[email]
	if !exists {
		t.Errorf("Expected user %s to exist", email)
	}
	if user.LoginAttempts != expectedAttempts {
		t.Errorf("Expected %d login attempts, got %d", expectedAttempts, user.LoginAttempts)
	}
}

// AssertMFARequired is a test helper to verify MFA requirements
func AssertMFARequired(t *testing.T, mockAuth *MockAuthService, email string) {
	t.Helper()
	user, exists := mockAuth.Users[email]
	if !exists {
		t.Errorf("Expected user %s to exist", email)
	}
	if !user.MFAEnabled {
		t.Error("Expected MFA to be enabled")
	}
}

// AssertRateLimitExceeded is a test helper to verify rate limiting
func AssertRateLimitExceeded(t *testing.T, mockAuth *MockAuthService) {
	t.Helper()
	if !mockAuth.RateLimitReached {
		t.Error("Expected rate limit to be reached")
	}
}

// CreateTestUser is a helper to create a test user with specific attributes
func CreateTestUser(email string, mfaEnabled bool) MockUser {
	return MockUser{
		ID:              "test_" + email,
		Email:           email,
		HashedPassword:  "$2a$10$abcdefghijklmnopqrstuvwxyz123456",
		MFAEnabled:      mfaEnabled,
		MFASecret:       "ABCDEFGHIJKLMNOP",
		LoginAttempts:   0,
		LastLoginAt:     time.Now(),
		PasswordUpdated: time.Now(),
	}
}
