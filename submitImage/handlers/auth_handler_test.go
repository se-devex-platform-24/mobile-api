package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"submit-image/models"
	"submit-image/repositories"
	"submit-image/services"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestAuthHandler_HandleRegister(t *testing.T) {
	// Setup test dependencies
	userRepo := &MockUserRepository{}
	emailService := services.NewMockEmailService()
	captchaService := services.NewMockCaptchaService(false)
	activityLogger := services.NewMockActivityLogger()
	logger := &services.SimpleLogger{}

	authService := services.NewAuthService(userRepo, emailService, captchaService, logger)
	handler := NewAuthHandler(authService, activityLogger)

	tests := []struct {
		name           string
		requestBody    string
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Valid registration",
			requestBody: `{
				"email": "test@example.com",
				"password": "StrongP@ss123",
				"firstName": "John",
				"lastName": "Doe",
				"deviceId": "device-123",
				"deviceType": "ios",
				"deviceToken": "token-123",
				"appVersion": "1.0.0",
				"captchaToken": "valid-captcha"
			}`,
			expectedStatus: 201,
		},
		{
			name: "Invalid email",
			requestBody: `{
				"email": "invalid-email",
				"password": "StrongP@ss123",
				"firstName": "John",
				"lastName": "Doe",
				"deviceId": "device-123",
				"deviceType": "ios",
				"deviceToken": "token-123",
				"appVersion": "1.0.0",
				"captchaToken": "valid-captcha"
			}`,
			expectedStatus: 400,
			expectedError:  "INVALID_EMAIL",
		},
		{
			name: "Weak password",
			requestBody: `{
				"email": "test@example.com",
				"password": "weak",
				"firstName": "John",
				"lastName": "Doe",
				"deviceId": "device-123",
				"deviceType": "ios",
				"deviceToken": "token-123",
				"appVersion": "1.0.0",
				"captchaToken": "valid-captcha"
			}`,
			expectedStatus: 400,
			expectedError:  "INVALID_PASSWORD",
		},
		{
			name: "Missing device info",
			requestBody: `{
				"email": "test@example.com",
				"password": "StrongP@ss123",
				"firstName": "John",
				"lastName": "Doe",
				"captchaToken": "valid-captcha"
			}`,
			expectedStatus: 400,
			expectedError:  "INVALID_DEVICE_INFO",
		},
		{
			name:           "Invalid JSON",
			requestBody:    `{invalid json}`,
			expectedStatus: 400,
			expectedError:  "INVALID_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := events.APIGatewayProxyRequest{
				Body: tt.requestBody,
				Headers: map[string]string{
					"User-Agent": "test-agent",
				},
				RequestContext: events.APIGatewayProxyRequestContext{
					Identity: events.APIGatewayRequestIdentity{
						SourceIP: "127.0.0.1",
					},
				},
			}

			response, err := handler.HandleRegister(context.Background(), request)
			if err != nil {
				t.Fatalf("Handler returned error: %v", err)
			}

			if response.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, response.StatusCode)
			}

			if tt.expectedError != "" {
				var errorResp map[string]interface{}
				if err := json.Unmarshal([]byte(response.Body), &errorResp); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}

				if errorResp["error"] != tt.expectedError {
					t.Errorf("Expected error %s, got %s", tt.expectedError, errorResp["error"])
				}
			}
		})
	}
}

func TestAuthHandler_HandleVerifyEmail(t *testing.T) {
	userRepo := &MockUserRepository{}
	emailService := services.NewMockEmailService()
	captchaService := services.NewMockCaptchaService(false)
	activityLogger := services.NewMockActivityLogger()
	logger := &services.SimpleLogger{}

	authService := services.NewAuthService(userRepo, emailService, captchaService, logger)
	handler := NewAuthHandler(authService, activityLogger)

	tests := []struct {
		name           string
		requestBody    string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "Valid verification token",
			requestBody:    `{"token": "valid-token"}`,
			expectedStatus: 200,
		},
		{
			name:           "Missing token",
			requestBody:    `{}`,
			expectedStatus: 400,
			expectedError:  "MISSING_TOKEN",
		},
		{
			name:           "Invalid JSON",
			requestBody:    `{invalid}`,
			expectedStatus: 400,
			expectedError:  "INVALID_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := events.APIGatewayProxyRequest{
				Body: tt.requestBody,
				RequestContext: events.APIGatewayProxyRequestContext{
					Identity: events.APIGatewayRequestIdentity{
						SourceIP: "127.0.0.1",
					},
				},
			}

			response, err := handler.HandleVerifyEmail(context.Background(), request)
			if err != nil {
				t.Fatalf("Handler returned error: %v", err)
			}

			if response.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, response.StatusCode)
			}

			if tt.expectedError != "" {
				var errorResp map[string]interface{}
				if err := json.Unmarshal([]byte(response.Body), &errorResp); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}

				if errorResp["error"] != tt.expectedError {
					t.Errorf("Expected error %s, got %s", tt.expectedError, errorResp["error"])
				}
			}
		})
	}
}

// MockUserRepository for testing
type MockUserRepository struct {
	users map[string]*models.User
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
	if m.users == nil {
		m.users = make(map[string]*models.User)
	}
	
	// Check if email already exists
	for _, existingUser := range m.users {
		if existingUser.Email == user.Email {
			return &MockError{message: "email already registered"}
		}
	}
	
	m.users[user.ID] = user
	return nil
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	if m.users == nil {
		return nil, &MockError{message: "user not found"}
	}
	
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, &MockError{message: "user not found"}
}

func (m *MockUserRepository) FindByID(ctx context.Context, id string) (*models.User, error) {
	if m.users == nil {
		return nil, &MockError{message: "user not found"}
	}
	
	user, exists := m.users[id]
	if !exists {
		return nil, &MockError{message: "user not found"}
	}
	return user, nil
}

func (m *MockUserRepository) Update(ctx context.Context, user *models.User) error {
	if m.users == nil {
		return &MockError{message: "user not found"}
	}
	
	if _, exists := m.users[user.ID]; !exists {
		return &MockError{message: "user not found"}
	}
	
	m.users[user.ID] = user
	return nil
}

func (m *MockUserRepository) UpdatePassword(ctx context.Context, userID, hashedPassword string) error {
	if m.users == nil {
		return &MockError{message: "user not found"}
	}
	
	user, exists := m.users[userID]
	if !exists {
		return &MockError{message: "user not found"}
	}
	
	user.Password = hashedPassword
	return nil
}

func (m *MockUserRepository) UpdateVerificationStatus(ctx context.Context, userID string, verified bool) error {
	if m.users == nil {
		return &MockError{message: "user not found"}
	}
	
	user, exists := m.users[userID]
	if !exists {
		return &MockError{message: "user not found"}
	}
	
	user.EmailVerified = verified
	if verified {
		user.UserStatus = models.UserStatusActive
	}
	return nil
}

func (m *MockUserRepository) UpdateResetToken(ctx context.Context, userID, token string, expiry time.Time) error {
	if m.users == nil {
		return &MockError{message: "user not found"}
	}
	
	user, exists := m.users[userID]
	if !exists {
		return &MockError{message: "user not found"}
	}
	
	user.ResetToken = token
	user.ResetTokenExpiry = expiry
	return nil
}

func (m *MockUserRepository) FindByVerificationToken(ctx context.Context, token string) (*models.User, error) {
	if m.users == nil {
		return nil, &MockError{message: "invalid verification token"}
	}
	
	for _, user := range m.users {
		if user.VerificationToken == token {
			return user, nil
		}
	}
	return nil, &MockError{message: "invalid verification token"}
}

func (m *MockUserRepository) FindByResetToken(ctx context.Context, token string) (*models.User, error) {
	if m.users == nil {
		return nil, &MockError{message: "invalid or expired reset token"}
	}
	
	for _, user := range m.users {
		if user.ResetToken == token {
			return user, nil
		}
	}
	return nil, &MockError{message: "invalid or expired reset token"}
}

func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, userID, ipAddress string) error {
	return nil // Not implemented for tests
}

func (m *MockUserRepository) UpdateFailedLoginCount(ctx context.Context, userID string, count int, lockoutUntil *time.Time) error {
	return nil // Not implemented for tests
}

// MockError for testing
type MockError struct {
	message string
}

func (e *MockError) Error() string {
	return e.message
}

import "time"