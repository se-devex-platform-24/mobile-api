package auth

import (
	"time"
)

// User represents a user in the system
type User struct {
	ID            string    `json:"id" dynamodb:"id"`
	Email         string    `json:"email" dynamodb:"email"`
	PasswordHash  string    `json:"-" dynamodb:"password_hash"`
	FirstName     string    `json:"firstName" dynamodb:"first_name"`
	LastName      string    `json:"lastName" dynamodb:"last_name"`
	PhoneNumber   string    `json:"phoneNumber,omitempty" dynamodb:"phone_number"`
	MFAEnabled    bool      `json:"mfaEnabled" dynamodb:"mfa_enabled"`
	MFASecret     string    `json:"-" dynamodb:"mfa_secret"`
	EmailVerified bool      `json:"emailVerified" dynamodb:"email_verified"`
	PhoneVerified bool      `json:"phoneVerified" dynamodb:"phone_verified"`
	CreatedAt     time.Time `json:"createdAt" dynamodb:"created_at"`
	UpdatedAt     time.Time `json:"updatedAt" dynamodb:"updated_at"`
	LastLoginAt   time.Time `json:"lastLoginAt" dynamodb:"last_login_at"`
	FailedLogins  int       `json:"-" dynamodb:"failed_logins"`
	LockedUntil   time.Time `json:"-" dynamodb:"locked_until"`
	IsActive      bool      `json:"isActive" dynamodb:"is_active"`
}

// UserRegistration represents user registration request
type UserRegistration struct {
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,min=8"`
	FirstName   string `json:"firstName" validate:"required,min=1,max=50"`
	LastName    string `json:"lastName" validate:"required,min=1,max=50"`
	PhoneNumber string `json:"phoneNumber,omitempty" validate:"omitempty,e164"`
}

// UserLogin represents user login request
type UserLogin struct {
	Email      string `json:"email" validate:"required,email"`
	Password   string `json:"password" validate:"required"`
	RememberMe bool   `json:"rememberMe"`
}

// MFAVerification represents MFA verification request
type MFAVerification struct {
	SessionToken string `json:"sessionToken" validate:"required"`
	Code         string `json:"code" validate:"required,len=6,numeric"`
}

// RefreshTokenRequest represents token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

// ForgotPasswordRequest represents password reset request
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordRequest represents password reset confirmation
type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"newPassword" validate:"required,min=8"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
	ExpiresIn    int64  `json:"expiresIn,omitempty"`
	TokenType    string `json:"tokenType,omitempty"`
	User         *User  `json:"user,omitempty"`
	RequiresMFA  bool   `json:"requiresMFA,omitempty"`
	SessionToken string `json:"sessionToken,omitempty"`
}

// SuccessResponse represents a generic success response
type SuccessResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// Session represents a user session
type Session struct {
	ID           string    `json:"id" dynamodb:"id"`
	UserID       string    `json:"userId" dynamodb:"user_id"`
	RefreshToken string    `json:"refreshToken" dynamodb:"refresh_token"`
	ExpiresAt    time.Time `json:"expiresAt" dynamodb:"expires_at"`
	CreatedAt    time.Time `json:"createdAt" dynamodb:"created_at"`
	IPAddress    string    `json:"ipAddress" dynamodb:"ip_address"`
	UserAgent    string    `json:"userAgent" dynamodb:"user_agent"`
	IsActive     bool      `json:"isActive" dynamodb:"is_active"`
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	ID        string    `json:"id" dynamodb:"id"`
	UserID    string    `json:"userId" dynamodb:"user_id"`
	Token     string    `json:"token" dynamodb:"token"`
	ExpiresAt time.Time `json:"expiresAt" dynamodb:"expires_at"`
	CreatedAt time.Time `json:"createdAt" dynamodb:"created_at"`
	Used      bool      `json:"used" dynamodb:"used"`
}

// LoginAttempt represents a login attempt for rate limiting
type LoginAttempt struct {
	ID        string    `json:"id" dynamodb:"id"`
	Email     string    `json:"email" dynamodb:"email"`
	IPAddress string    `json:"ipAddress" dynamodb:"ip_address"`
	Success   bool      `json:"success" dynamodb:"success"`
	Timestamp time.Time `json:"timestamp" dynamodb:"timestamp"`
	UserAgent string    `json:"userAgent" dynamodb:"user_agent"`
}

// SecurityLog represents a security event log
type SecurityLog struct {
	ID        string                 `json:"id" dynamodb:"id"`
	UserID    string                 `json:"userId,omitempty" dynamodb:"user_id"`
	Event     string                 `json:"event" dynamodb:"event"`
	IPAddress string                 `json:"ipAddress" dynamodb:"ip_address"`
	UserAgent string                 `json:"userAgent" dynamodb:"user_agent"`
	Timestamp time.Time              `json:"timestamp" dynamodb:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty" dynamodb:"details"`
	Severity  string                 `json:"severity" dynamodb:"severity"`
}