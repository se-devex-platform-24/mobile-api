package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/google/uuid"
)

// AuthService provides authentication functionality
type AuthService struct {
	repo            *Repository
	jwtManager      *JWTManager
	mfaManager      *MFAManager
	rateLimiter     *RateLimiter
	securityLogger  *SecurityLogger
	securityValidator *SecurityValidator
	accountLockManager *AccountLockManager
	encryptionHelper *EncryptionHelper
}

// AuthServiceConfig contains configuration for the auth service
type AuthServiceConfig struct {
	JWTSecret       []byte
	JWTIssuer       string
	MFAIssuer       string
	TrustedProxies  []string
	EncryptionKey   []byte
}

// NewAuthService creates a new authentication service
func NewAuthService(dynamoDB dynamodbiface.DynamoDBAPI, config *AuthServiceConfig) *AuthService {
	repo := NewRepository(dynamoDB)
	jwtManager := NewJWTManager(config.JWTSecret, config.JWTIssuer)
	mfaManager := NewMFAManager(config.MFAIssuer)
	rateLimiter := NewRateLimiter()
	securityLogger := NewSecurityLogger()
	securityValidator := NewSecurityValidator(config.TrustedProxies)
	accountLockManager := NewAccountLockManager(5, 30*time.Minute) // 5 attempts, 30 min lock
	encryptionHelper := NewEncryptionHelper(config.EncryptionKey)

	return &AuthService{
		repo:               repo,
		jwtManager:         jwtManager,
		mfaManager:         mfaManager,
		rateLimiter:        rateLimiter,
		securityLogger:     securityLogger,
		securityValidator:  securityValidator,
		accountLockManager: accountLockManager,
		encryptionHelper:   encryptionHelper,
	}
}

// RegisterUser registers a new user
func (s *AuthService) RegisterUser(ctx context.Context, req *UserRegistration, ipAddress, userAgent string) (*AuthResponse, error) {
	// Check rate limit
	if err := s.rateLimiter.CheckLoginRateLimit(ctx, ipAddress); err != nil {
		s.logSecurityEvent(ctx, EventRateLimitExceeded, "", ipAddress, userAgent, SeverityWarning, map[string]interface{}{
			"operation": "register",
			"error":     err.Error(),
		})
		return nil, &ErrorResponse{
			Code:    http.StatusTooManyRequests,
			Message: "Rate limit exceeded",
		}
	}

	// Validate password strength
	if err := ValidatePasswordStrength(req.Password); err != nil {
		s.logSecurityEvent(ctx, "weak_password_attempt", "", ipAddress, userAgent, SeverityInfo, map[string]interface{}{
			"email": HashSensitiveData(req.Email),
		})
		return nil, &ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		}
	}

	// Check if user already exists
	existingUser, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		s.logSecurityEvent(ctx, "duplicate_registration_attempt", "", ipAddress, userAgent, SeverityInfo, map[string]interface{}{
			"email": HashSensitiveData(req.Email),
		})
		return nil, &ErrorResponse{
			Code:    http.StatusConflict,
			Message: "User already exists",
		}
	}

	// Hash password
	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to process password",
		}
	}

	// Create user
	user := &User{
		Email:         req.Email,
		PasswordHash:  passwordHash,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		PhoneNumber:   req.PhoneNumber,
		MFAEnabled:    false,
		EmailVerified: false,
		PhoneVerified: false,
		FailedLogins:  0,
		IsActive:      true,
	}

	// Generate MFA secret (even if not enabled yet)
	mfaSecret, _, err := s.mfaManager.GenerateSecret(user.Email)
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to generate MFA secret",
		}
	}
	user.MFASecret = mfaSecret

	// Save user to database
	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to create user",
		}
	}

	// Log successful registration
	s.logSecurityEvent(ctx, EventUserRegistered, user.ID, ipAddress, userAgent, SeverityInfo, map[string]interface{}{
		"email": HashSensitiveData(user.Email),
	})

	// Create session and tokens
	session := &Session{
		UserID:       user.ID,
		ExpiresAt:    time.Now().Add(RefreshTokenExpiry),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
	}

	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Email, "")
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to generate access token",
		}
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID, user.Email, "")
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to generate refresh token",
		}
	}

	session.RefreshToken = refreshToken
	if err := s.repo.CreateSession(ctx, session); err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to create session",
		}
	}

	// Remove sensitive data from user object
	user.PasswordHash = ""
	user.MFASecret = ""

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(AccessTokenExpiry.Seconds()),
		TokenType:    "Bearer",
		User:         user,
		RequiresMFA:  false,
	}, nil
}

// LoginUser authenticates a user
func (s *AuthService) LoginUser(ctx context.Context, req *UserLogin, ipAddress, userAgent string) (*AuthResponse, error) {
	// Check rate limit
	if err := s.rateLimiter.CheckLoginRateLimit(ctx, ipAddress); err != nil {
		s.logSecurityEvent(ctx, EventRateLimitExceeded, "", ipAddress, userAgent, SeverityWarning, map[string]interface{}{
			"operation": "login",
			"email":     HashSensitiveData(req.Email),
		})
		return nil, &ErrorResponse{
			Code:    http.StatusTooManyRequests,
			Message: "Rate limit exceeded",
		}
	}

	// Get user by email
	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// Log failed login attempt
		s.logFailedLogin(ctx, req.Email, ipAddress, userAgent, "user_not_found")
		return nil, &ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "Invalid credentials",
		}
	}

	// Check if account is locked
	if s.accountLockManager.IsAccountLocked(user.LockedUntil) {
		remainingTime := s.accountLockManager.GetRemainingLockTime(user.LockedUntil)
		s.logSecurityEvent(ctx, "locked_account_access_attempt", user.ID, ipAddress, userAgent, SeverityWarning, map[string]interface{}{
			"email":          HashSensitiveData(req.Email),
			"remaining_time": remainingTime.String(),
		})
		return nil, &ErrorResponse{
			Code:    http.StatusLocked,
			Message: fmt.Sprintf("Account locked. Try again in %v", remainingTime),
		}
	}

	// Verify password
	if err := VerifyPassword(req.Password, user.PasswordHash); err != nil {
		// Increment failed login count
		user.FailedLogins++
		
		// Check if account should be locked
		if s.accountLockManager.ShouldLockAccount(user.FailedLogins) {
			user.LockedUntil = s.accountLockManager.GetLockUntil()
			s.logSecurityEvent(ctx, EventAccountLocked, user.ID, ipAddress, userAgent, SeverityError, map[string]interface{}{
				"email":          HashSensitiveData(req.Email),
				"failed_attempts": user.FailedLogins,
			})
		}

		// Update user in database
		s.repo.UpdateUserFailedLogins(ctx, user.ID, user.FailedLogins, user.LockedUntil)

		// Log failed login
		s.logFailedLogin(ctx, req.Email, ipAddress, userAgent, "invalid_password")
		
		return nil, &ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "Invalid credentials",
		}
	}

	// Check for suspicious activity
	loginHistory, _ := s.repo.GetRecentLoginAttempts(ctx, req.Email, time.Now().Add(-24*time.Hour))
	if s.securityValidator.DetectSuspiciousActivity(ctx, user.ID, ipAddress, userAgent, loginHistory) {
		s.logSecurityEvent(ctx, EventSuspiciousActivity, user.ID, ipAddress, userAgent, SeverityCritical, map[string]interface{}{
			"email":        HashSensitiveData(req.Email),
			"reason":       "suspicious_login_pattern",
			"recent_attempts": len(loginHistory),
		})
		// In production, you might want to require additional verification
	}

	// Reset failed login count on successful authentication
	if user.FailedLogins > 0 {
		user.FailedLogins = 0
		user.LockedUntil = time.Time{}
		s.repo.UpdateUserFailedLogins(ctx, user.ID, 0, time.Time{})
	}

	// Update last login time
	user.LastLoginAt = time.Now()
	s.repo.UpdateUser(ctx, user)

	// Log successful login attempt
	s.repo.CreateLoginAttempt(ctx, &LoginAttempt{
		Email:     req.Email,
		IPAddress: ipAddress,
		Success:   true,
		UserAgent: userAgent,
	})

	// Check if MFA is enabled
	if user.MFAEnabled {
		// Generate session token for MFA verification
		sessionToken, err := s.jwtManager.GenerateSessionToken(user.ID, user.Email)
		if err != nil {
			return nil, &ErrorResponse{
				Code:    http.StatusInternalServerError,
				Message: "Failed to generate session token",
			}
		}

		s.logSecurityEvent(ctx, "mfa_required", user.ID, ipAddress, userAgent, SeverityInfo, map[string]interface{}{
			"email": HashSensitiveData(req.Email),
		})

		// Remove sensitive data
		user.PasswordHash = ""
		user.MFASecret = ""

		return &AuthResponse{
			RequiresMFA:  true,
			SessionToken: sessionToken,
			User:         user,
		}, nil
	}

	// Generate tokens for non-MFA login
	return s.generateTokensAndSession(ctx, user, ipAddress, userAgent)
}

// VerifyMFA verifies multi-factor authentication
func (s *AuthService) VerifyMFA(ctx context.Context, req *MFAVerification, ipAddress, userAgent string) (*AuthResponse, error) {
	// Check rate limit
	if err := s.rateLimiter.CheckMFAVerificationRateLimit(ctx, ipAddress); err != nil {
		s.logSecurityEvent(ctx, EventRateLimitExceeded, "", ipAddress, userAgent, SeverityWarning, map[string]interface{}{
			"operation": "mfa_verification",
		})
		return nil, &ErrorResponse{
			Code:    http.StatusTooManyRequests,
			Message: "Rate limit exceeded",
		}
	}

	// Validate session token
	claims, err := s.jwtManager.ValidateSessionToken(req.SessionToken)
	if err != nil {
		s.logSecurityEvent(ctx, "invalid_session_token", "", ipAddress, userAgent, SeverityWarning, map[string]interface{}{
			"error": err.Error(),
		})
		return nil, &ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "Invalid session token",
		}
	}

	// Get user
	user, err := s.repo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "User not found",
		}
	}

	// Verify MFA code
	if !s.mfaManager.ValidateCode(user.MFASecret, req.Code) {
		s.logSecurityEvent(ctx, EventMFAFailed, user.ID, ipAddress, userAgent, SeverityWarning, map[string]interface{}{
			"email": HashSensitiveData(user.Email),
		})
		return nil, &ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "Invalid MFA code",
		}
	}

	// Log successful MFA verification
	s.logSecurityEvent(ctx, EventMFAVerified, user.ID, ipAddress, userAgent, SeverityInfo, map[string]interface{}{
		"email": HashSensitiveData(user.Email),
	})

	// Generate tokens and session
	return s.generateTokensAndSession(ctx, user, ipAddress, userAgent)
}

// generateTokensAndSession creates tokens and session for authenticated user
func (s *AuthService) generateTokensAndSession(ctx context.Context, user *User, ipAddress, userAgent string) (*AuthResponse, error) {
	// Create session
	session := &Session{
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(RefreshTokenExpiry),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	// Generate tokens
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Email, "")
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to generate access token",
		}
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID, user.Email, "")
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to generate refresh token",
		}
	}

	session.RefreshToken = refreshToken
	if err := s.repo.CreateSession(ctx, session); err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to create session",
		}
	}

	// Log successful login
	s.logSecurityEvent(ctx, EventUserLogin, user.ID, ipAddress, userAgent, SeverityInfo, map[string]interface{}{
		"email": HashSensitiveData(user.Email),
	})

	// Remove sensitive data
	user.PasswordHash = ""
	user.MFASecret = ""

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(AccessTokenExpiry.Seconds()),
		TokenType:    "Bearer",
		User:         user,
		RequiresMFA:  false,
	}, nil
}

// RefreshToken refreshes an access token
func (s *AuthService) RefreshToken(ctx context.Context, req *RefreshTokenRequest, ipAddress, userAgent string) (*AuthResponse, error) {
	// Validate refresh token
	claims, err := s.jwtManager.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		s.logSecurityEvent(ctx, "invalid_refresh_token", "", ipAddress, userAgent, SeverityWarning, map[string]interface{}{
			"error": err.Error(),
		})
		return nil, &ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "Invalid refresh token",
		}
	}

	// Get session
	session, err := s.repo.GetSessionByRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "Session not found",
		}
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		s.repo.InvalidateSession(ctx, session.ID)
		s.logSecurityEvent(ctx, EventSessionExpired, claims.UserID, ipAddress, userAgent, SeverityInfo, nil)
		return nil, &ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "Session expired",
		}
	}

	// Get user
	user, err := s.repo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "User not found",
		}
	}

	// Generate new access token
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Email, session.ID)
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to generate access token",
		}
	}

	// Log token refresh
	s.logSecurityEvent(ctx, EventTokenRefreshed, user.ID, ipAddress, userAgent, SeverityInfo, map[string]interface{}{
		"email": HashSensitiveData(user.Email),
	})

	// Remove sensitive data
	user.PasswordHash = ""
	user.MFASecret = ""

	return &AuthResponse{
		AccessToken: accessToken,
		ExpiresIn:   int64(AccessTokenExpiry.Seconds()),
		TokenType:   "Bearer",
		User:        user,
	}, nil
}

// LogoutUser logs out a user
func (s *AuthService) LogoutUser(ctx context.Context, accessToken string, ipAddress, userAgent string) (*SuccessResponse, error) {
	// Validate access token
	claims, err := s.jwtManager.ValidateAccessToken(accessToken)
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "Invalid access token",
		}
	}

	// Invalidate all user sessions
	if err := s.repo.InvalidateUserSessions(ctx, claims.UserID); err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to logout",
		}
	}

	// Log logout
	s.logSecurityEvent(ctx, EventUserLogout, claims.UserID, ipAddress, userAgent, SeverityInfo, map[string]interface{}{
		"email": HashSensitiveData(claims.Email),
	})

	return &SuccessResponse{
		Message: "Logged out successfully",
		Success: true,
	}, nil
}

// ForgotPassword initiates password reset process
func (s *AuthService) ForgotPassword(ctx context.Context, req *ForgotPasswordRequest, ipAddress, userAgent string) (*SuccessResponse, error) {
	// Check rate limit
	if err := s.rateLimiter.CheckPasswordResetRateLimit(ctx, ipAddress); err != nil {
		s.logSecurityEvent(ctx, EventRateLimitExceeded, "", ipAddress, userAgent, SeverityWarning, map[string]interface{}{
			"operation": "forgot_password",
			"email":     HashSensitiveData(req.Email),
		})
		return nil, &ErrorResponse{
			Code:    http.StatusTooManyRequests,
			Message: "Rate limit exceeded",
		}
	}

	// Get user (but don't reveal if user exists or not)
	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// Still return success to prevent email enumeration
		s.logSecurityEvent(ctx, "password_reset_unknown_email", "", ipAddress, userAgent, SeverityInfo, map[string]interface{}{
			"email": HashSensitiveData(req.Email),
		})
		return &SuccessResponse{
			Message: "If the email exists, a password reset link has been sent",
			Success: true,
		}, nil
	}

	// Generate reset token
	resetToken, err := GenerateSecureToken(32)
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to generate reset token",
		}
	}

	// Create password reset token record
	tokenRecord := &PasswordResetToken{
		UserID:    user.ID,
		Token:     resetToken,
		ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour expiry
	}

	if err := s.repo.CreatePasswordResetToken(ctx, tokenRecord); err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to create reset token",
		}
	}

	// Log password reset request
	s.logSecurityEvent(ctx, EventPasswordResetRequest, user.ID, ipAddress, userAgent, SeverityInfo, map[string]interface{}{
		"email": HashSensitiveData(user.Email),
	})

	// In production, send email with reset link
	// For now, we'll just log the token (DO NOT DO THIS IN PRODUCTION)
	fmt.Printf("Password reset token for %s: %s\n", user.Email, resetToken)

	return &SuccessResponse{
		Message: "If the email exists, a password reset link has been sent",
		Success: true,
	}, nil
}

// ResetPassword resets a user's password
func (s *AuthService) ResetPassword(ctx context.Context, req *ResetPasswordRequest, ipAddress, userAgent string) (*SuccessResponse, error) {
	// Check rate limit
	if err := s.rateLimiter.CheckPasswordResetRateLimit(ctx, ipAddress); err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusTooManyRequests,
			Message: "Rate limit exceeded",
		}
	}

	// Get reset token
	tokenRecord, err := s.repo.GetPasswordResetToken(ctx, req.Token)
	if err != nil {
		s.logSecurityEvent(ctx, "invalid_reset_token", "", ipAddress, userAgent, SeverityWarning, map[string]interface{}{
			"token": HashSensitiveData(req.Token),
		})
		return nil, &ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid or expired reset token",
		}
	}

	// Check if token is expired
	if time.Now().After(tokenRecord.ExpiresAt) {
		s.logSecurityEvent(ctx, "expired_reset_token", tokenRecord.UserID, ipAddress, userAgent, SeverityWarning, nil)
		return nil, &ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Reset token has expired",
		}
	}

	// Get user
	user, err := s.repo.GetUserByID(ctx, tokenRecord.UserID)
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "User not found",
		}
	}

	// Validate new password
	if err := ValidatePasswordStrength(req.NewPassword); err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		}
	}

	// Hash new password
	passwordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to process password",
		}
	}

	// Update user password
	user.PasswordHash = passwordHash
	user.FailedLogins = 0
	user.LockedUntil = time.Time{}
	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update password",
		}
	}

	// Mark token as used
	if err := s.repo.MarkPasswordResetTokenUsed(ctx, tokenRecord.ID); err != nil {
		// Log error but don't fail the request
	}

	// Invalidate all user sessions
	s.repo.InvalidateUserSessions(ctx, user.ID)

	// Log password reset
	s.logSecurityEvent(ctx, EventPasswordReset, user.ID, ipAddress, userAgent, SeverityInfo, map[string]interface{}{
		"email": HashSensitiveData(user.Email),
	})

	return &SuccessResponse{
		Message: "Password reset successfully",
		Success: true,
	}, nil
}

// GetCurrentUser returns current user information
func (s *AuthService) GetCurrentUser(ctx context.Context, accessToken string) (*User, error) {
	// Validate access token
	claims, err := s.jwtManager.ValidateAccessToken(accessToken)
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusUnauthorized,
			Message: "Invalid access token",
		}
	}

	// Get user
	user, err := s.repo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, &ErrorResponse{
			Code:    http.StatusNotFound,
			Message: "User not found",
		}
	}

	// Remove sensitive data
	user.PasswordHash = ""
	user.MFASecret = ""

	return user, nil
}

// logFailedLogin logs a failed login attempt
func (s *AuthService) logFailedLogin(ctx context.Context, email, ipAddress, userAgent, reason string) {
	// Create login attempt record
	s.repo.CreateLoginAttempt(ctx, &LoginAttempt{
		Email:     email,
		IPAddress: ipAddress,
		Success:   false,
		UserAgent: userAgent,
	})

	// Log security event
	s.logSecurityEvent(ctx, EventUserLoginFailed, "", ipAddress, userAgent, SeverityWarning, map[string]interface{}{
		"email":  HashSensitiveData(email),
		"reason": reason,
	})
}

// logSecurityEvent logs a security event
func (s *AuthService) logSecurityEvent(ctx context.Context, event, userID, ipAddress, userAgent, severity string, details map[string]interface{}) {
	s.securityLogger.LogEvent(ctx, event, userID, ipAddress, userAgent, severity, details)
	
	// Also store in database for audit trail
	s.repo.CreateSecurityLog(ctx, &SecurityLog{
		UserID:    userID,
		Event:     event,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Details:   details,
		Severity:  severity,
	})
}

// Close closes the auth service and cleans up resources
func (s *AuthService) Close() {
	s.securityLogger.Close()
}