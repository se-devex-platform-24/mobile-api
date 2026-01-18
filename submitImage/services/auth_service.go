package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"regexp"
	"submit-image/models"
	"submit-image/repositories"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// AuthService handles all authentication related operations
type AuthService struct {
	userRepo       *repositories.UserRepository
	emailService   EmailService
	captchaService CaptchaService
	logger         Logger
}

// EmailService interface defines methods for sending emails
type EmailService interface {
	SendVerificationEmail(email, token string) error
	SendWelcomeEmail(email string) error
	SendPasswordResetEmail(email, resetLink string) error
}

// CaptchaService interface defines methods for CAPTCHA verification
type CaptchaService interface {
	VerifyCaptcha(token string) error
}

// Logger interface defines methods for logging
type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, err error, fields ...interface{})
}

// NewAuthService creates a new instance of AuthService
func NewAuthService(userRepo *repositories.UserRepository, emailService EmailService, captchaService CaptchaService, logger Logger) *AuthService {
	return &AuthService{
		userRepo:       userRepo,
		emailService:   emailService,
		captchaService: captchaService,
		logger:         logger,
	}
}

// RegisterUser handles the user registration process
func (s *AuthService) RegisterUser(ctx context.Context, req *models.UserRegistrationRequest) (*models.User, error) {
	s.logger.Info("Starting user registration process", "email", req.Email)

	// Validate input
	if err := s.validateRegistrationInput(req); err != nil {
		s.logger.Error("Invalid registration input", err, "email", req.Email)
		return nil, err
	}

	// Verify CAPTCHA
	if err := s.captchaService.VerifyCaptcha(req.CaptchaToken); err != nil {
		s.logger.Error("CAPTCHA verification failed", err, "email", req.Email)
		return nil, errors.New("invalid CAPTCHA")
	}

	// Check if user already exists
	existingUser, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		s.logger.Info("Registration attempt with existing email", "email", req.Email)
		return nil, errors.New("email already registered")
	}

	// Generate user ID
	userID := uuid.New().String()

	// Hash password
	hashedPassword, err := s.hashPassword(req.Password)
	if err != nil {
		s.logger.Error("Password hashing failed", err, "email", req.Email)
		return nil, errors.New("internal server error")
	}

	// Create new user
	user := &models.User{
		ID:          userID,
		Email:       req.Email,
		Password:    hashedPassword,
		FirstName:   req.FirstName,
		LastName:    req.LastName,
		Phone:       req.Phone,
		DeviceID:    req.DeviceID,
		DeviceType:  req.DeviceType,
		DeviceToken: req.DeviceToken,
		AppVersion:  req.AppVersion,
	}

	// Validate user model
	if err := user.Validate(); err != nil {
		s.logger.Error("User validation failed", err, "email", req.Email)
		return nil, err
	}

	// Generate verification token
	verificationToken := user.GenerateVerificationToken()

	// Store user
	if err := s.userRepo.Create(ctx, user); err != nil {
		s.logger.Error("User creation failed", err, "email", req.Email)
		return nil, errors.New("failed to create user")
	}

	// Send verification email
	if err := s.emailService.SendVerificationEmail(user.Email, verificationToken); err != nil {
		s.logger.Error("Failed to send verification email", err, "email", req.Email)
		return nil, errors.New("failed to send verification email")
	}

	s.logger.Info("User registered successfully", 
		"email", user.Email,
		"deviceType", user.DeviceType,
		"appVersion", user.AppVersion)
	
	return user, nil
}

// VerifyEmail handles email verification
func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	user, err := s.userRepo.FindByVerificationToken(ctx, token)
	if err != nil {
		s.logger.Error("Invalid verification token", err)
		return errors.New("invalid or expired verification token")
	}

	if user.EmailVerified {
		return errors.New("email already verified")
	}

	// Update verification status
	if err := s.userRepo.UpdateVerificationStatus(ctx, user.ID, true); err != nil {
		s.logger.Error("Failed to update verification status", err)
		return errors.New("failed to verify email")
	}

	// Send welcome email
	if err := s.emailService.SendWelcomeEmail(user.Email); err != nil {
		s.logger.Error("Failed to send welcome email", err)
		// Don't return error as this is not critical
	}

	s.logger.Info("Email verified successfully", "email", user.Email)
	return nil
}

// RequestPasswordReset handles password reset requests
func (s *AuthService) RequestPasswordReset(ctx context.Context, email, captchaToken string) error {
	// Verify CAPTCHA
	if err := s.captchaService.VerifyCaptcha(captchaToken); err != nil {
		s.logger.Error("CAPTCHA verification failed", err)
		return errors.New("invalid CAPTCHA")
	}

	// Find user by email
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		s.logger.Error("User not found for password reset", err, "email", email)
		// Don't reveal if email exists for security
		return nil
	}

	// Generate reset token
	resetToken := user.GeneratePasswordResetToken()

	// Store reset token
	if err := s.userRepo.UpdateResetToken(ctx, user.ID, resetToken, user.ResetTokenExpiry); err != nil {
		s.logger.Error("Failed to store reset token", err)
		return errors.New("internal server error")
	}

	// Create reset link
	resetLink := fmt.Sprintf("https://app.mfirst.com/reset-password?token=%s", resetToken)

	// Send password reset email
	if err := s.emailService.SendPasswordResetEmail(user.Email, resetLink); err != nil {
		s.logger.Error("Failed to send password reset email", err)
		return errors.New("failed to send password reset email")
	}

	s.logger.Info("Password reset email sent", "email", user.Email)
	return nil
}

// ResetPassword handles password reset with token
func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Validate new password
	if err := s.validatePassword(newPassword); err != nil {
		return err
	}

	// Find user by reset token
	user, err := s.userRepo.FindByResetToken(ctx, token)
	if err != nil {
		s.logger.Error("Invalid or expired reset token", err)
		return errors.New("invalid or expired reset token")
	}

	// Hash new password
	hashedPassword, err := s.hashPassword(newPassword)
	if err != nil {
		s.logger.Error("Password hashing failed", err)
		return errors.New("internal server error")
	}

	// Update password
	if err := s.userRepo.UpdatePassword(ctx, user.ID, hashedPassword); err != nil {
		s.logger.Error("Failed to update password", err)
		return errors.New("failed to update password")
	}

	s.logger.Info("Password reset successfully", "userID", user.ID)
	return nil
}

// UpdateProfile updates user profile information
func (s *AuthService) UpdateProfile(ctx context.Context, userID string, updates map[string]interface{}) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Update allowed fields
	if firstName, ok := updates["firstName"].(string); ok {
		user.FirstName = firstName
	}
	if lastName, ok := updates["lastName"].(string); ok {
		user.LastName = lastName
	}
	if phone, ok := updates["phone"].(string); ok {
		user.Phone = phone
	}
	if deviceToken, ok := updates["deviceToken"].(string); ok {
		user.DeviceToken = deviceToken
	}

	// Validate updated user
	if err := user.Validate(); err != nil {
		return err
	}

	// Save updates
	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.Error("Failed to update user profile", err)
		return errors.New("failed to update profile")
	}

	s.logger.Info("User profile updated", "userID", userID)
	return nil
}

// GetUserByID retrieves a user by ID
func (s *AuthService) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	return s.userRepo.FindByID(ctx, userID)
}

// GetUserByEmail retrieves a user by email
func (s *AuthService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return s.userRepo.FindByEmail(ctx, email)
}

// validateRegistrationInput validates the registration request
func (s *AuthService) validateRegistrationInput(req *models.UserRegistrationRequest) error {
	if req.Email == "" || !s.isValidEmail(req.Email) {
		return errors.New("invalid email address")
	}

	if err := s.validatePassword(req.Password); err != nil {
		return err
	}

	if req.FirstName == "" || req.LastName == "" {
		return errors.New("first name and last name are required")
	}

	if req.CaptchaToken == "" {
		return errors.New("CAPTCHA token is required")
	}

	// Validate mobile-specific fields
	if req.DeviceID == "" {
		return errors.New("device ID is required")
	}

	if req.DeviceType == "" {
		return errors.New("device type is required")
	}

	if !s.isValidDeviceType(req.DeviceType) {
		return errors.New("invalid device type. Must be 'ios' or 'android'")
	}

	if req.DeviceToken == "" {
		return errors.New("device token is required for push notifications")
	}

	if req.AppVersion == "" {
		return errors.New("app version is required")
	}

	if !s.isValidAppVersion(req.AppVersion) {
		return errors.New("invalid app version format. Must be in format x.y.z")
	}

	return nil
}

// isValidEmail checks if the email format is valid
func (s *AuthService) isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// validatePassword checks password strength requirements
func (s *AuthService) validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return errors.New("password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
	}

	return nil
}

// isValidDeviceType checks if the device type is valid
func (s *AuthService) isValidDeviceType(deviceType string) bool {
	validTypes := map[string]bool{
		"ios":     true,
		"android": true,
	}
	return validTypes[deviceType]
}

// isValidAppVersion checks if the app version format is valid
func (s *AuthService) isValidAppVersion(version string) bool {
	versionPattern := regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	return versionPattern.MatchString(version)
}

// hashPassword hashes the password using bcrypt
func (s *AuthService) hashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %v", err)
	}
	return string(hashedBytes), nil
}

// VerifyPassword verifies a password against its hash
func (s *AuthService) VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// generateToken generates a random token for various purposes
func generateToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SimpleLogger implements the Logger interface for basic logging
type SimpleLogger struct{}

func (l *SimpleLogger) Info(msg string, fields ...interface{}) {
	log.Printf("[INFO] %s %v", msg, fields)
}

func (l *SimpleLogger) Error(msg string, err error, fields ...interface{}) {
	log.Printf("[ERROR] %s: %v %v", msg, err, fields)
}