package models

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"regexp"
	"time"
)

// UserStatus represents the current status of a user account
type UserStatus string

const (
	// UserStatusPending indicates the user's email is not yet verified
	UserStatusPending UserStatus = "PENDING"
	// UserStatusActive indicates the user is active
	UserStatusActive UserStatus = "ACTIVE"
	// UserStatusSuspended indicates the user account has been suspended
	UserStatusSuspended UserStatus = "SUSPENDED"
	// UserStatusDeleted indicates the user account has been deleted
	UserStatusDeleted UserStatus = "DELETED"
)

// User represents the user model in the system
type User struct {
	ID                string     `json:"id" dynamodb:"id"`
	Email             string     `json:"email" dynamodb:"email"`
	Password          string     `json:"-" dynamodb:"password"`
	FirstName         string     `json:"firstName" dynamodb:"first_name"`
	LastName          string     `json:"lastName" dynamodb:"last_name"`
	Phone             string     `json:"phone" dynamodb:"phone"`
	UserStatus        UserStatus `json:"userStatus" dynamodb:"user_status"`
	EmailVerified     bool       `json:"emailVerified" dynamodb:"email_verified"`
	PhoneVerified     bool       `json:"phoneVerified" dynamodb:"phone_verified"`
	VerificationToken string     `json:"-" dynamodb:"verification_token"`
	ResetToken        string     `json:"-" dynamodb:"reset_token"`
	ResetTokenExpiry  time.Time  `json:"-" dynamodb:"reset_token_expiry"`
	DeviceID          string     `json:"deviceId" dynamodb:"device_id"`
	DeviceType        string     `json:"deviceType" dynamodb:"device_type"`
	DeviceToken       string     `json:"deviceToken" dynamodb:"device_token"`
	AppVersion        string     `json:"appVersion" dynamodb:"app_version"`
	LastLoginAt       time.Time  `json:"lastLoginAt" dynamodb:"last_login_at"`
	LastLoginIP       string     `json:"-" dynamodb:"last_login_ip"`
	FailedLoginCount  int        `json:"-" dynamodb:"failed_login_count"`
	LockoutUntil      *time.Time `json:"-" dynamodb:"lockout_until"`
	CreatedAt         time.Time  `json:"createdAt" dynamodb:"created_at"`
	UpdatedAt         time.Time  `json:"updatedAt" dynamodb:"updated_at"`
	DeletedAt         *time.Time `json:"-" dynamodb:"deleted_at"`
}

// UserRegistrationRequest represents the incoming registration request
type UserRegistrationRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	Phone        string `json:"phone,omitempty"`
	DeviceID     string `json:"deviceId"`
	DeviceType   string `json:"deviceType"`
	DeviceToken  string `json:"deviceToken"`
	AppVersion   string `json:"appVersion"`
	CaptchaToken string `json:"captchaToken"`
}

// Validate performs validation on the user model
func (u *User) Validate() error {
	if err := u.validateEmail(); err != nil {
		return err
	}
	if err := u.validatePassword(); err != nil {
		return err
	}
	if err := u.validateNames(); err != nil {
		return err
	}
	if err := u.validatePhone(); err != nil {
		return err
	}
	if err := u.validateMobileFields(); err != nil {
		return err
	}
	return nil
}

// validateEmail checks if the email is valid
func (u *User) validateEmail() error {
	if u.Email == "" {
		return errors.New("email is required")
	}
	// Basic email validation pattern
	emailPattern := `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
	match, _ := regexp.MatchString(emailPattern, u.Email)
	if !match {
		return errors.New("invalid email format")
	}
	return nil
}

// validatePassword checks if the password meets security requirements
func (u *User) validatePassword() error {
	if len(u.Password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	
	// Check for at least one uppercase letter
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(u.Password)
	// Check for at least one lowercase letter
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(u.Password)
	// Check for at least one digit
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(u.Password)
	// Check for at least one special character
	hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(u.Password)

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return errors.New("password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
	}

	return nil
}

// validateNames checks if the first name and last name are valid
func (u *User) validateNames() error {
	if u.FirstName == "" {
		return errors.New("first name is required")
	}
	if u.LastName == "" {
		return errors.New("last name is required")
	}
	if len(u.FirstName) > 50 {
		return errors.New("first name must not exceed 50 characters")
	}
	if len(u.LastName) > 50 {
		return errors.New("last name must not exceed 50 characters")
	}
	return nil
}

// validatePhone checks if the phone number is valid (optional field)
func (u *User) validatePhone() error {
	if u.Phone == "" {
		return nil // Phone is optional
	}
	// Basic phone number validation (international format)
	phonePattern := `^\+[1-9]\d{1,14}$`
	match, _ := regexp.MatchString(phonePattern, u.Phone)
	if !match {
		return errors.New("invalid phone number format. Must be in international format (e.g., +1234567890)")
	}
	return nil
}

// validateMobileFields validates mobile-specific fields
func (u *User) validateMobileFields() error {
	if u.DeviceID == "" {
		return errors.New("device ID is required")
	}
	if u.DeviceType == "" {
		return errors.New("device type is required")
	}
	if u.DeviceType != "ios" && u.DeviceType != "android" {
		return errors.New("device type must be 'ios' or 'android'")
	}
	if u.DeviceToken == "" {
		return errors.New("device token is required")
	}
	if u.AppVersion == "" {
		return errors.New("app version is required")
	}
	// Validate app version format (x.y.z)
	versionPattern := `^\d+\.\d+\.\d+$`
	match, _ := regexp.MatchString(versionPattern, u.AppVersion)
	if !match {
		return errors.New("app version must be in format x.y.z")
	}
	return nil
}

// BeforeCreate performs actions before creating a new user
func (u *User) BeforeCreate() {
	now := time.Now()
	u.CreatedAt = now
	u.UpdatedAt = now
	u.UserStatus = UserStatusPending
	u.EmailVerified = false
	u.PhoneVerified = false
	u.FailedLoginCount = 0
}

// BeforeUpdate performs actions before updating a user
func (u *User) BeforeUpdate() {
	u.UpdatedAt = time.Now()
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateVerificationToken generates a new email verification token
func (u *User) GenerateVerificationToken() string {
	token, err := generateSecureToken(32)
	if err != nil {
		// In case of error, fall back to a timestamp-based token
		token = base64.StdEncoding.EncodeToString([]byte(time.Now().String()))
	}
	u.VerificationToken = token
	return token
}

// GeneratePasswordResetToken generates a new password reset token
func (u *User) GeneratePasswordResetToken() string {
	token, err := generateSecureToken(32)
	if err != nil {
		// In case of error, fall back to a timestamp-based token
		token = base64.StdEncoding.EncodeToString([]byte(time.Now().String()))
	}
	u.ResetToken = token
	u.ResetTokenExpiry = time.Now().Add(24 * time.Hour)
	return token
}

// IsLocked checks if the user account is temporarily locked due to failed login attempts
func (u *User) IsLocked() bool {
	return u.LockoutUntil != nil && time.Now().Before(*u.LockoutUntil)
}

// IncrementFailedLogin increments the failed login counter and locks the account if necessary
func (u *User) IncrementFailedLogin() {
	u.FailedLoginCount++
	if u.FailedLoginCount >= 5 {
		lockoutTime := time.Now().Add(30 * time.Minute)
		u.LockoutUntil = &lockoutTime
	}
}

// ResetFailedLogin resets the failed login counter and removes any lockout
func (u *User) ResetFailedLogin() {
	u.FailedLoginCount = 0
	u.LockoutUntil = nil
}

// SoftDelete marks the user as deleted without removing from the database
func (u *User) SoftDelete() {
	now := time.Now()
	u.DeletedAt = &now
	u.UserStatus = UserStatusDeleted
}

// IsDeleted checks if the user has been soft deleted
func (u *User) IsDeleted() bool {
	return u.DeletedAt != nil
}

// IsPasswordResetTokenValid checks if the password reset token is valid and not expired
func (u *User) IsPasswordResetTokenValid(token string) bool {
	return u.ResetToken == token && time.Now().Before(u.ResetTokenExpiry)
}

// ToProfile converts User to a safe profile representation (without sensitive data)
func (u *User) ToProfile() map[string]interface{} {
	return map[string]interface{}{
		"id":            u.ID,
		"email":         u.Email,
		"firstName":     u.FirstName,
		"lastName":      u.LastName,
		"phone":         u.Phone,
		"emailVerified": u.EmailVerified,
		"phoneVerified": u.PhoneVerified,
		"status":        u.UserStatus,
		"deviceType":    u.DeviceType,
		"appVersion":    u.AppVersion,
		"lastLoginAt":   u.LastLoginAt,
		"createdAt":     u.CreatedAt,
		"updatedAt":     u.UpdatedAt,
	}
}