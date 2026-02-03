package auth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	// MFAIssuer defines the issuer name for MFA
	MFAIssuer = "Mobile Auth App"
	// MFACodeLength defines the length of MFA codes
	MFACodeLength = 6
	// MFACodeValidityPeriod defines how long a code is valid
	MFACodeValidityPeriod = 30 * time.Second
)

// MFAManager handles multi-factor authentication operations
type MFAManager struct {
	issuer string
}

// NewMFAManager creates a new MFA manager
func NewMFAManager(issuer string) *MFAManager {
	if issuer == "" {
		issuer = MFAIssuer
	}
	return &MFAManager{
		issuer: issuer,
	}
}

// GenerateSecret generates a new MFA secret for a user
func (m *MFAManager) GenerateSecret(userEmail string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      m.issuer,
		AccountName: userEmail,
		SecretSize:  32,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate MFA secret: %w", err)
	}

	return key.Secret(), key.URL(), nil
}

// GenerateCode generates a TOTP code for the given secret
func (m *MFAManager) GenerateCode(secret string) (string, error) {
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to generate MFA code: %w", err)
	}
	return code, nil
}

// ValidateCode validates a TOTP code against the secret
func (m *MFAManager) ValidateCode(secret, code string) bool {
	// Validate current time window
	if totp.Validate(code, secret) {
		return true
	}

	// Also check previous and next time windows to account for clock skew
	now := time.Now()
	
	// Check previous window (30 seconds ago)
	if totp.ValidateCustom(code, secret, now.Add(-MFACodeValidityPeriod), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}) {
		return true
	}

	// Check next window (30 seconds ahead)
	if totp.ValidateCustom(code, secret, now.Add(MFACodeValidityPeriod), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}) {
		return true
	}

	return false
}

// GenerateBackupCodes generates backup codes for MFA
func (m *MFAManager) GenerateBackupCodes(count int) ([]string, error) {
	if count <= 0 {
		count = 10 // Default to 10 backup codes
	}

	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code, err := m.generateBackupCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		codes[i] = code
	}

	return codes, nil
}

// generateBackupCode generates a single backup code
func (m *MFAManager) generateBackupCode() (string, error) {
	// Generate 8 random bytes
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Convert to base32 and format as XXXX-XXXX
	encoded := base32.StdEncoding.EncodeToString(bytes)
	// Take first 8 characters and format
	if len(encoded) >= 8 {
		return fmt.Sprintf("%s-%s", encoded[:4], encoded[4:8]), nil
	}

	return encoded, nil
}

// ValidateBackupCode validates a backup code
func (m *MFAManager) ValidateBackupCode(code string, validCodes []string) bool {
	for _, validCode := range validCodes {
		if code == validCode {
			return true
		}
	}
	return false
}

// GenerateSMSCode generates a 6-digit SMS code
func (m *MFAManager) GenerateSMSCode() (string, error) {
	// Generate 3 random bytes
	bytes := make([]byte, 3)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Convert to 6-digit number
	num := int(bytes[0])<<16 | int(bytes[1])<<8 | int(bytes[2])
	code := num % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// ValidateSMSCode validates an SMS code (with time window)
func (m *MFAManager) ValidateSMSCode(code, expectedCode string, generatedAt time.Time) bool {
	// Check if code matches
	if code != expectedCode {
		return false
	}

	// Check if code is still valid (5 minutes window)
	if time.Since(generatedAt) > 5*time.Minute {
		return false
	}

	return true
}

// IsValidMFACode checks if a code is a valid 6-digit numeric code
func IsValidMFACode(code string) bool {
	if len(code) != MFACodeLength {
		return false
	}

	_, err := strconv.Atoi(code)
	return err == nil
}

// FormatSecret formats a secret for display (with spaces every 4 characters)
func FormatSecret(secret string) string {
	if len(secret) == 0 {
		return secret
	}

	var formatted string
	for i, char := range secret {
		if i > 0 && i%4 == 0 {
			formatted += " "
		}
		formatted += string(char)
	}
	return formatted
}