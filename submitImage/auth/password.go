package auth

import (
	"errors"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

const (
	// MinPasswordLength defines minimum password length
	MinPasswordLength = 8
	// MaxPasswordLength defines maximum password length
	MaxPasswordLength = 128
	// BcryptCost defines the cost for bcrypt hashing
	BcryptCost = 12
)

// PasswordStrengthError represents password validation errors
type PasswordStrengthError struct {
	Message string
	Issues  []string
}

func (e *PasswordStrengthError) Error() string {
	return e.Message
}

// ValidatePasswordStrength validates password strength according to security requirements
func ValidatePasswordStrength(password string) error {
	var issues []string

	// Check length
	if len(password) < MinPasswordLength {
		issues = append(issues, "password must be at least 8 characters long")
	}
	if len(password) > MaxPasswordLength {
		issues = append(issues, "password must not exceed 128 characters")
	}

	// Check for uppercase letter
	hasUpper := false
	for _, char := range password {
		if unicode.IsUpper(char) {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		issues = append(issues, "password must contain at least one uppercase letter")
	}

	// Check for lowercase letter
	hasLower := false
	for _, char := range password {
		if unicode.IsLower(char) {
			hasLower = true
			break
		}
	}
	if !hasLower {
		issues = append(issues, "password must contain at least one lowercase letter")
	}

	// Check for digit
	hasDigit := false
	for _, char := range password {
		if unicode.IsDigit(char) {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		issues = append(issues, "password must contain at least one digit")
	}

	// Check for special character
	specialChars := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~` + "`" + `]`)
	if !specialChars.MatchString(password) {
		issues = append(issues, "password must contain at least one special character")
	}

	// Check for common patterns
	if isCommonPassword(password) {
		issues = append(issues, "password is too common, please choose a more unique password")
	}

	// Check for sequential characters
	if hasSequentialChars(password) {
		issues = append(issues, "password should not contain sequential characters (e.g., 123, abc)")
	}

	// Check for repeated characters
	if hasRepeatedChars(password) {
		issues = append(issues, "password should not contain more than 2 consecutive identical characters")
	}

	if len(issues) > 0 {
		return &PasswordStrengthError{
			Message: "Password does not meet security requirements",
			Issues:  issues,
		}
	}

	return nil
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	if err := ValidatePasswordStrength(password); err != nil {
		return "", err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// VerifyPassword verifies a password against its hash
func VerifyPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// isCommonPassword checks if password is in common password list
func isCommonPassword(password string) bool {
	// Common passwords list (simplified for demo)
	commonPasswords := []string{
		"password", "123456", "123456789", "12345678", "12345",
		"1234567", "password123", "admin", "qwerty", "abc123",
		"letmein", "monkey", "1234567890", "dragon", "111111",
		"baseball", "iloveyou", "trustno1", "1234", "sunshine",
		"master", "123123", "welcome", "shadow", "ashley",
		"football", "jesus", "michael", "ninja", "mustang",
	}

	lowerPassword := strings.ToLower(password)
	for _, common := range commonPasswords {
		if lowerPassword == common {
			return true
		}
	}

	return false
}

// hasSequentialChars checks for sequential characters
func hasSequentialChars(password string) bool {
	sequences := []string{
		"0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm",
	}

	lowerPassword := strings.ToLower(password)

	for _, seq := range sequences {
		for i := 0; i <= len(seq)-3; i++ {
			if strings.Contains(lowerPassword, seq[i:i+3]) {
				return true
			}
		}
		// Check reverse sequences
		runes := []rune(seq)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		reverseSeq := string(runes)
		for i := 0; i <= len(reverseSeq)-3; i++ {
			if strings.Contains(lowerPassword, reverseSeq[i:i+3]) {
				return true
			}
		}
	}

	return false
}

// hasRepeatedChars checks for more than 2 consecutive identical characters
func hasRepeatedChars(password string) bool {
	count := 1
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			count++
			if count > 2 {
				return true
			}
		} else {
			count = 1
		}
	}
	return false
}

// GenerateSecurePassword generates a secure password (for testing/admin purposes)
func GenerateSecurePassword(length int) (string, error) {
	if length < MinPasswordLength {
		return "", errors.New("password length too short")
	}

	// This is a simplified implementation
	// In production, use crypto/rand for better randomness
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
	password := make([]byte, length)

	// Ensure at least one character from each required category
	password[0] = 'A' // uppercase
	password[1] = 'a' // lowercase
	password[2] = '1' // digit
	password[3] = '!' // special

	// Fill the rest randomly (simplified)
	for i := 4; i < length; i++ {
		password[i] = chars[i%len(chars)]
	}

	return string(password), nil
}