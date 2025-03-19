package validation

import (
	"fmt"
	"regexp"
	"unicode"
)

// ValidationError represents a validation error with a specific message
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidateUsername checks if the username meets the required criteria
func ValidateUsername(username string) error {
	if len(username) < 3 || len(username) > 20 {
		return &ValidationError{
			Field:   "username",
			Message: "must be between 3 and 20 characters long",
		}
	}

	// Check if username contains only alphanumeric characters
	matched, _ := regexp.MatchString("^[a-zA-Z0-9]+$", username)
	if !matched {
		return &ValidationError{
			Field:   "username",
			Message: "must contain only alphanumeric characters",
		}
	}

	return nil
}

// ValidateEmail checks if the email format is valid
func ValidateEmail(email string) error {
	// RFC 5322 compliant email regex
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return &ValidationError{
			Field:   "email",
			Message: "invalid email format",
		}
	}

	return nil
}

// ValidatePassword checks if the password meets the required criteria
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return &ValidationError{
			Field:   "password",
			Message: "must be at least 8 characters long",
		}
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return &ValidationError{
			Field:   "password",
			Message: "must contain at least one uppercase letter",
		}
	}
	if !hasLower {
		return &ValidationError{
			Field:   "password",
			Message: "must contain at least one lowercase letter",
		}
	}
	if !hasNumber {
		return &ValidationError{
			Field:   "password",
			Message: "must contain at least one number",
		}
	}
	if !hasSpecial {
		return &ValidationError{
			Field:   "password",
			Message: "must contain at least one special character",
		}
	}

	return nil
}

// ValidateUserRegistration performs all validations for user registration
func ValidateUserRegistration(username, email, password string) []error {
	var errors []error

	if err := ValidateUsername(username); err != nil {
		errors = append(errors, err)
	}
	if err := ValidateEmail(email); err != nil {
		errors = append(errors, err)
	}
	if err := ValidatePassword(password); err != nil {
		errors = append(errors, err)
	}

	return errors
}