package user

import (
	"fmt"
	"regexp"
	"unicode"
)

// User represents the user model with validation rules
type User struct {
	Username string `json:"username" validate:"required,min=3,max=20,alphanum"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

// Validate performs validation on the User struct and returns any validation errors
func (u *User) Validate() error {
	if err := u.validateUsername(); err != nil {
		return err
	}
	if err := u.validateEmail(); err != nil {
		return err
	}
	if err := u.validatePassword(); err != nil {
		return err
	}
	return nil
}

// validateUsername checks if the username meets the required criteria
func (u *User) validateUsername() error {
	if len(u.Username) < 3 || len(u.Username) > 20 {
		return fmt.Errorf("username must be between 3 and 20 characters long")
	}

	for _, char := range u.Username {
		if !unicode.IsLetter(char) && !unicode.IsNumber(char) {
			return fmt.Errorf("username must contain only alphanumeric characters")
		}
	}

	return nil
}

// validateEmail checks if the email format is valid
func (u *User) validateEmail() error {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(u.Email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// validatePassword checks if the password meets the complexity requirements
func (u *User) validatePassword() error {
	if len(u.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range u.Password {
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
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}