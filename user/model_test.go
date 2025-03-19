package user

import (
	"testing"
)

func TestUser_Validate(t *testing.T) {
	tests := []struct {
		name     string
		user     User
		wantErr  bool
		errField string
	}{
		{
			name: "valid user",
			user: User{
				Username: "johndoe123",
				Email:    "john.doe@example.com",
				Password: "Pass123!@#",
			},
			wantErr: false,
		},
		{
			name: "username too short",
			user: User{
				Username: "jo",
				Email:    "john.doe@example.com",
				Password: "Pass123!@#",
			},
			wantErr:  true,
			errField: "username must be between 3 and 20 characters long",
		},
		{
			name: "username too long",
			user: User{
				Username: "johndoejohndoejohndoe123",
				Email:    "john.doe@example.com",
				Password: "Pass123!@#",
			},
			wantErr:  true,
			errField: "username must be between 3 and 20 characters long",
		},
		{
			name: "username with special characters",
			user: User{
				Username: "john@doe",
				Email:    "john.doe@example.com",
				Password: "Pass123!@#",
			},
			wantErr:  true,
			errField: "username must contain only alphanumeric characters",
		},
		{
			name: "invalid email format",
			user: User{
				Username: "johndoe123",
				Email:    "invalid.email",
				Password: "Pass123!@#",
			},
			wantErr:  true,
			errField: "invalid email format",
		},
		{
			name: "password too short",
			user: User{
				Username: "johndoe123",
				Email:    "john.doe@example.com",
				Password: "Pass1!",
			},
			wantErr:  true,
			errField: "password must be at least 8 characters long",
		},
		{
			name: "password without uppercase",
			user: User{
				Username: "johndoe123",
				Email:    "john.doe@example.com",
				Password: "password123!",
			},
			wantErr:  true,
			errField: "password must contain at least one uppercase letter",
		},
		{
			name: "password without lowercase",
			user: User{
				Username: "johndoe123",
				Email:    "john.doe@example.com",
				Password: "PASSWORD123!",
			},
			wantErr:  true,
			errField: "password must contain at least one lowercase letter",
		},
		{
			name: "password without number",
			user: User{
				Username: "johndoe123",
				Email:    "john.doe@example.com",
				Password: "Password!@#",
			},
			wantErr:  true,
			errField: "password must contain at least one number",
		},
		{
			name: "password without special character",
			user: User{
				Username: "johndoe123",
				Email:    "john.doe@example.com",
				Password: "Password123",
			},
			wantErr:  true,
			errField: "password must contain at least one special character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.user.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("User.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && err.Error() != tt.errField {
				t.Errorf("User.Validate() error message = %v, want %v", err.Error(), tt.errField)
			}
		})
	}
}

func TestUser_ValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{"valid username", "johndoe123", false},
		{"minimum length", "abc", false},
		{"maximum length", "abcdefghij1234567890", false},
		{"too short", "ab", true},
		{"too long", "abcdefghijklmnopqrstu", true},
		{"with spaces", "john doe", true},
		{"with special chars", "john@doe", true},
		{"numbers only", "12345", false},
		{"letters only", "johndoe", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{Username: tt.username}
			if err := u.validateUsername(); (err != nil) != tt.wantErr {
				t.Errorf("validateUsername() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUser_ValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid email", "test@example.com", false},
		{"valid email with subdomain", "test@sub.example.com", false},
		{"valid email with numbers", "test123@example.com", false},
		{"valid email with dots", "first.last@example.com", false},
		{"invalid email no @", "testexample.com", true},
		{"invalid email no domain", "test@", true},
		{"invalid email no username", "@example.com", true},
		{"invalid email special chars", "test!@example.com", true},
		{"invalid email no tld", "test@example", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{Email: tt.email}
			if err := u.validateEmail(); (err != nil) != tt.wantErr {
				t.Errorf("validateEmail() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUser_ValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid password", "Pass123!@#", false},
		{"minimum length with all requirements", "Pass1!@#", false},
		{"too short", "Pass1!", true},
		{"no uppercase", "pass123!@#", true},
		{"no lowercase", "PASS123!@#", true},
		{"no numbers", "Password!@#", true},
		{"no special chars", "Password123", true},
		{"only numbers", "12345678", true},
		{"only letters", "Password", true},
		{"only special chars", "!@#$%^&*()", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{Password: tt.password}
			if err := u.validatePassword(); (err != nil) != tt.wantErr {
				t.Errorf("validatePassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}