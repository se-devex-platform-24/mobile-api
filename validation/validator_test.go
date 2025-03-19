package validation

import (
	"testing"
)

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "Valid username",
			username: "johndoe123",
			wantErr:  false,
		},
		{
			name:     "Username too short",
			username: "jo",
			wantErr:  true,
			errMsg:   "username: must be between 3 and 20 characters long",
		},
		{
			name:     "Username too long",
			username: "thisusernameiswaytoolongtobevalid",
			wantErr:  true,
			errMsg:   "username: must be between 3 and 20 characters long",
		},
		{
			name:     "Username with special characters",
			username: "john@doe",
			wantErr:  true,
			errMsg:   "username: must contain only alphanumeric characters",
		},
		{
			name:     "Username with spaces",
			username: "john doe",
			wantErr:  true,
			errMsg:   "username: must contain only alphanumeric characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUsername() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("ValidateUsername() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Valid email",
			email:   "test@example.com",
			wantErr: false,
		},
		{
			name:    "Valid email with subdomain",
			email:   "test@sub.example.com",
			wantErr: false,
		},
		{
			name:    "Email without @",
			email:   "testexample.com",
			wantErr: true,
			errMsg:  "email: invalid email format",
		},
		{
			name:    "Email without domain",
			email:   "test@",
			wantErr: true,
			errMsg:  "email: invalid email format",
		},
		{
			name:    "Email with invalid characters",
			email:   "test!@example.com",
			wantErr: true,
			errMsg:  "email: invalid email format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("ValidateEmail() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "Valid password",
			password: "Test123!@#",
			wantErr:  false,
		},
		{
			name:     "Password too short",
			password: "Test1!",
			wantErr:  true,
			errMsg:   "password: must be at least 8 characters long",
		},
		{
			name:     "Password without uppercase",
			password: "test123!@#",
			wantErr:  true,
			errMsg:   "password: must contain at least one uppercase letter",
		},
		{
			name:     "Password without lowercase",
			password: "TEST123!@#",
			wantErr:  true,
			errMsg:   "password: must contain at least one lowercase letter",
		},
		{
			name:     "Password without number",
			password: "TestTest!@#",
			wantErr:  true,
			errMsg:   "password: must contain at least one number",
		},
		{
			name:     "Password without special character",
			password: "TestTest123",
			wantErr:  true,
			errMsg:   "password: must contain at least one special character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("ValidatePassword() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestValidateUserRegistration(t *testing.T) {
	tests := []struct {
		name     string
		username string
		email    string
		password string
		wantErr  bool
		errCount int
	}{
		{
			name:     "Valid registration",
			username: "johndoe123",
			email:    "john@example.com",
			password: "Test123!@#",
			wantErr:  false,
		},
		{
			name:     "All fields invalid",
			username: "j",
			email:    "notanemail",
			password: "weak",
			wantErr:  true,
			errCount: 3,
		},
		{
			name:     "Invalid username only",
			username: "j",
			email:    "john@example.com",
			password: "Test123!@#",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "Invalid email only",
			username: "johndoe123",
			email:    "notanemail",
			password: "Test123!@#",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "Invalid password only",
			username: "johndoe123",
			email:    "john@example.com",
			password: "weak",
			wantErr:  true,
			errCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := ValidateUserRegistration(tt.username, tt.email, tt.password)
			if (len(errors) > 0) != tt.wantErr {
				t.Errorf("ValidateUserRegistration() got %v errors, wantErr %v", len(errors), tt.wantErr)
				return
			}
			if tt.wantErr && len(errors) != tt.errCount {
				t.Errorf("ValidateUserRegistration() got %v errors, want %v errors", len(errors), tt.errCount)
			}
		})
	}
}