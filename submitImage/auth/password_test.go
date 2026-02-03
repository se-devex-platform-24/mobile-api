package auth

import (
	"testing"
)

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid strong password",
			password: "MyStr0ng!Pass",
			wantErr:  false,
		},
		{
			name:     "too short",
			password: "Sh0rt!",
			wantErr:  true,
		},
		{
			name:     "no uppercase",
			password: "mystr0ng!pass",
			wantErr:  true,
		},
		{
			name:     "no lowercase",
			password: "MYSTR0NG!PASS",
			wantErr:  true,
		},
		{
			name:     "no digit",
			password: "MyStrong!Pass",
			wantErr:  true,
		},
		{
			name:     "no special character",
			password: "MyStr0ngPass",
			wantErr:  true,
		},
		{
			name:     "common password",
			password: "Password123!",
			wantErr:  true,
		},
		{
			name:     "sequential characters",
			password: "MyAbc123!Pass",
			wantErr:  true,
		},
		{
			name:     "repeated characters",
			password: "MyStr000!Pass",
			wantErr:  true,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasswordStrength() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	password := "MyStr0ng!Pass"
	
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	
	if hash == "" {
		t.Error("HashPassword() returned empty hash")
	}
	
	if hash == password {
		t.Error("HashPassword() returned plaintext password")
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "MyStr0ng!Pass"
	wrongPassword := "WrongPassword123!"
	
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	
	// Test correct password
	err = VerifyPassword(password, hash)
	if err != nil {
		t.Errorf("VerifyPassword() with correct password error = %v", err)
	}
	
	// Test wrong password
	err = VerifyPassword(wrongPassword, hash)
	if err == nil {
		t.Error("VerifyPassword() with wrong password should return error")
	}
}

func TestHashPasswordWithWeakPassword(t *testing.T) {
	weakPassword := "weak"
	
	_, err := HashPassword(weakPassword)
	if err == nil {
		t.Error("HashPassword() with weak password should return error")
	}
}

func TestIsCommonPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{
			name:     "common password",
			password: "password",
			want:     true,
		},
		{
			name:     "common password uppercase",
			password: "PASSWORD",
			want:     true,
		},
		{
			name:     "common password mixed case",
			password: "Password",
			want:     true,
		},
		{
			name:     "unique password",
			password: "MyUniqueStr0ng!Pass",
			want:     false,
		},
		{
			name:     "123456",
			password: "123456",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCommonPassword(tt.password)
			if got != tt.want {
				t.Errorf("isCommonPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasSequentialChars(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{
			name:     "has sequential numbers",
			password: "pass123word",
			want:     true,
		},
		{
			name:     "has sequential letters",
			password: "passabcword",
			want:     true,
		},
		{
			name:     "has qwerty sequence",
			password: "passqweword",
			want:     true,
		},
		{
			name:     "no sequential chars",
			password: "MyStr0ng!Pass",
			want:     false,
		},
		{
			name:     "reverse sequence",
			password: "pass321word",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasSequentialChars(tt.password)
			if got != tt.want {
				t.Errorf("hasSequentialChars() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasRepeatedChars(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{
			name:     "has repeated chars",
			password: "passsword",
			want:     true,
		},
		{
			name:     "no repeated chars",
			password: "password",
			want:     false,
		},
		{
			name:     "two repeated chars (allowed)",
			password: "password",
			want:     false,
		},
		{
			name:     "three repeated chars",
			password: "passsword",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasRepeatedChars(tt.password)
			if got != tt.want {
				t.Errorf("hasRepeatedChars() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateSecurePassword(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantErr bool
	}{
		{
			name:    "valid length",
			length:  12,
			wantErr: false,
		},
		{
			name:    "minimum length",
			length:  8,
			wantErr: false,
		},
		{
			name:    "too short",
			length:  6,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := GenerateSecurePassword(tt.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSecurePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr {
				if len(password) != tt.length {
					t.Errorf("GenerateSecurePassword() length = %v, want %v", len(password), tt.length)
				}
				
				// Test that generated password passes validation
				if err := ValidatePasswordStrength(password); err != nil {
					t.Errorf("Generated password failed validation: %v", err)
				}
			}
		})
	}
}