package user

import (
	"time"
	"github.com/google/uuid"
)

// User represents the user model for registration and authentication
type User struct {
	ID        string    `json:"id" dynamodbav:"id"`
	Email     string    `json:"email" dynamodbav:"email"`
	Password  string    `json:"password" dynamodbav:"password"`
	FirstName string    `json:"firstName" dynamodbav:"firstName"`
	LastName  string    `json:"lastName" dynamodbav:"lastName"`
	CreatedAt time.Time `json:"createdAt" dynamodbav:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt" dynamodbav:"updatedAt"`
}

// NewUser creates a new user instance with default values
func NewUser(email, password, firstName, lastName string) *User {
	now := time.Now()
	return &User{
		ID:        uuid.New().String(),
		Email:     email,
		Password:  password,  // Note: Password should be hashed before storage
		FirstName: firstName,
		LastName:  lastName,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// Validate performs basic validation on user fields
func (u *User) Validate() error {
	if u.Email == "" {
		return ErrEmailRequired
	}
	if u.Password == "" {
		return ErrPasswordRequired
	}
	if len(u.Password) < 8 {
		return ErrPasswordTooShort
	}
	return nil
}

// Common errors for user validation
var (
	ErrEmailRequired    = errors.New("email is required")
	ErrPasswordRequired = errors.New("password is required")
	ErrPasswordTooShort = errors.New("password must be at least 8 characters")
)