# User Registration Data Validation

This project implements robust data validation for user registration in Go, ensuring secure and correct user inputs before processing registrations.

## Validation Rules

### Username Validation
- Length: 3-20 characters
- Allowed characters: Alphanumeric only (a-z, A-Z, 0-9)
- Error messages:
  - "username must be between 3 and 20 characters long"
  - "username must contain only alphanumeric characters"

### Email Validation
- Format: Follows RFC 5322 standard
- Pattern: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
- Error message: "invalid email format"

### Password Validation
- Minimum length: 8 characters
- Must contain:
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one number
  - At least one special character (punctuation or symbol)
- Error messages:
  - "password must be at least 8 characters long"
  - "password must contain at least one uppercase letter"
  - "password must contain at least one lowercase letter"
  - "password must contain at least one number"
  - "password must contain at least one special character"

## Implementation Details

### Validation Package
The validation logic is implemented in the `validation` package, which provides:
- Individual validation functions for username, email, and password
- A combined validation function `ValidateUserRegistration` for complete registration validation
- Custom `ValidationError` type for detailed error reporting

### User Model
The User struct uses struct tags for validation rules:
```go
type User struct {
    Username string `json:"username" validate:"required,min=3,max=20,alphanum"`
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required,min=8"`
}
```

### Security Features
- SQL injection prevention through input validation
- Custom error types to avoid leaking internal details
- Regular expression-based validation using Go's `regexp` package
- Unicode-aware string processing for password complexity checks

## Usage Example

```go
errors := validation.ValidateUserRegistration(username, email, password)
if len(errors) > 0 {
    // Handle validation errors
    for _, err := range errors {
        fmt.Println(err) // Will print field-specific error messages
    }
    return
}
// Proceed with registration
```

## Testing
The validation package includes comprehensive unit tests covering:
- Valid input scenarios
- Invalid input scenarios
- Edge cases
- All possible validation error conditions

Tests can be run using the standard Go test command:
```bash
go test ./...
```

## Dependencies
- Standard Go library only
  - `regexp` package for pattern matching
  - `unicode` package for character classification