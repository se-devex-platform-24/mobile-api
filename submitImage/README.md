# Mobile User Authentication System

A comprehensive, secure mobile user authentication system built with Go and AWS Lambda, featuring multi-factor authentication, rate limiting, session management, and comprehensive security logging.

## Features

### 🔐 Core Authentication
- **User Registration & Login**: Secure user account creation and authentication
- **Password Security**: Strong password validation with complexity requirements
- **Multi-Factor Authentication (MFA)**: TOTP-based 2FA for enhanced security
- **Session Management**: Secure JWT-based session handling with refresh tokens

### 🛡️ Security Features
- **Rate Limiting**: Prevents brute force attacks with configurable limits
- **Account Locking**: Automatic account lockout after failed login attempts
- **Password Reset**: Secure password recovery with time-limited tokens
- **Security Logging**: Comprehensive audit trail of all security events
- **Data Encryption**: Sensitive data encrypted in transit and at rest
- **IP Validation**: Real IP extraction with trusted proxy support

### 📊 Monitoring & Compliance
- **Security Auditing**: Detailed logging of all authentication events
- **Suspicious Activity Detection**: Automated detection of unusual login patterns
- **GDPR Compliance**: Privacy-focused design with data protection features
- **Real-time Monitoring**: Security event logging for incident response

## API Endpoints

### Authentication Endpoints

| Endpoint | Method | Description | Authentication Required |
|----------|--------|-------------|------------------------|
| `/auth/register` | POST | Register a new user | No |
| `/auth/login` | POST | User login | No |
| `/auth/verify-mfa` | POST | Verify MFA code | No |
| `/auth/logout` | POST | User logout | Yes |
| `/auth/refresh` | POST | Refresh access token | No |
| `/auth/forgot-password` | POST | Request password reset | No |
| `/auth/reset-password` | POST | Reset password with token | No |
| `/auth/me` | GET | Get current user info | Yes |

### Request/Response Examples

#### User Registration
```bash
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "MyStr0ng!Password",
  "firstName": "John",
  "lastName": "Doe",
  "phoneNumber": "+1234567890"
}
```

#### User Login
```bash
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "MyStr0ng!Password",
  "rememberMe": false
}
```

#### MFA Verification
```bash
POST /auth/verify-mfa
Content-Type: application/json

{
  "sessionToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "code": "123456"
}
```

## Security Requirements

### Password Policy
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character
- No common passwords
- No sequential characters
- No more than 2 consecutive identical characters

### Rate Limiting
- **Login attempts**: 5 per minute per IP
- **Password reset**: 3 per hour per IP
- **MFA verification**: 10 per minute per IP

### Account Security
- **Account lockout**: After 5 failed login attempts
- **Lockout duration**: 30 minutes
- **Session expiry**: 15 minutes (access token), 7 days (refresh token)
- **Password reset token**: 1 hour expiry

## Setup and Installation

### Prerequisites
- Go 1.16 or later
- AWS CLI configured with appropriate permissions
- AWS Lambda and DynamoDB access

### Environment Variables
```bash
# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_ISSUER=mobile-auth-app

# MFA Configuration
MFA_ISSUER=Mobile Auth App

# Encryption
ENCRYPTION_KEY=your-32-byte-encryption-key-here

# AWS Configuration (handled by Lambda runtime)
AWS_REGION=us-east-1
```

### Database Setup

1. Create DynamoDB tables:
```bash
cd submitImage
chmod +x scripts/create-tables.sh
./scripts/create-tables.sh
```

This creates the following tables:
- `Users`: User account information
- `Sessions`: User sessions and refresh tokens
- `PasswordResetTokens`: Password reset tokens
- `LoginAttempts`: Login attempts for security monitoring
- `SecurityLogs`: Security events audit trail
- `ImageLabels`: Image metadata (existing functionality)

### Build and Deploy

1. Install dependencies:
```bash
cd submitImage
go mod tidy
```

2. Build the Lambda function:
```bash
GOOS=linux GOARCH=amd64 go build -o main main.go
zip deployment.zip main
```

3. Deploy to AWS Lambda:
```bash
aws lambda update-function-code \
  --function-name your-function-name \
  --zip-file fileb://deployment.zip
```

## Configuration

### JWT Configuration
- **Secret Key**: Use a strong, randomly generated secret key
- **Token Expiry**: Configure based on security requirements
- **Issuer**: Set to your application identifier

### Security Configuration
- **Trusted Proxies**: Configure IP ranges for load balancers/proxies
- **Rate Limits**: Adjust based on expected traffic patterns
- **Account Lockout**: Configure attempts and duration based on security policy

### MFA Configuration
- **Issuer Name**: Displayed in authenticator apps
- **Code Validity**: 30-second windows with 1-window tolerance for clock skew

## Security Considerations

### Production Deployment
1. **Use strong secrets**: Generate cryptographically secure JWT and encryption keys
2. **Enable HTTPS**: All communication must be encrypted in transit
3. **Configure CORS**: Restrict origins to your mobile application domains
4. **Monitor logs**: Set up alerting for security events
5. **Regular updates**: Keep dependencies updated for security patches

### Data Protection
- **PII Encryption**: Sensitive data is encrypted at rest
- **Audit Logging**: All authentication events are logged
- **Data Retention**: Implement appropriate data retention policies
- **GDPR Compliance**: Support for data deletion and export requests

### Threat Mitigation
- **Brute Force**: Rate limiting and account lockout
- **Session Hijacking**: Secure token generation and validation
- **CSRF**: Stateless JWT tokens prevent CSRF attacks
- **XSS**: Tokens should be stored securely on mobile clients

## Testing

Run the test suite:
```bash
cd submitImage
go test ./auth/... -v
```

### Test Coverage
- Password validation and hashing
- JWT token generation and validation
- MFA functionality
- Rate limiting
- Authentication service methods
- HTTP handlers

## Monitoring and Alerting

### Security Events
The system logs the following security events:
- User registration and login attempts
- Failed authentication attempts
- Account lockouts and unlocks
- Password changes and resets
- MFA events
- Suspicious activity detection
- Rate limit violations

### Recommended Alerts
- Multiple failed login attempts
- Account lockouts
- Suspicious activity patterns
- Rate limit violations
- System errors

## API Documentation

For detailed API documentation, see the OpenAPI specification in `api.yaml`.

### Authentication Flow

1. **Registration**: User creates account with strong password
2. **Login**: User authenticates with email/password
3. **MFA** (if enabled): User provides TOTP code
4. **Token Issuance**: System provides access and refresh tokens
5. **API Access**: Client uses access token for authenticated requests
6. **Token Refresh**: Client uses refresh token to get new access token

### Error Handling

The API returns consistent error responses:
```json
{
  "code": 400,
  "message": "Password does not meet security requirements",
  "details": {
    "issues": [
      "password must contain at least one uppercase letter",
      "password must contain at least one special character"
    ]
  }
}
```

## Contributing

1. Follow Go coding standards
2. Add tests for new functionality
3. Update documentation for API changes
4. Ensure security best practices are followed

## License

MIT License - see LICENSE file for details.

## Support

For security issues, please email security@yourcompany.com instead of creating public issues.

For general support, create an issue in the repository.