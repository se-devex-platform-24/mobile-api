# MFIRST Mobile User Registration API

A comprehensive mobile user registration system built with Go and AWS Lambda, featuring secure user authentication, email verification, password reset functionality, and audit logging.

## Features

### ✅ User Registration
- **Mobile-first design** with device-specific fields (device ID, type, token, app version)
- **Email verification** with secure token-based verification
- **Password strength validation** with comprehensive requirements
- **CAPTCHA integration** to prevent automated registrations
- **Duplicate email detection** with clear error messages

### ✅ Security & Validation
- **Password requirements**: Minimum 8 characters, uppercase, lowercase, number, special character
- **Email format validation** with regex patterns
- **Phone number validation** in international format
- **Device information validation** for iOS and Android
- **App version validation** with semantic versioning format
- **Rate limiting** and security headers (production)

### ✅ Email System
- **Verification emails** with branded HTML templates
- **Welcome emails** after successful verification
- **Password reset emails** with secure reset links
- **Email service abstraction** supporting SMTP and mock implementations

### ✅ Password Management
- **Secure password hashing** using bcrypt
- **Password reset workflow** with time-limited tokens
- **Account lockout protection** after failed attempts
- **Password strength enforcement** on updates

### ✅ Audit & Logging
- **Comprehensive activity logging** for all user actions
- **Registration attempt tracking** with success/failure status
- **Email verification logging** with IP address tracking
- **Password reset activity logging** for security monitoring
- **Profile update tracking** with change details

### ✅ Profile Management
- **User profile retrieval** with safe data exposure
- **Profile updates** for allowed fields
- **Device token updates** for push notifications
- **Data validation** on all profile changes

## API Endpoints

### Authentication Endpoints

#### POST `/auth/register`
Register a new mobile user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "StrongP@ss123",
  "firstName": "John",
  "lastName": "Doe",
  "phone": "+12345678901",
  "deviceId": "device-123e4567-e89b-12d3-a456-426614174000",
  "deviceType": "ios",
  "deviceToken": "fcm-token-123456789",
  "appVersion": "1.0.0",
  "captchaToken": "captcha-token-123456789"
}
```

**Response (201):**
```json
{
  "message": "Registration successful. Please check your email for verification.",
  "userId": "user-123e4567-e89b-12d3-a456-426614174000"
}
```

#### POST `/auth/verify-email`
Verify user email address with token.

**Request Body:**
```json
{
  "token": "verification-token-123456789"
}
```

#### POST `/auth/forgot-password`
Request password reset email.

**Request Body:**
```json
{
  "email": "user@example.com",
  "captchaToken": "captcha-token-123456789"
}
```

#### POST `/auth/reset-password`
Reset password using token from email.

**Request Body:**
```json
{
  "token": "reset-token-123456789",
  "newPassword": "NewStrongP@ss123"
}
```

### User Profile Endpoints

#### GET `/user/profile`
Get authenticated user's profile information.

#### PUT `/user/profile`
Update user profile information.

**Request Body:**
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "phone": "+12345678901",
  "deviceToken": "updated-fcm-token"
}
```

### Legacy Endpoints

#### POST `/submit-image`
Process image uploads (existing functionality maintained).

## Architecture

### Components

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   API Gateway   │────│  Lambda Function │────│   DynamoDB      │
│                 │    │                  │    │                 │
│ - CORS Support  │    │ - User Mgmt      │    │ - Users Table   │
│ - Rate Limiting │    │ - Auth Logic     │    │ - Activity Logs │
│ - Validation    │    │ - Image Process  │    │ - Image Labels  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                       ┌────────┴────────┐
                       │                 │
                ┌──────▼──────┐   ┌──────▼──────┐
                │ Email Service│   │ S3 Storage  │
                │             │   │             │
                │ - SMTP      │   │ - Images    │
                │ - Templates │   │ - Encryption│
                └─────────────┘   └─────────────┘
```

## Development Setup

### Prerequisites
- Go 1.19+
- AWS CLI configured
- SAM CLI installed
- Docker (for local testing)

### Local Development

1. **Clone the repository:**
```bash
git clone <repository-url>
cd submit-image
```

2. **Install dependencies:**
```bash
cd submitImage
go mod tidy
```

3. **Set up environment variables:**
```bash
export ENVIRONMENT=development
export USERS_TABLE=Users-dev
export ACTIVITY_LOGS_TABLE=ActivityLogs-dev
export CAPTCHA_ENABLED=false
```

4. **Run tests:**
```bash
go test ./...
```

5. **Build and test locally:**
```bash
sam build
sam local start-api
```

### Testing the API

#### Register a new user:
```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "StrongP@ss123",
    "firstName": "Test",
    "lastName": "User",
    "deviceId": "test-device-123",
    "deviceType": "ios",
    "deviceToken": "test-token-123",
    "appVersion": "1.0.0",
    "captchaToken": "test-captcha"
  }'
```

#### Verify email (check logs for token):
```bash
curl -X POST http://localhost:3000/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{"token": "verification-token-from-logs"}'
```

## Deployment

### Environment Configuration

The application supports three environments: `development`, `staging`, and `production`.

#### Deploy to Development:
```bash
sam build
sam deploy --parameter-overrides Environment=development
```

#### Deploy to Staging:
```bash
sam build
sam deploy --parameter-overrides Environment=staging --config-env staging
```

#### Deploy to Production:
```bash
sam build
sam deploy --parameter-overrides Environment=production --config-env production
```

### Environment Variables

Configure these in AWS Systems Manager Parameter Store:

#### Required Parameters:
- `/mfirst/{environment}/smtp-host`
- `/mfirst/{environment}/smtp-username`
- `/mfirst/{environment}/smtp-password` (SecureString)
- `/mfirst/{environment}/smtp-from`
- `/mfirst/{environment}/recaptcha-secret` (SecureString)
- `/mfirst/{environment}/recaptcha-site-key`
- `/mfirst/{environment}/captcha-enabled`
- `/mfirst/{environment}/jwt-secret` (SecureString)

#### Example Parameter Setup:
```bash
# SMTP Configuration
aws ssm put-parameter --name "/mfirst/production/smtp-host" --value "smtp.sendgrid.net" --type "String"
aws ssm put-parameter --name "/mfirst/production/smtp-username" --value "apikey" --type "String"
aws ssm put-parameter --name "/mfirst/production/smtp-password" --value "your-sendgrid-api-key" --type "SecureString"
aws ssm put-parameter --name "/mfirst/production/smtp-from" --value "noreply@mfirst.com" --type "String"

# CAPTCHA Configuration
aws ssm put-parameter --name "/mfirst/production/recaptcha-secret" --value "your-recaptcha-secret" --type "SecureString"
aws ssm put-parameter --name "/mfirst/production/recaptcha-site-key" --value "your-recaptcha-site-key" --type "String"
aws ssm put-parameter --name "/mfirst/production/captcha-enabled" --value "true" --type "String"

# Security Configuration
aws ssm put-parameter --name "/mfirst/production/jwt-secret" --value "your-jwt-secret-key" --type "SecureString"
```

## Security Considerations

### Password Security
- **Bcrypt hashing** with default cost factor
- **Minimum 8 characters** with complexity requirements
- **Account lockout** after 5 failed attempts (30-minute lockout)
- **Password reset tokens** expire after 24 hours

### Data Protection
- **DynamoDB encryption** at rest enabled
- **S3 bucket encryption** with AES-256
- **Sensitive data exclusion** from logs and responses
- **HTTPS enforcement** for all API endpoints

### Access Control
- **IAM policies** with least privilege access
- **VPC endpoints** for DynamoDB and S3 access (production)
- **API Gateway throttling** and rate limiting
- **CORS configuration** for web client access

### Monitoring & Auditing
- **CloudWatch logging** with structured log format
- **Activity logging** for all user actions
- **Failed login tracking** with IP address logging
- **Email delivery tracking** for verification workflows

## Error Handling

### Error Response Format
```json
{
  "error": "ERROR_CODE",
  "message": "Human-readable error message",
  "details": ["Additional error details"]
}
```

### Common Error Codes
- `INVALID_EMAIL`: Email format validation failed
- `INVALID_PASSWORD`: Password strength requirements not met
- `EMAIL_EXISTS`: Email address already registered
- `INVALID_CAPTCHA`: CAPTCHA verification failed
- `INVALID_TOKEN`: Verification or reset token invalid/expired
- `USER_NOT_FOUND`: User account not found
- `ACCOUNT_LOCKED`: Account temporarily locked due to failed attempts

## Monitoring & Observability

### CloudWatch Metrics
- **Registration success/failure rates**
- **Email verification completion rates**
- **Password reset request volumes**
- **API response times and error rates**

### Logging
- **Structured JSON logging** for easy parsing
- **Request/response correlation IDs**
- **User activity tracking** with anonymized data
- **Error logging** with stack traces (development only)

### Alerting
- **High error rate alerts** for registration failures
- **Email delivery failure notifications**
- **Unusual activity pattern detection**
- **Performance degradation alerts**

## Contributing

### Code Style
- Follow Go standard formatting (`gofmt`)
- Use meaningful variable and function names
- Add comments for exported functions
- Write unit tests for new functionality

### Testing
- **Unit tests** for all business logic
- **Integration tests** for API endpoints
- **Mock implementations** for external services
- **Test coverage** minimum 80%

### Pull Request Process
1. Create feature branch from `main`
2. Implement changes with tests
3. Update documentation as needed
4. Submit pull request with description
5. Address review feedback
6. Merge after approval

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions or issues:
- **Email**: support@mfirst.com
- **Documentation**: [API Documentation](https://docs.mfirst.com)
- **Issues**: Create GitHub issue with detailed description
