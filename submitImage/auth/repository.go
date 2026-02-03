package auth

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/google/uuid"
)

const (
	// Table names
	UsersTable             = "Users"
	SessionsTable          = "Sessions"
	PasswordResetTable     = "PasswordResetTokens"
	LoginAttemptsTable     = "LoginAttempts"
	SecurityLogsTable      = "SecurityLogs"
	
	// GSI names
	UserEmailIndex         = "email-index"
	SessionUserIndex       = "user-id-index"
	LoginAttemptsEmailIndex = "email-index"
	LoginAttemptsIPIndex   = "ip-address-index"
)

// Repository handles database operations
type Repository struct {
	dynamoDB dynamodbiface.DynamoDBAPI
}

// NewRepository creates a new repository
func NewRepository(dynamoDB dynamodbiface.DynamoDBAPI) *Repository {
	return &Repository{
		dynamoDB: dynamoDB,
	}
}

// User operations

// CreateUser creates a new user in the database
func (r *Repository) CreateUser(ctx context.Context, user *User) error {
	user.ID = uuid.New().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	user.IsActive = true

	item, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(UsersTable),
		Item:      item,
		ConditionExpression: aws.String("attribute_not_exists(email)"),
	}

	_, err = r.dynamoDB.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetUserByEmail retrieves a user by email
func (r *Repository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(UsersTable),
		IndexName:              aws.String(UserEmailIndex),
		KeyConditionExpression: aws.String("email = :email"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":email": {
				S: aws.String(email),
			},
		},
	}

	result, err := r.dynamoDB.QueryWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to query user by email: %w", err)
	}

	if len(result.Items) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	var user User
	err = dynamodbattribute.UnmarshalMap(result.Items[0], &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return &user, nil
}

// GetUserByID retrieves a user by ID
func (r *Repository) GetUserByID(ctx context.Context, userID string) (*User, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String(UsersTable),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(userID),
			},
		},
	}

	result, err := r.dynamoDB.GetItemWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if result.Item == nil {
		return nil, fmt.Errorf("user not found")
	}

	var user User
	err = dynamodbattribute.UnmarshalMap(result.Item, &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return &user, nil
}

// UpdateUser updates a user in the database
func (r *Repository) UpdateUser(ctx context.Context, user *User) error {
	user.UpdatedAt = time.Now()

	item, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(UsersTable),
		Item:      item,
	}

	_, err = r.dynamoDB.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// UpdateUserFailedLogins updates the failed login count and lock status
func (r *Repository) UpdateUserFailedLogins(ctx context.Context, userID string, failedLogins int, lockedUntil time.Time) error {
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(UsersTable),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(userID),
			},
		},
		UpdateExpression: aws.String("SET failed_logins = :failed_logins, locked_until = :locked_until, updated_at = :updated_at"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":failed_logins": {
				N: aws.String(strconv.Itoa(failedLogins)),
			},
			":locked_until": {
				S: aws.String(lockedUntil.Format(time.RFC3339)),
			},
			":updated_at": {
				S: aws.String(time.Now().Format(time.RFC3339)),
			},
		},
	}

	_, err := r.dynamoDB.UpdateItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update user failed logins: %w", err)
	}

	return nil
}

// Session operations

// CreateSession creates a new session
func (r *Repository) CreateSession(ctx context.Context, session *Session) error {
	session.ID = uuid.New().String()
	session.CreatedAt = time.Now()
	session.IsActive = true

	item, err := dynamodbattribute.MarshalMap(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(SessionsTable),
		Item:      item,
	}

	_, err = r.dynamoDB.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// GetSessionByRefreshToken retrieves a session by refresh token
func (r *Repository) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*Session, error) {
	input := &dynamodb.ScanInput{
		TableName:        aws.String(SessionsTable),
		FilterExpression: aws.String("refresh_token = :refresh_token AND is_active = :is_active"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":refresh_token": {
				S: aws.String(refreshToken),
			},
			":is_active": {
				BOOL: aws.Bool(true),
			},
		},
	}

	result, err := r.dynamoDB.ScanWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to scan sessions: %w", err)
	}

	if len(result.Items) == 0 {
		return nil, fmt.Errorf("session not found")
	}

	var session Session
	err = dynamodbattribute.UnmarshalMap(result.Items[0], &session)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return &session, nil
}

// InvalidateSession invalidates a session
func (r *Repository) InvalidateSession(ctx context.Context, sessionID string) error {
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(SessionsTable),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(sessionID),
			},
		},
		UpdateExpression: aws.String("SET is_active = :is_active"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":is_active": {
				BOOL: aws.Bool(false),
			},
		},
	}

	_, err := r.dynamoDB.UpdateItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to invalidate session: %w", err)
	}

	return nil
}

// InvalidateUserSessions invalidates all sessions for a user
func (r *Repository) InvalidateUserSessions(ctx context.Context, userID string) error {
	// First, get all active sessions for the user
	input := &dynamodb.QueryInput{
		TableName:              aws.String(SessionsTable),
		IndexName:              aws.String(SessionUserIndex),
		KeyConditionExpression: aws.String("user_id = :user_id"),
		FilterExpression:       aws.String("is_active = :is_active"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":user_id": {
				S: aws.String(userID),
			},
			":is_active": {
				BOOL: aws.Bool(true),
			},
		},
	}

	result, err := r.dynamoDB.QueryWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to query user sessions: %w", err)
	}

	// Invalidate each session
	for _, item := range result.Items {
		var session Session
		err = dynamodbattribute.UnmarshalMap(item, &session)
		if err != nil {
			continue // Skip invalid items
		}

		err = r.InvalidateSession(ctx, session.ID)
		if err != nil {
			// Log error but continue with other sessions
			continue
		}
	}

	return nil
}

// Password reset operations

// CreatePasswordResetToken creates a password reset token
func (r *Repository) CreatePasswordResetToken(ctx context.Context, token *PasswordResetToken) error {
	token.ID = uuid.New().String()
	token.CreatedAt = time.Now()
	token.Used = false

	item, err := dynamodbattribute.MarshalMap(token)
	if err != nil {
		return fmt.Errorf("failed to marshal password reset token: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(PasswordResetTable),
		Item:      item,
	}

	_, err = r.dynamoDB.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create password reset token: %w", err)
	}

	return nil
}

// GetPasswordResetToken retrieves a password reset token
func (r *Repository) GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error) {
	input := &dynamodb.ScanInput{
		TableName:        aws.String(PasswordResetTable),
		FilterExpression: aws.String("token = :token AND used = :used"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":token": {
				S: aws.String(token),
			},
			":used": {
				BOOL: aws.Bool(false),
			},
		},
	}

	result, err := r.dynamoDB.ScanWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to scan password reset tokens: %w", err)
	}

	if len(result.Items) == 0 {
		return nil, fmt.Errorf("password reset token not found")
	}

	var resetToken PasswordResetToken
	err = dynamodbattribute.UnmarshalMap(result.Items[0], &resetToken)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal password reset token: %w", err)
	}

	return &resetToken, nil
}

// MarkPasswordResetTokenUsed marks a password reset token as used
func (r *Repository) MarkPasswordResetTokenUsed(ctx context.Context, tokenID string) error {
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(PasswordResetTable),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(tokenID),
			},
		},
		UpdateExpression: aws.String("SET used = :used"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":used": {
				BOOL: aws.Bool(true),
			},
		},
	}

	_, err := r.dynamoDB.UpdateItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to mark password reset token as used: %w", err)
	}

	return nil
}

// Login attempt operations

// CreateLoginAttempt creates a login attempt record
func (r *Repository) CreateLoginAttempt(ctx context.Context, attempt *LoginAttempt) error {
	attempt.ID = uuid.New().String()
	attempt.Timestamp = time.Now()

	item, err := dynamodbattribute.MarshalMap(attempt)
	if err != nil {
		return fmt.Errorf("failed to marshal login attempt: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(LoginAttemptsTable),
		Item:      item,
	}

	_, err = r.dynamoDB.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create login attempt: %w", err)
	}

	return nil
}

// GetRecentLoginAttempts retrieves recent login attempts for a user
func (r *Repository) GetRecentLoginAttempts(ctx context.Context, email string, since time.Time) ([]LoginAttempt, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(LoginAttemptsTable),
		IndexName:              aws.String(LoginAttemptsEmailIndex),
		KeyConditionExpression: aws.String("email = :email"),
		FilterExpression:       aws.String("timestamp >= :since"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":email": {
				S: aws.String(email),
			},
			":since": {
				S: aws.String(since.Format(time.RFC3339)),
			},
		},
	}

	result, err := r.dynamoDB.QueryWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to query login attempts: %w", err)
	}

	var attempts []LoginAttempt
	for _, item := range result.Items {
		var attempt LoginAttempt
		err = dynamodbattribute.UnmarshalMap(item, &attempt)
		if err != nil {
			continue // Skip invalid items
		}
		attempts = append(attempts, attempt)
	}

	return attempts, nil
}

// Security log operations

// CreateSecurityLog creates a security log entry
func (r *Repository) CreateSecurityLog(ctx context.Context, log *SecurityLog) error {
	log.ID = uuid.New().String()
	log.Timestamp = time.Now()

	item, err := dynamodbattribute.MarshalMap(log)
	if err != nil {
		return fmt.Errorf("failed to marshal security log: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(SecurityLogsTable),
		Item:      item,
	}

	_, err = r.dynamoDB.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create security log: %w", err)
	}

	return nil
}

// CleanupExpiredTokens removes expired password reset tokens
func (r *Repository) CleanupExpiredTokens(ctx context.Context) error {
	now := time.Now()
	
	input := &dynamodb.ScanInput{
		TableName:        aws.String(PasswordResetTable),
		FilterExpression: aws.String("expires_at < :now"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":now": {
				S: aws.String(now.Format(time.RFC3339)),
			},
		},
	}

	result, err := r.dynamoDB.ScanWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to scan expired tokens: %w", err)
	}

	// Delete expired tokens
	for _, item := range result.Items {
		var token PasswordResetToken
		err = dynamodbattribute.UnmarshalMap(item, &token)
		if err != nil {
			continue
		}

		deleteInput := &dynamodb.DeleteItemInput{
			TableName: aws.String(PasswordResetTable),
			Key: map[string]*dynamodb.AttributeValue{
				"id": {
					S: aws.String(token.ID),
				},
			},
		}

		_, err = r.dynamoDB.DeleteItemWithContext(ctx, deleteInput)
		if err != nil {
			// Log error but continue
			continue
		}
	}

	return nil
}

// CleanupExpiredSessions removes expired sessions
func (r *Repository) CleanupExpiredSessions(ctx context.Context) error {
	now := time.Now()
	
	input := &dynamodb.ScanInput{
		TableName:        aws.String(SessionsTable),
		FilterExpression: aws.String("expires_at < :now"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":now": {
				S: aws.String(now.Format(time.RFC3339)),
			},
		},
	}

	result, err := r.dynamoDB.ScanWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to scan expired sessions: %w", err)
	}

	// Delete expired sessions
	for _, item := range result.Items {
		var session Session
		err = dynamodbattribute.UnmarshalMap(item, &session)
		if err != nil {
			continue
		}

		deleteInput := &dynamodb.DeleteItemInput{
			TableName: aws.String(SessionsTable),
			Key: map[string]*dynamodb.AttributeValue{
				"id": {
					S: aws.String(session.ID),
				},
			},
		}

		_, err = r.dynamoDB.DeleteItemWithContext(ctx, deleteInput)
		if err != nil {
			// Log error but continue
			continue
		}
	}

	return nil
}