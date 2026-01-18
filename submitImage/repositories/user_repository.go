package repositories

import (
	"context"
	"errors"
	"fmt"
	"submit-image/models"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
)

// UserRepository handles all database operations for user management
type UserRepository struct {
	db        dynamodbiface.DynamoDBAPI
	tableName string
}

// NewUserRepository creates a new UserRepository instance
func NewUserRepository(db dynamodbiface.DynamoDBAPI, tableName string) *UserRepository {
	return &UserRepository{
		db:        db,
		tableName: tableName,
	}
}

// Create inserts a new user into the database
func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	user.BeforeCreate()

	item, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.tableName),
		Item:      item,
		ConditionExpression: aws.String("attribute_not_exists(id) AND attribute_not_exists(email)"),
	}

	_, err = r.db.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// FindByEmail retrieves a user by their email address
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(r.tableName),
		IndexName:              aws.String("email-index"),
		KeyConditionExpression: aws.String("email = :email"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":email": {
				S: aws.String(email),
			},
		},
	}

	result, err := r.db.QueryWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to query user by email: %w", err)
	}

	if len(result.Items) == 0 {
		return nil, errors.New("user not found")
	}

	var user models.User
	err = dynamodbattribute.UnmarshalMap(result.Items[0], &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return &user, nil
}

// FindByID retrieves a user by their ID
func (r *UserRepository) FindByID(ctx context.Context, id string) (*models.User, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(id),
			},
		},
	}

	result, err := r.db.GetItemWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	if result.Item == nil {
		return nil, errors.New("user not found")
	}

	var user models.User
	err = dynamodbattribute.UnmarshalMap(result.Item, &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return &user, nil
}

// Update updates an existing user's information
func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	user.BeforeUpdate()

	item, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.tableName),
		Item:      item,
		ConditionExpression: aws.String("attribute_exists(id)"),
	}

	_, err = r.db.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// UpdatePassword updates a user's password
func (r *UserRepository) UpdatePassword(ctx context.Context, userID, hashedPassword string) error {
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(userID),
			},
		},
		UpdateExpression: aws.String("SET password = :password, updated_at = :updated_at, reset_token = :null, reset_token_expiry = :null"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":password": {
				S: aws.String(hashedPassword),
			},
			":updated_at": {
				S: aws.String(time.Now().Format(time.RFC3339)),
			},
			":null": {
				NULL: aws.Bool(true),
			},
		},
		ConditionExpression: aws.String("attribute_exists(id)"),
	}

	_, err := r.db.UpdateItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// UpdateVerificationStatus updates a user's email verification status
func (r *UserRepository) UpdateVerificationStatus(ctx context.Context, userID string, verified bool) error {
	status := models.UserStatusActive
	if !verified {
		status = models.UserStatusPending
	}

	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(userID),
			},
		},
		UpdateExpression: aws.String("SET email_verified = :verified, user_status = :status, verification_token = :null, updated_at = :updated_at"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":verified": {
				BOOL: aws.Bool(verified),
			},
			":status": {
				S: aws.String(string(status)),
			},
			":null": {
				NULL: aws.Bool(true),
			},
			":updated_at": {
				S: aws.String(time.Now().Format(time.RFC3339)),
			},
		},
		ConditionExpression: aws.String("attribute_exists(id)"),
	}

	_, err := r.db.UpdateItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update verification status: %w", err)
	}

	return nil
}

// UpdateResetToken updates a user's password reset token and expiry
func (r *UserRepository) UpdateResetToken(ctx context.Context, userID, token string, expiry time.Time) error {
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(userID),
			},
		},
		UpdateExpression: aws.String("SET reset_token = :token, reset_token_expiry = :expiry, updated_at = :updated_at"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":token": {
				S: aws.String(token),
			},
			":expiry": {
				S: aws.String(expiry.Format(time.RFC3339)),
			},
			":updated_at": {
				S: aws.String(time.Now().Format(time.RFC3339)),
			},
		},
		ConditionExpression: aws.String("attribute_exists(id)"),
	}

	_, err := r.db.UpdateItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update reset token: %w", err)
	}

	return nil
}

// FindByVerificationToken retrieves a user by their verification token
func (r *UserRepository) FindByVerificationToken(ctx context.Context, token string) (*models.User, error) {
	input := &dynamodb.ScanInput{
		TableName:        aws.String(r.tableName),
		FilterExpression: aws.String("verification_token = :token"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":token": {
				S: aws.String(token),
			},
		},
	}

	result, err := r.db.ScanWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to scan for verification token: %w", err)
	}

	if len(result.Items) == 0 {
		return nil, errors.New("invalid verification token")
	}

	var user models.User
	err = dynamodbattribute.UnmarshalMap(result.Items[0], &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return &user, nil
}

// FindByResetToken retrieves a user by their password reset token
func (r *UserRepository) FindByResetToken(ctx context.Context, token string) (*models.User, error) {
	input := &dynamodb.ScanInput{
		TableName:        aws.String(r.tableName),
		FilterExpression: aws.String("reset_token = :token AND reset_token_expiry > :now"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":token": {
				S: aws.String(token),
			},
			":now": {
				S: aws.String(time.Now().Format(time.RFC3339)),
			},
		},
	}

	result, err := r.db.ScanWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to scan for reset token: %w", err)
	}

	if len(result.Items) == 0 {
		return nil, errors.New("invalid or expired reset token")
	}

	var user models.User
	err = dynamodbattribute.UnmarshalMap(result.Items[0], &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return &user, nil
}

// UpdateLastLogin updates the user's last login timestamp and IP
func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID, ipAddress string) error {
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(userID),
			},
		},
		UpdateExpression: aws.String("SET last_login_at = :login_time, last_login_ip = :ip, updated_at = :updated_at"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":login_time": {
				S: aws.String(time.Now().Format(time.RFC3339)),
			},
			":ip": {
				S: aws.String(ipAddress),
			},
			":updated_at": {
				S: aws.String(time.Now().Format(time.RFC3339)),
			},
		},
		ConditionExpression: aws.String("attribute_exists(id)"),
	}

	_, err := r.db.UpdateItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// UpdateFailedLoginCount updates the failed login count and lockout status
func (r *UserRepository) UpdateFailedLoginCount(ctx context.Context, userID string, count int, lockoutUntil *time.Time) error {
	updateExpression := "SET failed_login_count = :count, updated_at = :updated_at"
	expressionAttributeValues := map[string]*dynamodb.AttributeValue{
		":count": {
			N: aws.String(fmt.Sprintf("%d", count)),
		},
		":updated_at": {
			S: aws.String(time.Now().Format(time.RFC3339)),
		},
	}

	if lockoutUntil != nil {
		updateExpression += ", lockout_until = :lockout"
		expressionAttributeValues[":lockout"] = &dynamodb.AttributeValue{
			S: aws.String(lockoutUntil.Format(time.RFC3339)),
		}
	} else {
		updateExpression += ", lockout_until = :null"
		expressionAttributeValues[":null"] = &dynamodb.AttributeValue{
			NULL: aws.Bool(true),
		}
	}

	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(userID),
			},
		},
		UpdateExpression:          aws.String(updateExpression),
		ExpressionAttributeValues: expressionAttributeValues,
		ConditionExpression:       aws.String("attribute_exists(id)"),
	}

	_, err := r.db.UpdateItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update failed login count: %w", err)
	}

	return nil
}