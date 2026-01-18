package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/google/uuid"
)

// ActivityType represents different types of user activities that can be logged
type ActivityType string

const (
	// User registration related activities
	ActivityUserRegistration  ActivityType = "USER_REGISTRATION"
	ActivityEmailVerification ActivityType = "EMAIL_VERIFICATION"
	ActivityPasswordReset     ActivityType = "PASSWORD_RESET"
	ActivityProfileUpdate     ActivityType = "PROFILE_UPDATE"
	ActivityLoginAttempt      ActivityType = "LOGIN_ATTEMPT"
	ActivityPasswordChange    ActivityType = "PASSWORD_CHANGE"
)

// ActivityLog represents a single activity log entry
type ActivityLog struct {
	ID          string                 `json:"id" dynamodb:"id"`
	Timestamp   time.Time              `json:"timestamp" dynamodb:"timestamp"`
	Type        ActivityType           `json:"type" dynamodb:"type"`
	UserID      string                 `json:"userId,omitempty" dynamodb:"user_id"`
	Email       string                 `json:"email,omitempty" dynamodb:"email"`
	IPAddress   string                 `json:"ipAddress" dynamodb:"ip_address"`
	UserAgent   string                 `json:"userAgent" dynamodb:"user_agent"`
	Status      string                 `json:"status" dynamodb:"status"`
	Details     map[string]interface{} `json:"details,omitempty" dynamodb:"details"`
	ErrorDetail string                 `json:"errorDetail,omitempty" dynamodb:"error_detail"`
	DeviceType  string                 `json:"deviceType,omitempty" dynamodb:"device_type"`
	AppVersion  string                 `json:"appVersion,omitempty" dynamodb:"app_version"`
}

// ActivityLogger handles logging of user activities
type ActivityLogger struct {
	db        dynamodbiface.DynamoDBAPI
	tableName string
}

// NewActivityLogger creates a new instance of ActivityLogger
func NewActivityLogger(db dynamodbiface.DynamoDBAPI, tableName string) *ActivityLogger {
	return &ActivityLogger{
		db:        db,
		tableName: tableName,
	}
}

// LogActivity logs a user activity with the provided details
func (l *ActivityLogger) LogActivity(ctx context.Context, log ActivityLog) error {
	// Ensure timestamp and ID are set
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now()
	}
	if log.ID == "" {
		log.ID = uuid.New().String()
	}

	// Marshal the log entry to DynamoDB format
	item, err := dynamodbattribute.MarshalMap(log)
	if err != nil {
		return fmt.Errorf("failed to marshal activity log: %v", err)
	}

	// Store in DynamoDB
	input := &dynamodb.PutItemInput{
		TableName: aws.String(l.tableName),
		Item:      item,
	}

	_, err = l.db.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to store activity log: %v", err)
	}

	// Also log to stdout for immediate visibility
	logJSON, _ := json.Marshal(log)
	log.Printf("[ACTIVITY] %s", string(logJSON))

	return nil
}

// LogRegistrationActivity logs user registration related activities
func (l *ActivityLogger) LogRegistrationActivity(ctx context.Context, userID, email, ipAddress, userAgent, deviceType, appVersion, status string, details map[string]interface{}, errorDetail string) error {
	return l.LogActivity(ctx, ActivityLog{
		Timestamp:   time.Now(),
		Type:        ActivityUserRegistration,
		UserID:      userID,
		Email:       email,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		DeviceType:  deviceType,
		AppVersion:  appVersion,
		Status:      status,
		Details:     details,
		ErrorDetail: errorDetail,
	})
}

// LogEmailVerification logs email verification activities
func (l *ActivityLogger) LogEmailVerification(ctx context.Context, userID, email, ipAddress, status string, errorDetail string) error {
	return l.LogActivity(ctx, ActivityLog{
		Timestamp:   time.Now(),
		Type:        ActivityEmailVerification,
		UserID:      userID,
		Email:       email,
		IPAddress:   ipAddress,
		Status:      status,
		ErrorDetail: errorDetail,
	})
}

// LogPasswordReset logs password reset activities
func (l *ActivityLogger) LogPasswordReset(ctx context.Context, userID, email, ipAddress, status string, errorDetail string) error {
	return l.LogActivity(ctx, ActivityLog{
		Timestamp:   time.Now(),
		Type:        ActivityPasswordReset,
		UserID:      userID,
		Email:       email,
		IPAddress:   ipAddress,
		Status:      status,
		ErrorDetail: errorDetail,
	})
}

// LogProfileUpdate logs user profile update activities
func (l *ActivityLogger) LogProfileUpdate(ctx context.Context, userID, email, ipAddress, status string, details map[string]interface{}, errorDetail string) error {
	return l.LogActivity(ctx, ActivityLog{
		Timestamp:   time.Now(),
		Type:        ActivityProfileUpdate,
		UserID:      userID,
		Email:       email,
		IPAddress:   ipAddress,
		Status:      status,
		Details:     details,
		ErrorDetail: errorDetail,
	})
}

// LogLoginAttempt logs user login attempts
func (l *ActivityLogger) LogLoginAttempt(ctx context.Context, userID, email, ipAddress, userAgent, deviceType, appVersion, status string, errorDetail string) error {
	return l.LogActivity(ctx, ActivityLog{
		Timestamp:   time.Now(),
		Type:        ActivityLoginAttempt,
		UserID:      userID,
		Email:       email,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		DeviceType:  deviceType,
		AppVersion:  appVersion,
		Status:      status,
		ErrorDetail: errorDetail,
	})
}

// GetUserActivities retrieves activity logs for a specific user
func (l *ActivityLogger) GetUserActivities(ctx context.Context, userID string, limit int) ([]ActivityLog, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(l.tableName),
		IndexName:              aws.String("user-id-timestamp-index"),
		KeyConditionExpression: aws.String("user_id = :user_id"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":user_id": {
				S: aws.String(userID),
			},
		},
		ScanIndexForward: aws.Bool(false), // Sort by timestamp descending
		Limit:            aws.Int64(int64(limit)),
	}

	result, err := l.db.QueryWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to query user activities: %w", err)
	}

	var activities []ActivityLog
	for _, item := range result.Items {
		var activity ActivityLog
		err := dynamodbattribute.UnmarshalMap(item, &activity)
		if err != nil {
			log.Printf("[ACTIVITY ERROR] Failed to unmarshal activity: %v", err)
			continue
		}
		activities = append(activities, activity)
	}

	return activities, nil
}

// GetActivitiesByType retrieves activity logs by type within a time range
func (l *ActivityLogger) GetActivitiesByType(ctx context.Context, activityType ActivityType, startTime, endTime time.Time, limit int) ([]ActivityLog, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(l.tableName),
		IndexName:              aws.String("type-timestamp-index"),
		KeyConditionExpression: aws.String("#type = :type AND #timestamp BETWEEN :start_time AND :end_time"),
		ExpressionAttributeNames: map[string]*string{
			"#type":      aws.String("type"),
			"#timestamp": aws.String("timestamp"),
		},
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":type": {
				S: aws.String(string(activityType)),
			},
			":start_time": {
				S: aws.String(startTime.Format(time.RFC3339)),
			},
			":end_time": {
				S: aws.String(endTime.Format(time.RFC3339)),
			},
		},
		ScanIndexForward: aws.Bool(false), // Sort by timestamp descending
		Limit:            aws.Int64(int64(limit)),
	}

	result, err := l.db.QueryWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to query activities by type: %w", err)
	}

	var activities []ActivityLog
	for _, item := range result.Items {
		var activity ActivityLog
		err := dynamodbattribute.UnmarshalMap(item, &activity)
		if err != nil {
			log.Printf("[ACTIVITY ERROR] Failed to unmarshal activity: %v", err)
			continue
		}
		activities = append(activities, activity)
	}

	return activities, nil
}

// MockActivityLogger is a mock implementation for testing
type MockActivityLogger struct {
	Activities []ActivityLog
}

// NewMockActivityLogger creates a new mock activity logger
func NewMockActivityLogger() *MockActivityLogger {
	return &MockActivityLogger{
		Activities: make([]ActivityLog, 0),
	}
}

// LogActivity mock implementation
func (m *MockActivityLogger) LogActivity(ctx context.Context, log ActivityLog) error {
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now()
	}
	if log.ID == "" {
		log.ID = uuid.New().String()
	}
	
	m.Activities = append(m.Activities, log)
	
	// Log to stdout for visibility
	logJSON, _ := json.Marshal(log)
	log.Printf("[MOCK ACTIVITY] %s", string(logJSON))
	
	return nil
}

// LogRegistrationActivity mock implementation
func (m *MockActivityLogger) LogRegistrationActivity(ctx context.Context, userID, email, ipAddress, userAgent, deviceType, appVersion, status string, details map[string]interface{}, errorDetail string) error {
	return m.LogActivity(ctx, ActivityLog{
		Type:        ActivityUserRegistration,
		UserID:      userID,
		Email:       email,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		DeviceType:  deviceType,
		AppVersion:  appVersion,
		Status:      status,
		Details:     details,
		ErrorDetail: errorDetail,
	})
}

// LogEmailVerification mock implementation
func (m *MockActivityLogger) LogEmailVerification(ctx context.Context, userID, email, ipAddress, status string, errorDetail string) error {
	return m.LogActivity(ctx, ActivityLog{
		Type:        ActivityEmailVerification,
		UserID:      userID,
		Email:       email,
		IPAddress:   ipAddress,
		Status:      status,
		ErrorDetail: errorDetail,
	})
}

// LogPasswordReset mock implementation
func (m *MockActivityLogger) LogPasswordReset(ctx context.Context, userID, email, ipAddress, status string, errorDetail string) error {
	return m.LogActivity(ctx, ActivityLog{
		Type:        ActivityPasswordReset,
		UserID:      userID,
		Email:       email,
		IPAddress:   ipAddress,
		Status:      status,
		ErrorDetail: errorDetail,
	})
}

// LogProfileUpdate mock implementation
func (m *MockActivityLogger) LogProfileUpdate(ctx context.Context, userID, email, ipAddress, status string, details map[string]interface{}, errorDetail string) error {
	return m.LogActivity(ctx, ActivityLog{
		Type:        ActivityProfileUpdate,
		UserID:      userID,
		Email:       email,
		IPAddress:   ipAddress,
		Status:      status,
		Details:     details,
		ErrorDetail: errorDetail,
	})
}

// LogLoginAttempt mock implementation
func (m *MockActivityLogger) LogLoginAttempt(ctx context.Context, userID, email, ipAddress, userAgent, deviceType, appVersion, status string, errorDetail string) error {
	return m.LogActivity(ctx, ActivityLog{
		Type:        ActivityLoginAttempt,
		UserID:      userID,
		Email:       email,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		DeviceType:  deviceType,
		AppVersion:  appVersion,
		Status:      status,
		ErrorDetail: errorDetail,
	})
}

// Reset clears all logged activities (useful for testing)
func (m *MockActivityLogger) Reset() {
	m.Activities = make([]ActivityLog, 0)
}

// GetActivityCount returns the number of logged activities
func (m *MockActivityLogger) GetActivityCount() int {
	return len(m.Activities)
}

// GetLastActivity returns the last logged activity
func (m *MockActivityLogger) GetLastActivity() *ActivityLog {
	if len(m.Activities) == 0 {
		return nil
	}
	return &m.Activities[len(m.Activities)-1]
}