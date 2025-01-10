package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Dependency struct {
	DepDynamoDB dynamodbiface.DynamoDBAPI
}

type UserRegistration struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type UserResponse struct {
	UserId    string `json:"userId"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

func isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func isValidPassword(password string) bool {
	return len(password) >= 8
}

func (d *Dependency) checkEmailExists(email string) (bool, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String("Users"),
		Key: map[string]*dynamodb.AttributeValue{
			"Email": {
				S: aws.String(email),
			},
		},
	}

	result, err := d.DepDynamoDB.GetItem(input)
	if err != nil {
		return false, err
	}

	return len(result.Item) > 0, nil
}

func (d *Dependency) registerUser(user UserRegistration) (*UserResponse, error) {
	// Generate UUID for the user
	userId, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create DynamoDB item
	input := &dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{
			"UserId": {
				S: aws.String(userId.String()),
			},
			"Email": {
				S: aws.String(user.Email),
			},
			"Password": {
				B: hashedPassword,
			},
			"FirstName": {
				S: aws.String(user.FirstName),
			},
			"LastName": {
				S: aws.String(user.LastName),
			},
			"CreatedAt": {
				S: aws.String(time.Now().UTC().Format(time.RFC3339)),
			},
		},
		TableName:           aws.String("Users"),
		ConditionExpression: aws.String("attribute_not_exists(Email)"),
	}

	_, err = d.DepDynamoDB.PutItem(input)
	if err != nil {
		return nil, err
	}

	return &UserResponse{
		UserId:    userId.String(),
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}, nil
}

func (d *Dependency) Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Only handle POST requests
	if request.HTTPMethod != "POST" {
		return events.APIGatewayProxyResponse{
			StatusCode: 405,
			Body:      `{"error": "Method not allowed"}`,
		}, nil
	}

	// Parse request body
	var userReg UserRegistration
	if err := json.Unmarshal([]byte(request.Body), &userReg); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:      `{"error": "Invalid request body"}`,
		}, nil
	}

	// Validate input
	if !isValidEmail(userReg.Email) {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:      `{"error": "Invalid email format"}`,
		}, nil
	}

	if !isValidPassword(userReg.Password) {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:      `{"error": "Password must be at least 8 characters long"}`,
		}, nil
	}

	if userReg.FirstName == "" || userReg.LastName == "" {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:      `{"error": "First name and last name are required"}`,
		}, nil
	}

	// Check if email already exists
	exists, err := d.checkEmailExists(userReg.Email)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:      `{"error": "Internal server error"}`,
		}, err
	}
	if exists {
		return events.APIGatewayProxyResponse{
			StatusCode: 409,
			Body:      `{"error": "Email already registered"}`,
		}, nil
	}

	// Register the user
	response, err := d.registerUser(userReg)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:      `{"error": "Failed to register user"}`,
		}, err
	}

	// Convert response to JSON
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:      `{"error": "Failed to generate response"}`,
		}, err
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 201,
		Body:      string(jsonResponse),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}, nil
}