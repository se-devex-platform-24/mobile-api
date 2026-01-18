package main

import (
	"context"
	"log"
	"os"
	"submit-image/handlers"
	"submit-image/opendevopslambda"
	"submit-image/repositories"
	"submit-image/services"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/s3"
)

func init() {
	log.SetOutput(os.Stdout)
}

// AppHandler handles all application routes
type AppHandler struct {
	imageHandler *opendevopslambda.Dependency
	authHandler  *handlers.AuthHandler
}

func main() {
	sess := session.Must(session.NewSession())

	// Initialize AWS services
	s3Client := s3.New(sess)
	dynamoClient := dynamodb.New(sess)

	// Initialize image processing dependency (existing functionality)
	imageHandler := &opendevopslambda.Dependency{
		DepS3:       s3Client,
		DepDynamoDB: dynamoClient,
	}

	// Initialize user registration components
	userRepo := repositories.NewUserRepository(dynamoClient, getEnv("USERS_TABLE", "Users"))
	
	// Initialize services
	emailConfig := services.EmailConfig{
		Host:     getEnv("SMTP_HOST", "localhost"),
		Port:     587,
		Username: getEnv("SMTP_USERNAME", ""),
		Password: getEnv("SMTP_PASSWORD", ""),
		From:     getEnv("SMTP_FROM", "noreply@mfirst.com"),
	}
	
	captchaConfig := services.CaptchaConfig{
		SecretKey: getEnv("RECAPTCHA_SECRET_KEY", ""),
		SiteKey:   getEnv("RECAPTCHA_SITE_KEY", ""),
		Enabled:   getEnv("CAPTCHA_ENABLED", "false") == "true",
	}

	// Use mock services for development/testing
	var emailService services.EmailService
	var captchaService services.CaptchaService
	var activityLogger handlers.ActivityLogger

	if getEnv("ENVIRONMENT", "development") == "production" {
		emailService = services.NewEmailService(emailConfig)
		captchaService = services.NewCaptchaService(captchaConfig)
		activityLogger = services.NewActivityLogger(dynamoClient, getEnv("ACTIVITY_LOGS_TABLE", "ActivityLogs"))
	} else {
		// Use mock services for development
		emailService = services.NewMockEmailService()
		captchaService = services.NewMockCaptchaService(false)
		activityLogger = services.NewMockActivityLogger()
	}

	logger := &services.SimpleLogger{}
	authService := services.NewAuthService(userRepo, emailService, captchaService, logger)
	authHandler := handlers.NewAuthHandler(authService, activityLogger)

	// Initialize main app handler
	appHandler := &AppHandler{
		imageHandler: imageHandler,
		authHandler:  authHandler,
	}

	lambda.Start(appHandler.Handler)
}

// Handler routes requests to appropriate handlers based on path
func (app *AppHandler) Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("[REQUEST] %s %s", request.HTTPMethod, request.Path)

	// Handle CORS preflight requests
	if request.HTTPMethod == "OPTIONS" {
		return events.APIGatewayProxyResponse{
			StatusCode: 200,
			Headers: map[string]string{
				"Access-Control-Allow-Origin":  "*",
				"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
				"Access-Control-Allow-Headers": "Content-Type, Authorization",
			},
		}, nil
	}

	// Route based on path
	switch {
	case request.Path == "/auth/register" && request.HTTPMethod == "POST":
		return app.authHandler.HandleRegister(ctx, request)
	case request.Path == "/auth/verify-email" && request.HTTPMethod == "POST":
		return app.authHandler.HandleVerifyEmail(ctx, request)
	case request.Path == "/auth/forgot-password" && request.HTTPMethod == "POST":
		return app.authHandler.HandleForgotPassword(ctx, request)
	case request.Path == "/auth/reset-password" && request.HTTPMethod == "POST":
		return app.authHandler.HandleResetPassword(ctx, request)
	case request.Path == "/user/profile" && request.HTTPMethod == "GET":
		return app.authHandler.HandleGetProfile(ctx, request)
	case request.Path == "/user/profile" && request.HTTPMethod == "PUT":
		return app.authHandler.HandleUpdateProfile(ctx, request)
	case request.Path == "/submit-image" && request.HTTPMethod == "POST":
		// Existing image processing functionality
		return app.imageHandler.Handler(ctx, request)
	default:
		return events.APIGatewayProxyResponse{
			StatusCode: 404,
			Headers: map[string]string{
				"Content-Type":                 "application/json",
				"Access-Control-Allow-Origin":  "*",
				"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
				"Access-Control-Allow-Headers": "Content-Type, Authorization",
			},
			Body: `{"error":"NOT_FOUND","message":"Endpoint not found"}`,
		}, nil
	}
}

// getEnv gets environment variable with default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
