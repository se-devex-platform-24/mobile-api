package main

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/s3"
	"log"
	"os"
	"submit-image/auth"
	"submit-image/opendevopslambda"

	"github.com/aws/aws-lambda-go/lambda"
)

func init() {
	log.SetOutput(os.Stdout)
}

func main() {
	sess := session.Must(session.NewSession())

	// Initialize AWS services
	s3Client := s3.New(sess)
	dynamoClient := dynamodb.New(sess)

	// Initialize authentication service
	authConfig := &auth.AuthServiceConfig{
		JWTSecret:      []byte(getEnvOrDefault("JWT_SECRET", "your-super-secret-jwt-key-change-in-production")),
		JWTIssuer:      getEnvOrDefault("JWT_ISSUER", "mobile-auth-app"),
		MFAIssuer:      getEnvOrDefault("MFA_ISSUER", "Mobile Auth App"),
		TrustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}, // Common private networks
		EncryptionKey:  []byte(getEnvOrDefault("ENCRYPTION_KEY", "your-32-byte-encryption-key-here")),
	}

	authService := auth.NewAuthService(dynamoClient, authConfig)
	authHandlers := auth.NewAuthHandlers(authService)

	// Initialize main application dependency
	d := opendevopslambda.Dependency{
		DepS3:        s3Client,
		DepDynamoDB:  dynamoClient,
		AuthHandlers: authHandlers,
	}

	lambda.Start(d.Handler)
}

// getEnvOrDefault gets environment variable or returns default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
